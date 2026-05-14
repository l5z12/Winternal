// `winternal ntfs *` — NTFS monitoring + analyzing.
//
// User-mode FSCTL paths for convenience (volumes, USN journal, MFT enum,
// alternate data streams, dir-vs-MFT hide compare) live in
// WinternalCore/Ntfs.{h,cpp}. The driver-backed raw read goes through
// IOCTL_WINTERNAL_NTFS_RAW_READ to bypass every minifilter and user-mode
// hook in the device stack — that's what `ntfs raw` exercises.

#include "WinternalCore.h"
#include "../Winternal/Public.h"
#include "WClap.h"
#include <cstdio>
#include <cstring>

using namespace winternal;

namespace winternal {

namespace {

constexpr uint32_t REASON_ALL = 0xFFFFFFFF;

void PrintFileTime(int64_t ft) {
    if (!ft) { wprintf(L"-                  "); return; }
    FILETIME f{ (DWORD)ft, (DWORD)(ft >> 32) };
    SYSTEMTIME u{}, s{};
    if (::FileTimeToSystemTime(&f, &u) && ::SystemTimeToTzSpecificLocalTime(nullptr, &u, &s)) {
        wprintf(L"%04u-%02u-%02u %02u:%02u:%02u",
                s.wYear, s.wMonth, s.wDay, s.wHour, s.wMinute, s.wSecond);
    } else {
        wprintf(L"%19lld", (long long)ft);
    }
}

const wchar_t* ReasonString(uint32_t r) {
    // Most prominent reason wins; the bitmask can carry several but the
    // dominant one is informative enough for a CLI table.
    if (r & 0x00000200) return L"DELETE";       // USN_REASON_FILE_DELETE
    if (r & 0x00000100) return L"CREATE";       // USN_REASON_FILE_CREATE
    if (r & 0x00001000) return L"RENAME_NEW";   // RENAME_NEW_NAME
    if (r & 0x00000800) return L"RENAME_OLD";   // RENAME_OLD_NAME
    if (r & 0x00000001) return L"DATA_OVERWR";  // DATA_OVERWRITE
    if (r & 0x00000002) return L"DATA_EXTEND";  // DATA_EXTEND
    if (r & 0x00000004) return L"DATA_TRUNC";   // DATA_TRUNCATION
    if (r & 0x00000010) return L"NAMED_OVERWR"; // NAMED_DATA_OVERWRITE
    if (r & 0x00010000) return L"BASIC_INFO";   // BASIC_INFO_CHANGE
    if (r & 0x00080000) return L"REPARSE";      // REPARSE_POINT_CHANGE
    if (r & 0x00800000) return L"CLOSE";        // CLOSE
    return L"OTHER";
}

uint64_t ParseRange(std::wstring_view s) {
    if (s.empty()) return 0;
    int base = 10;
    const wchar_t* p = s.data();
    size_t n = s.size();
    if (n > 2 && p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) { p += 2; n -= 2; base = 16; }
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) {
        wchar_t c = p[i];
        int d = -1;
        if (c >= L'0' && c <= L'9') d = c - L'0';
        else if (base == 16 && c >= L'a' && c <= L'f') d = 10 + (c - L'a');
        else if (base == 16 && c >= L'A' && c <= L'F') d = 10 + (c - L'A');
        if (d < 0) return 0;
        v = v * base + d;
    }
    return v;
}

int CmdNtfsVols() {
    auto vols = ntfsEnumerateVolumes();
    wclap::style::init();
    const wchar_t* B = wclap::style::BOLD();
    const wchar_t* U = wclap::style::UNDERLINE();
    const wchar_t* R = wclap::style::RESET();
    wprintf(L"%ls%lsLetter  FS    Label                Total      Free       Serial    MFT-LCN%ls\n", B, U, R);
    for (auto& v : vols) {
        wprintf(L"%-7ls %-5ls %-20ls %-10llu %-10llu %08X  ",
                v.driveLetter.c_str(), v.fsName.c_str(),
                v.label.empty() ? L"(no label)" : v.label.c_str(),
                (unsigned long long)v.totalBytes,
                (unsigned long long)v.freeBytes,
                v.serialNumber);
        if (v.isNtfs) wprintf(L"0x%llX (mft size %llu)",
                              (unsigned long long)v.mftStartLcn,
                              (unsigned long long)v.mftValidDataLength);
        else          wprintf(L"-");
        wprintf(L"\n");
    }
    return 0;
}

int CmdNtfsUsn(int argc, wchar_t** argv) {
    wclap::App app(L"winternal ntfs usn");
    app.about(L"Read USN journal entries (rootkit-resistant: FSCTL_READ_USN_JOURNAL bypasses NtQueryDirectoryFile-style hooks).")
       .arg(wclap::Arg(L"volume").positional().required().help(L"Drive letter, e.g. C: or C"))
       .arg(wclap::Arg(L"count").long_name(L"count").takes_value().default_value(L"256").help(L"Max records to show"))
       .arg(wclap::Arg(L"start").long_name(L"start").takes_value().help(L"Start USN (default: journal first)"))
       .arg(wclap::Arg(L"tail").long_name(L"tail").help(L"Live tail (Ctrl+C to stop)"));
    auto m = app.parse(argc, argv);
    std::wstring vol = *m.value(L"volume");
    uint32_t count   = (uint32_t)*m.value_u64(L"count");
    int64_t  start   = (int64_t)m.value_u64(L"start").value_or(0);

    auto info = ntfsQueryUsnJournal(vol);
    if (!info) {
        fwprintf(stderr, L"ntfs usn: no active journal on %ls (err %lu)\n", vol.c_str(), ::GetLastError());
        return 1;
    }
    wprintf(L"journal %llu | first=%lld next=%lld lowestValid=%lld maxSize=%llu delta=%llu\n",
            (unsigned long long)info->journalId, info->firstUsn, info->nextUsn,
            info->lowestValidUsn, info->maxSize, info->allocationDelta);

    auto printOne = [](const UsnRecord& r) {
        wprintf(L"%18lld  ", (long long)r.usn);
        PrintFileTime(r.timestampFt);
        wprintf(L"  %-14ls  %016llx  %ls\n",
                ReasonString(r.reason),
                (unsigned long long)r.fileRefNumber,
                r.fileName.c_str());
    };

    if (m.present(L"tail")) {
        wprintf(L"-- live tail (Ctrl+C to stop) --\n");
        ntfsTailUsnJournal(vol, REASON_ALL, [&](const UsnRecord& r) {
            printOne(r);
            return true;  // keep going; Ctrl+C cancels the synchronous IOCTL
        });
        return 0;
    }

    int64_t next = 0;
    auto recs = ntfsReadUsnJournal(vol, start, REASON_ALL, count, &next);
    wprintf(L"%18ls  %-19ls  %-14ls  %-16ls  %ls\n", L"USN", L"TIME", L"REASON", L"FRN", L"NAME");
    for (auto& r : recs) printOne(r);
    wprintf(L"-- %zu records; next USN = %lld --\n", recs.size(), (long long)next);
    return 0;
}

int CmdNtfsMft(int argc, wchar_t** argv) {
    wclap::App app(L"winternal ntfs mft");
    app.about(L"Walk the MFT via FSCTL_ENUM_USN_DATA — bypasses NtQueryDirectoryFile filtering.")
       .arg(wclap::Arg(L"volume").positional().required().help(L"Drive letter, e.g. C:"))
       .arg(wclap::Arg(L"limit").long_name(L"limit").takes_value().default_value(L"100").help(L"Max entries"))
       .arg(wclap::Arg(L"name").long_name(L"name").takes_value().help(L"Substring filter on file name"));
    auto m = app.parse(argc, argv);
    std::wstring vol = *m.value(L"volume");
    uint64_t limit = *m.value_u64(L"limit");
    auto needle = m.value(L"name");

    auto rec = ntfsEnumMft(vol, limit ? limit * 8 : 0);  // over-fetch for name filter
    wprintf(L"%-16ls  %-16ls  %-19ls  %ls\n", L"FRN", L"PARENT-FRN", L"TIME", L"NAME");
    uint64_t shown = 0;
    for (auto& e : rec) {
        if (needle && e.fileName.find(*needle) == std::wstring::npos) continue;
        wprintf(L"%016llx  %016llx  ", (unsigned long long)e.fileRefNumber,
                (unsigned long long)e.parentFileRefNumber);
        PrintFileTime(e.timestampFt);
        wprintf(L"  %ls\n", e.fileName.c_str());
        if (limit && ++shown >= limit) break;
    }
    return 0;
}

int CmdNtfsStreams(int argc, wchar_t** argv) {
    wclap::App app(L"winternal ntfs streams");
    app.about(L"List alternate data streams of a file (driver-routed FileStreamInformation; rootkits hide payloads in ADS).")
       .arg(wclap::Arg(L"path").positional().required().help(L"Path to inspect (Win32 form OK)"));
    auto m = app.parse(argc, argv);
    auto streams = ntfsListStreams(*m.value(L"path"));
    if (streams.empty()) { wprintf(L"(no streams found / path unreadable; err %lu)\n", ::GetLastError()); return 0; }
    wprintf(L"%14ls  %ls\n", L"SIZE", L"STREAM");
    for (auto& s : streams) {
        wprintf(L"%14llu  %ls\n", (unsigned long long)s.size,
                s.name.empty() ? L"::$DATA (primary)" : s.name.c_str());
    }
    return 0;
}

int CmdNtfsCompare(int argc, wchar_t** argv) {
    wclap::App app(L"winternal ntfs compare");
    app.about(L"Compare FindFirstFile (hookable) vs MFT walk (FSCTL). Differences = candidates for user-mode hiding.")
       .arg(wclap::Arg(L"path").positional().required().help(L"Directory root, e.g. C:\\Windows"));
    auto m = app.parse(argc, argv);
    auto hidden = ntfsCompareDirVsMft(*m.value(L"path"));
    if (hidden.empty()) { wprintf(L"no candidate hides found under %ls\n", m.value(L"path")->c_str()); return 0; }
    wprintf(L"%-16ls  %ls\n", L"FRN", L"PATH (MFT-only — invisible to FindFirstFile)");
    for (auto& h : hidden) {
        wprintf(L"%016llx  %ls\n", (unsigned long long)h.fileRefNumber, h.parentPath.c_str());
    }
    return 0;
}

int CmdNtfsRaw(int argc, wchar_t** argv) {
    wclap::App app(L"winternal ntfs raw");
    app.about(L"Driver-backed raw read from a device object. Bypasses every minifilter and user-mode hook.")
       .arg(wclap::Arg(L"device").positional().required().help(L"Device, e.g. \\Device\\HarddiskVolume3"))
       .arg(wclap::Arg(L"offset").positional().required().help(L"Byte offset (hex with 0x prefix OK)"))
       .arg(wclap::Arg(L"length").positional().required().help(L"Byte length (max 1 MiB)"));
    auto m = app.parse(argc, argv);
    std::wstring dev = *m.value(L"device");
    uint64_t off = ParseRange(*m.value(L"offset"));
    uint64_t len = ParseRange(*m.value(L"length"));
    if (len == 0 || len > WINTERNAL_NTFS_RAW_MAX) {
        fwprintf(stderr, L"ntfs raw: length must be 1..%u\n", WINTERNAL_NTFS_RAW_MAX);
        return 1;
    }
    DriverSession s;
    if (!s.open()) {
        fwprintf(stderr, L"ntfs raw: Winternal.sys not loaded (err %lu)\n", ::GetLastError());
        return 1;
    }
    auto blob = s.ntfsRawRead(dev, off, (uint32_t)len);
    if (!blob) {
        fwprintf(stderr, L"ntfs raw: read failed (err %lu)\n", ::GetLastError());
        return 1;
    }
    // Print a hexdump.
    for (size_t i = 0; i < blob->size(); i += 16) {
        wprintf(L"%016llx  ", (unsigned long long)(off + i));
        size_t row = blob->size() - i < 16 ? blob->size() - i : 16;
        for (size_t j = 0; j < 16; ++j) {
            if (j < row) wprintf(L"%02X ", (*blob)[i + j]);
            else         wprintf(L"   ");
        }
        wprintf(L" ");
        for (size_t j = 0; j < row; ++j) {
            uint8_t c = (*blob)[i + j];
            wprintf(L"%lc", (c >= 32 && c < 127) ? (wchar_t)c : L'.');
        }
        wprintf(L"\n");
    }
    wprintf(L"-- %zu bytes from %ls @ 0x%llx --\n", blob->size(), dev.c_str(), (unsigned long long)off);
    return 0;
}

} // namespace

int RunNtfsCommand(int argc, wchar_t** argv) {
    if (argc < 1) {
        fwprintf(stderr,
            L"usage: winternal ntfs <vols|usn|mft|streams|compare|raw> [args]\n"
            L"  vols                        list NTFS volumes + metadata\n"
            L"  usn <vol> [--count N] [--start U] [--tail]\n"
            L"  mft <vol> [--limit N] [--name SUBSTR]\n"
            L"  streams <path>              list alternate data streams\n"
            L"  compare <path>              FindFirstFile vs MFT diff\n"
            L"  raw <device> <off> <len>    driver-backed raw read\n");
        return 1;
    }
    std::wstring_view sub = argv[0];
    int sa = argc - 1;
    wchar_t** av = argv + 1;
    if (sub == L"vols")    return CmdNtfsVols();
    if (sub == L"usn")     return CmdNtfsUsn(sa, av);
    if (sub == L"mft")     return CmdNtfsMft(sa, av);
    if (sub == L"streams") return CmdNtfsStreams(sa, av);
    if (sub == L"compare") return CmdNtfsCompare(sa, av);
    if (sub == L"raw")     return CmdNtfsRaw(sa, av);
    fwprintf(stderr, L"ntfs: unknown subcommand: %ls\n", argv[0]);
    return 1;
}

} // namespace winternal
