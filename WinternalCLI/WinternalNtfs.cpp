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
#include <regex>

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

// USN_REASON_* bits we care about, mirrored here so we don't drag in
// the full <winioctl.h> macro forest just for naming.
constexpr uint32_t REASON_FILE_CREATE       = 0x00000100;
constexpr uint32_t REASON_FILE_DELETE       = 0x00000200;
constexpr uint32_t REASON_RENAME_OLD_NAME   = 0x00001000;
constexpr uint32_t REASON_RENAME_NEW_NAME   = 0x00002000;
constexpr uint32_t REASON_DATA_OVERWRITE    = 0x00000001;
constexpr uint32_t REASON_DATA_EXTEND       = 0x00000002;
constexpr uint32_t REASON_DATA_TRUNCATION   = 0x00000004;
constexpr uint32_t REASON_BASIC_INFO_CHANGE = 0x00008000;
constexpr uint32_t REASON_SECURITY_CHANGE   = 0x00000800;
constexpr uint32_t REASON_REPARSE_POINT     = 0x00080000;
constexpr uint32_t REASON_CLOSE             = 0x80000000;

const wchar_t* ReasonString(uint32_t r) {
    // Highest-impact reason wins; the bitmask can carry several but the
    // dominant one is informative enough for a CLI table.
    if (r & REASON_FILE_DELETE)       return L"DELETE";
    if (r & REASON_FILE_CREATE)       return L"CREATE";
    if (r & REASON_RENAME_NEW_NAME)   return L"RENAME>";
    if (r & REASON_RENAME_OLD_NAME)   return L"RENAME<";
    if (r & REASON_DATA_TRUNCATION)   return L"TRUNCATE";
    if (r & REASON_DATA_EXTEND)       return L"WRITE+";
    if (r & REASON_DATA_OVERWRITE)    return L"WRITE";
    if (r & REASON_SECURITY_CHANGE)   return L"ACL";
    if (r & REASON_BASIC_INFO_CHANGE) return L"ATTR";
    if (r & REASON_REPARSE_POINT)     return L"REPARSE";
    if (r & REASON_CLOSE)             return L"close";
    return L"other";
}

// ANSI color for the reason. Bold green creates, bold red deletes,
// cyan renames, yellow writes, dim for attr / close. Falls back to
// empty strings on non-VT terminals (style::init drives the gating).
const wchar_t* ReasonColor(uint32_t r) {
    if (!wclap::style::enabled()) return L"";
    if (r & REASON_FILE_DELETE)       return L"\x1b[1;31m";  // bold red
    if (r & REASON_FILE_CREATE)       return L"\x1b[1;32m";  // bold green
    if (r & (REASON_RENAME_NEW_NAME |
             REASON_RENAME_OLD_NAME)) return L"\x1b[36m";    // cyan
    if (r & (REASON_DATA_OVERWRITE |
             REASON_DATA_EXTEND |
             REASON_DATA_TRUNCATION)) return L"\x1b[33m";    // yellow
    if (r & REASON_SECURITY_CHANGE)   return L"\x1b[35m";    // magenta
    return L"\x1b[2m";                                       // dim
}

// Parse a comma-separated list of reason keywords. Returns 0 mask if
// none match; caller treats that as "all".
uint32_t ParseReasonMask(std::wstring_view s) {
    if (s.empty()) return 0;
    uint32_t m = 0;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t end = s.find(L',', pos);
        if (end == std::wstring_view::npos) end = s.size();
        std::wstring_view tok = s.substr(pos, end - pos);
        // tiny lowercase compare
        auto eq = [&](const wchar_t* lit) {
            if (wcslen(lit) != tok.size()) return false;
            for (size_t i = 0; i < tok.size(); ++i) {
                wchar_t a = tok[i]; if (a >= L'A' && a <= L'Z') a += 32;
                if (a != lit[i]) return false;
            }
            return true;
        };
        if      (eq(L"create"))    m |= REASON_FILE_CREATE;
        else if (eq(L"delete"))    m |= REASON_FILE_DELETE;
        else if (eq(L"rename"))    m |= REASON_RENAME_OLD_NAME | REASON_RENAME_NEW_NAME;
        else if (eq(L"write"))     m |= REASON_DATA_OVERWRITE | REASON_DATA_EXTEND | REASON_DATA_TRUNCATION;
        else if (eq(L"attr"))      m |= REASON_BASIC_INFO_CHANGE;
        else if (eq(L"acl") ||
                 eq(L"security"))  m |= REASON_SECURITY_CHANGE;
        else if (eq(L"reparse"))   m |= REASON_REPARSE_POINT;
        else if (eq(L"close"))     m |= REASON_CLOSE;
        else if (eq(L"all"))       m |= REASON_ALL;
        pos = end + 1;
    }
    return m;
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
       .arg(wclap::Arg(L"name").long_name(L"name").takes_value().help(L"Substring match on file name"))
       .arg(wclap::Arg(L"regex").long_name(L"regex").takes_value().help(L"ECMAScript regex on file name"))
       .arg(wclap::Arg(L"iregex").long_name(L"iregex").takes_value().help(L"Case-insensitive regex"));
    auto m = app.parse(argc, argv);
    std::wstring vol = *m.value(L"volume");
    uint64_t limit = *m.value_u64(L"limit");
    auto needle = m.value(L"name");

    std::optional<std::wregex> rx;
    auto buildRx = [&](const std::wstring& pat, bool icase) -> bool {
        try {
            auto flags = std::regex::ECMAScript;
            if (icase) flags = (std::regex::flag_type)(flags | std::regex::icase);
            rx.emplace(pat, flags);
            return true;
        } catch (const std::regex_error& e) {
            fwprintf(stderr, L"ntfs mft: bad regex \"%ls\" — %hs\n", pat.c_str(), e.what());
            return false;
        }
    };
    if (auto p = m.value(L"regex"))  if (!buildRx(*p, false)) return 1;
    if (auto p = m.value(L"iregex")) if (!buildRx(*p, true))  return 1;

    // Over-fetch so a tight filter doesn't bail at `limit` before finding
    // matches. 0 = unlimited; otherwise grab 8x and trim post-filter.
    auto rec = ntfsEnumMft(vol, limit ? limit * 8 : 0);
    wprintf(L"%-16ls  %-16ls  %-19ls  %ls\n", L"FRN", L"PARENT-FRN", L"TIME", L"NAME");
    uint64_t shown = 0;
    for (auto& e : rec) {
        if (needle && e.fileName.find(*needle) == std::wstring::npos) continue;
        if (rx     && !std::regex_search(e.fileName, *rx))             continue;
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

int CmdNtfsMonitor(int argc, wchar_t** argv) {
    wclap::App app(L"winternal ntfs monitor");
    app.about(L"Live NTFS activity stream — driver-routed USN-journal tail. "
              L"The driver blocks in ZwFsControlFile until NTFS writes the next "
              L"journal entry, so events arrive within milliseconds with no polling.")
       .arg(wclap::Arg(L"volume").positional().required().help(L"Drive letter, e.g. C:"))
       .arg(wclap::Arg(L"reasons").long_name(L"reasons").takes_value()
                .help(L"Comma-separated: create,delete,rename,write,attr,acl,reparse,close,all"))
       .arg(wclap::Arg(L"filter").long_name(L"filter").takes_value()
                .help(L"Substring match on file name (case-sensitive)"))
       .arg(wclap::Arg(L"regex").long_name(L"regex").takes_value()
                .help(L"ECMAScript regex on file name (e.g. \".*\\\\.dll$\")"))
       .arg(wclap::Arg(L"iregex").long_name(L"iregex").takes_value()
                .help(L"Case-insensitive regex (same syntax, /i implicit)"))
       .arg(wclap::Arg(L"paths").long_name(L"paths")
                .help(L"Resolve FRN to full path (slow — extra OpenFileById per event)"))
       .arg(wclap::Arg(L"nocolor").long_name(L"nocolor").help(L"Disable ANSI color"));
    auto m = app.parse(argc, argv);

    std::wstring vol = *m.value(L"volume");
    auto filterStr   = m.value(L"filter");
    bool wantPaths   = m.present(L"paths");
    if (m.present(L"nocolor")) wclap::style::force(false);
    else                       wclap::style::init();

    // Compile the regex up-front so we can report syntax errors cleanly
    // and avoid the per-event compile cost. nullopt = no regex filter.
    std::optional<std::wregex> rxFilter;
    auto buildRegex = [&](const std::wstring& pat, bool icase) -> bool {
        try {
            auto flags = std::regex::ECMAScript;
            if (icase) flags = (std::regex::flag_type)(flags | std::regex::icase);
            rxFilter.emplace(pat, flags);
            return true;
        } catch (const std::regex_error& e) {
            fwprintf(stderr, L"ntfs monitor: bad regex \"%ls\" — %hs\n", pat.c_str(), e.what());
            return false;
        }
    };
    if (auto rs = m.value(L"regex"))  if (!buildRegex(*rs, false)) return 1;
    if (auto rs = m.value(L"iregex")) if (!buildRegex(*rs, true))  return 1;

    uint32_t reasonMask = REASON_ALL;
    if (auto rs = m.value(L"reasons")) {
        uint32_t parsed = ParseReasonMask(*rs);
        if (parsed) reasonMask = parsed;
    }

    auto info = ntfsQueryUsnJournal(vol);
    if (!info) {
        fwprintf(stderr, L"ntfs monitor: no active journal on %ls (err %lu)\n",
                 vol.c_str(), ::GetLastError());
        return 1;
    }
    wprintf(L"%lsmonitoring %ls (journal %llu, starting at USN %lld) — Ctrl+C to stop%ls\n",
            wclap::style::DIM(), vol.c_str(),
            (unsigned long long)info->journalId, info->nextUsn,
            wclap::style::RESET());
    wprintf(L"%ls%-12ls  %-9ls  %-16ls  %ls%ls\n",
            wclap::style::BOLD(), L"TIME", L"REASON", L"FRN", L"NAME / PATH",
            wclap::style::RESET());

    size_t count = 0;
    ntfsTailUsnJournal(vol, reasonMask, [&](const UsnRecord& r) {
        // Name-side filters are post-fetch — the USN journal API only
        // accepts a reason mask, not a name pattern. Both filters are
        // ANDed if specified: a record must pass substring AND regex.
        if (filterStr && r.fileName.find(*filterStr) == std::wstring::npos) return true;
        if (rxFilter && !std::regex_search(r.fileName, *rxFilter))           return true;

        // Compact local time (HH:MM:SS.mmm). Skip the date — monitoring
        // runs are typically same-day; full date burns a column.
        FILETIME ft{ (DWORD)r.timestampFt, (DWORD)(r.timestampFt >> 32) };
        SYSTEMTIME u{}, s{};
        if (::FileTimeToSystemTime(&ft, &u) &&
            ::SystemTimeToTzSpecificLocalTime(nullptr, &u, &s)) {
            wprintf(L"%02u:%02u:%02u.%03u  ", s.wHour, s.wMinute, s.wSecond, s.wMilliseconds);
        } else {
            wprintf(L"            ");
        }
        wprintf(L"%ls%-9ls%ls  %016llx  ",
                ReasonColor(r.reason), ReasonString(r.reason), wclap::style::RESET(),
                (unsigned long long)r.fileRefNumber);
        if (wantPaths) {
            auto path = ntfsResolveFileRef(vol, r.fileRefNumber);
            wprintf(L"%ls\n", path.empty() ? r.fileName.c_str() : path.c_str());
        } else {
            wprintf(L"%ls\n", r.fileName.c_str());
        }
        ++count;
        return true;  // keep streaming; CTRL+C aborts the synchronous IOCTL
                      // via CancelSynchronousIo on the main thread (set up in wmain).
    });

    wprintf(L"%ls-- stopped, %zu events --%ls\n",
            wclap::style::DIM(), count, wclap::style::RESET());
    return 0;
}

// ---- ntfs filter <add|list|remove|clear> ------------------------------
//
// Kernel-side NtCreateFile hook intercepts every file open. Patterns use
// RtlIsNameInExpression syntax (DOS wildcards: * ? < > "). First-match
// wins. The rule list lives in the driver; the CLI is just a thin
// management surface.
//
// Why wildcards instead of regex: full regex needs a kernel-mode regex
// engine, which is a substantial vendor-or-write decision. RtlIsName-
// InExpression is already in ntoskrnl, is what NTFS uses internally for
// name matching, and covers ~all real ARK use cases (extension globs,
// path globs, name shadows). If you need true regex, do the matching
// in user mode — `ntfs monitor --iregex` does that already.

static const wchar_t* ActionName(uint32_t a) {
    switch (a) {
    case WINTERNAL_FILTER_ACT_DENY:     return L"DENY";
    case WINTERNAL_FILTER_ACT_NOTFOUND: return L"NOTFOUND";
    case WINTERNAL_FILTER_ACT_READONLY: return L"READONLY";
    case WINTERNAL_FILTER_ACT_LOG:      return L"LOG";
    default:                            return L"?";
    }
}

static int ParseAction(std::wstring_view s) {
    auto eq = [&](const wchar_t* lit) -> bool {
        if (wcslen(lit) != s.size()) return false;
        for (size_t i = 0; i < s.size(); ++i) {
            wchar_t a = s[i]; if (a >= L'A' && a <= L'Z') a += 32;
            if (a != lit[i]) return false;
        }
        return true;
    };
    if (eq(L"deny"))     return WINTERNAL_FILTER_ACT_DENY;
    if (eq(L"notfound")) return WINTERNAL_FILTER_ACT_NOTFOUND;
    if (eq(L"readonly")) return WINTERNAL_FILTER_ACT_READONLY;
    if (eq(L"log"))      return WINTERNAL_FILTER_ACT_LOG;
    return -1;
}

static int CmdNtfsFilterAdd(int argc, wchar_t** argv) {
    wclap::App app(L"winternal ntfs filter add");
    app.about(L"Install a kernel-side minifilter rule (intercepts every IRP_MJ_CREATE). "
              L"Patterns use shell-style wildcards (case-insensitive), matched by a "
              L"path-aware matcher in the driver: `*` matches any sequence INCLUDING "
              L"path separators, `?` matches exactly one character. The match runs "
              L"against the full normalized path the FSD sees "
              L"(`\\Device\\HarddiskVolumeN\\path\\file`). Examples:\n"
              L"  *.exe              — every .exe open anywhere on any volume\n"
              L"  *\\Temp\\*          — anything under any \\Temp\\ directory\n"
              L"  *Secret*           — any path containing 'Secret'\n"
              L"  *\\users\\?\\private\\*  — single-character user dirs")
       .arg(wclap::Arg(L"pattern").positional().required()
                .help(L"Wildcard pattern, e.g. \"*\\\\Temp\\\\*.exe\""))
       .arg(wclap::Arg(L"action").positional().required()
                .help(L"deny | notfound | readonly | log"));
    auto m = app.parse(argc, argv);
    std::wstring pattern = *m.value(L"pattern");
    int act = ParseAction(*m.value(L"action"));
    if (act < 0) {
        fwprintf(stderr, L"ntfs filter add: bad action '%ls' "
                         L"(use deny|notfound|readonly|log)\n", m.value(L"action")->c_str());
        return 1;
    }
    DriverSession s;
    if (!s.open()) {
        fwprintf(stderr, L"ntfs filter: Winternal.sys not loaded (%lu)\n", ::GetLastError());
        return 1;
    }
    auto id = s.ntfsFilterAdd(pattern, (DriverSession::FilterAction)act);
    if (!id) {
        fwprintf(stderr, L"ntfs filter add: failed (%lu)\n", ::GetLastError());
        return 1;
    }
    wprintf(L"added rule %u: %ls -> %ls\n", *id, pattern.c_str(), ActionName((uint32_t)act));
    return 0;
}

static int CmdNtfsFilterList(int argc, wchar_t** argv) {
    wclap::App app(L"winternal ntfs filter list");
    app.about(L"List all installed NtCreateFile rules, with per-rule hit counts.");
    app.parse(argc, argv);
    DriverSession s;
    if (!s.open()) {
        fwprintf(stderr, L"ntfs filter: Winternal.sys not loaded (%lu)\n", ::GetLastError());
        return 1;
    }
    auto rules = s.ntfsFilterList();
    if (rules.empty()) { wprintf(L"(no rules)\n"); return 0; }
    wprintf(L"%-6ls  %-10ls  %-9ls  %ls\n", L"ID", L"ACTION", L"HITS", L"PATTERN");
    for (auto& r : rules) {
        wprintf(L"%-6u  %-10ls  %-9u  %ls\n",
                r.ruleId, ActionName(r.action), r.matchCount, r.pattern.c_str());
    }
    return 0;
}

static int CmdNtfsFilterRemove(int argc, wchar_t** argv) {
    wclap::App app(L"winternal ntfs filter remove");
    app.about(L"Remove a rule by its assigned ruleId (see `ntfs filter list`).")
       .arg(wclap::Arg(L"id").positional().required().help(L"Rule ID (decimal)"));
    auto m = app.parse(argc, argv);
    uint32_t id = (uint32_t)*m.value_u64(L"id");
    DriverSession s;
    if (!s.open()) {
        fwprintf(stderr, L"ntfs filter: Winternal.sys not loaded (%lu)\n", ::GetLastError());
        return 1;
    }
    if (!s.ntfsFilterRemove(id)) {
        fwprintf(stderr, L"ntfs filter remove %u: failed (%lu)\n", id, ::GetLastError());
        return 1;
    }
    wprintf(L"rule %u removed\n", id);
    return 0;
}

static int CmdNtfsFilterClear(int argc, wchar_t** argv) {
    wclap::App app(L"winternal ntfs filter clear");
    app.about(L"Remove every rule and tear down the NtCreateFile syscall hook.");
    app.parse(argc, argv);
    DriverSession s;
    if (!s.open()) {
        fwprintf(stderr, L"ntfs filter: Winternal.sys not loaded (%lu)\n", ::GetLastError());
        return 1;
    }
    if (!s.ntfsFilterClear()) {
        fwprintf(stderr, L"ntfs filter clear: failed (%lu)\n", ::GetLastError());
        return 1;
    }
    wprintf(L"all rules cleared\n");
    return 0;
}

int CmdNtfsFilter(int argc, wchar_t** argv) {
    if (argc < 1) {
        // Top-level usage for `ntfs filter` with no args. Each action has
        // its own WClap-styled help via `--help`.
        fwprintf(stderr,
            L"usage: winternal ntfs filter <add|list|remove|clear> [args]\n"
            L"  Run any action with --help for its argument doc.\n");
        return 1;
    }
    std::wstring_view sub = argv[0];
    int sa = argc - 1;
    wchar_t** av = argv + 1;
    if (sub == L"add")    return CmdNtfsFilterAdd(sa, av);
    if (sub == L"list")   return CmdNtfsFilterList(sa, av);
    if (sub == L"remove") return CmdNtfsFilterRemove(sa, av);
    if (sub == L"clear")  return CmdNtfsFilterClear(sa, av);
    fwprintf(stderr, L"ntfs filter: unknown action: %ls\n", argv[0]);
    return 1;
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
            L"usage: winternal ntfs <vols|usn|monitor|mft|streams|compare|raw|filter> [args]\n"
            L"  vols                        list NTFS volumes + metadata\n"
            L"  usn <vol> [--count N] [--start U] [--tail]\n"
            L"  monitor <vol> [--reasons ...] [--filter S] [--paths]   live activity stream\n"
            L"  mft <vol> [--limit N] [--name SUBSTR]\n"
            L"  streams <path>              list alternate data streams\n"
            L"  compare <path>              FindFirstFile vs MFT diff\n"
            L"  raw <device> <off> <len>    driver-backed raw read\n"
            L"  filter <add|list|remove|clear> [args]   block/redirect file opens\n");
        return 1;
    }
    std::wstring_view sub = argv[0];
    int sa = argc - 1;
    wchar_t** av = argv + 1;
    if (sub == L"vols")    return CmdNtfsVols();
    if (sub == L"usn")     return CmdNtfsUsn(sa, av);
    if (sub == L"monitor") return CmdNtfsMonitor(sa, av);
    if (sub == L"mft")     return CmdNtfsMft(sa, av);
    if (sub == L"streams") return CmdNtfsStreams(sa, av);
    if (sub == L"compare") return CmdNtfsCompare(sa, av);
    if (sub == L"raw")     return CmdNtfsRaw(sa, av);
    if (sub == L"filter")  return CmdNtfsFilter(sa, av);
    fwprintf(stderr, L"ntfs: unknown subcommand: %ls\n", argv[0]);
    return 1;
}

} // namespace winternal
