#include "Ntfs.h"
#include "Driver.h"
#include "Util.h"
#include "../../Winternal/Public.h"
#include <winioctl.h>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstring>

namespace winternal {

namespace {

// Resolve a drive letter ("C:") to its NT device path ("\Device\HarddiskVolume3").
// Driver-side FSCTL paths require the device-object name; user-mode
// FindFirstFile uses Win32 paths, so we need both forms.
std::wstring NtDeviceForDrive(std::wstring_view drive) {
    std::wstring d(drive);
    if (!d.empty() && d.back() == L'\\') d.pop_back();
    wchar_t target[MAX_PATH] = {};
    DWORD n = ::QueryDosDeviceW(d.c_str(), target, _countof(target));
    if (!n) return {};
    return target;
}

DriverSession& Driver() {
    // Per-call session keeps the surface stateless; the driver itself
    // serializes through its own queue. If callers fan out heavily they
    // can hold their own DriverSession instead.
    static thread_local DriverSession session;
    if (!session.isOpen()) session.open();
    return session;
}

// USN_RECORD_V2 fixed offsets (minus the variable name tail). Tightly
// packed so the trailing padding the compiler would otherwise add (due
// to the 8-byte fields) doesn't push sizeof past 0x3C.
#pragma pack(push, 1)
struct UsnRecordHeader {
    uint32_t RecordLength;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint64_t FileReferenceNumber;
    uint64_t ParentFileReferenceNumber;
    int64_t  Usn;
    int64_t  TimeStamp;
    uint32_t Reason;
    uint32_t SourceInfo;
    uint32_t SecurityId;
    uint32_t FileAttributes;
    uint16_t FileNameLength;
    uint16_t FileNameOffset;
};
#pragma pack(pop)
static_assert(sizeof(UsnRecordHeader) == 0x3C, "USN_RECORD_V2 header layout");

void ParseUsnBlob(const std::vector<uint8_t>& blob,
                  std::vector<UsnRecord>& out, uint32_t reasonMask,
                  int64_t* cursor) {
    if (blob.size() < 8) return;
    if (cursor) std::memcpy(cursor, blob.data(), 8);
    const uint8_t* p   = blob.data() + 8;
    const uint8_t* end = blob.data() + blob.size();
    while (p + sizeof(UsnRecordHeader) <= end) {
        UsnRecordHeader h{};
        std::memcpy(&h, p, sizeof(h));
        if (h.RecordLength == 0 || p + h.RecordLength > end) break;
        if (h.MajorVersion == 2) {
            if (reasonMask == 0 || (h.Reason & reasonMask)) {
                UsnRecord r;
                r.usn                 = h.Usn;
                r.fileRefNumber       = h.FileReferenceNumber;
                r.parentFileRefNumber = h.ParentFileReferenceNumber;
                r.timestampFt         = h.TimeStamp;
                r.reason              = h.Reason;
                r.sourceInfo          = h.SourceInfo;
                r.securityId          = h.SecurityId;
                r.fileAttributes      = h.FileAttributes;
                r.fileName.assign(
                    reinterpret_cast<const wchar_t*>(p + h.FileNameOffset),
                    h.FileNameLength / sizeof(wchar_t));
                out.push_back(std::move(r));
            }
        }
        p += h.RecordLength;
    }
}

void ParseMftBlob(const std::vector<uint8_t>& blob,
                  std::vector<MftEntry>& out, uint64_t* cursor) {
    if (blob.size() < 8) return;
    if (cursor) std::memcpy(cursor, blob.data(), 8);
    const uint8_t* p   = blob.data() + 8;
    const uint8_t* end = blob.data() + blob.size();
    while (p + sizeof(UsnRecordHeader) <= end) {
        UsnRecordHeader h{};
        std::memcpy(&h, p, sizeof(h));
        if (h.RecordLength == 0 || p + h.RecordLength > end) break;
        if (h.MajorVersion == 2) {
            MftEntry e;
            e.fileRefNumber       = h.FileReferenceNumber;
            e.parentFileRefNumber = h.ParentFileReferenceNumber;
            e.usn                 = h.Usn;
            e.timestampFt         = h.TimeStamp;
            e.fileAttributes      = h.FileAttributes;
            e.fileName.assign(
                reinterpret_cast<const wchar_t*>(p + h.FileNameOffset),
                h.FileNameLength / sizeof(wchar_t));
            out.push_back(std::move(e));
        }
        p += h.RecordLength;
    }
}

} // namespace

std::vector<NtfsVolume> ntfsEnumerateVolumes() {
    std::vector<NtfsVolume> out;
    auto& d = Driver();
    wchar_t drives[256] = {};
    DWORD n = ::GetLogicalDriveStringsW(_countof(drives), drives);
    for (wchar_t* p = drives; *p && p < drives + n; p += wcslen(p) + 1) {
        NtfsVolume v;
        v.driveLetter = p;
        if (!v.driveLetter.empty() && v.driveLetter.back() == L'\\')
            v.driveLetter.pop_back();

        wchar_t fsName[16] = {};
        wchar_t label[MAX_PATH] = {};
        DWORD serial = 0;
        if (::GetVolumeInformationW(p, label, _countof(label),
                                    &serial, nullptr, nullptr,
                                    fsName, _countof(fsName))) {
            v.fsName = fsName;
            v.label = label;
            v.serialNumber = serial;
        }

        wchar_t guidPath[64] = {};
        if (::GetVolumeNameForVolumeMountPointW(p, guidPath, _countof(guidPath)))
            v.volumeGuidPath = guidPath;

        ULARGE_INTEGER freeAvail{}, totalBytes{}, totalFree{};
        if (::GetDiskFreeSpaceExW(p, &freeAvail, &totalBytes, &totalFree)) {
            v.totalBytes = totalBytes.QuadPart;
            v.freeBytes  = totalFree.QuadPart;
        }

        v.isNtfs = (v.fsName == L"NTFS");
        if (v.isNtfs && d.isOpen()) {
            std::wstring dev = NtDeviceForDrive(v.driveLetter);
            if (!dev.empty()) {
                if (auto vd = d.ntfsVolData(dev)) {
                    v.bytesPerSector     = vd->bytesPerSector;
                    v.sectorsPerCluster  = vd->bytesPerSector
                        ? vd->bytesPerCluster / vd->bytesPerSector : 0;
                    v.mftStartLcn        = vd->mftStartLcn;
                    v.mftValidDataLength = vd->mftValidDataLength;
                }
            }
        }
        out.push_back(std::move(v));
    }
    return out;
}

std::optional<UsnJournalInfo> ntfsQueryUsnJournal(std::wstring_view volume) {
    std::wstring dev = NtDeviceForDrive(volume);
    if (dev.empty()) return std::nullopt;
    auto& d = Driver();
    if (!d.isOpen()) return std::nullopt;
    auto j = d.ntfsUsnQuery(dev);
    if (!j) return std::nullopt;
    UsnJournalInfo info{};
    info.journalId       = j->journalId;
    info.firstUsn        = j->firstUsn;
    info.nextUsn         = j->nextUsn;
    info.lowestValidUsn  = j->lowestValidUsn;
    info.maxUsn          = j->maxUsn;
    info.maxSize         = j->maxSize;
    info.allocationDelta = j->allocationDelta;
    return info;
}

std::vector<UsnRecord> ntfsReadUsnJournal(std::wstring_view volume,
                                          int64_t startUsn,
                                          uint32_t reasonMask,
                                          uint32_t maxRecords,
                                          int64_t* nextUsn) {
    std::vector<UsnRecord> out;
    if (maxRecords == 0) maxRecords = 1024;
    std::wstring dev = NtDeviceForDrive(volume);
    if (dev.empty()) return out;
    auto& d = Driver();
    if (!d.isOpen()) return out;
    auto info = d.ntfsUsnQuery(dev);
    if (!info) return out;

    int64_t cursor = startUsn ? startUsn : info->firstUsn;
    while (out.size() < maxRecords) {
        auto blob = d.ntfsUsnRead(dev, info->journalId, cursor, reasonMask, false);
        if (!blob || blob->size() < 8) break;
        int64_t prev = cursor;
        ParseUsnBlob(*blob, out, reasonMask, &cursor);
        if (cursor == prev) break;
        if (blob->size() <= 8) break;          // empty payload, no progress
    }
    if (nextUsn) *nextUsn = cursor;
    return out;
}

void ntfsTailUsnJournal(std::wstring_view volume, uint32_t reasonMask,
                        std::function<bool(const UsnRecord&)> onRecord) {
    std::wstring dev = NtDeviceForDrive(volume);
    if (dev.empty()) return;
    auto& d = Driver();
    if (!d.isOpen()) return;
    auto info = d.ntfsUsnQuery(dev);
    if (!info) return;
    int64_t cursor = info->nextUsn;
    bool keepGoing = true;
    while (keepGoing) {
        auto blob = d.ntfsUsnRead(dev, info->journalId, cursor, reasonMask, true);
        if (!blob) break;
        std::vector<UsnRecord> chunk;
        ParseUsnBlob(*blob, chunk, reasonMask, &cursor);
        for (auto& r : chunk) {
            if (!onRecord(r)) { keepGoing = false; break; }
        }
    }
}

std::vector<MftEntry> ntfsEnumMft(std::wstring_view volume, uint64_t maxEntries) {
    std::vector<MftEntry> out;
    std::wstring dev = NtDeviceForDrive(volume);
    if (dev.empty()) return out;
    auto& d = Driver();
    if (!d.isOpen()) return out;
    uint64_t cursor = 0;
    for (;;) {
        auto blob = d.ntfsMftEnum(dev, cursor);
        if (!blob || blob->size() < 8) break;
        uint64_t prev = cursor;
        ParseMftBlob(*blob, out, &cursor);
        if (cursor == prev) break;
        if (maxEntries && out.size() >= maxEntries) {
            out.resize((size_t)maxEntries);
            break;
        }
    }
    return out;
}

namespace {

std::wstring Win32ToNtPath(std::wstring_view w) {
    // C:\foo  ->  \??\C:\foo  (NT path the driver's ZwCreateFile expects)
    std::wstring p;
    p.reserve(w.size() + 4);
    if (w.size() >= 2 && w[1] == L':') {
        p = L"\\??\\";
        p.append(w);
    } else if (w.size() >= 4 && w.substr(0, 4) == L"\\??\\") {
        p = w;
    } else if (w.size() >= 4 && w.substr(0, 4) == L"\\\\?\\") {
        p = L"\\??\\";
        p.append(w.substr(4));
    } else {
        p = w;
    }
    return p;
}

} // namespace

std::vector<AltStream> ntfsListStreams(std::wstring_view path) {
    std::vector<AltStream> out;
    auto& d = Driver();
    if (!d.isOpen()) return out;
    std::wstring nt = Win32ToNtPath(path);
    auto blob = d.ntfsStreams(nt);
    if (!blob || blob->empty()) return out;
    // Walk FILE_STREAM_INFORMATION chain.
    const uint8_t* p = blob->data();
    const uint8_t* end = blob->data() + blob->size();
    while (p + 0x18 <= end) {
        uint32_t nextOff;
        uint32_t nameLen;
        int64_t  size;
        std::memcpy(&nextOff, p + 0x00, 4);
        std::memcpy(&nameLen, p + 0x04, 4);
        std::memcpy(&size,    p + 0x08, 8);
        AltStream s;
        if (nameLen && p + 0x18 + nameLen <= end) {
            s.name.assign(reinterpret_cast<const wchar_t*>(p + 0x18),
                          nameLen / sizeof(wchar_t));
        }
        s.size = (uint64_t)size;
        out.push_back(std::move(s));
        if (nextOff == 0) break;
        p += nextOff;
    }
    return out;
}

std::wstring ntfsResolveFileRef(std::wstring_view volume, uint64_t fileRefNumber) {
    // OpenFileById has no per-process kernel-mode bypass equivalent in
    // the driver surface, so this stays user-mode. It only touches a
    // single handle (no FSCTL), so the threat-model exposure is small.
    std::wstring drive(volume);
    if (!drive.empty() && drive.back() != L'\\') drive.push_back(L'\\');
    HandleGuard vh{::CreateFileW((std::wstring(L"\\\\.\\") + drive.substr(0, 2)).c_str(),
                                 GENERIC_READ,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 nullptr, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS, nullptr)};
    if (!vh.valid()) return {};
    FILE_ID_DESCRIPTOR id{};
    id.dwSize = sizeof(id);
    id.Type = FileIdType;
    id.FileId.QuadPart = (LONGLONG)fileRefNumber;
    HANDLE fh = ::OpenFileById(vh.get(), &id, READ_CONTROL,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, FILE_FLAG_BACKUP_SEMANTICS);
    if (fh == INVALID_HANDLE_VALUE) return {};
    wchar_t buf[1024] = {};
    DWORD got = ::GetFinalPathNameByHandleW(fh, buf, _countof(buf), FILE_NAME_NORMALIZED);
    ::CloseHandle(fh);
    if (!got || got >= _countof(buf)) return {};
    std::wstring s(buf, got);
    if (s.size() > 4 && s.compare(0, 4, L"\\\\?\\") == 0) s.erase(0, 4);
    return s;
}

std::vector<HiddenEntry> ntfsCompareDirVsMft(std::wstring_view rootPath) {
    std::vector<HiddenEntry> out;
    std::wstring root(rootPath);
    if (root.empty()) return out;
    if (root.back() != L'\\') root.push_back(L'\\');

    // Step 1: the (hookable) FindFirstFile view of `root`.
    std::unordered_set<std::wstring> seenViaFind;
    std::vector<std::wstring> stack;
    stack.push_back(root);
    while (!stack.empty()) {
        std::wstring dir = std::move(stack.back()); stack.pop_back();
        WIN32_FIND_DATAW fd;
        HANDLE h = ::FindFirstFileExW((dir + L"*").c_str(),
                                      FindExInfoBasic, &fd,
                                      FindExSearchNameMatch, nullptr,
                                      FIND_FIRST_EX_LARGE_FETCH);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring_view nm = fd.cFileName;
            if (nm == L"." || nm == L"..") continue;
            std::wstring full = dir + fd.cFileName;
            std::wstring norm = full;
            std::transform(norm.begin(), norm.end(), norm.begin(),
                           [](wchar_t c) { return (wchar_t)::towlower(c); });
            seenViaFind.insert(std::move(norm));
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                stack.push_back(full + L"\\");
        } while (::FindNextFileW(h, &fd));
        ::FindClose(h);
    }

    // Step 2: MFT view via the driver-routed FSCTL_ENUM_USN_DATA.
    std::wstring volume(rootPath.substr(0, 2));
    auto records = ntfsEnumMft(volume, 0);
    std::unordered_map<uint64_t, std::pair<uint64_t, std::wstring>> byFrn;
    byFrn.reserve(records.size());
    for (auto& r : records) byFrn[r.fileRefNumber] = { r.parentFileRefNumber, r.fileName };

    std::wstring rootLower = root;
    std::transform(rootLower.begin(), rootLower.end(), rootLower.begin(),
                   [](wchar_t c) { return (wchar_t)::towlower(c); });

    for (auto& r : records) {
        std::wstring path = r.fileName;
        uint64_t pf = r.parentFileRefNumber;
        for (int depth = 0; depth < 64 && pf; ++depth) {
            auto it = byFrn.find(pf);
            if (it == byFrn.end()) break;
            if (it->second.second.empty()) break;
            path = it->second.second + L"\\" + path;
            pf = it->second.first;
            if (pf == r.fileRefNumber) break;
        }
        std::wstring full = volume + L"\\" + path;
        std::wstring norm = full;
        std::transform(norm.begin(), norm.end(), norm.begin(),
                       [](wchar_t c) { return (wchar_t)::towlower(c); });
        if (norm.size() < rootLower.size()) continue;
        if (norm.compare(0, rootLower.size(), rootLower) != 0) continue;
        if (seenViaFind.find(norm) != seenViaFind.end()) continue;
        HiddenEntry h;
        h.fileRefNumber = r.fileRefNumber;
        h.fileName      = r.fileName;
        h.parentPath    = full;
        out.push_back(std::move(h));
    }
    return out;
}

} // namespace winternal
