// NTFS-focused helpers — volume metadata, USN journal access, raw MFT
// enumeration via FSCTL_ENUM_USN_DATA, alternate data streams, and a
// directory-vs-MFT compare for spotting rootkit-hidden files.
//
// Why this lives in WinternalCore: all of it is user-mode admin work
// (FSCTL_* via DeviceIoControl on volume handles like \\.\C:). No driver
// involvement needed — but the CLI exposes it under `winternal ntfs *`
// and the kernel-Lua side gets `wn.ntfs_*` bindings.
//
// Threat model: rootkit may hook ntdll's NtQueryDirectoryFile to filter
// FindFirstFile / FindNextFile results, but FSCTL_ENUM_USN_DATA returns
// records straight from the filesystem driver and bypasses user-mode
// hooks. Comparing the two views is how `ntfs compare` finds hides.
//
#pragma once
#include <Windows.h>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace winternal {

struct NtfsVolume {
    std::wstring driveLetter;    // "C:"
    std::wstring volumeGuidPath; // "\\?\Volume{...}\"
    std::wstring label;          // empty if no label
    std::wstring fsName;         // "NTFS", "ReFS", "FAT32" ...
    uint64_t     totalBytes = 0;
    uint64_t     freeBytes = 0;
    uint32_t     serialNumber = 0;
    uint32_t     bytesPerSector = 0;
    uint32_t     sectorsPerCluster = 0;
    uint64_t     mftStartLcn = 0;          // 0 if N/A
    uint64_t     mftValidDataLength = 0;
    bool         isNtfs = false;
};

struct UsnJournalInfo {
    uint64_t journalId = 0;
    int64_t  firstUsn = 0;
    int64_t  nextUsn = 0;
    int64_t  lowestValidUsn = 0;
    int64_t  maxUsn = 0;
    uint64_t maxSize = 0;
    uint64_t allocationDelta = 0;
};

struct UsnRecord {
    int64_t  usn = 0;
    uint64_t fileRefNumber = 0;        // MFT entry number + sequence
    uint64_t parentFileRefNumber = 0;
    int64_t  timestampFt = 0;          // FILETIME 100ns
    uint32_t reason = 0;
    uint32_t sourceInfo = 0;
    uint32_t securityId = 0;
    uint32_t fileAttributes = 0;
    std::wstring fileName;
};

struct MftEntry {
    uint64_t fileRefNumber = 0;
    uint64_t parentFileRefNumber = 0;
    int64_t  usn = 0;
    int64_t  timestampFt = 0;
    uint32_t fileAttributes = 0;
    std::wstring fileName;
};

struct AltStream {
    std::wstring name;       // ":Zone.Identifier:$DATA" style
    uint64_t     size = 0;
};

struct HiddenEntry {
    uint64_t fileRefNumber = 0;
    std::wstring fileName;
    std::wstring parentPath;   // best-effort reconstructed path
};

// Volume enumeration. Walks all logical drives and resolves NTFS-specific
// metadata (cluster size, MFT location, serial). Non-NTFS volumes are
// included with isNtfs=false so callers can decide what to do.
std::vector<NtfsVolume> ntfsEnumerateVolumes();

// USN journal status — fails (returns nullopt) if the volume has no
// journal active. Most modern NTFS volumes do.
std::optional<UsnJournalInfo> ntfsQueryUsnJournal(std::wstring_view volume);

// Read a chunk of USN records starting at `startUsn`. Passing 0 starts
// at firstUsn. `reasonMask` filters by REASON_* (0 = all reasons).
// `maxRecords` caps the result; default 1024. Returns nextUsn via out
// param so callers can chain reads / tail the journal.
std::vector<UsnRecord> ntfsReadUsnJournal(std::wstring_view volume,
                                          int64_t startUsn,
                                          uint32_t reasonMask,
                                          uint32_t maxRecords,
                                          int64_t* nextUsn);

// Live USN tail. Repeatedly calls FSCTL_READ_USN_JOURNAL with REASON_MASK
// = -1 in BlockUntilFreshData mode. `onRecord` returns true to keep
// streaming, false to stop. The function returns when onRecord asks it
// to or when an error occurs.
void ntfsTailUsnJournal(std::wstring_view volume,
                        uint32_t reasonMask,
                        std::function<bool(const UsnRecord&)> onRecord);

// MFT enumeration via FSCTL_ENUM_USN_DATA. Bypasses NtQueryDirectoryFile
// hooks. `maxEntries` 0 = unlimited. Records lack the parent's name (we
// only get parent FRN); resolve via subsequent lookups if needed.
std::vector<MftEntry> ntfsEnumMft(std::wstring_view volume, uint64_t maxEntries);

// Alternate data streams of a file. Empty vector if the path doesn't
// exist or has no streams.
std::vector<AltStream> ntfsListStreams(std::wstring_view path);

// Compare a directory tree's FindFirstFile/FindNextFile view (which a
// user-mode rootkit can filter) against MFT records under the same
// parent. Returns entries the MFT sees that FindFirstFile didn't —
// candidate hidden files. `rootPath` is a Win32 path like "C:\Windows".
std::vector<HiddenEntry> ntfsCompareDirVsMft(std::wstring_view rootPath);

// Resolve a file reference number to its full Win32 path on a given
// volume. Uses OpenFileById + GetFinalPathNameByHandle. Empty on error.
std::wstring ntfsResolveFileRef(std::wstring_view volume, uint64_t fileRefNumber);

} // namespace winternal
