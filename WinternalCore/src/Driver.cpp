#include "Driver.h"
#include "../../Winternal/Public.h"
#include <cstring>

namespace winternal {

namespace {

// Map driver NTSTATUS into a Win32 last-error so callers can use the same
// FormatError helper across user-mode and driver-call paths. DeviceIoControl
// already does this for the common cases; we just store whatever it gives us.
void StoreError(DWORD e) { ::SetLastError(e); }

constexpr DWORD kIoOpenFailMissing = ERROR_FILE_NOT_FOUND;

} // namespace

DriverSession::DriverSession() = default;
DriverSession::~DriverSession() { close(); }

bool DriverSession::open() {
    if (handle_.valid()) return true;
    HANDLE h = ::CreateFileW(WINTERNAL_USER_OPEN_PATH,
                             GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (::GetLastError() == ERROR_FILE_NOT_FOUND) StoreError(kIoOpenFailMissing);
        return false;
    }
    handle_.reset(h);
    return true;
}

void DriverSession::close() { handle_.reset(); }

bool DriverSession::ioctl_(uint32_t code, const void* in, uint32_t inLen,
                           void* out, uint32_t outLen, uint32_t* bytesReturned) {
    if (!handle_.valid() && !open()) return false;
    DWORD ret = 0;
    BOOL ok = ::DeviceIoControl(handle_.get(), code,
                                const_cast<void*>(in), inLen,
                                out, outLen, &ret, nullptr);
    if (bytesReturned) *bytesReturned = ret;
    return ok != FALSE;
}

std::optional<DriverVersion> DriverSession::getVersion() {
    WINTERNAL_VERSION v{};
    if (!ioctl_(IOCTL_WINTERNAL_GET_VERSION, nullptr, 0, &v, sizeof(v), nullptr)) return std::nullopt;
    return DriverVersion{ v.Major, v.Minor, v.BuildTime };
}

std::vector<DriverPidEntry> DriverSession::enumPids() {
    std::vector<DriverPidEntry> out;
    std::vector<uint8_t> buf(512 * 1024);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_ENUM_PIDS, nullptr, 0, buf.data(), (uint32_t)buf.size(), &ret)) return out;
    auto* list = reinterpret_cast<PWINTERNAL_PID_LIST>(buf.data());
    out.reserve(list->Count);
    for (uint32_t i = 0; i < list->Count; ++i) {
        DriverPidEntry e{};
        e.pid = list->Entries[i].Pid;
        e.parentPid = list->Entries[i].ParentPid;
        e.imageName = list->Entries[i].ImageFileName;
        out.push_back(std::move(e));
    }
    return out;
}

std::optional<std::vector<uint8_t>> DriverSession::kread(uint64_t address, uint32_t length) {
    if (length == 0 || length > WINTERNAL_KMEM_MAX_BYTES) {
        StoreError(ERROR_INVALID_PARAMETER);
        return std::nullopt;
    }
    WINTERNAL_KMEM_READ_IN in{ address, length, 0 };
    std::vector<uint8_t> out(length);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_KMEM_READ, &in, sizeof(in), out.data(), length, &ret)) return std::nullopt;
    out.resize(ret);
    return out;
}

bool DriverSession::kwrite(uint64_t address, const void* data, uint32_t length) {
    if (length == 0 || length > WINTERNAL_KMEM_MAX_BYTES) { StoreError(ERROR_INVALID_PARAMETER); return false; }
    std::vector<uint8_t> buf(FIELD_OFFSET(WINTERNAL_KMEM_WRITE_IN, Data) + length);
    auto* in = reinterpret_cast<PWINTERNAL_KMEM_WRITE_IN>(buf.data());
    in->Address = address;
    in->Length = length;
    in->Reserved = 0;
    std::memcpy(in->Data, data, length);
    return ioctl_(IOCTL_WINTERNAL_KMEM_WRITE, buf.data(), (uint32_t)buf.size(), nullptr, 0, nullptr);
}

std::optional<uint64_t> DriverSession::ksym(std::wstring_view name) {
    WINTERNAL_KSYM_IN in{};
    if (name.size() >= std::size(in.Name)) { StoreError(ERROR_INVALID_PARAMETER); return std::nullopt; }
    std::memcpy(in.Name, name.data(), name.size() * sizeof(wchar_t));
    in.Name[name.size()] = 0;
    WINTERNAL_KSYM_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_KSYM, &in, sizeof(in), &out, sizeof(out), nullptr)) return std::nullopt;
    if (out.Address == 0) { StoreError(ERROR_NOT_FOUND); return std::nullopt; }
    return out.Address;
}

std::optional<uint64_t> DriverSession::kalloc(uint32_t length, uint32_t tag, bool nonPaged) {
    WINTERNAL_KALLOC_IN in{ length, tag, nonPaged ? 1u : 0u, 0 };
    WINTERNAL_KALLOC_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_KALLOC, &in, sizeof(in), &out, sizeof(out), nullptr)) return std::nullopt;
    return out.Address;
}

bool DriverSession::kfree(uint64_t address, uint32_t tag) {
    WINTERNAL_KFREE_IN in{ address, tag, 0 };
    return ioctl_(IOCTL_WINTERNAL_KFREE, &in, sizeof(in), nullptr, 0, nullptr);
}

std::optional<KcallResult> DriverSession::kcall(uint64_t address, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4) {
    WINTERNAL_KCALL_IN in{};
    in.Address = address;
    in.Args[0] = a1; in.Args[1] = a2; in.Args[2] = a3; in.Args[3] = a4;
    WINTERNAL_KCALL_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_KCALL, &in, sizeof(in), &out, sizeof(out), nullptr)) return std::nullopt;
    return KcallResult{ out.ReturnValue, out.Faulted != 0 };
}

std::optional<DriverSession::UnprotectResult> DriverSession::unprotectProcess(uint32_t pid, uint8_t newValue, uint32_t fieldOffset) {
    WINTERNAL_UNPROTECT_IN in{};
    in.Pid = pid;
    in.FieldOffset = fieldOffset;
    in.NewValue = newValue;
    WINTERNAL_UNPROTECT_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_UNPROTECT_PROCESS, &in, sizeof(in), &out, sizeof(out), nullptr)) return std::nullopt;
    return UnprotectResult{ out.FieldOffsetUsed, out.PrevValue };
}

bool DriverSession::killProcess(uint32_t pid, uint32_t exitStatus) {
    WINTERNAL_KILL_IN in{ pid, exitStatus };
    return ioctl_(IOCTL_WINTERNAL_KILL_PROCESS, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::protectLock(uint32_t pid) {
    WINTERNAL_PROTECT_LOCK_IN in{ pid, 0 };
    return ioctl_(IOCTL_WINTERNAL_PROTECT_LOCK, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::protectUnlock(uint32_t pid) {
    WINTERNAL_PROTECT_LOCK_IN in{ pid, 0 };
    return ioctl_(IOCTL_WINTERNAL_PROTECT_UNLOCK, &in, sizeof(in), nullptr, 0, nullptr);
}

std::vector<uint32_t> DriverSession::protectList() {
    WINTERNAL_PROTECT_LIST_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_PROTECT_LIST, nullptr, 0, &out, sizeof(out), nullptr)) return {};
    std::vector<uint32_t> r;
    r.reserve(out.Count);
    for (uint32_t i = 0; i < out.Count && i < WINTERNAL_PROTECT_MAX; ++i) r.push_back(out.Pids[i]);
    return r;
}

bool DriverSession::setTokenUIAccess(uint32_t pid, bool enable,
                                     uint32_t* prevFlags, uint32_t* newFlags,
                                     uint32_t fieldOffset) {
    WINTERNAL_TOKEN_UIACCESS_IN in{ pid, enable ? 1u : 0u, fieldOffset, 0 };
    WINTERNAL_TOKEN_UIACCESS_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_TOKEN_UIACCESS, &in, sizeof(in), &out, sizeof(out), nullptr)) return false;
    if (prevFlags) *prevFlags = out.PrevFlags;
    if (newFlags)  *newFlags  = out.NewFlags;
    return true;
}

std::optional<uint64_t> DriverSession::getTrueStub() {
    WINTERNAL_GET_TRUE_STUB_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_GET_TRUE_STUB, nullptr, 0, &out, sizeof(out), nullptr)) return std::nullopt;
    return out.Address;
}

std::optional<uint64_t> DriverSession::getWin32Process(uint32_t pid) {
    WINTERNAL_GET_W32PROC_IN in{ pid, 0 };
    WINTERNAL_GET_W32PROC_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_GET_W32PROC, &in, sizeof(in), &out, sizeof(out), nullptr)) return std::nullopt;
    return out.Address;
}

std::vector<DriverSession::ThreadEntry> DriverSession::enumThreads(uint32_t pid) {
    WINTERNAL_PID_IN in{ pid, 0 };
    std::vector<uint8_t> buf(sizeof(WINTERNAL_THREADS_OUT) + sizeof(WINTERNAL_THREAD_ENTRY) * WINTERNAL_MAX_THREADS_PER_PROC);
    uint32_t ret = 0;
    std::vector<ThreadEntry> out;
    if (!ioctl_(IOCTL_WINTERNAL_ENUM_THREADS, &in, sizeof(in), buf.data(), (uint32_t)buf.size(), &ret)) return out;
    auto* o = reinterpret_cast<PWINTERNAL_THREADS_OUT>(buf.data());
    out.reserve(o->Count);
    for (uint32_t i = 0; i < o->Count; ++i) {
        auto& e = o->Entries[i];
        out.push_back({ e.Tid, e.State, e.WaitReason, e.Priority, e.StartAddress,
                        e.KernelTime100Ns, e.UserTime100Ns, e.CreateTimeFt });
    }
    return out;
}

std::vector<DriverSession::MitigationItem> DriverSession::queryMitigations(uint32_t pid) {
    WINTERNAL_PID_IN in{ pid, 0 };
    WINTERNAL_MITIGATIONS_OUT outBuf{};
    std::vector<MitigationItem> out;
    if (!ioctl_(IOCTL_WINTERNAL_K_MITIGATIONS, &in, sizeof(in), &outBuf, sizeof(outBuf), nullptr)) return out;
    out.reserve(outBuf.Count);
    for (uint32_t i = 0; i < outBuf.Count; ++i) {
        out.push_back({ outBuf.Items[i].PolicyId, outBuf.Items[i].NtStatus, outBuf.Items[i].Value });
    }
    return out;
}

std::optional<DriverSession::TokenInfo> DriverSession::queryTokenInfo(uint32_t pid) {
    WINTERNAL_PID_IN in{ pid, 0 };
    WINTERNAL_TOKEN_INFO_OUT o{};
    if (!ioctl_(IOCTL_WINTERNAL_K_TOKEN_INFO, &in, sizeof(in), &o, sizeof(o), nullptr)) return std::nullopt;
    TokenInfo t;
    // Trim trailing zeros so SidLength() works on the result.
    auto trim = [](const uint8_t* p, size_t cap) {
        size_t n = cap;
        while (n > 0 && p[n - 1] == 0) --n;
        return std::vector<uint8_t>(p, p + n);
    };
    t.userSid       = trim(o.UserSid, sizeof(o.UserSid));
    t.integritySid  = trim(o.IntegritySid, sizeof(o.IntegritySid));
    t.integrityRid  = o.IntegrityRid;
    t.elevationType = o.ElevationType;
    t.elevated      = o.Elevated != 0;
    t.uiAccess      = o.UIAccess != 0;
    t.sessionId     = o.SessionId;
    t.privileges.reserve(o.PrivCount);
    for (uint32_t i = 0; i < o.PrivCount; ++i) {
        t.privileges.push_back({ o.Privileges[i].Luid, o.Privileges[i].Attributes });
    }
    return t;
}

std::vector<DriverSession::MemRegion> DriverSession::queryMemRegions(uint32_t pid, bool* truncated) {
    WINTERNAL_PID_IN in{ pid, 0 };
    std::vector<uint8_t> buf(sizeof(WINTERNAL_MEM_QUERY_OUT) + sizeof(WINTERNAL_MEM_REGION) * WINTERNAL_MAX_MEM_REGIONS);
    uint32_t ret = 0;
    std::vector<MemRegion> out;
    if (!ioctl_(IOCTL_WINTERNAL_K_MEM_QUERY, &in, sizeof(in), buf.data(), (uint32_t)buf.size(), &ret)) return out;
    auto* o = reinterpret_cast<PWINTERNAL_MEM_QUERY_OUT>(buf.data());
    if (truncated) *truncated = (o->Truncated != 0);
    out.reserve(o->Count);
    for (uint32_t i = 0; i < o->Count; ++i) {
        auto& e = o->Entries[i];
        out.push_back({ e.BaseAddress, e.RegionSize, e.State, e.Protect, e.Type });
    }
    return out;
}

bool DriverSession::kcodePatch(uint64_t address, const void* data, uint32_t length) {
    if (length == 0 || length > WINTERNAL_KCODE_PATCH_MAX) {
        StoreError(ERROR_INVALID_PARAMETER);
        return false;
    }
    WINTERNAL_KCODE_PATCH_IN in{};
    in.Address = address;
    in.Length = length;
    std::memcpy(in.Data, data, length);
    return ioctl_(IOCTL_WINTERNAL_KCODE_PATCH, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::setSignatureLevel(uint32_t pid, uint8_t sigLevel, uint8_t sectionSigLevel,
                                      uint8_t* prevSig, uint8_t* prevSection,
                                      uint32_t fieldOffset) {
    WINTERNAL_SIGLEVEL_IN in{};
    in.Pid = pid;
    in.SignatureLevel = sigLevel;
    in.SectionSignatureLevel = sectionSigLevel;
    in.FieldOffset = fieldOffset;
    WINTERNAL_SIGLEVEL_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_SET_SIGLEVEL, &in, sizeof(in), &out, sizeof(out), nullptr)) return false;
    if (prevSig)     *prevSig     = out.PrevSignatureLevel;
    if (prevSection) *prevSection = out.PrevSectionSignatureLevel;
    return true;
}

std::vector<CallbackEntry> DriverSession::enumCallbacks(CallbackKind kind) {
    std::vector<CallbackEntry> out;
    WINTERNAL_CB_IN in{ static_cast<uint32_t>(kind), 0 };
    std::vector<uint8_t> buf(64 * 1024);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_ENUM_CALLBACKS, &in, sizeof(in), buf.data(), (uint32_t)buf.size(), &ret)) return out;
    auto* list = reinterpret_cast<PWINTERNAL_CB_LIST>(buf.data());
    out.reserve(list->Count);
    for (uint32_t i = 0; i < list->Count; ++i) {
        out.push_back({ list->Entries[i].Routine, list->Entries[i].ModuleBase, list->Entries[i].ModuleName });
    }
    return out;
}

std::vector<DriverModuleEntry> DriverSession::enumKernelDrivers() {
    std::vector<DriverModuleEntry> out;
    std::vector<uint8_t> buf(2 * 1024 * 1024);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_ENUM_DRIVERS, nullptr, 0, buf.data(), (uint32_t)buf.size(), &ret)) return out;
    auto* list = reinterpret_cast<PWINTERNAL_DRIVER_LIST>(buf.data());
    out.reserve(list->Count);
    for (uint32_t i = 0; i < list->Count; ++i) {
        out.push_back({ list->Entries[i].ImageBase, list->Entries[i].ImageSize, list->Entries[i].Name });
    }
    return out;
}

std::optional<uint64_t> DriverSession::khookInstall(uint64_t target, uint64_t detour, uint32_t prologueSize) {
    WINTERNAL_KHOOK_INSTALL_IN in{ target, detour, prologueSize, 0 };
    WINTERNAL_KHOOK_INSTALL_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_KHOOK_INSTALL, &in, sizeof(in), &out, sizeof(out), nullptr)) return std::nullopt;
    return out.Trampoline;
}

bool DriverSession::khookUninstall(uint64_t target) {
    WINTERNAL_KHOOK_UNINSTALL_IN in{ target };
    return ioctl_(IOCTL_WINTERNAL_KHOOK_UNINSTALL, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::khookUninstallAll() {
    return ioctl_(IOCTL_WINTERNAL_KHOOK_UNINSTALL_ALL, nullptr, 0, nullptr, 0, nullptr);
}

std::optional<DriverSession::LockdownStatus> DriverSession::lockdownEngage() {
    WINTERNAL_LOCKDOWN_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_LOCKDOWN_ENGAGE, nullptr, 0, &out, sizeof(out), nullptr)) return std::nullopt;
    return LockdownStatus{ out.Engaged != 0, out.EngagedTickMs };
}

std::optional<DriverSession::LockdownStatus> DriverSession::lockdownStatus() {
    WINTERNAL_LOCKDOWN_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_LOCKDOWN_STATUS, nullptr, 0, &out, sizeof(out), nullptr)) return std::nullopt;
    return LockdownStatus{ out.Engaged != 0, out.EngagedTickMs };
}

bool DriverSession::forceUnloadDriver(std::wstring_view name) {
    if (name.empty() || name.size() >= WINTERNAL_DRIVER_NAME_MAX) {
        StoreError(ERROR_INVALID_PARAMETER);
        return false;
    }
    WINTERNAL_FORCE_UNLOAD_IN in{};
    std::memcpy(in.Name, name.data(), name.size() * sizeof(wchar_t));
    in.Name[name.size()] = 0;
    return ioctl_(IOCTL_WINTERNAL_FORCE_UNLOAD_DRIVER, &in, sizeof(in), nullptr, 0, nullptr);
}

namespace {

bool FillName(wchar_t* dst, size_t cap, std::wstring_view n) {
    if (n.empty() || n.size() >= cap) return false;
    std::memcpy(dst, n.data(), n.size() * sizeof(wchar_t));
    dst[n.size()] = 0;
    return true;
}

} // namespace

bool DriverSession::kdrvRegister(std::wstring_view name, std::wstring_view ntImagePath, uint32_t startType) {
    WINTERNAL_KDRV_REGISTER_IN in{};
    if (!FillName(in.Name, WINTERNAL_DRIVER_NAME_MAX, name) ||
        !FillName(in.ImagePath, WINTERNAL_DRIVER_PATH_MAX, ntImagePath)) {
        StoreError(ERROR_INVALID_PARAMETER); return false;
    }
    in.StartType = startType;
    return ioctl_(IOCTL_WINTERNAL_KDRV_REGISTER, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::kdrvDeregister(std::wstring_view name) {
    WINTERNAL_KDRV_NAME_IN in{};
    if (!FillName(in.Name, WINTERNAL_DRIVER_NAME_MAX, name)) { StoreError(ERROR_INVALID_PARAMETER); return false; }
    return ioctl_(IOCTL_WINTERNAL_KDRV_DEREGISTER, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::kdrvLoad(std::wstring_view name) {
    WINTERNAL_KDRV_NAME_IN in{};
    if (!FillName(in.Name, WINTERNAL_DRIVER_NAME_MAX, name)) { StoreError(ERROR_INVALID_PARAMETER); return false; }
    return ioctl_(IOCTL_WINTERNAL_KDRV_LOAD, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::kdrvUnload(std::wstring_view name) {
    WINTERNAL_KDRV_NAME_IN in{};
    if (!FillName(in.Name, WINTERNAL_DRIVER_NAME_MAX, name)) { StoreError(ERROR_INVALID_PARAMETER); return false; }
    return ioctl_(IOCTL_WINTERNAL_KDRV_UNLOAD, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::kdrvSetStart(std::wstring_view name, uint32_t startType) {
    WINTERNAL_KDRV_SET_START_IN in{};
    if (!FillName(in.Name, WINTERNAL_DRIVER_NAME_MAX, name)) { StoreError(ERROR_INVALID_PARAMETER); return false; }
    in.StartType = startType;
    return ioctl_(IOCTL_WINTERNAL_KDRV_SET_START, &in, sizeof(in), nullptr, 0, nullptr);
}

std::optional<DriverSession::NtfsVolData>
DriverSession::ntfsVolData(std::wstring_view device) {
    WINTERNAL_NTFS_DEVICE_IN in{};
    if (!FillName(in.Device, WINTERNAL_NTFS_DEV_NAME_MAX, device)) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    WINTERNAL_NTFS_VOL_DATA_OUT out{};
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_NTFS_VOL_DATA, &in, sizeof(in),
                &out, sizeof(out), &ret)) return std::nullopt;
    NtfsVolData d{};
    d.serial                       = (uint64_t)out.VolumeSerialNumber.QuadPart;
    d.numberSectors                = (uint64_t)out.NumberSectors.QuadPart;
    d.totalClusters                = (uint64_t)out.TotalClusters.QuadPart;
    d.freeClusters                 = (uint64_t)out.FreeClusters.QuadPart;
    d.totalReserved                = (uint64_t)out.TotalReserved.QuadPart;
    d.bytesPerSector               = out.BytesPerSector;
    d.bytesPerCluster              = out.BytesPerCluster;
    d.bytesPerFileRecordSegment    = out.BytesPerFileRecordSegment;
    d.clustersPerFileRecordSegment = out.ClustersPerFileRecordSegment;
    d.mftValidDataLength           = (uint64_t)out.MftValidDataLength.QuadPart;
    d.mftStartLcn                  = (uint64_t)out.MftStartLcn.QuadPart;
    d.mft2StartLcn                 = (uint64_t)out.Mft2StartLcn.QuadPart;
    d.mftZoneStart                 = (uint64_t)out.MftZoneStart.QuadPart;
    d.mftZoneEnd                   = (uint64_t)out.MftZoneEnd.QuadPart;
    return d;
}

std::optional<DriverSession::UsnJournal>
DriverSession::ntfsUsnQuery(std::wstring_view device) {
    WINTERNAL_NTFS_DEVICE_IN in{};
    if (!FillName(in.Device, WINTERNAL_NTFS_DEV_NAME_MAX, device)) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    WINTERNAL_NTFS_USN_JOURNAL_OUT out{};
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_NTFS_USN_QUERY, &in, sizeof(in),
                &out, sizeof(out), &ret)) return std::nullopt;
    UsnJournal j{};
    j.journalId       = out.JournalId;
    j.firstUsn        = out.FirstUsn;
    j.nextUsn         = out.NextUsn;
    j.lowestValidUsn  = out.LowestValidUsn;
    j.maxUsn          = out.MaxUsn;
    j.maxSize         = out.MaxSize;
    j.allocationDelta = out.AllocationDelta;
    return j;
}

std::optional<std::vector<uint8_t>>
DriverSession::ntfsUsnRead(std::wstring_view device, uint64_t journalId,
                           int64_t startUsn, uint32_t reasonMask, bool waitForFresh) {
    WINTERNAL_NTFS_USN_READ_IN in{};
    if (!FillName(in.Device, WINTERNAL_NTFS_DEV_NAME_MAX, device)) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    in.JournalId    = journalId;
    in.StartUsn     = startUsn;
    in.ReasonMask   = reasonMask;
    in.WaitForFresh = waitForFresh ? 1 : 0;
    std::vector<uint8_t> out(WINTERNAL_NTFS_USN_BUF);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_NTFS_USN_READ, &in, sizeof(in),
                out.data(), (uint32_t)out.size(), &ret)) return std::nullopt;
    out.resize(ret);
    return out;
}

std::optional<std::vector<uint8_t>>
DriverSession::ntfsMftEnum(std::wstring_view device, uint64_t startFrn) {
    WINTERNAL_NTFS_MFT_ENUM_IN in{};
    if (!FillName(in.Device, WINTERNAL_NTFS_DEV_NAME_MAX, device)) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    in.StartFrn = startFrn;
    std::vector<uint8_t> out(WINTERNAL_NTFS_USN_BUF);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_NTFS_MFT_ENUM, &in, sizeof(in),
                out.data(), (uint32_t)out.size(), &ret)) return std::nullopt;
    out.resize(ret);
    return out;
}

std::optional<std::vector<uint8_t>>
DriverSession::ntfsStreams(std::wstring_view ntPath) {
    WINTERNAL_NTFS_STREAMS_IN in{};
    if (!FillName(in.Path, WINTERNAL_NTFS_PATH_MAX, ntPath)) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    std::vector<uint8_t> out(64 * 1024);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_NTFS_STREAMS, &in, sizeof(in),
                out.data(), (uint32_t)out.size(), &ret)) return std::nullopt;
    out.resize(ret);
    return out;
}

bool DriverSession::selfProtectSet(bool enable, uint32_t ownerPid) {
    WINTERNAL_SELFPROTECT_IN in{ enable ? 1u : 0u, ownerPid };
    return ioctl_(IOCTL_WINTERNAL_SELFPROTECT_SET, &in, sizeof(in), nullptr, 0, nullptr);
}

std::optional<DriverSession::SelfProtect> DriverSession::selfProtectStatus() {
    WINTERNAL_SELFPROTECT_OUT out{};
    if (!ioctl_(IOCTL_WINTERNAL_SELFPROTECT_STATUS, nullptr, 0, &out, sizeof(out), nullptr))
        return std::nullopt;
    return SelfProtect{ out.Engaged != 0, out.OwnerPid };
}

std::optional<uint32_t>
DriverSession::ntfsFilterAdd(std::wstring_view pattern, FilterAction action) {
    if (pattern.empty() || pattern.size() >= WINTERNAL_FILTER_PATTERN_MAX) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    WINTERNAL_FILTER_RULE in{};
    WINTERNAL_FILTER_RULE out{};
    in.Action = (uint32_t)action;
    std::memcpy(in.Pattern, pattern.data(), pattern.size() * sizeof(wchar_t));
    in.Pattern[pattern.size()] = 0;
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_NTFS_FILTER_ADD, &in, sizeof(in), &out, sizeof(out), &ret))
        return std::nullopt;
    return out.RuleId;
}

bool DriverSession::ntfsFilterRemove(uint32_t ruleId) {
    WINTERNAL_FILTER_REMOVE_IN in{ ruleId, 0 };
    return ioctl_(IOCTL_WINTERNAL_NTFS_FILTER_REMOVE, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::ntfsFilterClear() {
    return ioctl_(IOCTL_WINTERNAL_NTFS_FILTER_CLEAR, nullptr, 0, nullptr, 0, nullptr);
}

std::vector<DriverSession::FilterRule> DriverSession::ntfsFilterList() {
    std::vector<FilterRule> rules;
    size_t cap = FIELD_OFFSET(WINTERNAL_FILTER_LIST_OUT, Rules)
               + (size_t)WINTERNAL_FILTER_MAX_RULES * sizeof(WINTERNAL_FILTER_RULE);
    std::vector<uint8_t> buf(cap);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_NTFS_FILTER_LIST, nullptr, 0, buf.data(), (uint32_t)buf.size(), &ret))
        return rules;
    auto* out = reinterpret_cast<PWINTERNAL_FILTER_LIST_OUT>(buf.data());
    for (uint32_t i = 0; i < out->Count; ++i) {
        FilterRule r;
        r.ruleId     = out->Rules[i].RuleId;
        r.action     = out->Rules[i].Action;
        r.matchCount = out->Rules[i].MatchCount;
        r.pattern    = out->Rules[i].Pattern;
        rules.push_back(std::move(r));
    }
    return rules;
}

bool DriverSession::procMonitorStart() {
    return ioctl_(IOCTL_WINTERNAL_PROC_MONITOR_START, nullptr, 0, nullptr, 0, nullptr);
}
bool DriverSession::procMonitorStop() {
    return ioctl_(IOCTL_WINTERNAL_PROC_MONITOR_STOP, nullptr, 0, nullptr, 0, nullptr);
}
std::vector<DriverSession::ProcEvent> DriverSession::procMonitorRead() {
    std::vector<ProcEvent> out;
    // 64 events per call is a balance between roundtrip overhead and
    // memory for the driver's METHOD_BUFFERED copy.
    constexpr size_t kBatch = 64;
    size_t cap = FIELD_OFFSET(WINTERNAL_PROC_MON_OUT, Events)
               + kBatch * sizeof(WINTERNAL_PROC_EVENT);
    std::vector<uint8_t> buf(cap);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_PROC_MONITOR_READ, nullptr, 0,
                buf.data(), (uint32_t)buf.size(), &ret)) return out;
    auto* mo = reinterpret_cast<PWINTERNAL_PROC_MON_OUT>(buf.data());
    out.reserve(mo->Count);
    for (uint32_t i = 0; i < mo->Count; ++i) {
        const auto& e = mo->Events[i];
        ProcEvent r{};
        r.timestampNs = e.TimestampNs;
        r.eventType   = e.EventType;
        r.pid         = e.Pid;
        r.parentPid   = e.ParentPid;
        r.creatingPid = e.CreatingPid;
        r.creatingTid = e.CreatingTid;
        r.dropped     = e.Dropped;
        if (e.ImageLen) r.image.assign(e.Image, e.ImageLen ? e.ImageLen - 1 : 0);
        if (e.CmdLen)   r.cmdLine.assign(e.CmdLine, e.CmdLen ? e.CmdLen - 1 : 0);
        out.push_back(std::move(r));
    }
    return out;
}

std::optional<uint32_t>
DriverSession::procRuleAdd(std::wstring_view pattern, ProcRuleAction action, uint32_t status) {
    if (pattern.empty() || pattern.size() >= WINTERNAL_PROC_RULE_PATTERN_MAX) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    WINTERNAL_PROC_RULE in{};
    WINTERNAL_PROC_RULE out{};
    in.Action = (uint32_t)action;
    in.Status = status;
    std::memcpy(in.Pattern, pattern.data(), pattern.size() * sizeof(wchar_t));
    in.Pattern[pattern.size()] = 0;
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_PROC_RULE_ADD, &in, sizeof(in), &out, sizeof(out), &ret))
        return std::nullopt;
    return out.RuleId;
}

bool DriverSession::procRuleRemove(uint32_t ruleId) {
    WINTERNAL_PROC_RULE_REMOVE_IN in{ ruleId, 0 };
    return ioctl_(IOCTL_WINTERNAL_PROC_RULE_REMOVE, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::procRuleClear() {
    return ioctl_(IOCTL_WINTERNAL_PROC_RULE_CLEAR, nullptr, 0, nullptr, 0, nullptr);
}

std::vector<DriverSession::ProcRule> DriverSession::procRuleList() {
    std::vector<ProcRule> rules;
    size_t cap = FIELD_OFFSET(WINTERNAL_PROC_RULE_LIST_OUT, Rules)
               + (size_t)WINTERNAL_PROC_RULE_MAX_RULES * sizeof(WINTERNAL_PROC_RULE);
    std::vector<uint8_t> buf(cap);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_PROC_RULE_LIST, nullptr, 0, buf.data(), (uint32_t)buf.size(), &ret))
        return rules;
    auto* lo = reinterpret_cast<PWINTERNAL_PROC_RULE_LIST_OUT>(buf.data());
    rules.reserve(lo->Count);
    for (uint32_t i = 0; i < lo->Count; ++i) {
        ProcRule r;
        r.ruleId     = lo->Rules[i].RuleId;
        r.action     = lo->Rules[i].Action;
        r.matchCount = lo->Rules[i].MatchCount;
        r.status     = lo->Rules[i].Status;
        r.pattern    = lo->Rules[i].Pattern;
        rules.push_back(std::move(r));
    }
    return rules;
}

std::optional<uint32_t>
DriverSession::drvRuleAdd(std::wstring_view pattern, DrvRuleAction action, uint32_t status) {
    if (pattern.empty() || pattern.size() >= WINTERNAL_DRV_RULE_PATTERN_MAX) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    WINTERNAL_DRV_RULE in{};
    WINTERNAL_DRV_RULE out{};
    in.Action = (uint32_t)action;
    in.Status = status;
    std::memcpy(in.Pattern, pattern.data(), pattern.size() * sizeof(wchar_t));
    in.Pattern[pattern.size()] = 0;
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_DRV_RULE_ADD, &in, sizeof(in), &out, sizeof(out), &ret))
        return std::nullopt;
    return out.RuleId;
}

bool DriverSession::drvRuleRemove(uint32_t ruleId) {
    WINTERNAL_DRV_RULE_REMOVE_IN in{ ruleId, 0 };
    return ioctl_(IOCTL_WINTERNAL_DRV_RULE_REMOVE, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::drvRuleClear() {
    return ioctl_(IOCTL_WINTERNAL_DRV_RULE_CLEAR, nullptr, 0, nullptr, 0, nullptr);
}

std::vector<DriverSession::DrvRule> DriverSession::drvRuleList(bool* hookLive, bool* cmLive) {
    std::vector<DrvRule> rules;
    if (hookLive) *hookLive = false;
    if (cmLive)   *cmLive   = false;
    size_t cap = FIELD_OFFSET(WINTERNAL_DRV_RULE_LIST_OUT, Rules)
               + (size_t)WINTERNAL_DRV_RULE_MAX_RULES * sizeof(WINTERNAL_DRV_RULE);
    std::vector<uint8_t> buf(cap);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_DRV_RULE_LIST, nullptr, 0, buf.data(), (uint32_t)buf.size(), &ret))
        return rules;
    auto* lo = reinterpret_cast<PWINTERNAL_DRV_RULE_LIST_OUT>(buf.data());
    if (hookLive) *hookLive = (lo->Flags & WINTERNAL_DRV_RULE_FLAG_HOOK_LIVE) != 0;
    if (cmLive)   *cmLive   = (lo->Flags & WINTERNAL_DRV_RULE_FLAG_CM_LIVE)   != 0;
    rules.reserve(lo->Count);
    for (uint32_t i = 0; i < lo->Count; ++i) {
        DrvRule r;
        r.ruleId     = lo->Rules[i].RuleId;
        r.action     = lo->Rules[i].Action;
        r.matchCount = lo->Rules[i].MatchCount;
        r.status     = lo->Rules[i].Status;
        r.pattern    = lo->Rules[i].Pattern;
        rules.push_back(std::move(r));
    }
    return rules;
}

std::optional<uint32_t>
DriverSession::procProtectAdd(std::wstring_view pattern, uint32_t status, uint32_t* outFlags) {
    if (pattern.empty() || pattern.size() >= WINTERNAL_PROC_PROTECT_PATTERN_MAX) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    WINTERNAL_PROC_PROTECT_RULE in{};
    WINTERNAL_PROC_PROTECT_RULE out{};
    in.Status = status;
    std::memcpy(in.Pattern, pattern.data(), pattern.size() * sizeof(wchar_t));
    in.Pattern[pattern.size()] = 0;
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_PROC_PROTECT_ADD, &in, sizeof(in), &out, sizeof(out), &ret))
        return std::nullopt;
    if (outFlags) *outFlags = out.Flags;
    return out.RuleId;
}

bool DriverSession::procProtectRemove(uint32_t ruleId) {
    WINTERNAL_PROC_PROTECT_REMOVE_IN in{ ruleId, 0 };
    return ioctl_(IOCTL_WINTERNAL_PROC_PROTECT_REMOVE, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::procProtectClear() {
    return ioctl_(IOCTL_WINTERNAL_PROC_PROTECT_CLEAR, nullptr, 0, nullptr, 0, nullptr);
}

std::vector<DriverSession::ProcProtectRule> DriverSession::procProtectList() {
    std::vector<ProcProtectRule> rules;
    size_t cap = FIELD_OFFSET(WINTERNAL_PROC_PROTECT_LIST_OUT, Rules)
               + (size_t)WINTERNAL_PROC_PROTECT_MAX_RULES * sizeof(WINTERNAL_PROC_PROTECT_RULE);
    std::vector<uint8_t> buf(cap);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_PROC_PROTECT_LIST, nullptr, 0, buf.data(), (uint32_t)buf.size(), &ret))
        return rules;
    auto* lo = reinterpret_cast<PWINTERNAL_PROC_PROTECT_LIST_OUT>(buf.data());
    rules.reserve(lo->Count);
    for (uint32_t i = 0; i < lo->Count; ++i) {
        ProcProtectRule r;
        r.ruleId     = lo->Rules[i].RuleId;
        r.blockCount = lo->Rules[i].BlockCount;
        r.status     = lo->Rules[i].Status;
        r.flags      = lo->Rules[i].Flags;
        r.pattern    = lo->Rules[i].Pattern;
        rules.push_back(std::move(r));
    }
    return rules;
}

std::optional<uint32_t>
DriverSession::winRuleAdd(WinRuleKind kind, WinRuleAction action, std::wstring_view pattern,
                          uint32_t* outFlags, uint32_t* outLastHookError) {
    if (pattern.empty() || pattern.size() >= WINTERNAL_WIN_RULE_PATTERN_MAX) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    WINTERNAL_WIN_RULE in{};
    WINTERNAL_WIN_RULE out{};
    in.Kind   = (uint32_t)kind;
    in.Action = (uint32_t)action;
    std::memcpy(in.Pattern, pattern.data(), pattern.size() * sizeof(wchar_t));
    in.Pattern[pattern.size()] = 0;
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_WIN_RULE_ADD, &in, sizeof(in), &out, sizeof(out), &ret))
        return std::nullopt;
    if (outFlags)         *outFlags         = out.Flags;
    if (outLastHookError) *outLastHookError = out.LastHookError;
    return out.RuleId;
}

bool DriverSession::winRuleRemove(uint32_t ruleId) {
    WINTERNAL_WIN_RULE_REMOVE_IN in{ ruleId, 0 };
    return ioctl_(IOCTL_WINTERNAL_WIN_RULE_REMOVE, &in, sizeof(in), nullptr, 0, nullptr);
}

bool DriverSession::winRuleClear() {
    return ioctl_(IOCTL_WINTERNAL_WIN_RULE_CLEAR, nullptr, 0, nullptr, 0, nullptr);
}

std::vector<DriverSession::WinRule> DriverSession::winRuleList() {
    std::vector<WinRule> rules;
    size_t cap = FIELD_OFFSET(WINTERNAL_WIN_RULE_LIST_OUT, Rules)
               + (size_t)WINTERNAL_WIN_RULE_MAX_RULES * sizeof(WINTERNAL_WIN_RULE);
    std::vector<uint8_t> buf(cap);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_WIN_RULE_LIST, nullptr, 0, buf.data(), (uint32_t)buf.size(), &ret))
        return rules;
    auto* lo = reinterpret_cast<PWINTERNAL_WIN_RULE_LIST_OUT>(buf.data());
    rules.reserve(lo->Count);
    for (uint32_t i = 0; i < lo->Count; ++i) {
        WinRule r;
        r.ruleId        = lo->Rules[i].RuleId;
        r.kind          = lo->Rules[i].Kind;
        r.action        = lo->Rules[i].Action;
        r.hitCount      = lo->Rules[i].HitCount;
        r.flags         = lo->Rules[i].Flags;
        r.lastHookError = lo->Rules[i].LastHookError;
        r.pattern       = lo->Rules[i].Pattern;
        rules.push_back(std::move(r));
    }
    return rules;
}

std::optional<DriverSession::HookRvaResult>
DriverSession::hookInstallByRva(std::wstring_view moduleBaseName, uint32_t rva, uint32_t hookId) {
    if (moduleBaseName.empty() || moduleBaseName.size() >= 64 || rva == 0) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    WINTERNAL_HOOK_RVA_REQ  in{};
    WINTERNAL_HOOK_RVA_RESP out{};
    std::memcpy(in.Module, moduleBaseName.data(), moduleBaseName.size() * sizeof(wchar_t));
    in.Module[moduleBaseName.size()] = 0;
    in.Rva    = rva;
    in.HookId = hookId;
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_HOOK_INSTALL_BY_RVA, &in, sizeof(in), &out, sizeof(out), &ret))
        return std::nullopt;
    HookRvaResult r;
    r.installed  = (out.Installed != 0);
    r.ntStatus   = out.NtStatus;
    r.resolvedVa = out.ResolvedVa;
    return r;
}

std::optional<std::vector<uint8_t>>
DriverSession::ntfsRawRead(std::wstring_view device, uint64_t offset, uint32_t length) {
    if (length == 0 || length > WINTERNAL_NTFS_RAW_MAX) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    WINTERNAL_NTFS_RAW_READ_IN in{};
    if (!FillName(in.Device, WINTERNAL_NTFS_DEV_NAME_MAX, device)) {
        StoreError(ERROR_INVALID_PARAMETER); return std::nullopt;
    }
    in.Offset = offset;
    in.Length = length;
    std::vector<uint8_t> out(length);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_NTFS_RAW_READ, &in, sizeof(in),
                out.data(), length, &ret)) return std::nullopt;
    out.resize(ret);
    return out;
}

std::vector<DriverSession::AuditRow> DriverSession::auditTail(uint32_t maxRows) {
    std::vector<AuditRow> out;
    if (maxRows == 0) return out;
    size_t cap = FIELD_OFFSET(WINTERNAL_AUDIT_OUT, Rows) + maxRows * sizeof(WINTERNAL_AUDIT_ROW);
    std::vector<uint8_t> buf(cap);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_AUDIT_TAIL, nullptr, 0, buf.data(), (uint32_t)buf.size(), &ret)) return out;
    auto* p = reinterpret_cast<PWINTERNAL_AUDIT_OUT>(buf.data());
    out.reserve(p->RowCount);
    for (uint32_t i = 0; i < p->RowCount; ++i) {
        auto& r = p->Rows[i];
        out.push_back({ r.TimestampNs, r.IoControlCode, r.CallerPid, r.Target, r.Length, r.Status });
    }
    return out;
}

std::optional<DriverSession::LuaResult> DriverSession::luaExec(std::string_view script) {
    if (script.empty() || script.size() > WINTERNAL_LUA_MAX_SCRIPT) {
        StoreError(ERROR_INVALID_PARAMETER);
        return std::nullopt;
    }
    std::vector<uint8_t> in(FIELD_OFFSET(WINTERNAL_LUA_IN, Script) + script.size());
    auto* req = reinterpret_cast<PWINTERNAL_LUA_IN>(in.data());
    req->ScriptLength = (uint32_t)script.size();
    req->Reserved = 0;
    std::memcpy(req->Script, script.data(), script.size());

    std::vector<uint8_t> out(FIELD_OFFSET(WINTERNAL_LUA_OUT, Output) + WINTERNAL_LUA_OUT_DEFAULT);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_LUA_EXEC, in.data(), (uint32_t)in.size(),
                out.data(), (uint32_t)out.size(), &ret)) return std::nullopt;

    auto* res = reinterpret_cast<PWINTERNAL_LUA_OUT>(out.data());
    LuaResult r;
    r.luaStatus = res->LuaStatus;
    r.output.assign(reinterpret_cast<const char*>(res->Output), res->OutputLength);
    return r;
}

std::vector<SsdtEntry> DriverSession::enumSsdt() {
    std::vector<SsdtEntry> out;
    std::vector<uint8_t> buf(2 * 1024 * 1024);
    uint32_t ret = 0;
    if (!ioctl_(IOCTL_WINTERNAL_ENUM_SSDT, nullptr, 0, buf.data(), (uint32_t)buf.size(), &ret)) return out;
    auto* list = reinterpret_cast<PWINTERNAL_SSDT_LIST>(buf.data());
    out.reserve(list->Count);
    for (uint32_t i = 0; i < list->Count; ++i) {
        out.push_back({ list->Entries[i].Index, list->Entries[i].Routine,
                        list->Entries[i].ModuleBase, list->Entries[i].ModuleName });
    }
    return out;
}

} // namespace winternal
