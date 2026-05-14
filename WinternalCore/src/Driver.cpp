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
