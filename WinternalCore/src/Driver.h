// User-mode wrappers around the Winternal.sys IOCTL surface.
//
// All functions return std::optional / std::expected-like results: failure
// reasons live in GetLastError() (Win32 mapping of the driver's NTSTATUS).
// The DriverSession opens \\.\Winternal once; if the driver isn't loaded
// every method short-circuits to false/empty.
//
#pragma once
#include "Util.h"
#include <Windows.h>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace winternal {

struct DriverVersion { uint32_t major, minor, buildTime; };

struct DriverPidEntry {
    uint32_t pid;
    uint32_t parentPid;
    std::string imageName;   // 8.3 short name from EPROCESS->ImageFileName
};

enum class CallbackKind : uint32_t {
    Process = 1,
    Image   = 2,
    Thread  = 3,
};

struct CallbackEntry {
    uint64_t routine;
    uint64_t moduleBase;
    std::string moduleName;
};

struct DriverModuleEntry {
    uint64_t imageBase;
    uint32_t imageSize;
    std::string fullPath;     // \SystemRoot\system32\... etc.
};

struct SsdtEntry {
    uint32_t index;
    uint64_t routine;
    uint64_t moduleBase;
    std::string moduleName;
};

struct KcallResult {
    uint64_t returnValue;
    bool     faulted;
};

class DriverSession {
public:
    DriverSession();
    ~DriverSession();
    DriverSession(const DriverSession&) = delete;
    DriverSession& operator=(const DriverSession&) = delete;

    bool open();                 // returns false + sets GetLastError on failure
    void close();
    bool isOpen() const { return handle_.valid(); }

    // Basic
    std::optional<DriverVersion> getVersion();
    std::vector<DriverPidEntry>  enumPids();

    // Kernel memory R/W
    std::optional<std::vector<uint8_t>> kread(uint64_t address, uint32_t length);
    bool kwrite(uint64_t address, const void* data, uint32_t length);

    // Lookup / pool / call
    std::optional<uint64_t>   ksym(std::wstring_view name);
    std::optional<uint64_t>   kalloc(uint32_t length, uint32_t tag = 0, bool nonPaged = true);
    bool                      kfree(uint64_t address, uint32_t tag = 0);
    std::optional<KcallResult> kcall(uint64_t address, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);

    // Process control
    struct UnprotectResult { uint32_t fieldOffsetUsed; uint8_t prevValue; };
    std::optional<UnprotectResult> unprotectProcess(uint32_t pid, uint8_t newValue = 0, uint32_t fieldOffset = 0);
    bool killProcess(uint32_t pid, uint32_t exitStatus = 1);

    // Force-protect via Ob* pre-operation callbacks. While a PID is locked,
    // any user-mode caller that opens a handle to the process or its threads
    // gets destructive (and informational, by design) access bits stripped.
    // Kernel-mode openers are exempt. Idempotent; capped at WINTERNAL_PROTECT_MAX.
    bool protectLock(uint32_t pid);
    bool protectUnlock(uint32_t pid);
    std::vector<uint32_t> protectList();

    // Toggle TOKEN_HAS_UI_ACCESS on the target process's primary token.
    // Returns the previous and new TokenFlags ULONG via out-params when
    // they're non-null. Bypasses the SeTcbPrivilege check that blocks the
    // user-mode SetTokenInformation(TokenUIAccess) path.
    bool setTokenUIAccess(uint32_t pid, bool enable,
                          uint32_t* prevFlags = nullptr,
                          uint32_t* newFlags  = nullptr,
                          uint32_t fieldOffset = 0);

    // Write EPROCESS->SignatureLevel + SectionSignatureLevel. Used to make
    // a process appear MS-signed for win32k's high-band gates and for any
    // other check that consults the process signature level field.
    // Returns prev values via out-params when non-null.
    bool setSignatureLevel(uint32_t pid, uint8_t sigLevel, uint8_t sectionSigLevel,
                           uint8_t* prevSig = nullptr,
                           uint8_t* prevSection = nullptr,
                           uint32_t fieldOffset = 0);

    // Write into a kernel CODE page. Toggles CR0.WP, writes, verifies via
    // readback. Up to 64 bytes per call. Use kread() to capture originals
    // before patching so the caller can scope-restore on exit.
    bool kcodePatch(uint64_t address, const void* data, uint32_t length);

    // Kernel address of Winternal.sys's "always returns 1" stub. Caller
    // points an IAT slot at this address to neuter a bool-returning gate
    // without writing to the gate's .text (which HVCI typically blocks).
    std::optional<uint64_t> getTrueStub();

    // EPROCESS->Win32Process for the given PID (tagPROCESSINFO*). Returns
    // 0 if the process has no Win32 (no GUI) state. Pool memory — caller
    // can kread/kwrite into it directly without HVCI/CR0 issues.
    std::optional<uint64_t> getWin32Process(uint32_t pid);

    // Kernel-side process inspection — bypasses user-mode hooks since
    // each query runs through Zw* from kernel context.
    struct ThreadEntry {
        uint32_t tid; uint32_t state; uint32_t waitReason; int32_t priority;
        uint64_t startAddress; uint64_t kernelTime100Ns; uint64_t userTime100Ns;
        uint64_t createTimeFt;
    };
    std::vector<ThreadEntry> enumThreads(uint32_t pid);

    struct MitigationItem {
        uint32_t policyId; int32_t ntStatus; uint64_t value;
    };
    std::vector<MitigationItem> queryMitigations(uint32_t pid);

    struct TokenPriv { uint64_t luid; uint32_t attributes; };
    struct TokenInfo {
        std::vector<uint8_t> userSid;
        std::vector<uint8_t> integritySid;
        uint32_t integrityRid = 0;
        uint32_t elevationType = 0;
        bool elevated = false;
        bool uiAccess = false;
        uint32_t sessionId = 0;
        std::vector<TokenPriv> privileges;
    };
    std::optional<TokenInfo> queryTokenInfo(uint32_t pid);

    struct MemRegion {
        uint64_t baseAddress; uint64_t regionSize;
        uint32_t state; uint32_t protect; uint32_t type;
    };
    std::vector<MemRegion> queryMemRegions(uint32_t pid, bool* truncated = nullptr);

    // Rootkit detection
    std::vector<CallbackEntry>   enumCallbacks(CallbackKind kind);
    std::vector<DriverModuleEntry> enumKernelDrivers();
    std::vector<SsdtEntry>       enumSsdt();

    // Kernel-mode inline hooks. Returns trampoline kernel address on install.
    std::optional<uint64_t> khookInstall(uint64_t target, uint64_t detour, uint32_t prologueSize = 16);
    bool                    khookUninstall(uint64_t target);
    bool                    khookUninstallAll();

    // Kernel-mode Lua execution. Ships `script` to the driver, which runs
    // it with the `wnk` table exposed and captures all output. Returns the
    // captured output plus the lua status code.
    struct LuaResult { std::string output; int32_t luaStatus; };
    std::optional<LuaResult> luaExec(std::string_view script);

    // Lockdown / audit.
    struct LockdownStatus { bool engaged; uint32_t engagedTickMs; };
    std::optional<LockdownStatus> lockdownEngage();
    std::optional<LockdownStatus> lockdownStatus();

    struct AuditRow {
        uint64_t timestampNs;
        uint32_t ioControlCode;
        uint32_t callerPid;
        uint64_t target;
        uint32_t length;
        int32_t  status;
    };
    std::vector<AuditRow> auditTail(uint32_t maxRows = 256);

    // Force-unload another kernel driver by name (no "\Driver\" prefix).
    // Resolves the driver object and calls its DriverUnload directly,
    // bypassing SCM. Use only on drivers that won't sc stop. The target's
    // image stays mapped; this just runs its cleanup routine.
    bool forceUnloadDriver(std::wstring_view name);

    // Kernel-level service management. Registers / loads / unloads /
    // deregisters another kernel driver by going through Zw*Key +
    // ZwLoadDriver/ZwUnloadDriver. Bypasses SCM entirely; signing is NOT
    // bypassed — the kernel loader's signature check still applies when
    // DSE is enforcing.
    bool kdrvRegister(std::wstring_view name, std::wstring_view ntImagePath, uint32_t startType = 3);
    bool kdrvLoad(std::wstring_view name);
    bool kdrvUnload(std::wstring_view name);
    bool kdrvDeregister(std::wstring_view name);
    bool kdrvSetStart(std::wstring_view name, uint32_t startType);

    // Raw read from a kernel device path (typically L"\\Device\\HarddiskVolume3"
    // for a volume or L"\\Device\\PhysicalDriveN" for the whole disk). The
    // driver does the open + ZwReadFile in kernel mode, bypassing every
    // minifilter / user-mode hook above NTFS. Caller-chosen length is
    // capped server-side at 1 MiB. Empty on error.
    std::optional<std::vector<uint8_t>> ntfsRawRead(std::wstring_view device,
                                                    uint64_t offset, uint32_t length);

    // NTFS FSCTL surface — every entry below opens the device or file
    // inside the driver with PreviousMode=Kernel + OBJ_KERNEL_HANDLE,
    // so the FSCTL hits NTFS unfiltered by user-mode minifilters.
    struct NtfsVolData {
        uint64_t serial;
        uint64_t numberSectors, totalClusters, freeClusters, totalReserved;
        uint32_t bytesPerSector, bytesPerCluster;
        uint32_t bytesPerFileRecordSegment, clustersPerFileRecordSegment;
        uint64_t mftValidDataLength, mftStartLcn, mft2StartLcn;
        uint64_t mftZoneStart, mftZoneEnd;
    };
    std::optional<NtfsVolData> ntfsVolData(std::wstring_view device);

    struct UsnJournal {
        uint64_t journalId;
        int64_t  firstUsn, nextUsn, lowestValidUsn, maxUsn;
        uint64_t maxSize, allocationDelta;
    };
    std::optional<UsnJournal> ntfsUsnQuery(std::wstring_view device);

    // Returns the raw output blob from FSCTL_READ_USN_JOURNAL: first 8
    // bytes = next USN cursor, rest = USN_RECORD_V2 packed array.
    std::optional<std::vector<uint8_t>>
        ntfsUsnRead(std::wstring_view device, uint64_t journalId,
                    int64_t startUsn, uint32_t reasonMask, bool waitForFresh);

    // Same shape as ntfsUsnRead but driven by FSCTL_ENUM_USN_DATA.
    std::optional<std::vector<uint8_t>>
        ntfsMftEnum(std::wstring_view device, uint64_t startFrn);

    // Raw FILE_STREAM_INFORMATION blob (NextEntryOffset chain).
    std::optional<std::vector<uint8_t>>
        ntfsStreams(std::wstring_view ntPath);

    // NTFS filter rule management. Patterns are RtlIsNameInExpression-style
    // DOS wildcards (`*`, `?`, `<`, `>`, `"`). Actions: 0=deny, 1=notfound,
    // 2=readonly, 3=log. First-match-wins; max 64 rules.
    struct FilterRule {
        uint32_t ruleId;
        uint32_t action;
        uint32_t matchCount;
        std::wstring pattern;
    };
    enum class FilterAction { Deny = 0, NotFound = 1, ReadOnly = 2, Log = 3 };

    std::optional<uint32_t> ntfsFilterAdd(std::wstring_view pattern, FilterAction action);
    bool                    ntfsFilterRemove(uint32_t ruleId);
    bool                    ntfsFilterClear();
    std::vector<FilterRule> ntfsFilterList();

    // Real-time process monitor — driver registers PsSetCreateProcessNotifyRoutineEx
    // and streams events through a ring buffer + blocking IOCTL.
    struct ProcEvent {
        uint64_t timestampNs;     // KeQuerySystemTimePrecise units (100ns)
        uint32_t eventType;       // 0=create, 1=exit
        uint32_t pid;
        uint32_t parentPid;
        uint32_t creatingPid;
        uint32_t creatingTid;
        uint32_t dropped;         // events lost since last read (only set on
                                  // the first event of a chunk after a drop)
        std::wstring image;       // full NT path
        std::wstring cmdLine;
    };
    bool                    procMonitorStart();
    bool                    procMonitorStop();
    // Blocking read — waits up to ~2s on the kernel event; returns
    // whatever's accumulated. Empty vector means "no events in window";
    // call again in a loop.
    std::vector<ProcEvent>  procMonitorRead();

    // Process-create rules. Actions: 0=allow, 1=deny, 2=log. The deny
    // path writes `status` verbatim into PS_CREATE_NOTIFY_INFO::
    // CreationStatus — including STATUS_SUCCESS, which lets the rule
    // "deny by lying" so callers checking the syscall return don't
    // notice. Recommended default is STATUS_ACCESS_DENIED.
    enum class ProcRuleAction { Allow = 0, Deny = 1, Log = 2 };
    struct ProcRule {
        uint32_t ruleId;
        uint32_t action;
        uint32_t matchCount;
        uint32_t status;          // NTSTATUS written to CreationStatus on DENY
        std::wstring pattern;
    };
    std::optional<uint32_t> procRuleAdd(std::wstring_view pattern, ProcRuleAction action,
                                        uint32_t status);
    bool                    procRuleRemove(uint32_t ruleId);
    bool                    procRuleClear();
    std::vector<ProcRule>   procRuleList();

    // Driver-load rules. Symmetric to procRule* but enforced inside the
    // NtLoadDriver prologue hook. Patterns match the service-name leaf
    // of the registry path (e.g. "Foo" for
    // "\Registry\Machine\System\CurrentControlSet\Services\Foo"). Catches
    // both SCM-driven loads and direct ZwLoadDriver callers (including
    // our own `drv load`). hookLive (out-param on add/list) reports
    // whether the kernel hook is actually installed -- if FALSE, rules
    // are stored but inert (HVCI rejected the inline-hook write).
    enum class DrvRuleAction { Allow = 0, Deny = 1, Log = 2 };
    struct DrvRule {
        uint32_t ruleId;
        uint32_t action;
        uint32_t matchCount;
        uint32_t status;          // NTSTATUS returned on DENY
        std::wstring pattern;
    };
    std::optional<uint32_t> drvRuleAdd(std::wstring_view pattern, DrvRuleAction action,
                                       uint32_t status);
    bool                    drvRuleRemove(uint32_t ruleId);
    bool                    drvRuleClear();
    // hookLive: inline NtLoadDriver hook installed (precise, blocks only loads).
    // cmLive  : Cm-callback registered (broad, blocks all opens of denied
    //           service keys; works under HVCI / kernel-CI).
    std::vector<DrvRule>    drvRuleList(bool* hookLive = nullptr,
                                        bool* cmLive   = nullptr);

    // Process-termination protect rules. Evaluated inside the
    // NtTerminateProcess prologue hook; a target image matching any
    // pattern returns STATUS_ACCESS_DENIED to the terminator. Self-
    // termination always succeeds, so the system can still exit cleanly.
    struct ProcProtectRule {
        uint32_t ruleId;
        uint32_t blockCount;
        uint32_t status;          // NTSTATUS returned from NtTerminateProcess on match
        uint32_t flags;           // WINTERNAL_PROC_PROTECT_FLAG_HOOK_LIVE / FLAG_OB_LIVE
        std::wstring pattern;
    };

    // Window rules (driver-resident; the shield DLL reads them via IOCTL).
    enum class WinRuleKind : uint32_t {
        TitleGlob = 1, ClassGlob = 2, Pid = 3, ImageGlob = 4
    };
    enum class WinRuleAction : uint32_t {
        BlockClose = 0, BlockCreate = 1
    };
    struct WinRule {
        uint32_t ruleId;
        uint32_t kind;        // WinRuleKind
        uint32_t action;      // WinRuleAction
        uint32_t hitCount;
        uint32_t flags;       // WINTERNAL_WIN_FLAG_* bits
        uint32_t lastHookError; // NTSTATUS from last block-destroy install
        std::wstring pattern;
    };
    // outFlags receives WINTERNAL_WIN_FLAG_DESTROY_HOOK_LIVE et al so the
    // CLI can tell users whether a block-destroy rule is actually engaged.
    // outLastHookError receives the NTSTATUS from the last hook-install
    // attempt -- useful when the hook didn't install and you want to know
    // why (HVCI vs LDE bug vs symbol-not-found etc.).
    std::optional<uint32_t> winRuleAdd(WinRuleKind kind, WinRuleAction action,
                                       std::wstring_view pattern,
                                       uint32_t* outFlags = nullptr,
                                       uint32_t* outLastHookError = nullptr);
    bool                    winRuleRemove(uint32_t ruleId);
    bool                    winRuleClear();
    std::vector<WinRule>    winRuleList();
    // procProtectAdd returns the assigned rule ID; outFlags (if non-null)
    // receives the WINTERNAL_PROC_PROTECT_FLAG_* mask telling the caller
    // which enforcement paths are live for this rule.
    std::optional<uint32_t>     procProtectAdd(std::wstring_view pattern, uint32_t status,
                                               uint32_t* outFlags = nullptr);
    bool                        procProtectRemove(uint32_t ruleId);
    bool                        procProtectClear();
    std::vector<ProcProtectRule> procProtectList();

    // Install a kernel inline hook by pre-resolved RVA. Used after CLI-side
    // PDB lookup to bypass the driver's export-only locate path -- works on
    // non-exported symbols and across any Win11 build.
    struct HookRvaResult {
        bool        installed;
        uint32_t    ntStatus;     // detailed failure reason
        uint64_t    resolvedVa;   // base + RVA the driver computed
    };
    std::optional<HookRvaResult> hookInstallByRva(std::wstring_view moduleBaseName,
                                                  uint32_t rva,
                                                  uint32_t hookId);

    // Self-protection. When engaged, the driver auto-adds `ownerPid` to
    // the Ob protect list and refuses any IOCTL that would weaken
    // protection (disengage, unprotect of owner, force-unload Winternal,
    // SCM lifecycle of "Winternal") unless the caller IS the owner PID.
    bool selfProtectSet(bool enable, uint32_t ownerPid);
    struct SelfProtect { bool engaged; uint32_t ownerPid; };
    std::optional<SelfProtect> selfProtectStatus();

private:
    HandleGuard handle_;
    bool ioctl_(uint32_t code, const void* in, uint32_t inLen, void* out, uint32_t outLen, uint32_t* bytesReturned);
};

} // namespace winternal
