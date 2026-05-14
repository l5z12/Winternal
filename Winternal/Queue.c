/*++

Module Name:

    queue.c

Abstract:

    IOCTL dispatch for the Winternal driver. The driver exposes:

      VERSION / ENUM_PIDS  - sanity check + DKOM-resistant PID enumeration.

      KMEM_READ / WRITE    - arbitrary kernel virtual address read/write,
                             validated against MmSystemRangeStart and wrapped
                             in SEH. This is the "engine" primitive every
                             other operation can be built on from user mode.

      KSYM                 - MmGetSystemRoutineAddress() wrapper.
      KALLOC / KFREE       - ExAllocatePool2 / ExFreePoolWithTag wrappers.
      KCALL                - call a kernel routine at PASSIVE_LEVEL with up
                             to four ULONG_PTR arguments, SEH-wrapped.

      UNPROTECT_PROCESS    - clear EPROCESS->Protection on a target PID so
                             user-mode tools can subsequently open it.
      KILL_PROCESS         - ZwTerminateProcess via ObOpenObjectByPointer
                             so we can kill PPL/PP processes that user-mode
                             can't OpenProcess.

      ENUM_CALLBACKS       - walk PspCreateProcessNotifyRoutine[] etc. via
                             a one-shot pattern scan of the PsSet... export.
      ENUM_DRIVERS         - ZwQuerySystemInformation(SystemModuleInformation).
      ENUM_SSDT            - decode KeServiceDescriptorTable[0].KiServiceTable.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "queue.tmh"
#include <ntstrsafe.h>
#include <ntimage.h>
#include <intrin.h>
#include <bcrypt.h>     // SHA-256 via cng.lib (added in Winternal.vcxproj)

// SeLocateProcessImageName forward decl — exported by ntoskrnl on Win7+
// but the WDK doesn't always pick it up via the default ntddk.h chain.
NTKERNELAPI NTSTATUS SeLocateProcessImageName(
    _In_  PEPROCESS Process,
    _Out_ PUNICODE_STRING *ProcessImageName);

//
// Ntifs / ntoskrnl declarations the KMDF default headers don't include.
//
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
NTKERNELAPI UCHAR*   PsGetProcessImageFileName(_In_ PEPROCESS Process);
NTKERNELAPI HANDLE   PsGetProcessInheritedFromUniqueProcessId(_In_ PEPROCESS Process);
NTKERNELAPI PVOID    NTAPI MmGetSystemRoutineAddress(_In_ PUNICODE_STRING SystemRoutineName);
NTKERNELAPI BOOLEAN  NTAPI MmIsAddressValid(_In_ PVOID VirtualAddress);
NTKERNELAPI NTSTATUS NTAPI ObOpenObjectByPointer(
    _In_     PVOID            Object,
    _In_     ULONG            HandleAttributes,
    _In_opt_ PACCESS_STATE    PassedAccessState,
    _In_     ACCESS_MASK      DesiredAccess,
    _In_opt_ POBJECT_TYPE     ObjectType,
    _In_     KPROCESSOR_MODE  AccessMode,
    _Out_    PHANDLE          Handle);
NTSYSCALLAPI NTSTATUS NTAPI ZwTerminateProcess(_In_opt_ HANDLE ProcessHandle, _In_ NTSTATUS ExitStatus);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(_In_ ULONG SystemInformationClass,
                                                 _Inout_ PVOID SystemInformation,
                                                 _In_ ULONG SystemInformationLength,
                                                 _Out_opt_ PULONG ReturnLength);
extern POBJECT_TYPE *PsProcessType;
NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
    _In_     PUNICODE_STRING  ObjectName,
    _In_     ULONG            Attributes,
    _In_opt_ PACCESS_STATE    PassedAccessState,
    _In_     ACCESS_MASK      DesiredAccess,
    _In_     POBJECT_TYPE     ObjectType,
    _In_     KPROCESSOR_MODE  AccessMode,
    _Inout_opt_ PVOID         ParseContext,
    _Out_    PVOID*           Object);
extern POBJECT_TYPE *IoDriverObjectType;
extern POBJECT_TYPE *PsThreadType;

NTKERNELAPI HANDLE   NTAPI PsGetProcessId(_In_ PEPROCESS Process);
NTKERNELAPI HANDLE   NTAPI PsGetThreadProcessId(_In_ PETHREAD Thread);
NTKERNELAPI PACCESS_TOKEN NTAPI PsReferencePrimaryToken(_Inout_ PEPROCESS Process);
NTKERNELAPI VOID     NTAPI PsDereferencePrimaryToken(_In_ PACCESS_TOKEN PrimaryToken);
NTKERNELAPI PVOID    NTAPI PsGetProcessWin32Process(_In_ PEPROCESS Process);

// Process inspection primitives — all run with PreviousMode==KernelMode,
// so the user-mode-side hook surface that AVs/anti-cheat plant doesn't
// apply, and protection-level / handle-access checks are relaxed.
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(_In_ ULONG SystemInformationClass,
                                                 _Inout_ PVOID SystemInformation,
                                                 _In_ ULONG SystemInformationLength,
                                                 _Out_opt_ PULONG ReturnLength);
NTSYSAPI NTSTATUS NTAPI ZwOpenProcessTokenEx(_In_ HANDLE ProcessHandle, _In_ ACCESS_MASK DesiredAccess,
                                              _In_ ULONG HandleAttributes, _Out_ PHANDLE TokenHandle);
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationToken(_In_ HANDLE TokenHandle, _In_ ULONG TokenInformationClass,
                                                _Out_writes_bytes_opt_(TokenInformationLength) PVOID TokenInformation,
                                                _In_ ULONG TokenInformationLength,
                                                _Out_ PULONG ReturnLength);
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(_In_ HANDLE ProcessHandle, _In_ ULONG ProcessInformationClass,
                                                  _Out_writes_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
                                                  _In_ ULONG ProcessInformationLength,
                                                  _Out_opt_ PULONG ReturnLength);
NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                                              _In_ ULONG MemoryInformationClass,
                                              _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
                                              _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength);

// KAPC_STATE — internal kernel struct kept opaque here; the size needs
// to be large enough for ntoskrnl to write into. 64 bytes is the upper
// bound across Win10/11.
typedef struct _WN_KAPC_STATE { UCHAR Opaque[64]; } WN_KAPC_STATE;

NTKERNELAPI VOID NTAPI KeStackAttachProcess(_In_ PVOID Process, _Out_ PVOID ApcState);
NTKERNELAPI VOID NTAPI KeUnstackDetachProcess(_In_ PVOID ApcState);

// SID helpers — in ntifs.h, not always in ntddk.h's path.
NTSYSAPI ULONG  NTAPI RtlLengthSid(_In_ PSID Sid);
NTSYSAPI PUCHAR NTAPI RtlSubAuthorityCountSid(_In_ PSID Sid);
NTSYSAPI PULONG NTAPI RtlSubAuthoritySid(_In_ PSID Sid, _In_ ULONG SubAuthority);

// MEMORY_BASIC_INFORMATION and TOKEN_PRIVILEGES are in winnt.h-land; the
// driver only sees ntoskrnl headers. Define what we need locally.
typedef struct _WN_MEMORY_BASIC_INFORMATION {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    ULONG  AllocationProtect;
    USHORT PartitionId;
    SIZE_T RegionSize;
    ULONG  State;
    ULONG  Protect;
    ULONG  Type;
} WN_MEMORY_BASIC_INFORMATION;

typedef struct _WN_LUID_AND_ATTRIBUTES {
    LUID  Luid;
    ULONG Attributes;
} WN_LUID_AND_ATTRIBUTES;
typedef struct _WN_TOKEN_PRIVILEGES {
    ULONG PrivilegeCount;
    WN_LUID_AND_ATTRIBUTES Privileges[1];
} WN_TOKEN_PRIVILEGES, *PWN_TOKEN_PRIVILEGES;

#ifndef TOKEN_QUERY
#define TOKEN_QUERY 0x0008
#endif

// SystemInformation classes / sizes we need
#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

// SYSTEM_PROCESS_INFORMATION + SYSTEM_THREAD_INFORMATION layout (well-known,
// stable across Win10/11; size of SPI on x64 is 0x100 for 26100).
typedef struct _WN_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    struct { HANDLE UniqueProcess; HANDLE UniqueThread; } ClientId;
    LONG  Priority;
    LONG  BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} WN_SYSTEM_THREAD_INFORMATION;

// Service-management Zw functions. ZwLoadDriver/ZwUnloadDriver take a full
// registry path like \Registry\Machine\System\CurrentControlSet\Services\<name>.
NTSYSAPI NTSTATUS NTAPI ZwLoadDriver(_In_ PUNICODE_STRING DriverServiceName);
NTSYSAPI NTSTATUS NTAPI ZwUnloadDriver(_In_ PUNICODE_STRING DriverServiceName);
NTSYSAPI NTSTATUS NTAPI ZwCreateKey(_Out_ PHANDLE, _In_ ACCESS_MASK, _In_ POBJECT_ATTRIBUTES,
    _Reserved_ ULONG, _In_opt_ PUNICODE_STRING, _In_ ULONG, _Out_opt_ PULONG);
NTSYSAPI NTSTATUS NTAPI ZwOpenKey(_Out_ PHANDLE, _In_ ACCESS_MASK, _In_ POBJECT_ATTRIBUTES);
NTSYSAPI NTSTATUS NTAPI ZwSetValueKey(_In_ HANDLE, _In_ PUNICODE_STRING,
    _In_opt_ ULONG, _In_ ULONG, _In_reads_bytes_opt_(DataSize) PVOID Data, _In_ ULONG DataSize);
NTSYSAPI NTSTATUS NTAPI ZwDeleteKey(_In_ HANDLE);

#ifndef REG_OPTION_NON_VOLATILE
#define REG_OPTION_NON_VOLATILE     0x00000000L
#define REG_OPTION_VOLATILE         0x00000001L
#endif
#ifndef REG_DWORD
#define REG_DWORD                   4
#define REG_EXPAND_SZ               2
#define REG_SZ                      1
#endif

//
// SystemModuleInformation = 11. Layout matches NtApi.h on user side.
//
#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

//
// SSDT layout. On x64, KiServiceTable entries are ULONG offsets relative to
// the table base; the low 4 bits encode argument-count and must be masked off.
// KeServiceDescriptorTable is NOT exported by ntoskrnl — drivers have to
// locate it via the syscall entry point (IA32_LSTAR MSR -> KiSystemCall64,
// then pattern-scan for `lea r10, [KeServiceDescriptorTable]`).
//
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG     Base;       // points to KiServiceTable
    PULONG     Count;
    ULONG      Limit;      // number of entries
    PUCHAR     Number;     // KiArgumentTable
} KSERVICE_TABLE_DESCRIPTOR;

#define IA32_LSTAR 0xC0000082

static KSERVICE_TABLE_DESCRIPTOR* g_ServiceDescriptor = NULL;

static KSERVICE_TABLE_DESCRIPTOR* LocateServiceDescriptor(void)
{
    if (g_ServiceDescriptor) return g_ServiceDescriptor;

    PUCHAR kiSystemCall64 = (PUCHAR)__readmsr(IA32_LSTAR);
    if (!kiSystemCall64 || (ULONG_PTR)kiSystemCall64 < 0xFFFF800000000000ULL) return NULL;

    // Scan a generous window of the syscall entry for the
    //   4C 8D 15 ?? ?? ?? ??      lea r10, [rip+disp32]
    // that loads KeServiceDescriptorTable. The exact offset varies per build
    // but it's well within the first few hundred bytes on every public build.
    for (ULONG i = 0; i < 0x800; ++i) {
        __try {
            if (kiSystemCall64[i] == 0x4C && kiSystemCall64[i+1] == 0x8D && kiSystemCall64[i+2] == 0x15) {
                LONG disp = *(LONG*)(kiSystemCall64 + i + 3);
                PVOID target = kiSystemCall64 + i + 7 + disp;
                if ((ULONG_PTR)target >= 0xFFFF800000000000ULL) {
                    g_ServiceDescriptor = (KSERVICE_TABLE_DESCRIPTOR*)target;
                    return g_ServiceDescriptor;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return NULL;
        }
    }
    return NULL;
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, WinternalQueueInitialize)
#pragma alloc_text (PAGE, WinternalEnumProcessIds)
#pragma alloc_text (PAGE, WinternalEvtDriverUnload)
#endif

#define WINTERNAL_DRIVER_VERSION_MAJOR 0
#define WINTERNAL_DRIVER_VERSION_MINOR 2
#define WINTERNAL_POOL_TAG_DEFAULT     'WnTl'

// Process access masks not always pulled in by <ntddk.h>.
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

// -----------------------------------------------------------------------------
// Kernel-mode inline hook engine (declared up here so the IOCTL handlers can
// call into it; defined below).
// -----------------------------------------------------------------------------

#define WINTERNAL_KHOOK_JMP_SIZE   14
#define WINTERNAL_KHOOK_MAX_PROLOG 64
#define WINTERNAL_KHOOK_TRAMP_SIZE (WINTERNAL_KHOOK_MAX_PROLOG + WINTERNAL_KHOOK_JMP_SIZE + 16)

typedef struct _WINTERNAL_KHOOK_ENTRY {
    LIST_ENTRY  ListEntry;
    PVOID       Target;
    PVOID       Detour;
    PVOID       Trampoline;
    ULONG       PrologueSize;
    UCHAR       SavedBytes[WINTERNAL_KHOOK_MAX_PROLOG];
} WINTERNAL_KHOOK_ENTRY, *PWINTERNAL_KHOOK_ENTRY;

static LIST_ENTRY    g_KhookList;
static KSPIN_LOCK    g_KhookLock;
static BOOLEAN       g_KhookInitialized = FALSE;

// -----------------------------------------------------------------------------
// Force-protect (Ob callback) state
//
// One flat array protected by a spinlock; the Ob pre-op callback runs at
// PASSIVE/APC_LEVEL on the caller's thread, so contention is minimal and a
// spinlock + linear walk is cheaper than a hash table for N <= 32.
//
// Registration is lazy: the first PROTECT_LOCK adds the PID and calls
// ObRegisterCallbacks. If registration ever fails (unsigned driver on a
// system that enforces ObRegisterCallbacks signing), g_ObRegFailed is set
// so subsequent LOCK calls return that status immediately instead of
// silently filling the array with PIDs that aren't actually being
// filtered.
// -----------------------------------------------------------------------------

static UINT32        g_LockedPids[WINTERNAL_PROTECT_MAX];
static ULONG         g_LockedCount = 0;       // guarded by g_LockSpin
static KSPIN_LOCK    g_LockSpin;
static BOOLEAN       g_LockSpinInit = FALSE;
static PVOID         g_ObCallbackHandle = NULL;
static NTSTATUS      g_ObRegFailed = STATUS_SUCCESS;

// ObUnRegisterCallbacks inline-hook state. After we register our pre-op
// callback, we patch a JMP into the kernel's exported ObUnRegisterCallbacks
// that filters out the cookie WE own — so any system component (Defender,
// trust validator, anything else) that tries to tear down our callback
// gets a silent no-op. Other drivers' calls go through unchanged.
//
// Earlier revisions used KeIpiGenericCall + KhookPatchAtomic to write the
// new prologue; on Win11 24H2 that path hung indefinitely (HVCI / VBS
// intercepts the kernel-image write in a way that never returns from the
// IPI). We now write from the current CPU only, with CR0.WP cleared, and
// readback-verify — if the write is silently dropped by the hypervisor we
// detect it and fail clean instead of hanging.
typedef VOID (NTAPI *PFN_OB_UNREG_CB)(_In_ PVOID RegistrationHandle);
static PVOID         g_ObUnregTarget       = NULL;
static PUCHAR        g_ObUnregTrampoline   = NULL;
static PFN_OB_UNREG_CB g_ObUnregOriginal   = NULL;
static UCHAR         g_ObUnregSavedProlog[WINTERNAL_KHOOK_MAX_PROLOG];
static ULONG         g_ObUnregPrologSize   = 0;
static BOOLEAN       g_ObUnregHookInstalled = FALSE;


// -----------------------------------------------------------------------------
// Lockdown + audit log
// -----------------------------------------------------------------------------

static volatile LONG g_Lockdown = 0;       // 0 = open, 1 = engaged (one-way)
static UINT64        g_LockdownAtMs = 0;

// Audit ring buffer. Each row is FIXED-SIZE, so we can index without a lock
// during reads (writes use Interlocked for the head index).
static WINTERNAL_AUDIT_ROW g_AuditRing[WINTERNAL_AUDIT_MAX_ROWS];
static volatile LONG       g_AuditHead = 0;   // next write index
static volatile LONG       g_AuditCount = 0;  // total rows ever written

static VOID AuditAppend(UINT32 Ioctl, UINT64 Target, UINT32 Length, NTSTATUS Status)
{
    LONG idx = InterlockedIncrement(&g_AuditHead) - 1;
    LONG slot = idx % WINTERNAL_AUDIT_MAX_ROWS;
    LARGE_INTEGER now;
    KeQueryTickCount(&now);
    g_AuditRing[slot].TimestampNs   = (UINT64)now.QuadPart * KeQueryTimeIncrement();
    g_AuditRing[slot].IoControlCode = Ioctl;
    g_AuditRing[slot].CallerPid     = HandleToULong(PsGetCurrentProcessId());
    g_AuditRing[slot].Target        = Target;
    g_AuditRing[slot].Length        = Length;
    g_AuditRing[slot].Status        = (INT32)Status;
    InterlockedIncrement(&g_AuditCount);
}

// Returns TRUE if the IOCTL is a "write" (state-mutating) one that lockdown
// blocks. Read-only enumerators (kver, kpids, kread, ksym, lockdown_status,
// audit_tail, enum_*) stay open even under lockdown.
static BOOLEAN IsLockdownGated(ULONG Code)
{
    switch (Code) {
    case IOCTL_WINTERNAL_KMEM_WRITE:
    case IOCTL_WINTERNAL_KALLOC:
    case IOCTL_WINTERNAL_KFREE:
    case IOCTL_WINTERNAL_KCALL:
    case IOCTL_WINTERNAL_UNPROTECT_PROCESS:
    case IOCTL_WINTERNAL_KILL_PROCESS:
    case IOCTL_WINTERNAL_PROTECT_LOCK:
    case IOCTL_WINTERNAL_PROTECT_UNLOCK:
    case IOCTL_WINTERNAL_TOKEN_UIACCESS:
    case IOCTL_WINTERNAL_SET_SIGLEVEL:
    case IOCTL_WINTERNAL_KCODE_PATCH:
    case IOCTL_WINTERNAL_KHOOK_INSTALL:
    case IOCTL_WINTERNAL_KHOOK_UNINSTALL:
    case IOCTL_WINTERNAL_KHOOK_UNINSTALL_ALL:
    case IOCTL_WINTERNAL_LUA_EXEC:
    case IOCTL_WINTERNAL_FORCE_UNLOAD_DRIVER:
    case IOCTL_WINTERNAL_KDRV_REGISTER:
    case IOCTL_WINTERNAL_KDRV_DEREGISTER:
    case IOCTL_WINTERNAL_KDRV_SET_START:
    case IOCTL_WINTERNAL_KDRV_LOAD:
    case IOCTL_WINTERNAL_KDRV_UNLOAD:
        return TRUE;
    }
    return FALSE;
}

VOID WinternalKhookInit(VOID);
VOID WinternalKhookUninstallAll(VOID);

// Self-protection globals. At engage time we hash the caller's main
// image (SHA-256 via BCrypt) and remember the digest. Every later
// weaken-protection IOCTL re-hashes the current caller's image and
// compares — letting subsequent invocations of the *same binary* through
// while refusing anything else, including processes that have just been
// renamed to `Winternal.exe`. Owner PID is kept around for STATUS
// reporting only; the gate doesn't trust it.
#define WN_SELFPROT_HASH_LEN 32
static volatile LONG g_SelfProtect       = 0;
static volatile LONG g_SelfProtectOwner  = 0;
static UCHAR         g_SelfProtectHash[WN_SELFPROT_HASH_LEN] = {0};
static KSPIN_LOCK    g_SelfProtectSpin;
static BOOLEAN       g_SelfProtectSpinInit = FALSE;

#define WN_SELFPROT_IMAGE_MAX (16u * 1024u * 1024u)   // 16 MiB cap on hashed image

static NTSTATUS WinternalSha256(const void* data, ULONG len, UCHAR out[WN_SELFPROT_HASH_LEN])
{
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(s)) return s;
    s = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (NT_SUCCESS(s)) {
        s = BCryptHashData(hHash, (PUCHAR)data, len, 0);
        if (NT_SUCCESS(s)) s = BCryptFinishHash(hHash, out, WN_SELFPROT_HASH_LEN, 0);
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return s;
}

// Open the caller's main image by NT path and hash its on-disk bytes.
// Bypasses memory-resident image tampering (e.g. a hot-patch) — the
// hash compares against the file the loader will pick up next time.
// Capped at 16 MiB so a swapped image doesn't OOM the driver.
static NTSTATUS WinternalHashCallerImage(UCHAR out[WN_SELFPROT_HASH_LEN])
{
    PEPROCESS proc = PsGetCurrentProcess();
    if (!proc) return STATUS_NOT_FOUND;

    PUNICODE_STRING imgName = NULL;
    NTSTATUS s = SeLocateProcessImageName(proc, &imgName);
    if (!NT_SUCCESS(s) || !imgName) return NT_SUCCESS(s) ? STATUS_NOT_FOUND : s;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, imgName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE h = NULL;
    IO_STATUS_BLOCK iosb;
    s = ZwCreateFile(&h, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
                     FILE_ATTRIBUTE_NORMAL,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    ExFreePool(imgName);
    if (!NT_SUCCESS(s)) return s;

    FILE_STANDARD_INFORMATION info = {0};
    s = ZwQueryInformationFile(h, &iosb, &info, sizeof(info), FileStandardInformation);
    if (!NT_SUCCESS(s)) { ZwClose(h); return s; }
    if (info.EndOfFile.QuadPart <= 0 || info.EndOfFile.QuadPart > WN_SELFPROT_IMAGE_MAX) {
        ZwClose(h); return STATUS_FILE_TOO_LARGE;
    }
    ULONG size = (ULONG)info.EndOfFile.QuadPart;
    PUCHAR buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, size, WINTERNAL_POOL_TAG_DEFAULT);
    if (!buf) { ZwClose(h); return STATUS_INSUFFICIENT_RESOURCES; }

    LARGE_INTEGER off = {0};
    s = ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, size, &off, NULL);
    ZwClose(h);
    if (NT_SUCCESS(s) && iosb.Information != size) s = STATUS_END_OF_FILE;
    if (NT_SUCCESS(s)) s = WinternalSha256(buf, size, out);
    ExFreePoolWithTag(buf, WINTERNAL_POOL_TAG_DEFAULT);
    return s;
}

static BOOLEAN WinternalCallerIsOwner(VOID)
{
    if (!g_SelfProtect) return TRUE;  // not engaged, nothing to gate
    UCHAR h[WN_SELFPROT_HASH_LEN];
    if (!NT_SUCCESS(WinternalHashCallerImage(h))) return FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_SelfProtectSpin, &irql);
    BOOLEAN match = RtlEqualMemory(h, g_SelfProtectHash, WN_SELFPROT_HASH_LEN);
    KeReleaseSpinLock(&g_SelfProtectSpin, irql);
    return match;
}

// -----------------------------------------------------------------------------
// Unload drain
//
// KMDF for non-PnP drivers only wires DriverObject->DriverUnload when
// EvtDriverUnload is set. Without it, `sc stop` returns 1052
// (ERROR_INVALID_SERVICE_CONTROL) because the kernel reports no STOP support
// to SCM. With EvtDriverUnload wired (see Driver.c), `sc stop` calls into
// IoUnloadDriver -> framework's DriverUnload -> our WinternalEvtDriverUnload.
//
// At that point the IO queue is still alive, so we must drain any in-flight
// IOCTLs before letting the framework tear down state. The dispatcher gate
// (used by WinternalEvtIoDeviceControl) refuses new requests with
// STATUS_DELETE_PENDING once unload has started, and signals g_DrainEvent
// when the last in-flight handler exits.
// -----------------------------------------------------------------------------

static volatile LONG g_UnloadStarted   = 0;
static volatile LONG g_InFlightIoctls  = 0;
static KEVENT        g_DrainEvent;
static BOOLEAN       g_DrainInitialized = FALSE;

// Returns FALSE iff unload has begun. On TRUE the caller MUST pair the call
// with WinternalDispatchLeave so the in-flight counter stays balanced.
static BOOLEAN WinternalDispatchEnter(VOID)
{
    InterlockedIncrement(&g_InFlightIoctls);
    // Ensure the increment is globally visible before reading the unload
    // flag — otherwise unload could see count==0 and proceed while we are
    // about to start a handler.
    KeMemoryBarrier();
    if (g_UnloadStarted) {
        if (InterlockedDecrement(&g_InFlightIoctls) == 0 && g_DrainInitialized) {
            KeSetEvent(&g_DrainEvent, IO_NO_INCREMENT, FALSE);
        }
        return FALSE;
    }
    return TRUE;
}

static VOID WinternalDispatchLeave(VOID)
{
    if (InterlockedDecrement(&g_InFlightIoctls) == 0 && g_UnloadStarted && g_DrainInitialized) {
        KeSetEvent(&g_DrainEvent, IO_NO_INCREMENT, FALSE);
    }
}

// Kernel Lua glue (defined in klua/klua_kernel.c + Queue.c bottom).
NTSTATUS KluaExec(_In_reads_(ScriptLen) const char* Script, _In_ SIZE_T ScriptLen,
                  _Out_writes_bytes_(OutCapacity) char* Output, _In_ SIZE_T OutCapacity,
                  _Out_ SIZE_T* OutWritten, _Out_ INT32* OutLuaStatus);

//
// Build-26100 EPROCESS->Protection offset. The kernel doesn't expose this
// directly so we hard-code the value for Win11 24H2. Callers may override
// per-call via UNPROTECT_IN::FieldOffset for other builds.
//
#define WINTERNAL_DEFAULT_PROTECTION_OFFSET 0x87A

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

static BOOLEAN WinternalIsKernelAddress(_In_ PVOID Address)
{
    // On x64 Windows, kernel virtual addresses are sign-extended above the
    // canonical hole; user addresses sit below 0x0000800000000000 and the
    // first kernel byte is at 0xFFFF800000000000. Rejecting anything below
    // that prevents a caller from tricking us into reading/writing its own
    // pages via DeviceIoControl.
    return ((ULONG_PTR)Address >= 0xFFFF800000000000ULL);
}

static NTSTATUS WinternalKmemRead(
    _In_ PVOID KernelAddress,
    _In_ ULONG Length,
    _Out_writes_bytes_(Length) PVOID OutBuffer)
{
    NTSTATUS s = STATUS_SUCCESS;
    BOOLEAN  valid = MmIsAddressValid(KernelAddress);
    UNREFERENCED_PARAMETER(valid);   // referenced only when DBG/KdPrintEx is live
    __try {
        // Best-effort PTE probe (`valid` above). Not sufficient on its own —
        // pageable kernel addresses may show invalid here yet succeed after
        // a soft fault — so we still SEH-wrap the actual copy.
        RtlCopyMemory(OutBuffer, KernelAddress, Length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }
    // Best-effort diagnostic; DbgPrint is stripped in non-DBG Release builds.
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[winternal] kread @ %p len=%u valid=%u status=0x%08X\n",
               KernelAddress, Length, valid, s);
    return s;
}

static NTSTATUS WinternalKmemWrite(
    _In_ PVOID KernelAddress,
    _In_reads_bytes_(Length) PVOID Data,
    _In_ ULONG Length)
{
    NTSTATUS s = STATUS_SUCCESS;
    __try {
        RtlCopyMemory(KernelAddress, Data, Length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }
    return s;
}

// -----------------------------------------------------------------------------
// Original handlers
// -----------------------------------------------------------------------------

NTSTATUS
WinternalEnumProcessIds(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWritten
)
{
    PWINTERNAL_PID_LIST list = (PWINTERNAL_PID_LIST)OutputBuffer;
    size_t headerSize = FIELD_OFFSET(WINTERNAL_PID_LIST, Entries);
    size_t maxEntries = (OutputBufferLength > headerSize)
        ? (OutputBufferLength - headerSize) / sizeof(WINTERNAL_PID_ENTRY)
        : 0;

    PAGED_CODE();

    if (OutputBufferLength < headerSize) {
        *BytesWritten = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    list->Count = 0;
    list->Reserved = 0;

    UINT32 written = 0;
    for (UINT32 pid = 4; pid < 0x10000 && written < maxEntries; pid += 4) {
        PEPROCESS proc = NULL;
        NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
        if (!NT_SUCCESS(s)) continue;

        WINTERNAL_PID_ENTRY* e = &list->Entries[written++];
        RtlZeroMemory(e, sizeof(*e));
        e->Pid = pid;

        UCHAR* image = PsGetProcessImageFileName(proc);
        if (image) {
            RtlCopyMemory(e->ImageFileName, image, 15);
            e->ImageFileName[15] = '\0';
        }
        HANDLE parentId = PsGetProcessInheritedFromUniqueProcessId(proc);
        e->ParentPid = (UINT32)(ULONG_PTR)parentId;

        ObDereferenceObject(proc);
    }

    list->Count = written;
    *BytesWritten = headerSize + written * sizeof(WINTERNAL_PID_ENTRY);
    return STATUS_SUCCESS;
}

// -----------------------------------------------------------------------------
// New handlers
// -----------------------------------------------------------------------------

static NTSTATUS HandleKmemRead(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_KMEM_READ_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KMEM_READ_IN in = (PWINTERNAL_KMEM_READ_IN)InBuf;
    // METHOD_BUFFERED routes input + output through one shared SystemBuffer;
    // writing to OutBuf clobbers InBuf. Pull every field into a local
    // BEFORE the copy so post-copy reads of `in->...` don't see overwritten
    // bytes (the source-of-truth for *Written, for example).
    ULONG  length = in->Length;
    UINT64 addrU  = in->Address;
    if (length == 0 || length > WINTERNAL_KMEM_MAX_BYTES) return STATUS_INVALID_PARAMETER;
    if (OutLen < length) return STATUS_BUFFER_TOO_SMALL;
    PVOID kaddr = (PVOID)(ULONG_PTR)addrU;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[winternal] HandleKmemRead in: addr=0x%llx len=%u outbuf=%p outlen=%zu\n",
               addrU, length, OutBuf, OutLen);
    if (!WinternalIsKernelAddress(kaddr)) return STATUS_ACCESS_VIOLATION;

    NTSTATUS s = WinternalKmemRead(kaddr, length, OutBuf);
    if (NT_SUCCESS(s)) *Written = length;
    return s;
}

static NTSTATUS HandleKmemWrite(PVOID InBuf, size_t InLen)
{
    if (InLen < FIELD_OFFSET(WINTERNAL_KMEM_WRITE_IN, Data)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KMEM_WRITE_IN in = (PWINTERNAL_KMEM_WRITE_IN)InBuf;
    if (in->Length == 0 || in->Length > WINTERNAL_KMEM_MAX_BYTES) return STATUS_INVALID_PARAMETER;
    if (InLen < FIELD_OFFSET(WINTERNAL_KMEM_WRITE_IN, Data) + in->Length) return STATUS_BUFFER_TOO_SMALL;
    PVOID kaddr = (PVOID)(ULONG_PTR)in->Address;
    if (!WinternalIsKernelAddress(kaddr)) return STATUS_ACCESS_VIOLATION;

    return WinternalKmemWrite(kaddr, in->Data, in->Length);
}

static NTSTATUS HandleKsym(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_KSYM_IN) || OutLen < sizeof(WINTERNAL_KSYM_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KSYM_IN in = (PWINTERNAL_KSYM_IN)InBuf;
    PWINTERNAL_KSYM_OUT out = (PWINTERNAL_KSYM_OUT)OutBuf;

    // Force NUL-termination in case caller passed unterminated junk.
    in->Name[RTL_NUMBER_OF(in->Name) - 1] = 0;

    UNICODE_STRING us;
    RtlInitUnicodeString(&us, in->Name);
    out->Address = (UINT64)(ULONG_PTR)MmGetSystemRoutineAddress(&us);
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleKalloc(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_KALLOC_IN) || OutLen < sizeof(WINTERNAL_KALLOC_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KALLOC_IN in = (PWINTERNAL_KALLOC_IN)InBuf;
    PWINTERNAL_KALLOC_OUT out = (PWINTERNAL_KALLOC_OUT)OutBuf;
    if (in->Length == 0) return STATUS_INVALID_PARAMETER;

    ULONG tag = in->Tag ? in->Tag : WINTERNAL_POOL_TAG_DEFAULT;
    POOL_FLAGS flags = in->NonPaged ? POOL_FLAG_NON_PAGED : POOL_FLAG_PAGED;
    PVOID p = ExAllocatePool2(flags, in->Length, tag);
    if (!p) return STATUS_INSUFFICIENT_RESOURCES;

    out->Address = (UINT64)(ULONG_PTR)p;
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleKfree(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_KFREE_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KFREE_IN in = (PWINTERNAL_KFREE_IN)InBuf;
    PVOID kaddr = (PVOID)(ULONG_PTR)in->Address;
    if (!kaddr || !WinternalIsKernelAddress(kaddr)) return STATUS_INVALID_PARAMETER;

    ULONG tag = in->Tag ? in->Tag : WINTERNAL_POOL_TAG_DEFAULT;
    NTSTATUS s = STATUS_SUCCESS;
    __try {
        ExFreePoolWithTag(kaddr, tag);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }
    return s;
}

typedef ULONG_PTR (NTAPI *KCALL_FN)(ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

static NTSTATUS HandleKcall(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_KCALL_IN) || OutLen < sizeof(WINTERNAL_KCALL_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KCALL_IN in = (PWINTERNAL_KCALL_IN)InBuf;
    PWINTERNAL_KCALL_OUT out = (PWINTERNAL_KCALL_OUT)OutBuf;
    PVOID kaddr = (PVOID)(ULONG_PTR)in->Address;
    if (!WinternalIsKernelAddress(kaddr)) return STATUS_ACCESS_VIOLATION;

    RtlZeroMemory(out, sizeof(*out));

    KCALL_FN fn = (KCALL_FN)kaddr;
    __try {
        out->ReturnValue = (UINT64)fn(
            (ULONG_PTR)in->Args[0],
            (ULONG_PTR)in->Args[1],
            (ULONG_PTR)in->Args[2],
            (ULONG_PTR)in->Args[3]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        out->Faulted = 1;
        out->ReturnValue = GetExceptionCode();
    }
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleUnprotect(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_UNPROTECT_IN) || OutLen < sizeof(WINTERNAL_UNPROTECT_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_UNPROTECT_IN in = (PWINTERNAL_UNPROTECT_IN)InBuf;
    PWINTERNAL_UNPROTECT_OUT out = (PWINTERNAL_UNPROTECT_OUT)OutBuf;
    if (in->Pid < 4) return STATUS_INVALID_PARAMETER;

    ULONG offset = in->FieldOffset ? in->FieldOffset : WINTERNAL_DEFAULT_PROTECTION_OFFSET;

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)in->Pid, &proc);
    if (!NT_SUCCESS(s)) return s;

    PUCHAR field = (PUCHAR)proc + offset;
    __try {
        out->PrevValue = *field;
        *field = in->NewValue;
        out->FieldOffsetUsed = offset;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }
    ObDereferenceObject(proc);

    if (NT_SUCCESS(s)) *Written = sizeof(*out);
    return s;
}

// Direct kernel termination — bypasses Ob handle creation, the Ob
// pre-op callback chain, and the critical-process / token checks that
// live inside NtTerminateProcess. Just rips the threads down via the
// kernel's internal exit path. Resolved at first call so the lookup
// cost is one MmGetSystemRoutineAddress per session, not per kill.
typedef NTSTATUS (NTAPI *PFN_PsTerminateProcess)(PEPROCESS, NTSTATUS);
static PFN_PsTerminateProcess g_PsTerminateProcess = NULL;
static BOOLEAN                g_PsTerminateProcessTried = FALSE;

static PFN_PsTerminateProcess WinternalGetPsTerminateProcess(VOID)
{
    if (!g_PsTerminateProcessTried) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"PsTerminateProcess");
        g_PsTerminateProcess = (PFN_PsTerminateProcess)MmGetSystemRoutineAddress(&name);
        g_PsTerminateProcessTried = TRUE;
    }
    return g_PsTerminateProcess;
}

static NTSTATUS HandleKill(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_KILL_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KILL_IN in = (PWINTERNAL_KILL_IN)InBuf;

    // PIDs 0 (Idle) and 4 (System) are not real user-space processes — the
    // kernel silently ignores ZwTerminateProcess on them and returns
    // STATUS_SUCCESS, which would make the caller think the kill worked.
    // Refuse them explicitly so the user sees a real error.
    if (in->Pid <= 4) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)in->Pid, &proc);
    if (!NT_SUCCESS(s)) return s;

    // Path 1: PsTerminateProcess — exported on Win10/11. Takes EPROCESS
    // directly, no handle, no access check. Wins for protected/restricted
    // user-mode processes (Defender's MsMpEng, antimalware brokers,
    // PowerShell instances with hardened tokens, etc).
    PFN_PsTerminateProcess pfn = WinternalGetPsTerminateProcess();
    if (pfn) {
        __try {
            s = pfn(proc, (NTSTATUS)in->ExitStatus);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            s = GetExceptionCode();
        }
        if (NT_SUCCESS(s)) {
            ObDereferenceObject(proc);
            return s;
        }
        // Fall through to the legacy path if PsTerminateProcess refused —
        // shouldn't happen for ordinary processes but stays defensive.
    }

    // Path 2: classic ObOpenObjectByPointer + ZwTerminateProcess. Kept as
    // a fallback for kernels that don't export PsTerminateProcess, and
    // because for the common case it still works.
    HANDLE h = NULL;
    s = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL, PROCESS_TERMINATE,
                              *PsProcessType, KernelMode, &h);
    if (NT_SUCCESS(s)) {
        s = ZwTerminateProcess(h, (NTSTATUS)in->ExitStatus);
        ZwClose(h);
    }
    ObDereferenceObject(proc);
    return s;
}

// -----------------------------------------------------------------------------
// Win32 access constants
//
// Some of these are pulled in by ntddk.h via the WDM headers, but the
// non-basic ones (VM_*, SET_*, SUSPEND_RESUME, the LIMITED_INFORMATION pair)
// only live in winnt.h which kernel drivers don't include. Redefine the
// numeric values under #ifndef guards so we don't double-define when the
// platform headers do happen to expose them.
// -----------------------------------------------------------------------------

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE                  0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD              0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION               0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ                    0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                   0x0020
#endif
#ifndef PROCESS_DUP_HANDLE
#define PROCESS_DUP_HANDLE                 0x0040
#endif
#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS             0x0080
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA                  0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION            0x0200
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION          0x0400
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME             0x0800
#endif
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION  0x1000
#endif
#ifndef PROCESS_SET_LIMITED_INFORMATION
#define PROCESS_SET_LIMITED_INFORMATION    0x2000
#endif

#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                   0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME              0x0002
#endif
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT                 0x0008
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT                 0x0010
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION             0x0020
#endif
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION           0x0040
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN            0x0080
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE                 0x0100
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION        0x0200
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION     0x0400
#endif
#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION   0x0800
#endif

// -----------------------------------------------------------------------------
// Force-protect: Ob pre-operation callbacks
//
// User chose "total + block QUERY_INFORMATION": strip every documented
// process access right except the synchronize/standard bits. The kernel
// path (Info->KernelHandle == TRUE) is untouched so our own driver — and
// any other kernel component — can still operate on locked PIDs.
//
// Thread mask mirrors the process mask: terminate, suspend/resume,
// set/get context, set/query info, impersonation rights.
// -----------------------------------------------------------------------------

#define WN_LOCK_STRIP_PROCESS  ( \
    PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | \
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | \
    PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | \
    PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME | \
    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_LIMITED_INFORMATION)

#define WN_LOCK_STRIP_THREAD ( \
    THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | \
    THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION | \
    THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | \
    THREAD_DIRECT_IMPERSONATION | THREAD_QUERY_LIMITED_INFORMATION | \
    THREAD_SET_LIMITED_INFORMATION)

static BOOLEAN WinternalIsPidLocked(UINT32 Pid)
{
    if (Pid == 0 || !g_LockSpinInit) return FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&g_LockSpin, &irql);
    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < g_LockedCount; ++i) {
        if (g_LockedPids[i] == Pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_LockSpin, irql);
    return found;
}

static OB_PREOP_CALLBACK_STATUS WinternalProtectPreOpProcess(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (Info->KernelHandle) return OB_PREOP_SUCCESS;

    UINT32 targetPid = HandleToULong(PsGetProcessId((PEPROCESS)Info->Object));
    if (!WinternalIsPidLocked(targetPid)) return OB_PREOP_SUCCESS;

    // Don't strip rights from a process opening a handle to ITSELF; otherwise
    // the locked process loses access to its own threads/state.
    if ((HANDLE)(ULONG_PTR)targetPid == PsGetCurrentProcessId()) return OB_PREOP_SUCCESS;

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~WN_LOCK_STRIP_PROCESS;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~WN_LOCK_STRIP_PROCESS;
    }
    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS WinternalProtectPreOpThread(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    if (Info->KernelHandle) return OB_PREOP_SUCCESS;

    UINT32 targetPid = HandleToULong(PsGetThreadProcessId((PETHREAD)Info->Object));
    if (!WinternalIsPidLocked(targetPid)) return OB_PREOP_SUCCESS;

    if ((HANDLE)(ULONG_PTR)targetPid == PsGetCurrentProcessId()) return OB_PREOP_SUCCESS;

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        Info->Parameters->CreateHandleInformation.DesiredAccess &= ~WN_LOCK_STRIP_THREAD;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        Info->Parameters->DuplicateHandleInformation.DesiredAccess &= ~WN_LOCK_STRIP_THREAD;
    }
    return OB_PREOP_SUCCESS;
}

// MmVerifyCallbackFunction (called from the ObRegisterCallbacks path)
// rejects drivers whose loader entry doesn't have the "forced integrity"
// bit set in KLDR_DATA_TABLE_ENTRY.Flags — i.e., drivers not linked with
// /INTEGRITYCHECK. The build sets that flag in the PE header, but on top
// of that we set the loader-side bit at runtime so the bypass survives
// even on systems that ignore the PE bit, or on legacy builds that didn't
// re-link with /INTEGRITYCHECK.
//
// KLDR_DATA_TABLE_ENTRY is an undocumented struct that lives behind
// DRIVER_OBJECT->DriverSection. Field layout from public Microsoft
// research kernel sources; the offset of Flags has been stable across
// Win7..Win11 24H2 (build 26100).
typedef struct _WN_KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    PVOID          ExceptionTable;
    ULONG          ExceptionTableSize;
    // 4 bytes natural padding on x64 follows
    PVOID          GpValue;
    PVOID          NonPagedDebugInfo;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    // 4 bytes natural padding
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG          Flags;
    USHORT         LoadCount;
} WN_KLDR_DATA_TABLE_ENTRY, *PWN_KLDR_DATA_TABLE_ENTRY;

#define WN_LDRP_INTEGRITY_FORCED 0x00000020

// Set at DriverEntry by Driver.c; lets WinternalProtectForceIntegrity find
// our own DRIVER_OBJECT without dragging WDF dependencies in here.
static PDRIVER_OBJECT g_SelfDriverObject = NULL;

VOID WinternalProtectSetSelf(PDRIVER_OBJECT Self) { g_SelfDriverObject = Self; }

static VOID WinternalProtectForceIntegrity(VOID)
{
    if (!g_SelfDriverObject || !g_SelfDriverObject->DriverSection) return;
    PWN_KLDR_DATA_TABLE_ENTRY entry = (PWN_KLDR_DATA_TABLE_ENTRY)g_SelfDriverObject->DriverSection;
    // KLDR is in non-paged pool and writable; no WP toggle needed.
    entry->Flags |= WN_LDRP_INTEGRITY_FORCED;
}


// Forward decls of the JMP helper (defined with the khook engine further
// down). We don't use KhookPatchAtomic (its KeIpiGenericCall hangs on the
// user's system); we drive the write ourselves below.
static VOID KhookWriteJmpAbs(PUCHAR Dst, PVOID To);

// Bypass kernel WP for a single write from the current CPU. Avoid raising
// IRQL — at DPC_LEVEL a paging fault would BSOD, and we don't need SMP
// coherence for ObUnRegisterCallbacks (called rarely enough that a torn-
// write window is effectively zero risk). Reads the bytes back after the
// write so we can detect silent HVCI/VBS rejection and report failure.
static NTSTATUS WinternalProtectWriteCode(PVOID Target, const VOID* Src, SIZE_T Length)
{
    // Earlier rev raised IRQL to APC_LEVEL and did _disable() to keep the
    // CR0.WP=0 window invisible to other threads. That created a deadlock
    // when the write faulted (page-fault handler couldn't run with
    // interrupts masked at elevated IRQL, so RtlCopyMemory wedged
    // indefinitely). At PASSIVE_LEVEL the fault path is fully serviceable
    // and SEH can actually catch the access violation.
    //
    // Trade-off: brief window where this CPU's CR0.WP is 0, observable to
    // any concurrent kernel code on this CPU. For a research driver that's
    // the right call vs. hanging the system. SMP coherence — other CPUs
    // see their own CR0, this only affects ours.
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ULL);              // clear WP (bit 16) on this CPU
    __try {
        RtlCopyMemory(Target, Src, Length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    __writecr0(cr0);                             // restore

    if (NT_SUCCESS(status)) {
        // HVCI may swallow the write silently; verify by reading back.
        if (RtlCompareMemory(Target, Src, Length) != Length) {
            status = STATUS_NOT_SUPPORTED;
        }
    }
    return status;
}

static VOID NTAPI WinternalObUnreg_Detour(_In_ PVOID RegistrationHandle)
{
    if (RegistrationHandle != NULL && RegistrationHandle == g_ObCallbackHandle) {
        // Refuse to tear down OUR callback. Everyone else passes through.
        return;
    }
    if (g_ObUnregOriginal) g_ObUnregOriginal(RegistrationHandle);
}

static NTSTATUS WinternalInstallObUnregHook(VOID)
{
    if (g_ObUnregHookInstalled) return STATUS_SUCCESS;

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"ObUnRegisterCallbacks");
    PVOID target = MmGetSystemRoutineAddress(&name);
    if (!target) return STATUS_PROCEDURE_NOT_FOUND;

    PUCHAR tramp = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE,
                                           WINTERNAL_KHOOK_TRAMP_SIZE,
                                           WINTERNAL_POOL_TAG_DEFAULT);
    if (!tramp) return STATUS_INSUFFICIENT_RESOURCES;

    ULONG prolog = WINTERNAL_KHOOK_JMP_SIZE;
    UCHAR newProlog[WINTERNAL_KHOOK_MAX_PROLOG];
    NTSTATUS status;
    __try {
        RtlCopyMemory(g_ObUnregSavedProlog, target, prolog);
        RtlCopyMemory(tramp, target, prolog);
        KhookWriteJmpAbs(tramp + prolog, (PUCHAR)target + prolog);
        KhookWriteJmpAbs(newProlog, (PVOID)(ULONG_PTR)WinternalObUnreg_Detour);
        status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(tramp, WINTERNAL_POOL_TAG_DEFAULT);
        return status;
    }

    status = WinternalProtectWriteCode(target, newProlog, prolog);
    if (!NT_SUCCESS(status)) {
        // HVCI / EPT blocked the write. Nothing else to try without going
        // deeper (PT remap, hypervisor exit) — bail with the original
        // status so the caller can report it.
        ExFreePoolWithTag(tramp, WINTERNAL_POOL_TAG_DEFAULT);
        return status;
    }

    g_ObUnregTarget        = target;
    g_ObUnregTrampoline    = tramp;
    g_ObUnregOriginal      = (PFN_OB_UNREG_CB)tramp;
    g_ObUnregPrologSize    = prolog;
    g_ObUnregHookInstalled = TRUE;
    return STATUS_SUCCESS;
}

static VOID WinternalUninstallObUnregHook(VOID)
{
    if (!g_ObUnregHookInstalled) return;
    (void)WinternalProtectWriteCode(g_ObUnregTarget, g_ObUnregSavedProlog, g_ObUnregPrologSize);
    if (g_ObUnregTrampoline) {
        ExFreePoolWithTag(g_ObUnregTrampoline, WINTERNAL_POOL_TAG_DEFAULT);
        g_ObUnregTrampoline = NULL;
    }
    g_ObUnregTarget        = NULL;
    g_ObUnregOriginal      = NULL;
    g_ObUnregPrologSize    = 0;
    g_ObUnregHookInstalled = FALSE;
}

// -----------------------------------------------------------------------------
// NtUnloadDriver hook — refuses `sc stop` of our own driver while selfprotect
// is engaged. Without this, an admin who escalates to SYSTEM (psexec -s,
// scheduled task, etc.) trivially bypasses the SCM DACL we set. The SCM
// DACL is a usability layer; this hook is the actual stop-prevention.
// -----------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *PFN_NT_UNLOAD_DRIVER)(_In_ PUNICODE_STRING DriverServiceName);
static PVOID         g_NtUnloadTarget        = NULL;
static PUCHAR        g_NtUnloadTrampoline    = NULL;
static PFN_NT_UNLOAD_DRIVER g_NtUnloadOriginal = NULL;
static UCHAR         g_NtUnloadSavedProlog[WINTERNAL_KHOOK_MAX_PROLOG];
static ULONG         g_NtUnloadPrologSize    = 0;
static BOOLEAN       g_NtUnloadHookInstalled = FALSE;

// Suffix-match the service-key path against "\Winternal" case-insensitively.
// Real arg is L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Winternal".
static BOOLEAN NtUnloadTargetsUs(_In_ PUNICODE_STRING name)
{
    if (!name || !name->Buffer || name->Length < (USHORT)(10 * sizeof(WCHAR))) return FALSE;
    static const WCHAR kSuffix[] = L"\\Winternal";
    const USHORT sufWchars = (USHORT)((sizeof(kSuffix) / sizeof(WCHAR)) - 1);
    USHORT nameWchars = name->Length / sizeof(WCHAR);
    if (nameWchars < sufWchars) return FALSE;
    const WCHAR* tail = name->Buffer + (nameWchars - sufWchars);
    for (USHORT i = 0; i < sufWchars; ++i) {
        WCHAR a = tail[i], b = kSuffix[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

static NTSTATUS NTAPI WinternalNtUnloadDriver_Detour(_In_ PUNICODE_STRING DriverServiceName)
{
    if (g_SelfProtect) {
        BOOLEAN refuse = FALSE;
        __try {
            // From user-mode callers (services.exe) the pointer is in user
            // memory. ProbeForRead validates it's accessible; the embedded
            // Buffer pointer also needs probing.
            if (ExGetPreviousMode() != KernelMode) {
                ProbeForRead(DriverServiceName, sizeof(UNICODE_STRING), sizeof(ULONG_PTR));
            }
            UNICODE_STRING local = *DriverServiceName;
            if (local.Buffer && local.Length) {
                if (ExGetPreviousMode() != KernelMode)
                    ProbeForRead(local.Buffer, local.Length, sizeof(WCHAR));
                refuse = NtUnloadTargetsUs(&local);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
        if (refuse) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[winternal] NtUnloadDriver: refused (selfprotect engaged)\n");
            return STATUS_ACCESS_DENIED;
        }
    }
    return g_NtUnloadOriginal ? g_NtUnloadOriginal(DriverServiceName) : STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS WinternalInstallNtUnloadHook(VOID)
{
    if (g_NtUnloadHookInstalled) return STATUS_SUCCESS;
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"NtUnloadDriver");
    PVOID target = MmGetSystemRoutineAddress(&name);
    if (!target) return STATUS_PROCEDURE_NOT_FOUND;

    PUCHAR tramp = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE,
                                           WINTERNAL_KHOOK_TRAMP_SIZE,
                                           WINTERNAL_POOL_TAG_DEFAULT);
    if (!tramp) return STATUS_INSUFFICIENT_RESOURCES;

    ULONG prolog = WINTERNAL_KHOOK_JMP_SIZE;
    UCHAR newProlog[WINTERNAL_KHOOK_MAX_PROLOG];
    NTSTATUS status;
    __try {
        RtlCopyMemory(g_NtUnloadSavedProlog, target, prolog);
        RtlCopyMemory(tramp, target, prolog);
        KhookWriteJmpAbs(tramp + prolog, (PUCHAR)target + prolog);
        KhookWriteJmpAbs(newProlog, (PVOID)(ULONG_PTR)WinternalNtUnloadDriver_Detour);
        status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(tramp, WINTERNAL_POOL_TAG_DEFAULT);
        return status;
    }

    status = WinternalProtectWriteCode(target, newProlog, prolog);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(tramp, WINTERNAL_POOL_TAG_DEFAULT);
        return status;
    }
    g_NtUnloadTarget        = target;
    g_NtUnloadTrampoline    = tramp;
    g_NtUnloadOriginal      = (PFN_NT_UNLOAD_DRIVER)tramp;
    g_NtUnloadPrologSize    = prolog;
    g_NtUnloadHookInstalled = TRUE;
    return STATUS_SUCCESS;
}

static VOID WinternalUninstallNtUnloadHook(VOID)
{
    if (!g_NtUnloadHookInstalled) return;
    (void)WinternalProtectWriteCode(g_NtUnloadTarget, g_NtUnloadSavedProlog, g_NtUnloadPrologSize);
    if (g_NtUnloadTrampoline) {
        ExFreePoolWithTag(g_NtUnloadTrampoline, WINTERNAL_POOL_TAG_DEFAULT);
        g_NtUnloadTrampoline = NULL;
    }
    g_NtUnloadTarget        = NULL;
    g_NtUnloadOriginal      = NULL;
    g_NtUnloadPrologSize    = 0;
    g_NtUnloadHookInstalled = FALSE;
}

// Lazy one-time registration. Altitude string is in the "free" altitude
// range; it just needs to be unique on the system. If the system enforces
// signing on ObRegisterCallbacks (some hardened SKUs do), this returns
// STATUS_ACCESS_DENIED and we remember it so subsequent LOCK calls fail
// loud instead of silently adding PIDs that aren't actually filtered.
static NTSTATUS WinternalEnsureObCallbacks(VOID)
{
    if (g_ObCallbackHandle) return STATUS_SUCCESS;
    if (!NT_SUCCESS(g_ObRegFailed) && g_ObRegFailed != STATUS_SUCCESS) return g_ObRegFailed;

    // Belt-and-suspenders: even with /INTEGRITYCHECK in the link line, set
    // the loader's runtime bit before calling Ob* — the kernel reads the
    // KLDR flag, not the PE header, when validating the caller.
    WinternalProtectForceIntegrity();

    OB_OPERATION_REGISTRATION ops[2] = {0};
    ops[0].ObjectType    = PsProcessType;
    ops[0].Operations    = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[0].PreOperation  = WinternalProtectPreOpProcess;
    ops[0].PostOperation = NULL;

    ops[1].ObjectType    = PsThreadType;
    ops[1].Operations    = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    ops[1].PreOperation  = WinternalProtectPreOpThread;
    ops[1].PostOperation = NULL;

    OB_CALLBACK_REGISTRATION reg = {0};
    reg.Version                    = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    reg.RegistrationContext        = NULL;
    RtlInitUnicodeString(&reg.Altitude, L"385720.1932");
    reg.OperationRegistration      = ops;

    NTSTATUS s = ObRegisterCallbacks(&reg, &g_ObCallbackHandle);
    if (!NT_SUCCESS(s)) {
        g_ObCallbackHandle = NULL;
        g_ObRegFailed = s;
        return s;
    }

    // Pin the registration: from now on, any system component that calls
    // ObUnRegisterCallbacks with OUR cookie gets a silent no-op. Hook
    // failure isn't fatal — registration still happened, so the callback
    // works until somebody tries to unregister it.
    (void)WinternalInstallObUnregHook();
    return s;
}

VOID WinternalProtectUnregister(VOID)
{
    // Order matters: pull our hook off ObUnRegisterCallbacks BEFORE calling
    // it ourselves, or we'd silently no-op our own cleanup. Also pull the
    // NtUnloadDriver hook — if we unload while it's still installed, the
    // jmp lands in freed pool and the next sc stop bug-checks the system.
    WinternalUninstallNtUnloadHook();
    WinternalUninstallObUnregHook();

    if (g_ObCallbackHandle) {
        ObUnRegisterCallbacks(g_ObCallbackHandle);
        g_ObCallbackHandle = NULL;
    }
}

static NTSTATUS HandleProtectLock(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_PROTECT_LOCK_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_PROTECT_LOCK_IN in = (PWINTERNAL_PROTECT_LOCK_IN)InBuf;
    if (in->Pid <= 4) return STATUS_INVALID_PARAMETER;

    // Make sure the PID actually exists; an invalid PID would silently sit
    // in the array forever.
    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)in->Pid, &proc);
    if (!NT_SUCCESS(s)) return s;
    ObDereferenceObject(proc);

    if (!g_LockSpinInit) {
        KeInitializeSpinLock(&g_LockSpin);
        g_LockSpinInit = TRUE;
    }

    s = WinternalEnsureObCallbacks();
    if (!NT_SUCCESS(s)) return s;

    KIRQL irql;
    KeAcquireSpinLock(&g_LockSpin, &irql);
    for (ULONG i = 0; i < g_LockedCount; ++i) {
        if (g_LockedPids[i] == in->Pid) {
            KeReleaseSpinLock(&g_LockSpin, irql);
            return STATUS_SUCCESS;       // idempotent
        }
    }
    if (g_LockedCount >= WINTERNAL_PROTECT_MAX) {
        KeReleaseSpinLock(&g_LockSpin, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_LockedPids[g_LockedCount++] = in->Pid;
    KeReleaseSpinLock(&g_LockSpin, irql);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleProtectUnlock(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_PROTECT_LOCK_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_PROTECT_LOCK_IN in = (PWINTERNAL_PROTECT_LOCK_IN)InBuf;
    if (!g_LockSpinInit) return STATUS_NOT_FOUND;

    KIRQL irql;
    KeAcquireSpinLock(&g_LockSpin, &irql);
    BOOLEAN removed = FALSE;
    for (ULONG i = 0; i < g_LockedCount; ++i) {
        if (g_LockedPids[i] == in->Pid) {
            for (ULONG j = i; j + 1 < g_LockedCount; ++j) g_LockedPids[j] = g_LockedPids[j + 1];
            --g_LockedCount;
            removed = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_LockSpin, irql);
    return removed ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static NTSTATUS HandleProtectList(PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (OutLen < sizeof(WINTERNAL_PROTECT_LIST_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_PROTECT_LIST_OUT out = (PWINTERNAL_PROTECT_LIST_OUT)OutBuf;
    RtlZeroMemory(out, sizeof(*out));
    if (g_LockSpinInit) {
        KIRQL irql;
        KeAcquireSpinLock(&g_LockSpin, &irql);
        out->Count = g_LockedCount;
        for (ULONG i = 0; i < g_LockedCount; ++i) out->Pids[i] = g_LockedPids[i];
        KeReleaseSpinLock(&g_LockSpin, irql);
    }
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

// Engage / disengage self-protection. On engage the owner PID is added to
// the Ob-callback protect list so destructive OpenProcess access bits are
// stripped from any other caller. Disengage is gated to the owner PID at
// the dispatcher (so a different admin process can't flip the bit). The
// IOCTL itself just toggles state + walks the protect list.
static NTSTATUS HandleSelfProtectSet(PVOID InBuf, size_t InLen)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[winternal] SELFPROTECT_SET entry: InLen=%zu InBuf=%p\n", InLen, InBuf);
    if (InLen < sizeof(WINTERNAL_SELFPROTECT_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_SELFPROTECT_IN in = (PWINTERNAL_SELFPROTECT_IN)InBuf;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[winternal] SELFPROTECT_SET: enable=%u owner=%u\n", in->Enable, in->OwnerPid);

    if (in->Enable) {
        if (in->OwnerPid == 0) return STATUS_INVALID_PARAMETER;
        UINT32 ownerPid = in->OwnerPid;

        // Hash the caller's main image. Every later weaken-protection
        // IOCTL re-hashes its caller and must match this digest. We
        // DON'T add the PID to the Ob protect list — the engaging CLI
        // is one-shot and exits seconds after this returns, which would
        // leave a stale (and eventually reusable) PID in the list. The
        // identity that matters across CLI invocations is the binary
        // hash, not the PID. If you want short-lived OpenProcess
        // protection on an interactive session, run
        // `winternal protect <pid> --force` explicitly.
        UCHAR hash[WN_SELFPROT_HASH_LEN];
        NTSTATUS hs = WinternalHashCallerImage(hash);
        if (!NT_SUCCESS(hs)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[winternal] SELFPROTECT_SET: image hash failed 0x%08X\n", hs);
            return hs;
        }

        if (!g_SelfProtectSpinInit) {
            KeInitializeSpinLock(&g_SelfProtectSpin);
            g_SelfProtectSpinInit = TRUE;
        }
        KIRQL irql;
        KeAcquireSpinLock(&g_SelfProtectSpin, &irql);
        RtlCopyMemory(g_SelfProtectHash, hash, WN_SELFPROT_HASH_LEN);
        KeReleaseSpinLock(&g_SelfProtectSpin, irql);
        InterlockedExchange(&g_SelfProtectOwner, (LONG)ownerPid);
        InterlockedExchange(&g_SelfProtect, 1);

        // Install the NtUnloadDriver syscall hook so `sc stop` from any
        // caller (admin, SYSTEM-elevated process, scheduler task) is
        // refused. The hook reads g_SelfProtect at every call — disengage
        // both flips the flag and rips the hook out, so subsequent stops
        // work normally.
        NTSTATUS hkStatus = WinternalInstallNtUnloadHook();
        if (!NT_SUCCESS(hkStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[winternal] SELFPROTECT_SET: NtUnloadDriver hook failed 0x%08X "
                       "(SCM DACL still active)\n", hkStatus);
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[winternal] SELFPROTECT_SET: engaged, sha256=%02X%02X%02X%02X...\n",
                   hash[0], hash[1], hash[2], hash[3]);
        return STATUS_SUCCESS;
    } else {
        InterlockedExchange(&g_SelfProtectOwner, 0);
        InterlockedExchange(&g_SelfProtect, 0);
        if (g_SelfProtectSpinInit) {
            KIRQL irql;
            KeAcquireSpinLock(&g_SelfProtectSpin, &irql);
            RtlZeroMemory(g_SelfProtectHash, WN_SELFPROT_HASH_LEN);
            KeReleaseSpinLock(&g_SelfProtectSpin, irql);
        }
        // Pull the NtUnloadDriver hook so `sc stop` works again. Must
        // happen BEFORE driver unload (which we also call into) — leaving
        // a JMP to freed pool memory in ntoskrnl is a guaranteed BSOD.
        WinternalUninstallNtUnloadHook();
        // No Ob-list manipulation: engage didn't add to it, disengage
        // doesn't remove from it. `winternal protect/unprotect` still
        // works for explicit per-PID Ob protection on interactive sessions.
        return STATUS_SUCCESS;
    }
}

static NTSTATUS HandleSelfProtectStatus(PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (OutLen < sizeof(WINTERNAL_SELFPROTECT_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_SELFPROTECT_OUT out = (PWINTERNAL_SELFPROTECT_OUT)OutBuf;
    out->Engaged  = (UINT32)g_SelfProtect;
    out->OwnerPid = (UINT32)g_SelfProtectOwner;
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

// Write SignatureLevel + SectionSignatureLevel into EPROCESS. win32k's
// per-band check looks at these to decide whether the caller is "Microsoft
// trusted" for high z-bands. Bumping both to SE_SIGNING_LEVEL_WINDOWS
// (0x0C) makes the calling process appear MS-signed. Adjacent to the
// Protection byte we already write via UNPROTECT_PROCESS so the offset
// is stable per build (0x878 on 24H2 26100).
static NTSTATUS HandleSetSigLevel(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_SIGLEVEL_IN))  return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(WINTERNAL_SIGLEVEL_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_SIGLEVEL_IN  in  = (PWINTERNAL_SIGLEVEL_IN)InBuf;
    PWINTERNAL_SIGLEVEL_OUT out = (PWINTERNAL_SIGLEVEL_OUT)OutBuf;
    if (in->Pid <= 4) return STATUS_INVALID_PARAMETER;

    ULONG offset = in->FieldOffset ? in->FieldOffset : WINTERNAL_DEFAULT_SIGLEVEL_OFFSET;

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)in->Pid, &proc);
    if (!NT_SUCCESS(s)) return s;

    __try {
        PUCHAR p = (PUCHAR)proc + offset;
        out->PrevSignatureLevel        = p[0];
        out->PrevSectionSignatureLevel = p[1];
        p[0] = in->SignatureLevel;
        p[1] = in->SectionSignatureLevel;
        out->FieldOffsetUsed = offset;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }
    ObDereferenceObject(proc);
    if (NT_SUCCESS(s)) *Written = sizeof(*out);
    return s;
}

// Forward decl — defined in the protect block further down.
static NTSTATUS WinternalProtectWriteCode(PVOID Target, const VOID* Src, SIZE_T Length);

// Stub the CLI redirects win32k IAT entries to (e.g. __imp_IsImmersiveBroker).
// Lives in Winternal.sys's .text, so the IAT slot just needs to be flipped
// to point here — no need to allocate executable pool (which HVCI can also
// refuse). Returns TRUE in AL via the standard x64 ABI.
NTSTATUS WinternalAlwaysOne(PVOID Unused)
{
    UNREFERENCED_PARAMETER(Unused);
    return (NTSTATUS)1;
}

static NTSTATUS HandleGetTrueStub(PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (OutLen < sizeof(WINTERNAL_GET_TRUE_STUB_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_GET_TRUE_STUB_OUT out = (PWINTERNAL_GET_TRUE_STUB_OUT)OutBuf;
    out->Address = (UINT64)(ULONG_PTR)&WinternalAlwaysOne;
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleGetW32Process(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_GET_W32PROC_IN))  return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(WINTERNAL_GET_W32PROC_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_GET_W32PROC_IN  in  = (PWINTERNAL_GET_W32PROC_IN)InBuf;
    PWINTERNAL_GET_W32PROC_OUT out = (PWINTERNAL_GET_W32PROC_OUT)OutBuf;
    if (in->Pid <= 4) return STATUS_INVALID_PARAMETER;

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)in->Pid, &proc);
    if (!NT_SUCCESS(s)) return s;
    PVOID w32 = PsGetProcessWin32Process(proc);
    ObDereferenceObject(proc);
    out->Address = (UINT64)(ULONG_PTR)w32;
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

// Kernel-side EnumThreads: ZwQuerySystemInformation gives us all processes
// + threads in one shot. Iterate to find the target PID's thread block.
// Bypasses user-mode hooks since the syscall completes inside the kernel.
static NTSTATUS HandleEnumThreads(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_PID_IN)) return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(WINTERNAL_THREADS_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_PID_IN in = (PWINTERNAL_PID_IN)InBuf;
    PWINTERNAL_THREADS_OUT out = (PWINTERNAL_THREADS_OUT)OutBuf;

    // Allocate scratch large enough for the whole system process list.
    SIZE_T bufSize = 4 * 1024 * 1024;
    PVOID scratch = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, WINTERNAL_POOL_TAG_DEFAULT);
    if (!scratch) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS s = STATUS_INFO_LENGTH_MISMATCH;
    for (int attempt = 0; attempt < 4 && s == STATUS_INFO_LENGTH_MISMATCH; ++attempt) {
        ULONG ret = 0;
        s = ZwQuerySystemInformation(SystemProcessInformation, scratch, (ULONG)bufSize, &ret);
        if (s == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePoolWithTag(scratch, WINTERNAL_POOL_TAG_DEFAULT);
            bufSize *= 2;
            scratch = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, WINTERNAL_POOL_TAG_DEFAULT);
            if (!scratch) return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    if (!NT_SUCCESS(s)) {
        ExFreePoolWithTag(scratch, WINTERNAL_POOL_TAG_DEFAULT);
        return s;
    }

    // Walk SYSTEM_PROCESS_INFORMATION entries. UniqueProcessId is at +0x50
    // on x64; NumberOfThreads at +0x04; thread array starts at +0x100 in
    // 24H2 26100. These offsets are stable across Win10/11.
    PUCHAR p = (PUCHAR)scratch;
    out->Count = 0;
    *Written = FIELD_OFFSET(WINTERNAL_THREADS_OUT, Entries);
    SIZE_T outCap = (OutLen - FIELD_OFFSET(WINTERNAL_THREADS_OUT, Entries)) / sizeof(WINTERNAL_THREAD_ENTRY);
    s = STATUS_NOT_FOUND;
    for (;;) {
        ULONG nextOffset  = *(PULONG)(p + 0x00);
        ULONG numThreads  = *(PULONG)(p + 0x04);
        ULONG_PTR uniqPid = *(PULONG_PTR)(p + 0x50);
        if ((UINT32)uniqPid == in->Pid) {
            WN_SYSTEM_THREAD_INFORMATION* t = (WN_SYSTEM_THREAD_INFORMATION*)(p + 0x100);
            ULONG emit = (numThreads > outCap) ? (ULONG)outCap : numThreads;
            for (ULONG i = 0; i < emit; ++i) {
                out->Entries[i].Tid             = HandleToULong(t[i].ClientId.UniqueThread);
                out->Entries[i].State           = t[i].ThreadState;
                out->Entries[i].WaitReason      = t[i].WaitReason;
                out->Entries[i].Priority        = t[i].Priority;
                out->Entries[i].StartAddress    = (UINT64)(ULONG_PTR)t[i].StartAddress;
                out->Entries[i].KernelTime100Ns = (UINT64)t[i].KernelTime.QuadPart;
                out->Entries[i].UserTime100Ns   = (UINT64)t[i].UserTime.QuadPart;
                out->Entries[i].CreateTimeFt    = (UINT64)t[i].CreateTime.QuadPart;
            }
            out->Count = emit;
            *Written = FIELD_OFFSET(WINTERNAL_THREADS_OUT, Entries) + emit * sizeof(WINTERNAL_THREAD_ENTRY);
            s = STATUS_SUCCESS;
            break;
        }
        if (nextOffset == 0) break;
        p += nextOffset;
    }
    ExFreePoolWithTag(scratch, WINTERNAL_POOL_TAG_DEFAULT);
    return s;
}

// Helper: open a kernel-mode HANDLE to the target process for use by the
// Zw* query family. Use OBJ_KERNEL_HANDLE so handle resolution skips the
// per-process handle-table check.
static NTSTATUS WinternalOpenProcessHandle(UINT32 Pid, ACCESS_MASK Access, PHANDLE OutH)
{
    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc);
    if (!NT_SUCCESS(s)) return s;
    s = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL, Access,
                              *PsProcessType, KernelMode, OutH);
    ObDereferenceObject(proc);
    return s;
}

static NTSTATUS HandleKMitigations(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_PID_IN)) return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(WINTERNAL_MITIGATIONS_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_PID_IN in = (PWINTERNAL_PID_IN)InBuf;
    PWINTERNAL_MITIGATIONS_OUT out = (PWINTERNAL_MITIGATIONS_OUT)OutBuf;

    HANDLE h = NULL;
    NTSTATUS s = WinternalOpenProcessHandle(in->Pid, PROCESS_QUERY_INFORMATION, &h);
    if (!NT_SUCCESS(s)) return s;

    // PROCESSINFOCLASS for mitigation policies; the kernel-side class
    // matches the user-mode index 52 (ProcessMitigationPolicy) which then
    // takes a sub-policy id in the input buffer. From a kernel-mode
    // ZwQIP, we just emit each policy as a raw query.
    out->Count = 0;
    for (ULONG i = 0; i < WINTERNAL_MITIGATION_COUNT; ++i) {
        struct { ULONG PolicyId; ULONG_PTR Buffer; } pkt = { i, 0 };
        ULONG ret = 0;
        NTSTATUS qs = ZwQueryInformationProcess(h, 52 /* ProcessMitigationPolicy */,
                                                &pkt, sizeof(pkt), &ret);
        out->Items[out->Count].PolicyId = i;
        out->Items[out->Count].NtStatus = qs;
        out->Items[out->Count].Value    = (UINT64)pkt.Buffer;
        out->Count++;
    }
    ZwClose(h);
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleKTokenInfo(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_PID_IN)) return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(WINTERNAL_TOKEN_INFO_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_PID_IN in = (PWINTERNAL_PID_IN)InBuf;
    PWINTERNAL_TOKEN_INFO_OUT out = (PWINTERNAL_TOKEN_INFO_OUT)OutBuf;
    RtlZeroMemory(out, sizeof(*out));

    HANDLE ph = NULL;
    NTSTATUS s = WinternalOpenProcessHandle(in->Pid, PROCESS_QUERY_INFORMATION, &ph);
    if (!NT_SUCCESS(s)) return s;

    HANDLE th = NULL;
    s = ZwOpenProcessTokenEx(ph, TOKEN_QUERY, OBJ_KERNEL_HANDLE, &th);
    ZwClose(ph);
    if (!NT_SUCCESS(s)) return s;

    ULONG ret = 0;
    UCHAR buf[512];

    // TokenUser (class 1)
    if (NT_SUCCESS(ZwQueryInformationToken(th, 1, buf, sizeof(buf), &ret))) {
        // Buf layout: SID_AND_ATTRIBUTES { PSID Sid; ULONG Attributes; } at offset 0.
        PSID sid = *(PSID*)buf;
        if (sid) {
            ULONG sidLen = RtlLengthSid(sid);
            if (sidLen > sizeof(out->UserSid)) sidLen = sizeof(out->UserSid);
            RtlCopyMemory(out->UserSid, sid, sidLen);
        }
    }
    // TokenIntegrityLevel (class 25)
    if (NT_SUCCESS(ZwQueryInformationToken(th, 25, buf, sizeof(buf), &ret))) {
        PSID sid = *(PSID*)buf;
        if (sid) {
            ULONG sidLen = RtlLengthSid(sid);
            if (sidLen > sizeof(out->IntegritySid)) sidLen = sizeof(out->IntegritySid);
            RtlCopyMemory(out->IntegritySid, sid, sidLen);
            UCHAR subCount = *RtlSubAuthorityCountSid(sid);
            if (subCount) out->IntegrityRid = *RtlSubAuthoritySid(sid, subCount - 1);
        }
    }
    // TokenElevationType (class 18)
    {
        ULONG et = 0;
        if (NT_SUCCESS(ZwQueryInformationToken(th, 18, &et, sizeof(et), &ret))) out->ElevationType = et;
    }
    // TokenElevation (class 20)
    {
        ULONG el = 0;
        if (NT_SUCCESS(ZwQueryInformationToken(th, 20, &el, sizeof(el), &ret))) out->Elevated = el;
    }
    // TokenUIAccess (class 26)
    {
        ULONG ui = 0;
        if (NT_SUCCESS(ZwQueryInformationToken(th, 26, &ui, sizeof(ui), &ret))) out->UIAccess = ui;
    }
    // TokenSessionId (class 12)
    {
        ULONG sid = 0;
        if (NT_SUCCESS(ZwQueryInformationToken(th, 12, &sid, sizeof(sid), &ret))) out->SessionId = sid;
    }
    // TokenPrivileges (class 3)
    {
        ULONG privLen = 0;
        ZwQueryInformationToken(th, 3, NULL, 0, &privLen);
        if (privLen) {
            PVOID pbuf = ExAllocatePool2(POOL_FLAG_PAGED, privLen, WINTERNAL_POOL_TAG_DEFAULT);
            if (pbuf && NT_SUCCESS(ZwQueryInformationToken(th, 3, pbuf, privLen, &ret))) {
                PWN_TOKEN_PRIVILEGES tp = (PWN_TOKEN_PRIVILEGES)pbuf;
                ULONG n = tp->PrivilegeCount;
                if (n > WINTERNAL_MAX_PRIVILEGES) n = WINTERNAL_MAX_PRIVILEGES;
                for (ULONG i = 0; i < n; ++i) {
                    out->Privileges[i].Luid = ((UINT64)tp->Privileges[i].Luid.HighPart << 32) | tp->Privileges[i].Luid.LowPart;
                    out->Privileges[i].Attributes = tp->Privileges[i].Attributes;
                }
                out->PrivCount = n;
            }
            if (pbuf) ExFreePoolWithTag(pbuf, WINTERNAL_POOL_TAG_DEFAULT);
        }
    }

    ZwClose(th);
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleKMemQuery(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_PID_IN)) return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(WINTERNAL_MEM_QUERY_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_PID_IN in = (PWINTERNAL_PID_IN)InBuf;
    PWINTERNAL_MEM_QUERY_OUT out = (PWINTERNAL_MEM_QUERY_OUT)OutBuf;
    RtlZeroMemory(out, FIELD_OFFSET(WINTERNAL_MEM_QUERY_OUT, Entries));

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)in->Pid, &proc);
    if (!NT_SUCCESS(s)) return s;

    SIZE_T outCap = (OutLen - FIELD_OFFSET(WINTERNAL_MEM_QUERY_OUT, Entries)) / sizeof(WINTERNAL_MEM_REGION);
    if (outCap > WINTERNAL_MAX_MEM_REGIONS) outCap = WINTERNAL_MAX_MEM_REGIONS;

    WN_KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    ULONG_PTR addr = 0;
    ULONG count = 0;
    BOOLEAN truncated = FALSE;
    HANDLE selfHandle = (HANDLE)(LONG_PTR)-1;   // ZwCurrentProcess()
    for (;;) {
        WN_MEMORY_BASIC_INFORMATION mbi;
        SIZE_T ret = 0;
        // MemoryBasicInformation class = 0.
        NTSTATUS qs = ZwQueryVirtualMemory(selfHandle, (PVOID)addr, 0, &mbi, sizeof(mbi), &ret);
        if (!NT_SUCCESS(qs) || mbi.RegionSize == 0) break;

        if (count < outCap) {
            out->Entries[count].BaseAddress = (UINT64)(ULONG_PTR)mbi.BaseAddress;
            out->Entries[count].RegionSize  = (UINT64)mbi.RegionSize;
            out->Entries[count].State       = mbi.State;
            out->Entries[count].Protect     = mbi.Protect;
            out->Entries[count].Type        = mbi.Type;
            count++;
        } else {
            truncated = TRUE;
            break;
        }
        addr += mbi.RegionSize;
        if (addr >= 0x00007FFFFFFFFFFFull) break;
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    out->Count = count;
    out->Truncated = truncated ? 1 : 0;
    *Written = FIELD_OFFSET(WINTERNAL_MEM_QUERY_OUT, Entries) + count * sizeof(WINTERNAL_MEM_REGION);
    return STATUS_SUCCESS;
}


// Patch a kernel-code page. Toggles CR0.WP on this CPU, writes, restores,
// reads back to verify (HVCI / VBS can silently swallow the write — the
// readback turns that into a clean STATUS_NOT_SUPPORTED instead of a hang
// or undetected failure).
static NTSTATUS HandleKcodePatch(PVOID InBuf, size_t InLen)
{
    if (InLen < FIELD_OFFSET(WINTERNAL_KCODE_PATCH_IN, Data)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KCODE_PATCH_IN in = (PWINTERNAL_KCODE_PATCH_IN)InBuf;
    if (in->Length == 0 || in->Length > WINTERNAL_KCODE_PATCH_MAX) return STATUS_INVALID_PARAMETER;
    if (InLen < FIELD_OFFSET(WINTERNAL_KCODE_PATCH_IN, Data) + in->Length) return STATUS_BUFFER_TOO_SMALL;

    PVOID target = (PVOID)(ULONG_PTR)in->Address;
    if (!WinternalIsKernelAddress(target)) return STATUS_ACCESS_VIOLATION;

    return WinternalProtectWriteCode(target, in->Data, in->Length);
}

// Toggle TOKEN_HAS_UI_ACCESS on a process's primary token. From kernel
// mode this is a 4-byte write to TOKEN->TokenFlags — none of the user-mode
// path's privilege checks (SeTcbPrivilege, "running process" rejection)
// apply. Lifts the gate that makes user32!SetWindowBand / CreateWindowInBand
// fail for normal admin processes on bands like SYSTEM_TOOLS.
static NTSTATUS HandleTokenUIAccess(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_TOKEN_UIACCESS_IN))  return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(WINTERNAL_TOKEN_UIACCESS_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_TOKEN_UIACCESS_IN  in  = (PWINTERNAL_TOKEN_UIACCESS_IN)InBuf;
    PWINTERNAL_TOKEN_UIACCESS_OUT out = (PWINTERNAL_TOKEN_UIACCESS_OUT)OutBuf;
    if (in->Pid <= 4) return STATUS_INVALID_PARAMETER;

    ULONG offset = in->FieldOffset ? in->FieldOffset : WINTERNAL_DEFAULT_TOKENFLAGS_OFFSET;

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)in->Pid, &proc);
    if (!NT_SUCCESS(s)) return s;

    PACCESS_TOKEN token = PsReferencePrimaryToken(proc);
    if (!token) { ObDereferenceObject(proc); return STATUS_NOT_FOUND; }

    __try {
        PULONG flagsPtr = (PULONG)((PUCHAR)token + offset);
        out->PrevFlags = *flagsPtr;
        if (in->Enable) *flagsPtr |= WINTERNAL_TOKEN_FLAG_UIACCESS;
        else             *flagsPtr &= ~WINTERNAL_TOKEN_FLAG_UIACCESS;
        out->NewFlags = *flagsPtr;
        out->FieldOffsetUsed = offset;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }

    PsDereferencePrimaryToken(token);
    ObDereferenceObject(proc);
    if (NT_SUCCESS(s)) *Written = sizeof(*out);
    return s;
}

//
// PspCreateProcessNotifyRoutine[]-style arrays aren't exported. We locate them
// by scanning the body of the corresponding PsSet... export for a RIP-relative
// `lea rax, [array]` (48 8D 0D / 4C 8D 25 / 48 8D 05 etc) and pulling the
// resolved pointer. The arrays hold EX_FAST_REF-encoded pointers (low bits are
// reference count) so we mask them off when reporting.
//
// This is intentionally best-effort: if the export's prologue changes between
// builds, the scan returns zero entries rather than reading garbage.
//
static PVOID FindCallbackArray(const wchar_t* SetRoutineName, ULONG ScanBytes)
{
    UNICODE_STRING us; RtlInitUnicodeString(&us, (PWSTR)SetRoutineName);
    PUCHAR fn = (PUCHAR)MmGetSystemRoutineAddress(&us);
    if (!fn) return NULL;

    for (ULONG i = 0; i < ScanBytes - 7; ++i) {
        __try {
            // 48 8D ?? ?? ?? ?? ??   lea r64, [rip+disp32]
            // 4C 8D ?? ?? ?? ?? ??   lea r8-r15, [rip+disp32]
            UCHAR a = fn[i], b = fn[i+1];
            if ((a == 0x48 || a == 0x4C) && b == 0x8D) {
                LONG disp = *(LONG*)(fn + i + 3);
                PVOID target = fn + i + 7 + disp;
                // Sanity: target should be in the kernel image (ntoskrnl data).
                if ((ULONG_PTR)target >= (ULONG_PTR)MmHighestUserAddress &&
                    (ULONG_PTR)target < (ULONG_PTR)0xFFFFFFFFFFFF0000ULL) {
                    return target;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return NULL;
        }
    }
    return NULL;
}

// Resolve a kernel address to its owning module (base + short name). Writes
// out the base/short name into the caller-provided slots; either may be NULL.
static void ResolveModule(PVOID Routine, PRTL_PROCESS_MODULES Mods,
                          UINT64* OutBase, char* OutName, size_t OutNameSize)
{
    if (OutBase) *OutBase = 0;
    if (OutName && OutNameSize) OutName[0] = 0;
    if (!Routine || !Mods) return;

    for (ULONG j = 0; j < Mods->NumberOfModules; ++j) {
        PVOID base = Mods->Modules[j].ImageBase;
        ULONG size = Mods->Modules[j].ImageSize;
        if ((ULONG_PTR)Routine >= (ULONG_PTR)base &&
            (ULONG_PTR)Routine <  (ULONG_PTR)base + size) {
            if (OutBase) *OutBase = (UINT64)(ULONG_PTR)base;
            const UCHAR* full = Mods->Modules[j].FullPathName;
            USHORT off = Mods->Modules[j].OffsetToFileName;
            if (OutName && OutNameSize && off < sizeof(Mods->Modules[j].FullPathName)) {
                RtlStringCbCopyA(OutName, OutNameSize, (const char*)(full + off));
            }
            return;
        }
    }
}

static PRTL_PROCESS_MODULES QueryAllModules(void)
{
    ULONG needed = 0;
    NTSTATUS s = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &needed);
    if (s != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(s)) return NULL;
    if (needed == 0) return NULL;

    needed += 4096;
    PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)ExAllocatePool2(
        POOL_FLAG_PAGED, needed, WINTERNAL_POOL_TAG_DEFAULT);
    if (!mods) return NULL;
    s = ZwQuerySystemInformation(SystemModuleInformation, mods, needed, &needed);
    if (!NT_SUCCESS(s)) {
        ExFreePoolWithTag(mods, WINTERNAL_POOL_TAG_DEFAULT);
        return NULL;
    }
    return mods;
}

static NTSTATUS HandleEnumCallbacks(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_CB_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_CB_IN in = (PWINTERNAL_CB_IN)InBuf;
    PWINTERNAL_CB_LIST out = (PWINTERNAL_CB_LIST)OutBuf;
    size_t header = FIELD_OFFSET(WINTERNAL_CB_LIST, Entries);
    if (OutLen < header) return STATUS_BUFFER_TOO_SMALL;
    size_t maxEntries = (OutLen - header) / sizeof(WINTERNAL_CB_ENTRY);

    const wchar_t* exportName;
    ULONG slots;
    switch (in->Kind) {
    case WINTERNAL_CB_KIND_PROCESS: exportName = L"PsSetCreateProcessNotifyRoutineEx"; slots = 64; break;
    case WINTERNAL_CB_KIND_IMAGE:   exportName = L"PsSetLoadImageNotifyRoutineEx";     slots = 64; break;
    case WINTERNAL_CB_KIND_THREAD:  exportName = L"PsSetCreateThreadNotifyRoutine";    slots = 64; break;
    default: return STATUS_INVALID_PARAMETER;
    }

    PVOID array = FindCallbackArray(exportName, 0x400);
    out->Count = 0;
    out->Reserved = 0;
    if (!array) { *Written = header; return STATUS_SUCCESS; }

    PRTL_PROCESS_MODULES mods = QueryAllModules();
    UINT32 written = 0;
    for (ULONG i = 0; i < slots && written < maxEntries; ++i) {
        ULONG_PTR slot = 0;
        __try {
            slot = ((ULONG_PTR*)array)[i];
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
        if (!slot) continue;
        // EX_FAST_REF encoding: bottom 4 bits are reference count on x64.
        PVOID routine = (PVOID)(slot & ~(ULONG_PTR)0xF);
        // The slot points to a wrapper structure (CallbackObject); the routine
        // is the 2nd pointer in it. Best-effort dereference.
        PVOID actual = routine;
        __try {
            actual = *((PVOID*)((PUCHAR)routine + sizeof(PVOID)));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            actual = routine;
        }
        WINTERNAL_CB_ENTRY* e = &out->Entries[written++];
        e->Routine = (UINT64)(ULONG_PTR)actual;
        ResolveModule(actual, mods, &e->ModuleBase, e->ModuleName, sizeof(e->ModuleName));
    }
    if (mods) ExFreePoolWithTag(mods, WINTERNAL_POOL_TAG_DEFAULT);

    out->Count = written;
    *Written = header + written * sizeof(WINTERNAL_CB_ENTRY);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleEnumDrivers(PVOID OutBuf, size_t OutLen, size_t* Written)
{
    PWINTERNAL_DRIVER_LIST out = (PWINTERNAL_DRIVER_LIST)OutBuf;
    size_t header = FIELD_OFFSET(WINTERNAL_DRIVER_LIST, Entries);
    if (OutLen < header) return STATUS_BUFFER_TOO_SMALL;
    size_t maxEntries = (OutLen - header) / sizeof(WINTERNAL_DRIVER_ENTRY);

    PRTL_PROCESS_MODULES mods = QueryAllModules();
    out->Count = 0;
    out->Reserved = 0;
    if (!mods) { *Written = header; return STATUS_UNSUCCESSFUL; }

    UINT32 written = 0;
    for (ULONG i = 0; i < mods->NumberOfModules && written < maxEntries; ++i) {
        WINTERNAL_DRIVER_ENTRY* e = &out->Entries[written++];
        RtlZeroMemory(e, sizeof(*e));
        e->ImageBase = (UINT64)(ULONG_PTR)mods->Modules[i].ImageBase;
        e->ImageSize = mods->Modules[i].ImageSize;
        RtlStringCbCopyA(e->Name, sizeof(e->Name), (const char*)mods->Modules[i].FullPathName);
    }
    ExFreePoolWithTag(mods, WINTERNAL_POOL_TAG_DEFAULT);

    out->Count = written;
    *Written = header + written * sizeof(WINTERNAL_DRIVER_ENTRY);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleEnumSsdt(PVOID OutBuf, size_t OutLen, size_t* Written)
{
    PWINTERNAL_SSDT_LIST out = (PWINTERNAL_SSDT_LIST)OutBuf;
    size_t header = FIELD_OFFSET(WINTERNAL_SSDT_LIST, Entries);
    if (OutLen < header) return STATUS_BUFFER_TOO_SMALL;
    size_t maxEntries = (OutLen - header) / sizeof(WINTERNAL_SSDT_ENTRY);

    KSERVICE_TABLE_DESCRIPTOR* desc = LocateServiceDescriptor();
    if (!desc) return STATUS_NOT_FOUND;
    PULONG table = desc->Base;
    ULONG limit = desc->Limit;
    PRTL_PROCESS_MODULES mods = QueryAllModules();

    out->Count = 0;
    out->Base = 0;     // The 32-bit Base field can't hold a 64-bit address;
                       // emit 0 (callers can ksym("KeServiceDescriptorTable") for the real one).
    UINT32 written = 0;
    for (ULONG i = 0; i < limit && written < maxEntries; ++i) {
        // x64 encoding: routine = (LONG)(entry >> 4) + table_base.
        LONG offset = (LONG)(table[i] >> 4);
        ULONG_PTR routine = (ULONG_PTR)table + offset;
        WINTERNAL_SSDT_ENTRY* e = &out->Entries[written++];
        RtlZeroMemory(e, sizeof(*e));
        e->Index = i;
        e->Routine = (UINT64)routine;
        ResolveModule((PVOID)routine, mods, &e->ModuleBase, e->ModuleName, sizeof(e->ModuleName));
    }
    if (mods) ExFreePoolWithTag(mods, WINTERNAL_POOL_TAG_DEFAULT);

    out->Count = written;
    *Written = header + written * sizeof(WINTERNAL_SSDT_ENTRY);
    return STATUS_SUCCESS;
}

// -----------------------------------------------------------------------------
// Kernel inline hooks
//
// Install pattern: overwrite `prologueSize` bytes at the target with
//   FF 25 00 00 00 00      jmp [rip+0]
//   <8 bytes: detour>
// followed by 0x90 (NOP) fill. The original prologue is copied into a
// non-paged-pool trampoline, followed by a same-encoding jump back to
// `target+prologueSize`. Writes go through a CR0.WP toggle so we can write
// into read-only kernel pages without re-mapping them.
//
// SMP-safety here is minimal: we raise to HIGH_LEVEL on the current CPU to
// prevent preemption, but we don't IPI other cores. For a research tool on
// a VM this is fine; production-grade engines (live-patch et al.) IPI all
// CPUs and pause them around the write.
// -----------------------------------------------------------------------------

static VOID KhookWriteJmpAbs(PUCHAR Dst, PVOID To)
{
    Dst[0] = 0xFF;
    Dst[1] = 0x25;
    Dst[2] = 0; Dst[3] = 0; Dst[4] = 0; Dst[5] = 0;
    RtlCopyMemory(Dst + 6, &To, sizeof(PVOID));
}

// SMP-safe patch via KeIpiGenericCall. The broadcast pauses every CPU at
// IPI_LEVEL while the worker runs; the first CPU into the worker does the
// actual write, every other CPU spins-then-exits, so the patched bytes
// are coherent across cores by the time KeIpiGenericCall returns. CR0.WP
// is cleared on the writing CPU only and restored before the worker exits.
typedef ULONG_PTR (NTAPI *KHOOK_IPI_WORKER)(ULONG_PTR Argument);
NTKERNELAPI ULONG_PTR KeIpiGenericCall(_In_ KHOOK_IPI_WORKER BroadcastFunction, _In_ ULONG_PTR Context);

typedef struct _KHOOK_IPI_PATCH {
    PVOID  Target;
    PVOID  NewBytes;
    SIZE_T Length;
    volatile LONG Claim;       // 0 -> available; first CPU swaps to 1 and writes
    volatile LONG WrittenAck;  // first CPU sets to 1 once writing is done
} KHOOK_IPI_PATCH;

static ULONG_PTR NTAPI KhookIpiWorker(ULONG_PTR Context)
{
    KHOOK_IPI_PATCH* p = (KHOOK_IPI_PATCH*)Context;
    if (InterlockedCompareExchange(&p->Claim, 1, 0) == 0) {
        ULONG_PTR prevCr0 = __readcr0();
        __writecr0(prevCr0 & ~0x10000ULL);     // clear WP (bit 16)
        RtlCopyMemory(p->Target, p->NewBytes, p->Length);
        __writecr0(prevCr0);
        InterlockedExchange(&p->WrittenAck, 1);
    } else {
        // Other CPUs spin until the writing CPU finishes. Necessary because
        // KeIpiGenericCall only returns after every CPU has returned from
        // its worker; without the spin, other CPUs could lower IRQL before
        // the patch completed.
        while (!p->WrittenAck) { YieldProcessor(); }
    }
    return 0;
}

static VOID KhookPatchAtomic(PVOID Target, const VOID* NewBytes, SIZE_T Length)
{
    KHOOK_IPI_PATCH ctx = { Target, (PVOID)NewBytes, Length, 0, 0 };
    KeIpiGenericCall(KhookIpiWorker, (ULONG_PTR)&ctx);
}

VOID WinternalKhookInit(VOID)
{
    if (g_KhookInitialized) return;
    InitializeListHead(&g_KhookList);
    KeInitializeSpinLock(&g_KhookLock);
    g_KhookInitialized = TRUE;
}

static NTSTATUS HandleKhookInstall(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_KHOOK_INSTALL_IN) || OutLen < sizeof(WINTERNAL_KHOOK_INSTALL_OUT))
        return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KHOOK_INSTALL_IN in = (PWINTERNAL_KHOOK_INSTALL_IN)InBuf;
    PWINTERNAL_KHOOK_INSTALL_OUT out = (PWINTERNAL_KHOOK_INSTALL_OUT)OutBuf;

    PVOID target = (PVOID)(ULONG_PTR)in->Target;
    PVOID detour = (PVOID)(ULONG_PTR)in->Detour;
    ULONG prolog = in->PrologueSize ? in->PrologueSize : 16;

    if (!WinternalIsKernelAddress(target) || !WinternalIsKernelAddress(detour))
        return STATUS_ACCESS_VIOLATION;
    if (prolog < WINTERNAL_KHOOK_JMP_SIZE || prolog > WINTERNAL_KHOOK_MAX_PROLOG)
        return STATUS_INVALID_PARAMETER;

    WinternalKhookInit();

    // Check duplicate.
    KIRQL irql;
    KeAcquireSpinLock(&g_KhookLock, &irql);
    for (PLIST_ENTRY le = g_KhookList.Flink; le != &g_KhookList; le = le->Flink) {
        PWINTERNAL_KHOOK_ENTRY e = CONTAINING_RECORD(le, WINTERNAL_KHOOK_ENTRY, ListEntry);
        if (e->Target == target) { KeReleaseSpinLock(&g_KhookLock, irql); return STATUS_OBJECT_NAME_EXISTS; }
    }
    KeReleaseSpinLock(&g_KhookLock, irql);

    PWINTERNAL_KHOOK_ENTRY entry = (PWINTERNAL_KHOOK_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*entry), WINTERNAL_POOL_TAG_DEFAULT);
    if (!entry) return STATUS_INSUFFICIENT_RESOURCES;

    PUCHAR tramp = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED_EXECUTE, WINTERNAL_KHOOK_TRAMP_SIZE, WINTERNAL_POOL_TAG_DEFAULT);
    if (!tramp) {
        ExFreePoolWithTag(entry, WINTERNAL_POOL_TAG_DEFAULT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = STATUS_SUCCESS;
    __try {
        // Save original prologue + populate trampoline.
        RtlCopyMemory(entry->SavedBytes, target, prolog);
        RtlCopyMemory(tramp, target, prolog);
        KhookWriteJmpAbs(tramp + prolog, (PUCHAR)target + prolog);

        // Build the new prologue locally, then patch atomically across all
        // CPUs so a target executing on another core never sees a half-
        // written prologue.
        UCHAR newProlog[WINTERNAL_KHOOK_MAX_PROLOG];
        KhookWriteJmpAbs(newProlog, detour);
        for (ULONG i = WINTERNAL_KHOOK_JMP_SIZE; i < prolog; ++i) newProlog[i] = 0x90;
        KhookPatchAtomic(target, newProlog, prolog);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(tramp, WINTERNAL_POOL_TAG_DEFAULT);
        ExFreePoolWithTag(entry, WINTERNAL_POOL_TAG_DEFAULT);
        return status;
    }

    entry->Target = target;
    entry->Detour = detour;
    entry->Trampoline = tramp;
    entry->PrologueSize = prolog;

    KeAcquireSpinLock(&g_KhookLock, &irql);
    InsertTailList(&g_KhookList, &entry->ListEntry);
    KeReleaseSpinLock(&g_KhookLock, irql);

    out->Trampoline = (UINT64)(ULONG_PTR)tramp;
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleKhookUninstall(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_KHOOK_UNINSTALL_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KHOOK_UNINSTALL_IN in = (PWINTERNAL_KHOOK_UNINSTALL_IN)InBuf;
    PVOID target = (PVOID)(ULONG_PTR)in->Target;
    if (!g_KhookInitialized) return STATUS_NOT_FOUND;

    KIRQL irql;
    PWINTERNAL_KHOOK_ENTRY entry = NULL;
    KeAcquireSpinLock(&g_KhookLock, &irql);
    for (PLIST_ENTRY le = g_KhookList.Flink; le != &g_KhookList; le = le->Flink) {
        PWINTERNAL_KHOOK_ENTRY e = CONTAINING_RECORD(le, WINTERNAL_KHOOK_ENTRY, ListEntry);
        if (e->Target == target) { RemoveEntryList(le); entry = e; break; }
    }
    KeReleaseSpinLock(&g_KhookLock, irql);
    if (!entry) return STATUS_NOT_FOUND;

    NTSTATUS status = STATUS_SUCCESS;
    __try {
        KhookPatchAtomic(target, entry->SavedBytes, entry->PrologueSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    ExFreePoolWithTag(entry->Trampoline, WINTERNAL_POOL_TAG_DEFAULT);
    ExFreePoolWithTag(entry, WINTERNAL_POOL_TAG_DEFAULT);
    return status;
}

VOID WinternalKhookUninstallAll(VOID)
{
    if (!g_KhookInitialized) return;
    KIRQL irql;
    KeAcquireSpinLock(&g_KhookLock, &irql);
    while (!IsListEmpty(&g_KhookList)) {
        PLIST_ENTRY le = RemoveHeadList(&g_KhookList);
        PWINTERNAL_KHOOK_ENTRY entry = CONTAINING_RECORD(le, WINTERNAL_KHOOK_ENTRY, ListEntry);
        KeReleaseSpinLock(&g_KhookLock, irql);

        __try {
            KhookPatchAtomic(entry->Target, entry->SavedBytes, entry->PrologueSize);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Best-effort; if we can't restore, we have to leak rather than
            // free the trampoline because something might still be executing
            // inside it.
        }
        ExFreePoolWithTag(entry->Trampoline, WINTERNAL_POOL_TAG_DEFAULT);
        ExFreePoolWithTag(entry, WINTERNAL_POOL_TAG_DEFAULT);

        KeAcquireSpinLock(&g_KhookLock, &irql);
    }
    KeReleaseSpinLock(&g_KhookLock, irql);
}

// -----------------------------------------------------------------------------
// Kernel-side Lua bindings (wnk.*)
//
// These are thin Lua C functions that call directly into the same handlers
// the IOCTL surface uses. The big advantage over user-mode wn.*: no IOCTL
// round-trip, no buffer-size cap (each call works with whatever the lua
// allocator gives us), and immediate access to in-flight kernel state.
// -----------------------------------------------------------------------------

#include "klua/lua.h"
#include "klua/lauxlib.h"
#include "klua/klua_kernel.h"

static int KluaPrint(lua_State* L) {
    int n = lua_gettop(L);
    for (int i = 1; i <= n; ++i) {
        size_t l = 0;
        const char* s = luaL_tolstring(L, i, &l);
        if (i > 1) klua_print_n("\t", 1);
        klua_print_n(s, l);
        lua_pop(L, 1);
    }
    klua_print_n("\n", 1);
    return 0;
}

static int KluaKsym(lua_State* L) {
    size_t l = 0;
    const char* name = luaL_checklstring(L, 1, &l);
    UNICODE_STRING us;
    WCHAR wbuf[64];
    if (l >= 64) { lua_pushnil(L); return 1; }
    for (size_t i = 0; i < l; ++i) wbuf[i] = (WCHAR)name[i];
    wbuf[l] = 0;
    RtlInitUnicodeString(&us, wbuf);
    PVOID p = MmGetSystemRoutineAddress(&us);
    if (!p) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)(ULONG_PTR)p);
    return 1;
}

static int KluaKread(lua_State* L) {
    PVOID addr = (PVOID)(ULONG_PTR)luaL_checkinteger(L, 1);
    size_t n = (size_t)luaL_checkinteger(L, 2);
    if (n == 0 || n > 1024 * 1024) return luaL_error(L, "wnk.kread: bad length");
    if ((ULONG_PTR)addr < 0xFFFF800000000000ULL) return luaL_error(L, "wnk.kread: user pointer");
    char* tmp = (char*)ExAllocatePool2(POOL_FLAG_PAGED, n, WINTERNAL_POOL_TAG_DEFAULT);
    if (!tmp) return luaL_error(L, "wnk.kread: out of memory");
    NTSTATUS s = STATUS_SUCCESS;
    __try { RtlCopyMemory(tmp, addr, n); }
    __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); }
    if (NT_SUCCESS(s)) lua_pushlstring(L, tmp, n);
    ExFreePoolWithTag(tmp, WINTERNAL_POOL_TAG_DEFAULT);
    if (!NT_SUCCESS(s)) return luaL_error(L, "wnk.kread: access violation");
    return 1;
}

static int KluaKwrite(lua_State* L) {
    PVOID addr = (PVOID)(ULONG_PTR)luaL_checkinteger(L, 1);
    size_t n = 0;
    const char* data = luaL_checklstring(L, 2, &n);
    if (n == 0 || n > 1024 * 1024) return luaL_error(L, "wnk.kwrite: bad length");
    if ((ULONG_PTR)addr < 0xFFFF800000000000ULL) return luaL_error(L, "wnk.kwrite: user pointer");
    NTSTATUS s = STATUS_SUCCESS;
    __try { RtlCopyMemory(addr, data, n); }
    __except (EXCEPTION_EXECUTE_HANDLER) { s = GetExceptionCode(); }
    if (!NT_SUCCESS(s)) return luaL_error(L, "wnk.kwrite: access violation");
    return 0;
}

static int KluaKalloc(lua_State* L) {
    size_t n = (size_t)luaL_checkinteger(L, 1);
    int nonPaged = lua_toboolean(L, 2);
    PVOID p = ExAllocatePool2(nonPaged ? POOL_FLAG_NON_PAGED : POOL_FLAG_PAGED,
                              n, WINTERNAL_POOL_TAG_DEFAULT);
    if (!p) return luaL_error(L, "wnk.kalloc: out of memory");
    lua_pushinteger(L, (lua_Integer)(ULONG_PTR)p);
    return 1;
}

static int KluaKfree(lua_State* L) {
    PVOID p = (PVOID)(ULONG_PTR)luaL_checkinteger(L, 1);
    if (!p) return 0;
    __try { ExFreePoolWithTag(p, WINTERNAL_POOL_TAG_DEFAULT); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return luaL_error(L, "wnk.kfree: invalid pointer"); }
    return 0;
}

// Lockdown gate for write-side wnk bindings. Matches the user-mode IOCTL
// dispatcher: once `wnk.lockdown_engage()` (or its IOCTL twin) has run,
// every write/patch primitive refuses with STATUS_ACCESS_DENIED so the
// caller's script can't worsen things after a deliberate freeze. Read-
// only enumerations stay open.
static int KluaLockdownBlock(lua_State* L, const char* op) {
    if (g_Lockdown) return luaL_error(L, "wnk.%s: lockdown engaged", op);
    return 0;
}

// Allocate a kernel scratch buffer + auto-free guard via Lua's userdata gc.
// Easier than maintaining manual free paths through every error edge.
typedef struct { PVOID Buf; } KluaPoolGuard;
static int KluaPoolGuard_gc(lua_State* L) {
    KluaPoolGuard* g = (KluaPoolGuard*)lua_touserdata(L, 1);
    if (g && g->Buf) { ExFreePoolWithTag(g->Buf, WINTERNAL_POOL_TAG_DEFAULT); g->Buf = NULL; }
    return 0;
}
static PVOID KluaAllocScratch(lua_State* L, size_t bytes, BOOLEAN nonPaged) {
    PVOID p = ExAllocatePool2(nonPaged ? POOL_FLAG_NON_PAGED : POOL_FLAG_PAGED,
                              bytes, WINTERNAL_POOL_TAG_DEFAULT);
    if (!p) { luaL_error(L, "wnk: out of pool memory (%zu bytes)", bytes); return NULL; }
    KluaPoolGuard* g = (KluaPoolGuard*)lua_newuserdata(L, sizeof(KluaPoolGuard));
    g->Buf = p;
    if (luaL_newmetatable(L, "Winternal.PoolGuard")) {
        lua_pushcfunction(L, KluaPoolGuard_gc);
        lua_setfield(L, -2, "__gc");
    }
    lua_setmetatable(L, -2);
    return p;
}

// Forward refs for the handlers we'll call (defined earlier in this file).
static NTSTATUS HandleKcall(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleUnprotect(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleKill(PVOID, size_t);
static NTSTATUS HandleProtectLock(PVOID, size_t);
static NTSTATUS HandleProtectUnlock(PVOID, size_t);
static NTSTATUS HandleProtectList(PVOID, size_t, size_t*);
static NTSTATUS HandleSetSigLevel(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleTokenUIAccess(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleKcodePatch(PVOID, size_t);
static NTSTATUS HandleGetTrueStub(PVOID, size_t, size_t*);
static NTSTATUS HandleGetW32Process(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleEnumThreads(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleKMitigations(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleKTokenInfo(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleKMemQuery(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleEnumCallbacks(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleEnumDrivers(PVOID, size_t, size_t*);
static NTSTATUS HandleEnumSsdt(PVOID, size_t, size_t*);
static NTSTATUS HandleKhookInstall(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleKhookUninstall(PVOID, size_t);
static NTSTATUS HandleLockdownEngage(PVOID, size_t, size_t*);
static NTSTATUS HandleLockdownStatus(PVOID, size_t, size_t*);
static NTSTATUS HandleAuditTail(PVOID, size_t, size_t*);
static NTSTATUS HandleNtfsRawRead(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleNtfsVolData(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleNtfsUsnQuery(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleNtfsUsnRead(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleNtfsMftEnum(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleNtfsStreams(PVOID, size_t, PVOID, size_t, size_t*);
static NTSTATUS HandleForceUnload(PVOID, size_t);
static NTSTATUS HandleKdrvRegister(PVOID, size_t);
static NTSTATUS HandleKdrvDeregister(PVOID, size_t);
static NTSTATUS HandleKdrvSetStart(PVOID, size_t);
static NTSTATUS HandleKdrvLoad(PVOID, size_t);
static NTSTATUS HandleKdrvUnload(PVOID, size_t);

static int KluaCheckNt(lua_State* L, const char* op, NTSTATUS s) {
    if (NT_SUCCESS(s)) return 0;
    return luaL_error(L, "wnk.%s: NTSTATUS 0x%X", op, (unsigned)s);
}

// Copy a Lua string into a fixed-width WCHAR buffer for *_NAME_IN / *_IMAGEPATH structs.
static void KluaStringToWide(lua_State* L, int idx, WCHAR* dst, size_t maxChars) {
    size_t n = 0;
    const char* s = luaL_checklstring(L, idx, &n);
    if (n >= maxChars) n = maxChars - 1;
    for (size_t i = 0; i < n; ++i) dst[i] = (WCHAR)(unsigned char)s[i];
    dst[n] = 0;
}

// ---- wnk.kcall(addr, ...) -> (returnValue, faulted) ----
//
// Variadic invoker. The IOCTL twin (HandleKcall) caps at 4 args because of
// the wire struct, but from kernel-Lua we can dispatch through one of N
// fixed-arity function-pointer typedefs and let MSVC emit the proper x64
// calling sequence (RCX/RDX/R8/R9 + shadow space + stack spill for args
// 5+). SEH-wrapped: a target that raises sets `faulted = true` rather
// than bug-checking the dispatch thread.
//
// Args coerce: integers/booleans pass through; Lua strings pass as a
// pointer to their byte data (lifetime: at least the duration of the
// call, since the script holds the reference); nil is 0. For more
// complex argument shapes the caller composes a buffer with `wnk.kalloc`
// + `wnk.kwrite` (or `string.pack` + `wnk.kalloc` round-trip) and passes
// its kernel address.
typedef UINT64 (*Wn_F0 )(void);
typedef UINT64 (*Wn_F1 )(UINT64);
typedef UINT64 (*Wn_F2 )(UINT64,UINT64);
typedef UINT64 (*Wn_F3 )(UINT64,UINT64,UINT64);
typedef UINT64 (*Wn_F4 )(UINT64,UINT64,UINT64,UINT64);
typedef UINT64 (*Wn_F5 )(UINT64,UINT64,UINT64,UINT64,UINT64);
typedef UINT64 (*Wn_F6 )(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64);
typedef UINT64 (*Wn_F7 )(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64);
typedef UINT64 (*Wn_F8 )(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64);
typedef UINT64 (*Wn_F9 )(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64);
typedef UINT64 (*Wn_F10)(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64);
typedef UINT64 (*Wn_F11)(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64);
typedef UINT64 (*Wn_F12)(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,UINT64);

static int KluaKcall(lua_State* L) {
    KluaLockdownBlock(L, "kcall");
    UINT64 addr = (UINT64)luaL_checkinteger(L, 1);
    int n = lua_gettop(L) - 1;
    if (n < 0)  n = 0;
    if (n > 12) return luaL_error(L, "wnk.kcall: max 12 args, got %d", n);
    UINT64 a[12] = {0};
    for (int i = 0; i < n; ++i) {
        int t = lua_type(L, 2 + i);
        switch (t) {
        case LUA_TNUMBER:  a[i] = (UINT64)lua_tointeger(L, 2 + i); break;
        case LUA_TBOOLEAN: a[i] = lua_toboolean(L, 2 + i) ? 1 : 0; break;
        case LUA_TSTRING:  a[i] = (UINT64)(ULONG_PTR)lua_tostring(L, 2 + i); break;
        case LUA_TNIL:     a[i] = 0; break;
        default:
            return luaL_error(L, "wnk.kcall: arg %d has unsupported type %s",
                              i + 1, lua_typename(L, t));
        }
    }
    UINT64 rv = 0;
    int faulted = 0;
    __try {
        switch (n) {
        case 0:  rv = ((Wn_F0 )(ULONG_PTR)addr)(); break;
        case 1:  rv = ((Wn_F1 )(ULONG_PTR)addr)(a[0]); break;
        case 2:  rv = ((Wn_F2 )(ULONG_PTR)addr)(a[0],a[1]); break;
        case 3:  rv = ((Wn_F3 )(ULONG_PTR)addr)(a[0],a[1],a[2]); break;
        case 4:  rv = ((Wn_F4 )(ULONG_PTR)addr)(a[0],a[1],a[2],a[3]); break;
        case 5:  rv = ((Wn_F5 )(ULONG_PTR)addr)(a[0],a[1],a[2],a[3],a[4]); break;
        case 6:  rv = ((Wn_F6 )(ULONG_PTR)addr)(a[0],a[1],a[2],a[3],a[4],a[5]); break;
        case 7:  rv = ((Wn_F7 )(ULONG_PTR)addr)(a[0],a[1],a[2],a[3],a[4],a[5],a[6]); break;
        case 8:  rv = ((Wn_F8 )(ULONG_PTR)addr)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]); break;
        case 9:  rv = ((Wn_F9 )(ULONG_PTR)addr)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8]); break;
        case 10: rv = ((Wn_F10)(ULONG_PTR)addr)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9]); break;
        case 11: rv = ((Wn_F11)(ULONG_PTR)addr)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10]); break;
        case 12: rv = ((Wn_F12)(ULONG_PTR)addr)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11]); break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        faulted = 1;
    }
    lua_pushinteger(L, (lua_Integer)rv);
    lua_pushboolean(L, faulted);
    return 2;
}

// ---- wnk.modksym(moduleName, exportName) -> kernelAddress or nil ----
//
// `wnk.ksym` only resolves ntoskrnl + hal exports (MmGetSystemRoutineAddress).
// For anything else — win32k*, tcpip, ndis, nsi, third-party drivers — we
// walk PsLoadedModuleList via ZwQuerySystemInformation(SystemModuleInformation),
// match the module by basename (case-insensitive), then parse its PE export
// table at runtime. Forwarded exports return nil; resolve through the
// forwarded module yourself if needed.
static PVOID Klua_ResolveExportInModule(PVOID base, const char* name) {
    if (!base) return NULL;
    PVOID result = NULL;
    __try {
        IMAGE_DOS_HEADER* dh = (IMAGE_DOS_HEADER*)base;
        if (dh->e_magic != IMAGE_DOS_SIGNATURE) __leave;
        IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((PUCHAR)base + dh->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) __leave;
        IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!dir->VirtualAddress || dir->Size < sizeof(IMAGE_EXPORT_DIRECTORY)) __leave;
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((PUCHAR)base + dir->VirtualAddress);
        if (!exp->AddressOfNames || !exp->AddressOfNameOrdinals || !exp->AddressOfFunctions) __leave;
        ULONG*  names = (ULONG*) ((PUCHAR)base + exp->AddressOfNames);
        USHORT* ords  = (USHORT*)((PUCHAR)base + exp->AddressOfNameOrdinals);
        ULONG*  funcs = (ULONG*) ((PUCHAR)base + exp->AddressOfFunctions);
        for (ULONG i = 0; i < exp->NumberOfNames; ++i) {
            const char* en = (const char*)((PUCHAR)base + names[i]);
            if (strcmp(en, name) == 0) {
                if (ords[i] >= exp->NumberOfFunctions) __leave;
                ULONG rva = funcs[ords[i]];
                if (!rva) __leave;
                // Skip forwarders (RVA inside the export directory range).
                if (rva >= dir->VirtualAddress && rva < dir->VirtualAddress + dir->Size) __leave;
                result = (PUCHAR)base + rva;
                __leave;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { result = NULL; }
    return result;
}

static int Klua_StrICmpA(const char* a, const char* b) {
    while (*a && *b) {
        int ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return ca - cb;
        ++a; ++b;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static const char* Klua_Basename(const char* path) {
    const char* p = path;
    const char* last = path;
    while (*p) {
        if (*p == '\\' || *p == '/') last = p + 1;
        ++p;
    }
    return last;
}

static int KluaModKsym(lua_State* L) {
    const char* modName = luaL_checkstring(L, 1);
    const char* fnName  = luaL_checkstring(L, 2);
    PRTL_PROCESS_MODULES mods = QueryAllModules();
    if (!mods) { lua_pushnil(L); return 1; }
    PVOID resolved = NULL;
    for (ULONG i = 0; i < mods->NumberOfModules; ++i) {
        const char* bn = Klua_Basename((const char*)mods->Modules[i].FullPathName);
        if (Klua_StrICmpA(bn, modName) == 0) {
            resolved = Klua_ResolveExportInModule(mods->Modules[i].ImageBase, fnName);
            if (resolved) break;
            // module matched but symbol missing — keep looking in case
            // there are multiple modules with the same basename (rare).
        }
    }
    ExFreePoolWithTag(mods, WINTERNAL_POOL_TAG_DEFAULT);
    if (!resolved) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)(ULONG_PTR)resolved);
    return 1;
}

// ---- wnk.module(name) -> { base, size } or nil ----
//
// Returns the load base + image size of any kernel module by basename
// (case-insensitive). Useful for bounding a signature scan to a single
// module's address range.
static int KluaModule(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    PRTL_PROCESS_MODULES mods = QueryAllModules();
    if (!mods) { lua_pushnil(L); return 1; }
    PVOID base = NULL;
    UINT32 size = 0;
    for (ULONG i = 0; i < mods->NumberOfModules; ++i) {
        const char* bn = Klua_Basename((const char*)mods->Modules[i].FullPathName);
        if (Klua_StrICmpA(bn, name) == 0) {
            base = mods->Modules[i].ImageBase;
            size = mods->Modules[i].ImageSize;
            break;
        }
    }
    ExFreePoolWithTag(mods, WINTERNAL_POOL_TAG_DEFAULT);
    if (!base) { lua_pushnil(L); return 1; }
    lua_createtable(L, 0, 2);
    lua_pushinteger(L, (lua_Integer)(ULONG_PTR)base); lua_setfield(L, -2, "base");
    lua_pushinteger(L, size);                          lua_setfield(L, -2, "size");
    return 1;
}

// ---- wnk.scan(addr, length, pattern) -> address or nil ----
//
// Byte-pattern scan for finding unexported routines, globals, references
// — the standard kernel-research move when `ksym` / `modksym` come up
// empty. `pattern` is an IDA-style string: `"48 89 5C 24 ? ? 57"` —
// hex pairs separated by whitespace, `?` (or `??`) for wildcards. Max
// pattern length 256 bytes. SEH-wrapped: a partial/torn page mid-scan
// returns nil rather than bug-checking.
static int Klua_NybbleHex(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int KluaScan(lua_State* L) {
    PVOID base   = (PVOID)(ULONG_PTR)luaL_checkinteger(L, 1);
    size_t len   = (size_t)luaL_checkinteger(L, 2);
    const char* pat = luaL_checkstring(L, 3);
    if ((ULONG_PTR)base < 0xFFFF800000000000ULL)
        return luaL_error(L, "wnk.scan: user pointer");
    if (len == 0 || len > 0x4000000)   // 64 MiB cap
        return luaL_error(L, "wnk.scan: bad length");

    UCHAR bytes[256] = {0};
    UCHAR mask [256] = {0};
    int np = 0;
    const char* p = pat;
    while (*p && np < 256) {
        while (*p == ' ' || *p == '\t' || *p == ',') ++p;
        if (!*p) break;
        if (*p == '?') {
            bytes[np] = 0; mask[np] = 0;
            ++p; if (*p == '?') ++p;
        } else {
            int hi = Klua_NybbleHex(*p++);
            int lo = (*p && *p != ' ' && *p != '\t') ? Klua_NybbleHex(*p++) : hi;
            if (hi < 0 || lo < 0) return luaL_error(L, "wnk.scan: bad hex at byte %d", np);
            // If only one nibble was present (single hex digit), treat lo
            // as the actual digit and hi as 0.
            if (lo == hi && (*p == 0 || *p == ' ')) { bytes[np] = (UCHAR)hi; }
            else                                    { bytes[np] = (UCHAR)((hi << 4) | lo); }
            mask[np] = 0xFF;
        }
        ++np;
    }
    if (np == 0) return luaL_error(L, "wnk.scan: empty pattern");

    PVOID found = NULL;
    __try {
        const UCHAR* b = (const UCHAR*)base;
        for (size_t i = 0; i + (size_t)np <= len; ++i) {
            int j = 0;
            for (; j < np; ++j) {
                if (mask[j] == 0) continue;
                if (b[i + j] != bytes[j]) break;
            }
            if (j == np) { found = (PVOID)(b + i); break; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { found = NULL; }

    if (!found) { lua_pushnil(L); return 1; }
    lua_pushinteger(L, (lua_Integer)(ULONG_PTR)found);
    return 1;
}

// ---- wnk.kreadstr(addr [, maxLen=4096]) -> string ----
//
// Read a NUL-terminated ASCII string from kernel memory, capped at
// `maxLen` bytes (default 4 KiB). Useful for return-value strings from
// kernel APIs that hand back a `const char*`. SEH-wrapped.
static int KluaKreadStr(lua_State* L) {
    PVOID addr = (PVOID)(ULONG_PTR)luaL_checkinteger(L, 1);
    size_t maxLen = (size_t)luaL_optinteger(L, 2, 4096);
    if (maxLen == 0 || maxLen > 1024 * 1024) return luaL_error(L, "wnk.kreadstr: bad length");
    if ((ULONG_PTR)addr < 0xFFFF800000000000ULL) return luaL_error(L, "wnk.kreadstr: user pointer");
    char* tmp = (char*)ExAllocatePool2(POOL_FLAG_PAGED, maxLen + 1, WINTERNAL_POOL_TAG_DEFAULT);
    if (!tmp) return luaL_error(L, "wnk.kreadstr: out of memory");
    size_t n = 0;
    __try {
        const char* p = (const char*)addr;
        for (; n < maxLen; ++n) {
            char c = p[n];
            tmp[n] = c;
            if (!c) break;
        }
        tmp[n] = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(tmp, WINTERNAL_POOL_TAG_DEFAULT);
        return luaL_error(L, "wnk.kreadstr: access violation");
    }
    lua_pushlstring(L, tmp, n);
    ExFreePoolWithTag(tmp, WINTERNAL_POOL_TAG_DEFAULT);
    return 1;
}

// ---- wnk.unprotect(pid [, newValue [, fieldOffset]]) -> (prev, offsetUsed) ----
static int KluaUnprotect(lua_State* L) {
    KluaLockdownBlock(L, "unprotect");
    WINTERNAL_UNPROTECT_IN  in  = {0};
    WINTERNAL_UNPROTECT_OUT out = {0};
    in.Pid         = (UINT32)luaL_checkinteger(L, 1);
    in.NewValue    = (UINT8)luaL_optinteger(L, 2, 0);
    in.FieldOffset = (UINT32)luaL_optinteger(L, 3, 0);
    size_t w = 0;
    NTSTATUS s = HandleUnprotect(&in, sizeof(in), &out, sizeof(out), &w);
    KluaCheckNt(L, "unprotect", s);
    lua_pushinteger(L, out.PrevValue);
    lua_pushinteger(L, out.FieldOffsetUsed);
    return 2;
}

// ---- wnk.kill(pid [, exitStatus]) ----
static int KluaKill(lua_State* L) {
    KluaLockdownBlock(L, "kill");
    WINTERNAL_KILL_IN in = { (UINT32)luaL_checkinteger(L, 1),
                             (UINT32)luaL_optinteger(L, 2, 1) };
    KluaCheckNt(L, "kill", HandleKill(&in, sizeof(in)));
    return 0;
}

// ---- wnk.protect_lock(pid) ----
static int KluaProtectLock(lua_State* L) {
    KluaLockdownBlock(L, "protect_lock");
    WINTERNAL_PROTECT_LOCK_IN in = { (UINT32)luaL_checkinteger(L, 1), 0 };
    KluaCheckNt(L, "protect_lock", HandleProtectLock(&in, sizeof(in)));
    return 0;
}

// ---- wnk.protect_unlock(pid) ----
static int KluaProtectUnlock(lua_State* L) {
    KluaLockdownBlock(L, "protect_unlock");
    WINTERNAL_PROTECT_LOCK_IN in = { (UINT32)luaL_checkinteger(L, 1), 0 };
    KluaCheckNt(L, "protect_unlock", HandleProtectUnlock(&in, sizeof(in)));
    return 0;
}

// ---- wnk.protect_list() -> { pid, pid, ... } ----
static int KluaProtectList(lua_State* L) {
    WINTERNAL_PROTECT_LIST_OUT out = {0};
    size_t w = 0;
    KluaCheckNt(L, "protect_list", HandleProtectList(&out, sizeof(out), &w));
    lua_createtable(L, (int)out.Count, 0);
    for (UINT32 i = 0; i < out.Count; ++i) {
        lua_pushinteger(L, out.Pids[i]);
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

// ---- wnk.set_siglevel(pid, sigLevel, sectionSigLevel [, fieldOffset]) -> (prevSig, prevSection) ----
static int KluaSetSigLevel(lua_State* L) {
    KluaLockdownBlock(L, "set_siglevel");
    WINTERNAL_SIGLEVEL_IN  in  = {0};
    WINTERNAL_SIGLEVEL_OUT out = {0};
    in.Pid                   = (UINT32)luaL_checkinteger(L, 1);
    in.SignatureLevel        = (UINT8)luaL_checkinteger(L, 2);
    in.SectionSignatureLevel = (UINT8)luaL_checkinteger(L, 3);
    in.FieldOffset           = (UINT32)luaL_optinteger(L, 4, 0);
    size_t w = 0;
    KluaCheckNt(L, "set_siglevel", HandleSetSigLevel(&in, sizeof(in), &out, sizeof(out), &w));
    lua_pushinteger(L, out.PrevSignatureLevel);
    lua_pushinteger(L, out.PrevSectionSignatureLevel);
    return 2;
}

// ---- wnk.token_uiaccess(pid, enable [, fieldOffset]) -> (prevFlags, newFlags) ----
static int KluaTokenUIAccess(lua_State* L) {
    KluaLockdownBlock(L, "token_uiaccess");
    WINTERNAL_TOKEN_UIACCESS_IN  in  = {0};
    WINTERNAL_TOKEN_UIACCESS_OUT out = {0};
    in.Pid         = (UINT32)luaL_checkinteger(L, 1);
    in.Enable      = lua_toboolean(L, 2) ? 1 : 0;
    in.FieldOffset = (UINT32)luaL_optinteger(L, 3, 0);
    size_t w = 0;
    KluaCheckNt(L, "token_uiaccess", HandleTokenUIAccess(&in, sizeof(in), &out, sizeof(out), &w));
    lua_pushinteger(L, out.PrevFlags);
    lua_pushinteger(L, out.NewFlags);
    return 2;
}

// ---- wnk.kcode_patch(addr, bytes) ----
static int KluaKcodePatch(lua_State* L) {
    KluaLockdownBlock(L, "kcode_patch");
    WINTERNAL_KCODE_PATCH_IN in = {0};
    in.Address = (UINT64)luaL_checkinteger(L, 1);
    size_t n = 0;
    const char* data = luaL_checklstring(L, 2, &n);
    if (n == 0 || n > WINTERNAL_KCODE_PATCH_MAX)
        return luaL_error(L, "wnk.kcode_patch: bad length (1..%u)", WINTERNAL_KCODE_PATCH_MAX);
    in.Length = (UINT32)n;
    RtlCopyMemory(in.Data, data, n);
    KluaCheckNt(L, "kcode_patch", HandleKcodePatch(&in, sizeof(in)));
    return 0;
}

// ---- wnk.get_true_stub() -> addr ----
static int KluaGetTrueStub(lua_State* L) {
    WINTERNAL_GET_TRUE_STUB_OUT out = {0};
    size_t w = 0;
    KluaCheckNt(L, "get_true_stub", HandleGetTrueStub(&out, sizeof(out), &w));
    lua_pushinteger(L, (lua_Integer)out.Address);
    return 1;
}

// ---- wnk.get_w32proc(pid) -> addr (0 if none) ----
static int KluaGetW32Proc(lua_State* L) {
    WINTERNAL_GET_W32PROC_IN  in  = { (UINT32)luaL_checkinteger(L, 1), 0 };
    WINTERNAL_GET_W32PROC_OUT out = {0};
    size_t w = 0;
    KluaCheckNt(L, "get_w32proc", HandleGetW32Process(&in, sizeof(in), &out, sizeof(out), &w));
    lua_pushinteger(L, (lua_Integer)out.Address);
    return 1;
}

// ---- wnk.threads(pid) -> array of thread tables ----
static int KluaThreads(lua_State* L) {
    WINTERNAL_PID_IN in = { (UINT32)luaL_checkinteger(L, 1), 0 };
    size_t cap = FIELD_OFFSET(WINTERNAL_THREADS_OUT, Entries)
               + WINTERNAL_MAX_THREADS_PER_PROC * sizeof(WINTERNAL_THREAD_ENTRY);
    PWINTERNAL_THREADS_OUT out = (PWINTERNAL_THREADS_OUT)KluaAllocScratch(L, cap, FALSE);
    int guardIdx = lua_gettop(L);
    size_t w = 0;
    KluaCheckNt(L, "threads", HandleEnumThreads(&in, sizeof(in), out, cap, &w));
    lua_createtable(L, (int)out->Count, 0);
    int tableIdx = lua_gettop(L);
    for (UINT32 i = 0; i < out->Count; ++i) {
        PWINTERNAL_THREAD_ENTRY e = &out->Entries[i];
        lua_createtable(L, 0, 8);
        lua_pushinteger(L, e->Tid);             lua_setfield(L, -2, "tid");
        lua_pushinteger(L, e->State);           lua_setfield(L, -2, "state");
        lua_pushinteger(L, e->WaitReason);      lua_setfield(L, -2, "waitReason");
        lua_pushinteger(L, e->Priority);        lua_setfield(L, -2, "priority");
        lua_pushinteger(L, (lua_Integer)e->StartAddress);    lua_setfield(L, -2, "startAddress");
        lua_pushinteger(L, (lua_Integer)e->KernelTime100Ns); lua_setfield(L, -2, "kernelTime100Ns");
        lua_pushinteger(L, (lua_Integer)e->UserTime100Ns);   lua_setfield(L, -2, "userTime100Ns");
        lua_pushinteger(L, (lua_Integer)e->CreateTimeFt);    lua_setfield(L, -2, "createTimeFt");
        lua_rawseti(L, tableIdx, (lua_Integer)(i + 1));
    }
    // Stack: [..., guard, table]. Move table below guard so the gc fires
    // when guard goes out of scope after we return.
    lua_remove(L, guardIdx);
    return 1;
}

// ---- wnk.mitigations(pid) -> array of {policyId, status, value} ----
static int KluaMitigations(lua_State* L) {
    WINTERNAL_PID_IN in = { (UINT32)luaL_checkinteger(L, 1), 0 };
    WINTERNAL_MITIGATIONS_OUT out = {0};
    size_t w = 0;
    KluaCheckNt(L, "mitigations", HandleKMitigations(&in, sizeof(in), &out, sizeof(out), &w));
    lua_createtable(L, (int)out.Count, 0);
    for (UINT32 i = 0; i < out.Count; ++i) {
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, out.Items[i].PolicyId); lua_setfield(L, -2, "policyId");
        lua_pushinteger(L, out.Items[i].NtStatus); lua_setfield(L, -2, "ntStatus");
        lua_pushinteger(L, (lua_Integer)out.Items[i].Value); lua_setfield(L, -2, "value");
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    return 1;
}

// ---- wnk.token_info(pid) -> table ----
static int KluaTokenInfo(lua_State* L) {
    WINTERNAL_PID_IN in = { (UINT32)luaL_checkinteger(L, 1), 0 };
    WINTERNAL_TOKEN_INFO_OUT out = {0};
    size_t w = 0;
    KluaCheckNt(L, "token_info", HandleKTokenInfo(&in, sizeof(in), &out, sizeof(out), &w));
    lua_createtable(L, 0, 8);
    lua_pushlstring(L, (const char*)out.UserSid,      sizeof(out.UserSid));      lua_setfield(L, -2, "userSid");
    lua_pushlstring(L, (const char*)out.IntegritySid, sizeof(out.IntegritySid)); lua_setfield(L, -2, "integritySid");
    lua_pushinteger(L, out.IntegrityRid);   lua_setfield(L, -2, "integrityRid");
    lua_pushinteger(L, out.ElevationType);  lua_setfield(L, -2, "elevationType");
    lua_pushboolean(L, out.Elevated ? 1 : 0); lua_setfield(L, -2, "elevated");
    lua_pushboolean(L, out.UIAccess ? 1 : 0); lua_setfield(L, -2, "uiAccess");
    lua_pushinteger(L, out.SessionId);      lua_setfield(L, -2, "sessionId");
    lua_createtable(L, (int)out.PrivCount, 0);
    for (UINT32 i = 0; i < out.PrivCount; ++i) {
        lua_createtable(L, 0, 2);
        lua_pushinteger(L, (lua_Integer)out.Privileges[i].Luid);     lua_setfield(L, -2, "luid");
        lua_pushinteger(L, out.Privileges[i].Attributes);            lua_setfield(L, -2, "attributes");
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    lua_setfield(L, -2, "privileges");
    return 1;
}

// ---- wnk.mem_query(pid) -> (regions, truncated) ----
static int KluaMemQuery(lua_State* L) {
    WINTERNAL_PID_IN in = { (UINT32)luaL_checkinteger(L, 1), 0 };
    size_t cap = FIELD_OFFSET(WINTERNAL_MEM_QUERY_OUT, Entries)
               + WINTERNAL_MAX_MEM_REGIONS * sizeof(WINTERNAL_MEM_REGION);
    PWINTERNAL_MEM_QUERY_OUT out = (PWINTERNAL_MEM_QUERY_OUT)KluaAllocScratch(L, cap, FALSE);
    int guardIdx = lua_gettop(L);
    size_t w = 0;
    KluaCheckNt(L, "mem_query", HandleKMemQuery(&in, sizeof(in), out, cap, &w));
    lua_createtable(L, (int)out->Count, 0);
    int tableIdx = lua_gettop(L);
    for (UINT32 i = 0; i < out->Count; ++i) {
        PWINTERNAL_MEM_REGION r = &out->Entries[i];
        lua_createtable(L, 0, 5);
        lua_pushinteger(L, (lua_Integer)r->BaseAddress); lua_setfield(L, -2, "baseAddress");
        lua_pushinteger(L, (lua_Integer)r->RegionSize);  lua_setfield(L, -2, "regionSize");
        lua_pushinteger(L, r->State);                    lua_setfield(L, -2, "state");
        lua_pushinteger(L, r->Protect);                  lua_setfield(L, -2, "protect");
        lua_pushinteger(L, r->Type);                     lua_setfield(L, -2, "type");
        lua_rawseti(L, tableIdx, (lua_Integer)(i + 1));
    }
    lua_pushboolean(L, out->Truncated ? 1 : 0);
    // [..., guard, table, truncated] -> drop guard
    lua_remove(L, guardIdx);
    return 2;
}

// ---- wnk.callbacks(kind) -> array; kind: "process"|"image"|"thread" or 1|2|3 ----
static int KluaCallbacks(lua_State* L) {
    WINTERNAL_CB_IN in = {0};
    if (lua_isstring(L, 1)) {
        const char* k = lua_tostring(L, 1);
        if      (!strcmp(k, "process")) in.Kind = WINTERNAL_CB_KIND_PROCESS;
        else if (!strcmp(k, "image"))   in.Kind = WINTERNAL_CB_KIND_IMAGE;
        else if (!strcmp(k, "thread"))  in.Kind = WINTERNAL_CB_KIND_THREAD;
        else return luaL_error(L, "wnk.callbacks: bad kind %s", k);
    } else {
        in.Kind = (UINT32)luaL_checkinteger(L, 1);
    }
    // PsSetCreateProcessNotifyRoutineEx supports 64 slots historically; use
    // a generous 256-entry buffer to cover image/thread arrays as well.
    size_t cap = FIELD_OFFSET(WINTERNAL_CB_LIST, Entries) + 256 * sizeof(WINTERNAL_CB_ENTRY);
    PWINTERNAL_CB_LIST out = (PWINTERNAL_CB_LIST)KluaAllocScratch(L, cap, FALSE);
    int guardIdx = lua_gettop(L);
    size_t w = 0;
    KluaCheckNt(L, "callbacks", HandleEnumCallbacks(&in, sizeof(in), out, cap, &w));
    lua_createtable(L, (int)out->Count, 0);
    int tableIdx = lua_gettop(L);
    for (UINT32 i = 0; i < out->Count; ++i) {
        PWINTERNAL_CB_ENTRY e = &out->Entries[i];
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, (lua_Integer)e->Routine);    lua_setfield(L, -2, "routine");
        lua_pushinteger(L, (lua_Integer)e->ModuleBase); lua_setfield(L, -2, "moduleBase");
        lua_pushstring(L, e->ModuleName);               lua_setfield(L, -2, "moduleName");
        lua_rawseti(L, tableIdx, (lua_Integer)(i + 1));
    }
    lua_remove(L, guardIdx);
    return 1;
}

// ---- wnk.kdrivers() -> array of {imageBase, imageSize, name} ----
static int KluaKdriversBinding(lua_State* L) {
    size_t cap = FIELD_OFFSET(WINTERNAL_DRIVER_LIST, Entries) + 512 * sizeof(WINTERNAL_DRIVER_ENTRY);
    PWINTERNAL_DRIVER_LIST out = (PWINTERNAL_DRIVER_LIST)KluaAllocScratch(L, cap, FALSE);
    int guardIdx = lua_gettop(L);
    size_t w = 0;
    KluaCheckNt(L, "kdrivers", HandleEnumDrivers(out, cap, &w));
    lua_createtable(L, (int)out->Count, 0);
    int tableIdx = lua_gettop(L);
    for (UINT32 i = 0; i < out->Count; ++i) {
        PWINTERNAL_DRIVER_ENTRY e = &out->Entries[i];
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, (lua_Integer)e->ImageBase); lua_setfield(L, -2, "imageBase");
        lua_pushinteger(L, e->ImageSize);              lua_setfield(L, -2, "imageSize");
        lua_pushstring(L, e->Name);                    lua_setfield(L, -2, "name");
        lua_rawseti(L, tableIdx, (lua_Integer)(i + 1));
    }
    lua_remove(L, guardIdx);
    return 1;
}

// ---- wnk.ssdt() -> table with .base + .entries ----
static int KluaSsdtBinding(lua_State* L) {
    // KiServiceTable has ~500 entries on modern Windows; 2048 is generous.
    size_t cap = FIELD_OFFSET(WINTERNAL_SSDT_LIST, Entries) + 2048 * sizeof(WINTERNAL_SSDT_ENTRY);
    PWINTERNAL_SSDT_LIST out = (PWINTERNAL_SSDT_LIST)KluaAllocScratch(L, cap, FALSE);
    int guardIdx = lua_gettop(L);
    size_t w = 0;
    KluaCheckNt(L, "ssdt", HandleEnumSsdt(out, cap, &w));
    lua_createtable(L, 0, 2);
    lua_pushinteger(L, out->Base); lua_setfield(L, -2, "base");
    lua_createtable(L, (int)out->Count, 0);
    for (UINT32 i = 0; i < out->Count; ++i) {
        PWINTERNAL_SSDT_ENTRY e = &out->Entries[i];
        lua_createtable(L, 0, 4);
        lua_pushinteger(L, e->Index);                  lua_setfield(L, -2, "index");
        lua_pushinteger(L, (lua_Integer)e->Routine);   lua_setfield(L, -2, "routine");
        lua_pushinteger(L, (lua_Integer)e->ModuleBase);lua_setfield(L, -2, "moduleBase");
        lua_pushstring(L, e->ModuleName);              lua_setfield(L, -2, "moduleName");
        lua_rawseti(L, -2, (lua_Integer)(i + 1));
    }
    lua_setfield(L, -2, "entries");
    lua_remove(L, guardIdx);
    return 1;
}

// ---- wnk.khook(target, detour [, prologue]) -> trampoline addr ----
static int KluaKhookBinding(lua_State* L) {
    KluaLockdownBlock(L, "khook");
    WINTERNAL_KHOOK_INSTALL_IN  in  = {0};
    WINTERNAL_KHOOK_INSTALL_OUT out = {0};
    in.Target       = (UINT64)luaL_checkinteger(L, 1);
    in.Detour       = (UINT64)luaL_checkinteger(L, 2);
    in.PrologueSize = (UINT32)luaL_optinteger(L, 3, 16);
    size_t w = 0;
    KluaCheckNt(L, "khook", HandleKhookInstall(&in, sizeof(in), &out, sizeof(out), &w));
    lua_pushinteger(L, (lua_Integer)out.Trampoline);
    return 1;
}

// ---- wnk.kunhook(target) ----
static int KluaKunhookBinding(lua_State* L) {
    KluaLockdownBlock(L, "kunhook");
    WINTERNAL_KHOOK_UNINSTALL_IN in = { (UINT64)luaL_checkinteger(L, 1) };
    KluaCheckNt(L, "kunhook", HandleKhookUninstall(&in, sizeof(in)));
    return 0;
}

// ---- wnk.kunhook_all() ----
static int KluaKunhookAllBinding(lua_State* L) {
    KluaLockdownBlock(L, "kunhook_all");
    WinternalKhookUninstallAll();
    return 0;
}

// ---- wnk.lockdown_engage() -> {engaged, engagedTickMs} ----
static int KluaLockdownEngageBinding(lua_State* L) {
    WINTERNAL_LOCKDOWN_OUT out = {0};
    size_t w = 0;
    KluaCheckNt(L, "lockdown_engage", HandleLockdownEngage(&out, sizeof(out), &w));
    lua_createtable(L, 0, 2);
    lua_pushboolean(L, out.Engaged ? 1 : 0); lua_setfield(L, -2, "engaged");
    lua_pushinteger(L, out.EngagedTickMs);   lua_setfield(L, -2, "engagedTickMs");
    return 1;
}

// ---- wnk.lockdown_status() -> {engaged, engagedTickMs} ----
static int KluaLockdownStatusBinding(lua_State* L) {
    WINTERNAL_LOCKDOWN_OUT out = {0};
    size_t w = 0;
    KluaCheckNt(L, "lockdown_status", HandleLockdownStatus(&out, sizeof(out), &w));
    lua_createtable(L, 0, 2);
    lua_pushboolean(L, out.Engaged ? 1 : 0); lua_setfield(L, -2, "engaged");
    lua_pushinteger(L, out.EngagedTickMs);   lua_setfield(L, -2, "engagedTickMs");
    return 1;
}

// ---- wnk.audit_tail([maxRows]) -> array of {timestampNs, ioctl, pid, target, length, status} ----
static int KluaAuditTailBinding(lua_State* L) {
    UINT32 maxRows = (UINT32)luaL_optinteger(L, 1, 256);
    if (maxRows > 1024) maxRows = 1024;
    size_t cap = FIELD_OFFSET(WINTERNAL_AUDIT_OUT, Rows) + (size_t)maxRows * sizeof(WINTERNAL_AUDIT_ROW);
    PWINTERNAL_AUDIT_OUT out = (PWINTERNAL_AUDIT_OUT)KluaAllocScratch(L, cap, FALSE);
    int guardIdx = lua_gettop(L);
    size_t w = 0;
    KluaCheckNt(L, "audit_tail", HandleAuditTail(out, cap, &w));
    lua_createtable(L, (int)out->RowCount, 0);
    int tableIdx = lua_gettop(L);
    for (UINT32 i = 0; i < out->RowCount; ++i) {
        PWINTERNAL_AUDIT_ROW r = &out->Rows[i];
        lua_createtable(L, 0, 6);
        lua_pushinteger(L, (lua_Integer)r->TimestampNs);  lua_setfield(L, -2, "timestampNs");
        lua_pushinteger(L, r->IoControlCode);             lua_setfield(L, -2, "ioctl");
        lua_pushinteger(L, r->CallerPid);                 lua_setfield(L, -2, "pid");
        lua_pushinteger(L, (lua_Integer)r->Target);       lua_setfield(L, -2, "target");
        lua_pushinteger(L, r->Length);                    lua_setfield(L, -2, "length");
        lua_pushinteger(L, r->Status);                    lua_setfield(L, -2, "status");
        lua_rawseti(L, tableIdx, (lua_Integer)(i + 1));
    }
    lua_remove(L, guardIdx);
    return 1;
}

// ---- wnk.force_unload(name) ----
static int KluaForceUnloadBinding(lua_State* L) {
    KluaLockdownBlock(L, "force_unload");
    WINTERNAL_FORCE_UNLOAD_IN in = {0};
    KluaStringToWide(L, 1, in.Name, WINTERNAL_DRIVER_NAME_MAX);
    KluaCheckNt(L, "force_unload", HandleForceUnload(&in, sizeof(in)));
    return 0;
}

// ---- wnk.kdrv_register(name, ntImagePath [, startType=3]) ----
static int KluaKdrvRegisterBinding(lua_State* L) {
    KluaLockdownBlock(L, "kdrv_register");
    WINTERNAL_KDRV_REGISTER_IN in = {0};
    KluaStringToWide(L, 1, in.Name, WINTERNAL_DRIVER_NAME_MAX);
    KluaStringToWide(L, 2, in.ImagePath, WINTERNAL_DRIVER_PATH_MAX);
    in.StartType = (UINT32)luaL_optinteger(L, 3, 3);
    KluaCheckNt(L, "kdrv_register", HandleKdrvRegister(&in, sizeof(in)));
    return 0;
}

static int KluaKdrvNameOpBinding_(lua_State* L, const char* op, NTSTATUS (*fn)(PVOID, size_t)) {
    KluaLockdownBlock(L, op);
    WINTERNAL_KDRV_NAME_IN in = {0};
    KluaStringToWide(L, 1, in.Name, WINTERNAL_DRIVER_NAME_MAX);
    KluaCheckNt(L, op, fn(&in, sizeof(in)));
    return 0;
}
static int KluaKdrvLoadBinding(lua_State* L)       { return KluaKdrvNameOpBinding_(L, "kdrv_load",       HandleKdrvLoad); }
static int KluaKdrvUnloadBinding(lua_State* L)     { return KluaKdrvNameOpBinding_(L, "kdrv_unload",     HandleKdrvUnload); }
static int KluaKdrvDeregisterBinding(lua_State* L) { return KluaKdrvNameOpBinding_(L, "kdrv_deregister", HandleKdrvDeregister); }

// ---- wnk.ntfs_raw_read(device, offset, length) -> bytes or nil ----
//
// Raw bytes from a device object — typically `\Device\HarddiskVolume3`
// for a volume, or `\Device\PhysicalDriveN` for a whole disk. PreviousMode
// = Kernel, so the read bypasses every minifilter / hook above NTFS in
// the device stack. Capped at WINTERNAL_NTFS_RAW_MAX (1 MiB) per call.
static int KluaNtfsRawRead(lua_State* L) {
    WINTERNAL_NTFS_RAW_READ_IN in = {0};
    KluaStringToWide(L, 1, in.Device, WINTERNAL_NTFS_DEV_NAME_MAX);
    in.Offset = (UINT64)luaL_checkinteger(L, 2);
    in.Length = (UINT32)luaL_checkinteger(L, 3);
    if (in.Length == 0 || in.Length > WINTERNAL_NTFS_RAW_MAX)
        return luaL_error(L, "wnk.ntfs_raw_read: bad length (1..%u)", WINTERNAL_NTFS_RAW_MAX);

    PVOID outBuf = ExAllocatePool2(POOL_FLAG_PAGED, in.Length, WINTERNAL_POOL_TAG_DEFAULT);
    if (!outBuf) return luaL_error(L, "wnk.ntfs_raw_read: out of pool memory");
    size_t got = 0;
    NTSTATUS s = HandleNtfsRawRead(&in, sizeof(in), outBuf, in.Length, &got);
    if (!NT_SUCCESS(s)) {
        ExFreePoolWithTag(outBuf, WINTERNAL_POOL_TAG_DEFAULT);
        return luaL_error(L, "wnk.ntfs_raw_read: NTSTATUS 0x%X", (unsigned)s);
    }
    lua_pushlstring(L, (const char*)outBuf, got);
    ExFreePoolWithTag(outBuf, WINTERNAL_POOL_TAG_DEFAULT);
    return 1;
}

// ---- wnk.ntfs_usn_query(device) -> table ----
static int KluaNtfsUsnQuery(lua_State* L) {
    WINTERNAL_NTFS_DEVICE_IN in = {0};
    KluaStringToWide(L, 1, in.Device, WINTERNAL_NTFS_DEV_NAME_MAX);
    WINTERNAL_NTFS_USN_JOURNAL_OUT out = {0};
    size_t w = 0;
    KluaCheckNt(L, "ntfs_usn_query", HandleNtfsUsnQuery(&in, sizeof(in), &out, sizeof(out), &w));
    lua_createtable(L, 0, 7);
    lua_pushinteger(L, (lua_Integer)out.JournalId);       lua_setfield(L, -2, "journalId");
    lua_pushinteger(L, (lua_Integer)out.FirstUsn);        lua_setfield(L, -2, "firstUsn");
    lua_pushinteger(L, (lua_Integer)out.NextUsn);         lua_setfield(L, -2, "nextUsn");
    lua_pushinteger(L, (lua_Integer)out.LowestValidUsn);  lua_setfield(L, -2, "lowestValidUsn");
    lua_pushinteger(L, (lua_Integer)out.MaxUsn);          lua_setfield(L, -2, "maxUsn");
    lua_pushinteger(L, (lua_Integer)out.MaxSize);         lua_setfield(L, -2, "maxSize");
    lua_pushinteger(L, (lua_Integer)out.AllocationDelta); lua_setfield(L, -2, "allocationDelta");
    return 1;
}

// ---- wnk.ntfs_usn_read(device, journalId, startUsn, reasonMask, waitForFresh) -> raw blob ----
static int KluaNtfsUsnRead(lua_State* L) {
    WINTERNAL_NTFS_USN_READ_IN in = {0};
    KluaStringToWide(L, 1, in.Device, WINTERNAL_NTFS_DEV_NAME_MAX);
    in.JournalId    = (UINT64)luaL_checkinteger(L, 2);
    in.StartUsn     = (INT64) luaL_checkinteger(L, 3);
    in.ReasonMask   = (UINT32)luaL_optinteger(L, 4, 0xFFFFFFFF);
    in.WaitForFresh = lua_toboolean(L, 5) ? 1 : 0;
    PVOID outBuf = ExAllocatePool2(POOL_FLAG_PAGED, WINTERNAL_NTFS_USN_BUF, WINTERNAL_POOL_TAG_DEFAULT);
    if (!outBuf) return luaL_error(L, "wnk.ntfs_usn_read: out of pool memory");
    size_t got = 0;
    NTSTATUS s = HandleNtfsUsnRead(&in, sizeof(in), outBuf, WINTERNAL_NTFS_USN_BUF, &got);
    if (!NT_SUCCESS(s)) { ExFreePoolWithTag(outBuf, WINTERNAL_POOL_TAG_DEFAULT);
        return luaL_error(L, "wnk.ntfs_usn_read: NTSTATUS 0x%X", (unsigned)s); }
    lua_pushlstring(L, (const char*)outBuf, got);
    ExFreePoolWithTag(outBuf, WINTERNAL_POOL_TAG_DEFAULT);
    return 1;
}

// ---- wnk.ntfs_mft_enum(device, startFrn) -> raw blob ----
static int KluaNtfsMftEnum(lua_State* L) {
    WINTERNAL_NTFS_MFT_ENUM_IN in = {0};
    KluaStringToWide(L, 1, in.Device, WINTERNAL_NTFS_DEV_NAME_MAX);
    in.StartFrn = (UINT64)luaL_optinteger(L, 2, 0);
    PVOID outBuf = ExAllocatePool2(POOL_FLAG_PAGED, WINTERNAL_NTFS_USN_BUF, WINTERNAL_POOL_TAG_DEFAULT);
    if (!outBuf) return luaL_error(L, "wnk.ntfs_mft_enum: out of pool memory");
    size_t got = 0;
    NTSTATUS s = HandleNtfsMftEnum(&in, sizeof(in), outBuf, WINTERNAL_NTFS_USN_BUF, &got);
    if (!NT_SUCCESS(s)) { ExFreePoolWithTag(outBuf, WINTERNAL_POOL_TAG_DEFAULT);
        return luaL_error(L, "wnk.ntfs_mft_enum: NTSTATUS 0x%X", (unsigned)s); }
    lua_pushlstring(L, (const char*)outBuf, got);
    ExFreePoolWithTag(outBuf, WINTERNAL_POOL_TAG_DEFAULT);
    return 1;
}

// ---- wnk.ntfs_streams(ntPath) -> raw FILE_STREAM_INFORMATION blob ----
static int KluaNtfsStreams(lua_State* L) {
    WINTERNAL_NTFS_STREAMS_IN in = {0};
    KluaStringToWide(L, 1, in.Path, WINTERNAL_NTFS_PATH_MAX);
    PVOID outBuf = ExAllocatePool2(POOL_FLAG_PAGED, 64 * 1024, WINTERNAL_POOL_TAG_DEFAULT);
    if (!outBuf) return luaL_error(L, "wnk.ntfs_streams: out of pool memory");
    size_t got = 0;
    NTSTATUS s = HandleNtfsStreams(&in, sizeof(in), outBuf, 64 * 1024, &got);
    if (!NT_SUCCESS(s)) { ExFreePoolWithTag(outBuf, WINTERNAL_POOL_TAG_DEFAULT);
        return luaL_error(L, "wnk.ntfs_streams: NTSTATUS 0x%X", (unsigned)s); }
    lua_pushlstring(L, (const char*)outBuf, got);
    ExFreePoolWithTag(outBuf, WINTERNAL_POOL_TAG_DEFAULT);
    return 1;
}

// ---- wnk.kdrv_set_start(name, startType) ----
static int KluaKdrvSetStartBinding(lua_State* L) {
    KluaLockdownBlock(L, "kdrv_set_start");
    WINTERNAL_KDRV_SET_START_IN in = {0};
    KluaStringToWide(L, 1, in.Name, WINTERNAL_DRIVER_NAME_MAX);
    in.StartType = (UINT32)luaL_checkinteger(L, 2);
    KluaCheckNt(L, "kdrv_set_start", HandleKdrvSetStart(&in, sizeof(in)));
    return 0;
}

static int KluaPids(lua_State* L) {
    lua_newtable(L);
    int idx = 0;
    for (UINT32 pid = 4; pid < 0x10000; pid += 4) {
        PEPROCESS proc = NULL;
        if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc))) continue;
        UCHAR* image = PsGetProcessImageFileName(proc);
        char name[16] = {0};
        if (image) { RtlCopyMemory(name, image, 15); name[15] = 0; }
        HANDLE parent = PsGetProcessInheritedFromUniqueProcessId(proc);
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, pid); lua_setfield(L, -2, "pid");
        lua_pushinteger(L, (lua_Integer)(ULONG_PTR)parent); lua_setfield(L, -2, "ppid");
        lua_pushstring(L, name); lua_setfield(L, -2, "name");
        lua_rawseti(L, -2, ++idx);
        ObDereferenceObject(proc);
    }
    return 1;
}

void KluaRegisterWnk(lua_State* L) {
    static const luaL_Reg lib[] = {
        // basics
        {"print",            KluaPrint},
        {"ksym",             KluaKsym},
        {"modksym",          KluaModKsym},
        {"module",           KluaModule},
        {"scan",             KluaScan},
        {"kread",            KluaKread},
        {"kreadstr",         KluaKreadStr},
        {"kwrite",           KluaKwrite},
        {"kalloc",           KluaKalloc},
        {"kfree",            KluaKfree},
        {"pids",             KluaPids},
        // kernel-side function call + EPROCESS field tools
        {"kcall",            KluaKcall},
        {"unprotect",        KluaUnprotect},
        {"kill",             KluaKill},
        {"protect_lock",     KluaProtectLock},
        {"protect_unlock",   KluaProtectUnlock},
        {"protect_list",     KluaProtectList},
        {"set_siglevel",     KluaSetSigLevel},
        {"token_uiaccess",   KluaTokenUIAccess},
        {"kcode_patch",      KluaKcodePatch},
        {"get_true_stub",    KluaGetTrueStub},
        {"get_w32proc",      KluaGetW32Proc},
        // kernel-side process inspection
        {"threads",          KluaThreads},
        {"mitigations",      KluaMitigations},
        {"token_info",       KluaTokenInfo},
        {"mem_query",        KluaMemQuery},
        // rootkit detection
        {"callbacks",        KluaCallbacks},
        {"kdrivers",         KluaKdriversBinding},
        {"ssdt",             KluaSsdtBinding},
        // kernel inline hooks
        {"khook",            KluaKhookBinding},
        {"kunhook",          KluaKunhookBinding},
        {"kunhook_all",      KluaKunhookAllBinding},
        // lockdown / audit
        {"lockdown_engage",  KluaLockdownEngageBinding},
        {"lockdown_status",  KluaLockdownStatusBinding},
        {"audit_tail",       KluaAuditTailBinding},
        // ntfs / raw disk
        {"ntfs_raw_read",    KluaNtfsRawRead},
        {"ntfs_usn_query",   KluaNtfsUsnQuery},
        {"ntfs_usn_read",    KluaNtfsUsnRead},
        {"ntfs_mft_enum",    KluaNtfsMftEnum},
        {"ntfs_streams",     KluaNtfsStreams},
        // driver lifecycle
        {"force_unload",     KluaForceUnloadBinding},
        {"kdrv_register",    KluaKdrvRegisterBinding},
        {"kdrv_load",        KluaKdrvLoadBinding},
        {"kdrv_unload",      KluaKdrvUnloadBinding},
        {"kdrv_deregister",  KluaKdrvDeregisterBinding},
        {"kdrv_set_start",   KluaKdrvSetStartBinding},
        {NULL, NULL},
    };
    lua_newtable(L);
    luaL_setfuncs(L, lib, 0);
    lua_setglobal(L, "wnk");
    // Also expose wnk.print as global print so naive scripts work.
    lua_getglobal(L, "wnk");
    lua_getfield(L, -1, "print");
    lua_setglobal(L, "print");
    lua_pop(L, 1);
}

// -----------------------------------------------------------------------------
// IOCTL handler
// -----------------------------------------------------------------------------

static NTSTATUS HandleLuaExec(PVOID InBuf, size_t InLen, PVOID OutBuf, size_t OutLen, size_t* BytesWritten)
{
    if (InLen < FIELD_OFFSET(WINTERNAL_LUA_IN, Script) ||
        OutLen < FIELD_OFFSET(WINTERNAL_LUA_OUT, Output))
        return STATUS_BUFFER_TOO_SMALL;

    PWINTERNAL_LUA_IN  in  = (PWINTERNAL_LUA_IN)InBuf;
    PWINTERNAL_LUA_OUT out = (PWINTERNAL_LUA_OUT)OutBuf;

    if (in->ScriptLength == 0 || in->ScriptLength > WINTERNAL_LUA_MAX_SCRIPT)
        return STATUS_INVALID_PARAMETER;
    if (InLen < FIELD_OFFSET(WINTERNAL_LUA_IN, Script) + in->ScriptLength)
        return STATUS_BUFFER_TOO_SMALL;

    SIZE_T outCap = OutLen - FIELD_OFFSET(WINTERNAL_LUA_OUT, Output);
    SIZE_T outWritten = 0;
    INT32  luaStatus = 0;
    NTSTATUS s = KluaExec(in->Script, in->ScriptLength,
                          (char*)out->Output, outCap,
                          &outWritten, &luaStatus);
    out->LuaStatus = luaStatus;
    out->OutputLength = (UINT32)outWritten;
    *BytesWritten = FIELD_OFFSET(WINTERNAL_LUA_OUT, Output) + outWritten;
    return s;
}

static NTSTATUS HandleLockdownEngage(PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (OutLen < sizeof(WINTERNAL_LOCKDOWN_OUT)) return STATUS_BUFFER_TOO_SMALL;
    if (InterlockedCompareExchange(&g_Lockdown, 1, 0) == 0) {
        LARGE_INTEGER now;
        KeQueryTickCount(&now);
        g_LockdownAtMs = ((UINT64)now.QuadPart * KeQueryTimeIncrement()) / 10000ULL;
    }
    PWINTERNAL_LOCKDOWN_OUT o = (PWINTERNAL_LOCKDOWN_OUT)OutBuf;
    o->Engaged = 1;
    o->EngagedTickMs = (UINT32)g_LockdownAtMs;
    *Written = sizeof(*o);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleLockdownStatus(PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (OutLen < sizeof(WINTERNAL_LOCKDOWN_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_LOCKDOWN_OUT o = (PWINTERNAL_LOCKDOWN_OUT)OutBuf;
    o->Engaged = (UINT32)g_Lockdown;
    o->EngagedTickMs = (UINT32)g_LockdownAtMs;
    *Written = sizeof(*o);
    return STATUS_SUCCESS;
}

//
// Force-unload another kernel driver by name. Steps:
//   1. Sanitize the caller-supplied name (refuse "..", path separators,
//      empty strings) so we only resolve a leaf `\Driver\<name>`.
//   2. ObReferenceObjectByName under IoDriverObjectType.
//   3. If the target DRIVER_OBJECT has a DriverUnload, invoke it under SEH
//      so a misbehaving target doesn't bug-check the queue thread.
//   4. ObDereferenceObject and report.
//
// The image stays mapped in kernel memory until the system frees it; this
// path just runs the target's cleanup routine. We never NULL-deref if the
// target has no DriverUnload (legacy or PnP drivers without one).
//
static NTSTATUS HandleForceUnload(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_FORCE_UNLOAD_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_FORCE_UNLOAD_IN in = (PWINTERNAL_FORCE_UNLOAD_IN)InBuf;
    in->Name[WINTERNAL_DRIVER_NAME_MAX - 1] = 0;  // force-terminate

    // Refuse names with separators or empty. The kernel resolves
    // unqualified names under \Driver\ which is what we want; anything
    // else risks pointing at the wrong object namespace.
    for (ULONG i = 0; in->Name[i]; ++i) {
        if (in->Name[i] == L'\\' || in->Name[i] == L'/' || in->Name[i] == L'.') {
            return STATUS_INVALID_PARAMETER;
        }
    }
    if (in->Name[0] == 0) return STATUS_INVALID_PARAMETER;

    // Refuse to unload OURSELVES. The driver's own service name is
    // "Winternal" (case-insensitive); calling DriverUnload from within
    // our own dispatch path would explode.
    if (_wcsicmp(in->Name, L"Winternal") == 0) return STATUS_NOT_SUPPORTED;

    WCHAR fullBuf[WINTERNAL_DRIVER_NAME_MAX + 8];
    NTSTATUS s = RtlStringCchPrintfW(fullBuf, RTL_NUMBER_OF(fullBuf), L"\\Driver\\%ws", in->Name);
    if (!NT_SUCCESS(s)) return s;

    UNICODE_STRING fullName;
    RtlInitUnicodeString(&fullName, fullBuf);

    PDRIVER_OBJECT drv = NULL;
    s = ObReferenceObjectByName(&fullName, OBJ_CASE_INSENSITIVE, NULL,
                                0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&drv);
    if (!NT_SUCCESS(s)) return s;

    NTSTATUS unloadStatus = STATUS_SUCCESS;
    PDRIVER_UNLOAD unload = drv->DriverUnload;
    if (!unload) {
        unloadStatus = STATUS_NOT_SUPPORTED;
    } else {
        __try {
            unload(drv);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            unloadStatus = GetExceptionCode();
        }
    }

    ObDereferenceObject(drv);
    return unloadStatus;
}

// Build "\Registry\Machine\System\CurrentControlSet\Services\<name>" into
// caller-provided buffer. Returns the UNICODE_STRING ready to pass to
// ZwLoadDriver / ZwUnloadDriver.
static NTSTATUS KdrvBuildServicePath(
    _In_  PCWSTR Name,
    _Out_writes_(BufChars) PWCHAR Buf,
    _In_  ULONG  BufChars,
    _Out_ PUNICODE_STRING Out)
{
    NTSTATUS s = RtlStringCchPrintfW(Buf, BufChars,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%ws", Name);
    if (!NT_SUCCESS(s)) return s;
    RtlInitUnicodeString(Out, Buf);
    return STATUS_SUCCESS;
}

// Refuse names with separators, ".." traversal, or empty. The kernel
// resolves names verbatim under \Services\, so a name like "..\..\foo"
// would escape the services namespace.
static BOOLEAN KdrvNameOK(PCWSTR n)
{
    if (!n || !n[0]) return FALSE;
    for (ULONG i = 0; n[i]; ++i) {
        if (n[i] == L'\\' || n[i] == L'/' || n[i] == L'.') return FALSE;
    }
    return TRUE;
}

// Refuse to mess with ourselves so a buggy script can't yank Winternal.
static BOOLEAN KdrvIsSelf(PCWSTR n) { return _wcsicmp(n, L"Winternal") == 0; }

static NTSTATUS HandleKdrvRegister(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_KDRV_REGISTER_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KDRV_REGISTER_IN in = (PWINTERNAL_KDRV_REGISTER_IN)InBuf;
    in->Name[WINTERNAL_DRIVER_NAME_MAX - 1] = 0;
    in->ImagePath[WINTERNAL_DRIVER_PATH_MAX - 1] = 0;

    if (!KdrvNameOK(in->Name) || KdrvIsSelf(in->Name)) return STATUS_INVALID_PARAMETER;
    if (in->ImagePath[0] == 0) return STATUS_INVALID_PARAMETER;
    if (in->StartType > 4) return STATUS_INVALID_PARAMETER;

    WCHAR keyPathBuf[300];
    UNICODE_STRING keyPath;
    NTSTATUS s = KdrvBuildServicePath(in->Name, keyPathBuf, RTL_NUMBER_OF(keyPathBuf), &keyPath);
    if (!NT_SUCCESS(s)) return s;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE key = NULL;
    ULONG disposition = 0;
    s = ZwCreateKey(&key, KEY_ALL_ACCESS, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
    if (!NT_SUCCESS(s)) return s;

    // Type = 1 (SERVICE_KERNEL_DRIVER), Start = in->StartType,
    // ErrorControl = 1 (NORMAL), ImagePath, DisplayName (= service name).
    ULONG dword;
    DECLARE_CONST_UNICODE_STRING(vType,          L"Type");
    DECLARE_CONST_UNICODE_STRING(vStart,         L"Start");
    DECLARE_CONST_UNICODE_STRING(vErrorControl,  L"ErrorControl");
    DECLARE_CONST_UNICODE_STRING(vImagePath,     L"ImagePath");
    DECLARE_CONST_UNICODE_STRING(vDisplayName,   L"DisplayName");

    dword = 1; ZwSetValueKey(key, (PUNICODE_STRING)&vType, 0, REG_DWORD, &dword, sizeof(dword));
    dword = in->StartType; ZwSetValueKey(key, (PUNICODE_STRING)&vStart, 0, REG_DWORD, &dword, sizeof(dword));
    dword = 1; ZwSetValueKey(key, (PUNICODE_STRING)&vErrorControl, 0, REG_DWORD, &dword, sizeof(dword));

    UNICODE_STRING imagePath;
    RtlInitUnicodeString(&imagePath, in->ImagePath);
    ZwSetValueKey(key, (PUNICODE_STRING)&vImagePath, 0, REG_EXPAND_SZ,
                  imagePath.Buffer, imagePath.Length + sizeof(WCHAR));

    UNICODE_STRING dispName;
    RtlInitUnicodeString(&dispName, in->Name);
    ZwSetValueKey(key, (PUNICODE_STRING)&vDisplayName, 0, REG_SZ,
                  dispName.Buffer, dispName.Length + sizeof(WCHAR));

    ZwClose(key);
    return STATUS_SUCCESS;
}

static NTSTATUS HandleKdrvDeregister(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_KDRV_NAME_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KDRV_NAME_IN in = (PWINTERNAL_KDRV_NAME_IN)InBuf;
    in->Name[WINTERNAL_DRIVER_NAME_MAX - 1] = 0;
    if (!KdrvNameOK(in->Name) || KdrvIsSelf(in->Name)) return STATUS_INVALID_PARAMETER;

    WCHAR keyPathBuf[300];
    UNICODE_STRING keyPath;
    NTSTATUS s = KdrvBuildServicePath(in->Name, keyPathBuf, RTL_NUMBER_OF(keyPathBuf), &keyPath);
    if (!NT_SUCCESS(s)) return s;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE key = NULL;
    s = ZwOpenKey(&key, DELETE, &oa);
    if (!NT_SUCCESS(s)) return s;
    s = ZwDeleteKey(key);
    ZwClose(key);
    return s;
}

static NTSTATUS HandleKdrvSetStart(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_KDRV_SET_START_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KDRV_SET_START_IN in = (PWINTERNAL_KDRV_SET_START_IN)InBuf;
    in->Name[WINTERNAL_DRIVER_NAME_MAX - 1] = 0;
    if (!KdrvNameOK(in->Name) || KdrvIsSelf(in->Name)) return STATUS_INVALID_PARAMETER;
    if (in->StartType > 4) return STATUS_INVALID_PARAMETER;

    WCHAR keyPathBuf[300];
    UNICODE_STRING keyPath;
    NTSTATUS s = KdrvBuildServicePath(in->Name, keyPathBuf, RTL_NUMBER_OF(keyPathBuf), &keyPath);
    if (!NT_SUCCESS(s)) return s;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE key = NULL;
    s = ZwOpenKey(&key, KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(s)) return s;

    DECLARE_CONST_UNICODE_STRING(vStart, L"Start");
    ULONG dword = in->StartType;
    s = ZwSetValueKey(key, (PUNICODE_STRING)&vStart, 0, REG_DWORD, &dword, sizeof(dword));
    ZwClose(key);
    return s;
}

static NTSTATUS HandleKdrvLoad(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_KDRV_NAME_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KDRV_NAME_IN in = (PWINTERNAL_KDRV_NAME_IN)InBuf;
    in->Name[WINTERNAL_DRIVER_NAME_MAX - 1] = 0;
    if (!KdrvNameOK(in->Name) || KdrvIsSelf(in->Name)) return STATUS_INVALID_PARAMETER;

    WCHAR svcPathBuf[300];
    UNICODE_STRING svcPath;
    NTSTATUS s = KdrvBuildServicePath(in->Name, svcPathBuf, RTL_NUMBER_OF(svcPathBuf), &svcPath);
    if (!NT_SUCCESS(s)) return s;

    return ZwLoadDriver(&svcPath);
}

static NTSTATUS HandleKdrvUnload(PVOID InBuf, size_t InLen)
{
    if (InLen < sizeof(WINTERNAL_KDRV_NAME_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_KDRV_NAME_IN in = (PWINTERNAL_KDRV_NAME_IN)InBuf;
    in->Name[WINTERNAL_DRIVER_NAME_MAX - 1] = 0;
    if (!KdrvNameOK(in->Name) || KdrvIsSelf(in->Name)) return STATUS_INVALID_PARAMETER;

    WCHAR svcPathBuf[300];
    UNICODE_STRING svcPath;
    NTSTATUS s = KdrvBuildServicePath(in->Name, svcPathBuf, RTL_NUMBER_OF(svcPathBuf), &svcPath);
    if (!NT_SUCCESS(s)) return s;

    return ZwUnloadDriver(&svcPath);
}

// FSCTL codes + ZwFsControlFile prototype declared locally so we don't
// pull in <ntifs.h> (which conflicts with the KMDF includes the rest of
// this driver already pulls in via driver.h). The numeric codes match
// ntifs.h byte-for-byte; see WDK ntifs.h or MS-FSA reference for the
// authoritative definitions.
#ifndef FSCTL_GET_NTFS_VOLUME_DATA
#define FSCTL_GET_NTFS_VOLUME_DATA  CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 25, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_QUERY_USN_JOURNAL
#define FSCTL_QUERY_USN_JOURNAL     CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 61, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_READ_USN_JOURNAL
#define FSCTL_READ_USN_JOURNAL      CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 46, METHOD_NEITHER,  FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_ENUM_USN_DATA
#define FSCTL_ENUM_USN_DATA         CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 44, METHOD_NEITHER,  FILE_ANY_ACCESS)
#endif

NTSYSAPI NTSTATUS NTAPI ZwFsControlFile(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode,
    PVOID InputBuffer, ULONG InputBufferLength,
    PVOID OutputBuffer, ULONG OutputBufferLength);

// Open a kernel device or NTFS path with PreviousMode = Kernel + the
// OBJ_KERNEL_HANDLE flag (so it never appears in a user handle table).
// Used by every NTFS handler below; the kernel-side open is what makes
// the subsequent FSCTL/Read bypass per-process / per-mode minifilters.
static NTSTATUS NtfsOpenK(PCWSTR name, ACCESS_MASK access, BOOLEAN forCreate, HANDLE* outH)
{
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, name);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    IO_STATUS_BLOCK iosb;
    return ZwCreateFile(outH, access | SYNCHRONIZE, &oa, &iosb, NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        forCreate ? FILE_OPEN_IF : FILE_OPEN,
                        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

// Helper: clamp + NUL-terminate a fixed WCHAR buffer in place.
static void NtfsClampWcs(WCHAR* p, size_t maxChars) {
    p[maxChars - 1] = 0;
}

// Raw read from a device object (volume, physical disk, etc.). The
// driver opens the named device with FILE_READ_DATA and reads at the
// caller-supplied offset, bypassing every filter above NTFS in the
// device stack — useful for parsing on-disk structures (MFT, $LogFile,
// boot sector) without trusting anything user-mode-hookable.
static NTSTATUS HandleNtfsRawRead(PVOID InBuf, size_t InLen,
                                  PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen  < sizeof(WINTERNAL_NTFS_RAW_READ_IN)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_NTFS_RAW_READ_IN in = (PWINTERNAL_NTFS_RAW_READ_IN)InBuf;
    if (in->Length == 0 || in->Length > WINTERNAL_NTFS_RAW_MAX) return STATUS_INVALID_PARAMETER;
    if (OutLen < in->Length) return STATUS_BUFFER_TOO_SMALL;

    // Guarantee NUL-terminated device name (within the fixed buffer).
    WCHAR devName[WINTERNAL_NTFS_DEV_NAME_MAX + 1];
    RtlZeroMemory(devName, sizeof(devName));
    RtlCopyMemory(devName, in->Device, sizeof(in->Device));

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, devName);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE h = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS s = ZwCreateFile(&h, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(s)) return s;

    LARGE_INTEGER off;
    off.QuadPart = (LONGLONG)in->Offset;
    RtlZeroMemory(&iosb, sizeof(iosb));
    s = ZwReadFile(h, NULL, NULL, NULL, &iosb, OutBuf, in->Length, &off, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(s)) return s;
    *Written = iosb.Information;
    return STATUS_SUCCESS;
}

// ---- FSCTL_GET_NTFS_VOLUME_DATA ----
static NTSTATUS HandleNtfsVolData(PVOID InBuf, size_t InLen,
                                  PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen  < sizeof(WINTERNAL_NTFS_DEVICE_IN))    return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(WINTERNAL_NTFS_VOL_DATA_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_NTFS_DEVICE_IN in = (PWINTERNAL_NTFS_DEVICE_IN)InBuf;
    NtfsClampWcs(in->Device, WINTERNAL_NTFS_DEV_NAME_MAX);

    HANDLE h = NULL;
    NTSTATUS s = NtfsOpenK(in->Device, FILE_READ_DATA, FALSE, &h);
    if (!NT_SUCCESS(s)) return s;

    IO_STATUS_BLOCK iosb = {0};
    s = ZwFsControlFile(h, NULL, NULL, NULL, &iosb,
                        FSCTL_GET_NTFS_VOLUME_DATA, NULL, 0, OutBuf,
                        (ULONG)OutLen);
    ZwClose(h);
    if (!NT_SUCCESS(s)) return s;
    *Written = iosb.Information ? iosb.Information : sizeof(WINTERNAL_NTFS_VOL_DATA_OUT);
    return STATUS_SUCCESS;
}

// ---- FSCTL_QUERY_USN_JOURNAL ----
static NTSTATUS HandleNtfsUsnQuery(PVOID InBuf, size_t InLen,
                                   PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen  < sizeof(WINTERNAL_NTFS_DEVICE_IN))     return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(WINTERNAL_NTFS_USN_JOURNAL_OUT)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_NTFS_DEVICE_IN  in  = (PWINTERNAL_NTFS_DEVICE_IN)InBuf;
    PWINTERNAL_NTFS_USN_JOURNAL_OUT out = (PWINTERNAL_NTFS_USN_JOURNAL_OUT)OutBuf;
    NtfsClampWcs(in->Device, WINTERNAL_NTFS_DEV_NAME_MAX);

    HANDLE h = NULL;
    NTSTATUS s = NtfsOpenK(in->Device, FILE_READ_DATA, FALSE, &h);
    if (!NT_SUCCESS(s)) return s;

    // The kernel returns USN_JOURNAL_DATA_V2 (about 80 bytes); allocate
    // generously so newer Windows versions with V3 don't truncate.
    UCHAR jd[256] = {0};
    IO_STATUS_BLOCK iosb = {0};
    s = ZwFsControlFile(h, NULL, NULL, NULL, &iosb,
                        FSCTL_QUERY_USN_JOURNAL, NULL, 0, jd, sizeof(jd));
    ZwClose(h);
    if (!NT_SUCCESS(s)) return s;

    // V2 layout (compatible with V1 prefix). Cast at fixed offsets so we
    // don't pull in the ntifs.h struct definitions here.
    RtlCopyMemory(&out->JournalId,       jd + 0x00, sizeof(UINT64));
    RtlCopyMemory(&out->FirstUsn,        jd + 0x08, sizeof(INT64));
    RtlCopyMemory(&out->NextUsn,         jd + 0x10, sizeof(INT64));
    RtlCopyMemory(&out->LowestValidUsn,  jd + 0x18, sizeof(INT64));
    RtlCopyMemory(&out->MaxUsn,          jd + 0x20, sizeof(INT64));
    RtlCopyMemory(&out->MaxSize,         jd + 0x28, sizeof(UINT64));
    RtlCopyMemory(&out->AllocationDelta, jd + 0x30, sizeof(UINT64));
    *Written = sizeof(*out);
    return STATUS_SUCCESS;
}

// Kernel-side layout of READ_USN_JOURNAL_DATA_V1 (96 bytes).
typedef struct {
    INT64  StartUsn;
    UINT32 ReasonMask;
    UINT32 ReturnOnlyOnClose;
    UINT64 Timeout;
    UINT64 BytesToWaitFor;
    UINT64 UsnJournalID;
    UINT16 MinMajorVersion;
    UINT16 MaxMajorVersion;
    UINT8  _pad[8];
} READ_USN_V1_LOCAL;

// ---- FSCTL_READ_USN_JOURNAL ----
static NTSTATUS HandleNtfsUsnRead(PVOID InBuf, size_t InLen,
                                  PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen  < sizeof(WINTERNAL_NTFS_USN_READ_IN)) return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < 8)                                   return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_NTFS_USN_READ_IN in = (PWINTERNAL_NTFS_USN_READ_IN)InBuf;
    NtfsClampWcs(in->Device, WINTERNAL_NTFS_DEV_NAME_MAX);

    HANDLE h = NULL;
    NTSTATUS s = NtfsOpenK(in->Device, FILE_READ_DATA, FALSE, &h);
    if (!NT_SUCCESS(s)) return s;

    READ_USN_V1_LOCAL req = {0};
    req.StartUsn        = in->StartUsn;
    req.ReasonMask      = in->ReasonMask ? in->ReasonMask : 0xFFFFFFFF;
    req.BytesToWaitFor  = in->WaitForFresh ? 1 : 0;
    req.UsnJournalID    = in->JournalId;
    req.MinMajorVersion = 2;
    req.MaxMajorVersion = 2;

    IO_STATUS_BLOCK iosb = {0};
    s = ZwFsControlFile(h, NULL, NULL, NULL, &iosb,
                        FSCTL_READ_USN_JOURNAL, &req, sizeof(req),
                        OutBuf, (ULONG)OutLen);
    ZwClose(h);
    if (!NT_SUCCESS(s)) return s;
    *Written = iosb.Information;
    return STATUS_SUCCESS;
}

// Kernel-side layout of MFT_ENUM_DATA_V0 (24 bytes).
typedef struct {
    UINT64 StartFileReferenceNumber;
    INT64  LowUsn;
    INT64  HighUsn;
} MFT_ENUM_V0_LOCAL;

// ---- FSCTL_ENUM_USN_DATA ----
static NTSTATUS HandleNtfsMftEnum(PVOID InBuf, size_t InLen,
                                  PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen  < sizeof(WINTERNAL_NTFS_MFT_ENUM_IN)) return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < 8)                                   return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_NTFS_MFT_ENUM_IN in = (PWINTERNAL_NTFS_MFT_ENUM_IN)InBuf;
    NtfsClampWcs(in->Device, WINTERNAL_NTFS_DEV_NAME_MAX);

    HANDLE h = NULL;
    NTSTATUS s = NtfsOpenK(in->Device, FILE_READ_DATA, FALSE, &h);
    if (!NT_SUCCESS(s)) return s;

    MFT_ENUM_V0_LOCAL req = {0};
    req.StartFileReferenceNumber = in->StartFrn;
    req.LowUsn  = 0;
    req.HighUsn = MAXLONGLONG;

    IO_STATUS_BLOCK iosb = {0};
    s = ZwFsControlFile(h, NULL, NULL, NULL, &iosb,
                        FSCTL_ENUM_USN_DATA, &req, sizeof(req),
                        OutBuf, (ULONG)OutLen);
    ZwClose(h);
    if (!NT_SUCCESS(s)) return s;
    *Written = iosb.Information;
    return STATUS_SUCCESS;
}

// ---- FileStreamInformation ----
// Returns the kernel's packed FILE_STREAM_INFORMATION records as a blob.
// FileStreamInformation = 22.
#define WN_FILE_STREAM_INFORMATION 22

static NTSTATUS HandleNtfsStreams(PVOID InBuf, size_t InLen,
                                  PVOID OutBuf, size_t OutLen, size_t* Written)
{
    if (InLen < sizeof(WINTERNAL_NTFS_STREAMS_IN)) return STATUS_BUFFER_TOO_SMALL;
    if (OutLen < sizeof(ULONG)) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_NTFS_STREAMS_IN in = (PWINTERNAL_NTFS_STREAMS_IN)InBuf;
    NtfsClampWcs(in->Path, WINTERNAL_NTFS_PATH_MAX);

    HANDLE h = NULL;
    NTSTATUS s = NtfsOpenK(in->Path, FILE_READ_ATTRIBUTES, FALSE, &h);
    if (!NT_SUCCESS(s)) return s;

    IO_STATUS_BLOCK iosb = {0};
    s = ZwQueryInformationFile(h, &iosb, OutBuf, (ULONG)OutLen,
                               (FILE_INFORMATION_CLASS)WN_FILE_STREAM_INFORMATION);
    ZwClose(h);
    if (!NT_SUCCESS(s)) return s;
    *Written = iosb.Information;
    return STATUS_SUCCESS;
}

static NTSTATUS HandleAuditTail(PVOID OutBuf, size_t OutLen, size_t* Written)
{
    size_t header = FIELD_OFFSET(WINTERNAL_AUDIT_OUT, Rows);
    if (OutLen < header) return STATUS_BUFFER_TOO_SMALL;
    PWINTERNAL_AUDIT_OUT out = (PWINTERNAL_AUDIT_OUT)OutBuf;
    size_t maxRows = (OutLen - header) / sizeof(WINTERNAL_AUDIT_ROW);

    LONG total = g_AuditCount;
    LONG available = total < WINTERNAL_AUDIT_MAX_ROWS ? total : WINTERNAL_AUDIT_MAX_ROWS;
    UINT32 toReturn = (UINT32)((size_t)available < maxRows ? available : maxRows);

    // Copy out the most recent `toReturn` rows in chronological order.
    LONG head = g_AuditHead;
    for (UINT32 i = 0; i < toReturn; ++i) {
        LONG src = ((head - toReturn + (LONG)i) % WINTERNAL_AUDIT_MAX_ROWS + WINTERNAL_AUDIT_MAX_ROWS) % WINTERNAL_AUDIT_MAX_ROWS;
        out->Rows[i] = g_AuditRing[src];
    }
    out->RowCount = toReturn;
    out->Reserved = 0;
    *Written = header + (size_t)toReturn * sizeof(WINTERNAL_AUDIT_ROW);
    return STATUS_SUCCESS;
}

// -----------------------------------------------------------------------------
// Dispatch
// -----------------------------------------------------------------------------

VOID
WinternalEvtDriverUnload(
    _In_ WDFDRIVER Driver
    )
{
    UNREFERENCED_PARAMETER(Driver);
    PAGED_CODE();

    // Tell the dispatcher to refuse new work and wait for in-flight handlers
    // to leave. Order matters: set the flag first (with a barrier) so any
    // thread that already incremented the in-flight counter observes it on
    // the way back out and signals us if it's the last one to leave.
    InterlockedExchange(&g_UnloadStarted, 1);
    KeMemoryBarrier();

    // Wait for in-flight IOCTLs to drain, but with a hard ceiling so a
    // wedged handler (LUA_EXEC stuck in a tight loop, an Ob-callback hook
    // that hung inside KeIpiGenericCall, etc.) doesn't make `sc stop`
    // un-completable. After the timeout we proceed with teardown anyway —
    // the wedged caller's request will never complete, but the driver
    // gets to unload so the operator can reboot/reinstall.
    if (g_DrainInitialized && g_InFlightIoctls > 0) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -((LONGLONG)10 * 1000 * 10000);   // 10 seconds
        (void)KeWaitForSingleObject(&g_DrainEvent, Executive, KernelMode, FALSE, &timeout);
    }

    // Hooks installed by Winternal must be removed before our image leaves
    // memory — otherwise the trampolines would jump into freed pool.
    WinternalKhookUninstallAll();

    // Ob callbacks (if any were registered for force-protect) — leaving
    // these registered after our image unmaps would crash the next caller
    // who opens a process handle. WinternalProtectUnregister also pulls
    // our inline hook off ObUnRegisterCallbacks before calling it.
    WinternalProtectUnregister();
}

NTSTATUS
WinternalQueueInitialize(
    _In_ WDFDEVICE Device
    )
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;

    PAGED_CODE();

    // One-time init for the unload-drain event. NotificationEvent so every
    // waiter (we only ever have one — the unload thread) sees the signal.
    if (!g_DrainInitialized) {
        KeInitializeEvent(&g_DrainEvent, NotificationEvent, FALSE);
        g_DrainInitialized = TRUE;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
         &queueConfig,
        WdfIoQueueDispatchParallel
        );

    queueConfig.EvtIoDeviceControl = WinternalEvtIoDeviceControl;
    queueConfig.EvtIoStop = WinternalEvtIoStop;

    status = WdfIoQueueCreate(
                 Device,
                 &queueConfig,
                 WDF_NO_OBJECT_ATTRIBUTES,
                 &queue
                 );

    if(!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfIoQueueCreate failed %!STATUS!", status);
        return status;
    }

    return status;
}

//
// Outermost dispatcher. Every handler is also SEH-wrapped internally, but we
// catch any escape here too so a bug in our own code (or in a kernel routine
// invoked via KCALL) fails the IOCTL rather than bug-checking the queue
// thread. The system can still crash if the misbehaving target was holding a
// spinlock or running above PASSIVE_LEVEL when it faulted — SEH won't save us
// from that — but it removes the most common foot-guns.
//
static NTSTATUS DispatchIoctl(ULONG Code, PVOID InBuf, size_t InLen,
                              PVOID OutBuf, size_t OutLen, size_t* BytesWritten)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    *BytesWritten = 0;

    switch (Code) {
    case IOCTL_WINTERNAL_GET_VERSION: {
        if (OutLen < sizeof(WINTERNAL_VERSION)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        PWINTERNAL_VERSION ver = (PWINTERNAL_VERSION)OutBuf;
        ver->Major = WINTERNAL_DRIVER_VERSION_MAJOR;
        ver->Minor = WINTERNAL_DRIVER_VERSION_MINOR;
        ver->BuildTime = 0;
        ver->Reserved = 0;
        *BytesWritten = sizeof(*ver);
        status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_WINTERNAL_ENUM_PIDS:
        status = WinternalEnumProcessIds(OutBuf, OutLen, BytesWritten);
        break;

    case IOCTL_WINTERNAL_KMEM_READ:
        status = HandleKmemRead(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_KMEM_WRITE:
        status = HandleKmemWrite(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_KSYM:
        status = HandleKsym(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_KALLOC:
        status = HandleKalloc(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_KFREE:
        status = HandleKfree(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_KCALL:
        status = HandleKcall(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;

    case IOCTL_WINTERNAL_UNPROTECT_PROCESS:
        status = HandleUnprotect(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_KILL_PROCESS:
        status = HandleKill(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_PROTECT_LOCK:
        status = HandleProtectLock(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_PROTECT_UNLOCK:
        status = HandleProtectUnlock(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_PROTECT_LIST:
        status = HandleProtectList(OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_TOKEN_UIACCESS:
        status = HandleTokenUIAccess(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_SET_SIGLEVEL:
        status = HandleSetSigLevel(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_KCODE_PATCH:
        status = HandleKcodePatch(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_GET_TRUE_STUB:
        status = HandleGetTrueStub(OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_GET_W32PROC:
        status = HandleGetW32Process(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_ENUM_THREADS:
        status = HandleEnumThreads(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_K_MITIGATIONS:
        status = HandleKMitigations(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_K_TOKEN_INFO:
        status = HandleKTokenInfo(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_K_MEM_QUERY:
        status = HandleKMemQuery(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;

    case IOCTL_WINTERNAL_ENUM_CALLBACKS:
        status = HandleEnumCallbacks(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_ENUM_DRIVERS:
        status = HandleEnumDrivers(OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_ENUM_SSDT:
        status = HandleEnumSsdt(OutBuf, OutLen, BytesWritten);
        break;

    case IOCTL_WINTERNAL_KHOOK_INSTALL:
        status = HandleKhookInstall(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_KHOOK_UNINSTALL:
        status = HandleKhookUninstall(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_KHOOK_UNINSTALL_ALL:
        WinternalKhookUninstallAll();
        status = STATUS_SUCCESS;
        break;

    case IOCTL_WINTERNAL_LUA_EXEC:
        status = HandleLuaExec(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;

    case IOCTL_WINTERNAL_LOCKDOWN_ENGAGE:
        status = HandleLockdownEngage(OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_LOCKDOWN_STATUS:
        status = HandleLockdownStatus(OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_AUDIT_TAIL:
        status = HandleAuditTail(OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_NTFS_RAW_READ:
        status = HandleNtfsRawRead(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_NTFS_VOL_DATA:
        status = HandleNtfsVolData(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_NTFS_USN_QUERY:
        status = HandleNtfsUsnQuery(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_NTFS_USN_READ:
        status = HandleNtfsUsnRead(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_NTFS_MFT_ENUM:
        status = HandleNtfsMftEnum(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_NTFS_STREAMS:
        status = HandleNtfsStreams(InBuf, InLen, OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_SELFPROTECT_SET:
        status = HandleSelfProtectSet(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_SELFPROTECT_STATUS:
        status = HandleSelfProtectStatus(OutBuf, OutLen, BytesWritten);
        break;
    case IOCTL_WINTERNAL_FORCE_UNLOAD_DRIVER:
        status = HandleForceUnload(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_KDRV_REGISTER:
        status = HandleKdrvRegister(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_KDRV_DEREGISTER:
        status = HandleKdrvDeregister(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_KDRV_SET_START:
        status = HandleKdrvSetStart(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_KDRV_LOAD:
        status = HandleKdrvLoad(InBuf, InLen);
        break;
    case IOCTL_WINTERNAL_KDRV_UNLOAD:
        status = HandleKdrvUnload(InBuf, InLen);
        break;

    default:
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE, "%!FUNC! unknown IOCTL 0x%x", Code);
        break;
    }

    return status;
}

VOID
WinternalEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    UNREFERENCED_PARAMETER(Queue);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t bytesWritten = 0;
    PVOID inBuf = NULL;
    PVOID outBuf = NULL;

    // Unload gate: once EvtDriverUnload has begun, fail new IOCTLs with
    // STATUS_DELETE_PENDING and let the unload thread drain.
    if (!WinternalDispatchEnter()) {
        WdfRequestCompleteWithInformation(Request, STATUS_DELETE_PENDING, 0);
        return;
    }

    // Pull both buffers up front; METHOD_BUFFERED gives us safe non-paged copies.
    if (InputBufferLength) {
        status = WdfRequestRetrieveInputBuffer(Request, 0, &inBuf, NULL);
        if (!NT_SUCCESS(status)) { WdfRequestCompleteWithInformation(Request, status, 0); WinternalDispatchLeave(); return; }
    }
    if (OutputBufferLength) {
        status = WdfRequestRetrieveOutputBuffer(Request, 0, &outBuf, NULL);
        if (!NT_SUCCESS(status)) { WdfRequestCompleteWithInformation(Request, status, 0); WinternalDispatchLeave(); return; }
    }

    // Lockdown gate: refuse state-mutating IOCTLs after lockdown engaged.
    if (g_Lockdown && IsLockdownGated(IoControlCode)) {
        AuditAppend(IoControlCode, 0, 0, STATUS_ACCESS_DENIED);
        WdfRequestCompleteWithInformation(Request, STATUS_ACCESS_DENIED, 0);
        WinternalDispatchLeave();
        return;
    }

    // Self-protection gate: when engaged, only the owner PID may submit
    // IOCTLs that would weaken protection. Includes turning off self-
    // protect itself, unprotecting the owner, force-unloading our own
    // driver, or driving SCM lifecycle against our service name.
    if (g_SelfProtect) {
        BOOLEAN refuse = FALSE;
        switch (IoControlCode) {
        case IOCTL_WINTERNAL_SELFPROTECT_SET: {
            // Engage is fine from any admin (owner needs to be set once);
            // disengage is owner-only.
            if (InputBufferLength >= sizeof(WINTERNAL_SELFPROTECT_IN)) {
                PWINTERNAL_SELFPROTECT_IN in = (PWINTERNAL_SELFPROTECT_IN)inBuf;
                if (!in->Enable && !WinternalCallerIsOwner()) refuse = TRUE;
            }
            break;
        }
        case IOCTL_WINTERNAL_PROTECT_UNLOCK: {
            if (InputBufferLength >= sizeof(WINTERNAL_PROTECT_LOCK_IN)) {
                PWINTERNAL_PROTECT_LOCK_IN in = (PWINTERNAL_PROTECT_LOCK_IN)inBuf;
                if ((LONG)in->Pid == g_SelfProtectOwner && !WinternalCallerIsOwner()) refuse = TRUE;
            }
            break;
        }
        case IOCTL_WINTERNAL_FORCE_UNLOAD_DRIVER:
        case IOCTL_WINTERNAL_KDRV_UNLOAD: {
            // Refuse if target name is "Winternal" (our own driver) and
            // caller isn't us. Both IOCTLs use the same name struct layout.
            if (InputBufferLength >= sizeof(WINTERNAL_FORCE_UNLOAD_IN)) {
                PWINTERNAL_FORCE_UNLOAD_IN in = (PWINTERNAL_FORCE_UNLOAD_IN)inBuf;
                if (_wcsnicmp(in->Name, L"Winternal", WINTERNAL_DRIVER_NAME_MAX) == 0
                    && !WinternalCallerIsOwner()) refuse = TRUE;
            }
            break;
        }
        case IOCTL_WINTERNAL_KDRV_DEREGISTER:
        case IOCTL_WINTERNAL_KDRV_SET_START: {
            if (InputBufferLength >= sizeof(WINTERNAL_KDRV_NAME_IN)) {
                PWINTERNAL_KDRV_NAME_IN in = (PWINTERNAL_KDRV_NAME_IN)inBuf;
                if (_wcsnicmp(in->Name, L"Winternal", WINTERNAL_DRIVER_NAME_MAX) == 0
                    && !WinternalCallerIsOwner()) refuse = TRUE;
            }
            break;
        }
        }
        if (refuse) {
            AuditAppend(IoControlCode, 0, 0, STATUS_ACCESS_DENIED);
            WdfRequestCompleteWithInformation(Request, STATUS_ACCESS_DENIED, 0);
            WinternalDispatchLeave();
            return;
        }
    }

    __try {
        status = DispatchIoctl(IoControlCode, inBuf, InputBufferLength,
                               outBuf, OutputBufferLength, &bytesWritten);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE,
                    "%!FUNC! IOCTL 0x%x raised SEH 0x%x — failing request",
                    IoControlCode, GetExceptionCode());
        status = STATUS_UNHANDLED_EXCEPTION;
        bytesWritten = 0;
    }

    // Audit every privileged IOCTL (skip the bulky read enumerators).
    if (IsLockdownGated(IoControlCode) ||
        IoControlCode == IOCTL_WINTERNAL_LOCKDOWN_ENGAGE) {
        UINT64 target = 0;
        UINT32 length = 0;
        switch (IoControlCode) {
        case IOCTL_WINTERNAL_KMEM_WRITE: {
            PWINTERNAL_KMEM_WRITE_IN in = (PWINTERNAL_KMEM_WRITE_IN)inBuf;
            if (InputBufferLength >= FIELD_OFFSET(WINTERNAL_KMEM_WRITE_IN, Data)) {
                target = in->Address; length = in->Length;
            }
            break;
        }
        case IOCTL_WINTERNAL_KCALL: {
            PWINTERNAL_KCALL_IN in = (PWINTERNAL_KCALL_IN)inBuf;
            if (InputBufferLength >= sizeof(*in)) target = in->Address;
            break;
        }
        case IOCTL_WINTERNAL_KHOOK_INSTALL: {
            PWINTERNAL_KHOOK_INSTALL_IN in = (PWINTERNAL_KHOOK_INSTALL_IN)inBuf;
            if (InputBufferLength >= sizeof(*in)) { target = in->Target; length = in->PrologueSize; }
            break;
        }
        case IOCTL_WINTERNAL_KHOOK_UNINSTALL: {
            PWINTERNAL_KHOOK_UNINSTALL_IN in = (PWINTERNAL_KHOOK_UNINSTALL_IN)inBuf;
            if (InputBufferLength >= sizeof(*in)) target = in->Target;
            break;
        }
        case IOCTL_WINTERNAL_UNPROTECT_PROCESS: {
            PWINTERNAL_UNPROTECT_IN in = (PWINTERNAL_UNPROTECT_IN)inBuf;
            if (InputBufferLength >= sizeof(*in)) target = in->Pid;
            break;
        }
        case IOCTL_WINTERNAL_KILL_PROCESS: {
            PWINTERNAL_KILL_IN in = (PWINTERNAL_KILL_IN)inBuf;
            if (InputBufferLength >= sizeof(*in)) target = in->Pid;
            break;
        }
        }
        AuditAppend(IoControlCode, target, length, status);
    }

    WdfRequestCompleteWithInformation(Request, status, bytesWritten);
    WinternalDispatchLeave();
}

VOID
WinternalEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(ActionFlags);
    return;
}
