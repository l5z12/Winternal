/*++

Module Name:

    public.h

Abstract:

    Common declarations shared by the Winternal driver and user-mode clients.

    The driver exposes a small "kernel scripting" surface that lets user-mode
    callers read/write arbitrary kernel virtual memory, resolve exports,
    allocate pool, and invoke kernel routines. Higher-level helpers
    (process unprotect/kill, callback enumeration, SSDT/driver list) are
    layered on top of those primitives for convenience and so that user
    code can stay portable across builds. The intent is research and
    rootkit-detection on a VM — see README.

Environment:

    user and kernel

--*/

#pragma once

//
// Device interface GUID and symbolic link name. Apps may either:
//   1) Use SetupDi to find the device interface, OR
//   2) CreateFile(L"\\\\.\\Winternal", ...) which goes through the symlink
//      created by the driver in DriverEntry.
//
DEFINE_GUID (GUID_DEVINTERFACE_Winternal,
    0xfa6d6eff,0xf155,0x4ada,0xb9,0xd6,0xa2,0x4b,0x5d,0x40,0x7e,0x1c);
// {fa6d6eff-f155-4ada-b9d6-a24b5d407e1c}

#define WINTERNAL_DEVICE_NAME       L"\\Device\\Winternal"
#define WINTERNAL_SYMLINK_NAME      L"\\DosDevices\\Winternal"   // -> \\.\Winternal
#define WINTERNAL_USER_OPEN_PATH    L"\\\\.\\Winternal"

//
// SDDL restricting CreateFile() on the device to SYSTEM and Administrators
// only. The kernel resolves this at AddDevice time, so unprivileged callers
// fail at open before any IOCTL plumbing runs.
//
#define WINTERNAL_DEVICE_SDDL       L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

#ifndef CTL_CODE
#include <winioctl.h>
#endif

//
// IOCTL codes. Function codes 0x800-0xFFF are reserved for vendor use.
// METHOD_BUFFERED keeps probing/locking off the fast path. Per-IOCTL caps
// (see WINTERNAL_KMEM_MAX_BYTES) limit the worst-case allocation.
//
#define IOCTL_WINTERNAL_GET_VERSION       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_ENUM_PIDS         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Raw kernel memory (the "engine" — everything else can be built on these).
#define IOCTL_WINTERNAL_KMEM_READ         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KMEM_WRITE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KSYM              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KALLOC            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KFREE             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KCALL             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Process control.
#define IOCTL_WINTERNAL_UNPROTECT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KILL_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Force-protect: registers an Ob* pre-operation callback that strips
// destructive (and optionally informational) access bits when any caller
// opens a handle to the target PID. Survives until the driver unloads.
#define IOCTL_WINTERNAL_PROTECT_LOCK   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_PROTECT_UNLOCK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_PROTECT_LIST   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Flip the TOKEN_HAS_UI_ACCESS bit of a target process's primary token.
// User-mode SetTokenInformation(TokenUIAccess) demands SeTcbPrivilege and
// even with it can't enable UIAccess on a running process (NtSetInfoToken
// rejects the request). From kernel we just write the byte. Lifts the
// CreateWindowInBand / SetWindowBand restrictions on bands >= UIACCESS.
#define IOCTL_WINTERNAL_TOKEN_UIACCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Rootkit detection helpers.
#define IOCTL_WINTERNAL_ENUM_CALLBACKS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_ENUM_DRIVERS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_ENUM_SSDT         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kernel-mode inline hooks. Detour must be a kernel address (typically a
// buffer allocated via KALLOC and populated with shellcode via KMEM_WRITE).
// On unload, the driver uninstalls everything still installed — otherwise a
// dangling JMP into freed pool would bug-check on next call.
//
// PatchGuard (KPP) will detect hooks on most ntoskrnl / SSDT targets and
// bug-check the system within ~30 minutes. Test on a VM with HVCI/VBS off.
#define IOCTL_WINTERNAL_KHOOK_INSTALL     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KHOOK_UNINSTALL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KHOOK_UNINSTALL_ALL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x842, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kernel-mode Lua execution. Input is a UTF-8 Lua script; output is a
// captured stdout-like buffer (everything the script's print() emits) plus
// the Lua status code. The script runs with a `wnk` table exposing direct
// kernel primitives (ksym, kread, kwrite, kcall, pids, etc.).
#define IOCTL_WINTERNAL_LUA_EXEC          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Lockdown — once set, the driver refuses every write/patch IOCTL
// (kwrite, kalloc, kfree, kcall, unprotect, kill, khook*, lua_exec).
// One-way intentionally: the bit clears only on driver unload. Caller
// uses this after disabling PG so a buggy script can't worsen things.
#define IOCTL_WINTERNAL_LOCKDOWN_ENGAGE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x860, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_LOCKDOWN_STATUS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x861, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Force-unload another kernel driver by name. Resolves \Driver\<name> via
// ObReferenceObjectByName, then calls its DriverUnload routine directly.
// Bypasses SCM entirely so it works on drivers that don't accept
// SERVICE_ACCEPT_STOP. Dangerous: the target may have outstanding IRPs,
// callbacks, or timers it expected PnP to drain first.
// Self-protection — when engaged, the driver:
//   * adds the owner PID to the protect_list (Ob callbacks strip destructive
//     access on any OpenProcess to the CLI from anywhere else);
//   * refuses IOCTLs that would weaken protection unless the caller is the
//     owner PID: SELFPROTECT_SET (turning off), PROTECT_UNLOCK on the owner,
//     FORCE_UNLOAD_DRIVER / KDRV_UNLOAD targeting "Winternal".
// User-mode tightens the SCM service DACL in parallel so `sc stop` /
// `sc delete` from outside the owner's session fails with ACCESS_DENIED.
#define IOCTL_WINTERNAL_SELFPROTECT_SET    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x890, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_SELFPROTECT_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x891, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _WINTERNAL_SELFPROTECT_IN {
    UINT32 Enable;       // 1 = engage, 0 = disengage
    UINT32 OwnerPid;     // ignored on disengage
} WINTERNAL_SELFPROTECT_IN, *PWINTERNAL_SELFPROTECT_IN;

typedef struct _WINTERNAL_SELFPROTECT_OUT {
    UINT32 Engaged;
    UINT32 OwnerPid;
} WINTERNAL_SELFPROTECT_OUT, *PWINTERNAL_SELFPROTECT_OUT;

#define IOCTL_WINTERNAL_FORCE_UNLOAD_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x870, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kernel-level driver management — uses ZwLoadDriver / ZwUnloadDriver and
// direct registry manipulation (ZwCreateKey/ZwSetValueKey/ZwDeleteKey).
// Bypasses SCM entirely; signing requirements are NOT bypassed — the
// kernel loader still validates signatures when DSE is enforcing.
#define IOCTL_WINTERNAL_KDRV_REGISTER     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x871, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KDRV_LOAD         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x872, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KDRV_UNLOAD       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x873, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KDRV_DEREGISTER   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x874, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_KDRV_SET_START    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x875, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Audit log — every privileged IOCTL records a row. Caller reads up to
// the last N rows. Useful for forensic review after a session.
#define IOCTL_WINTERNAL_AUDIT_TAIL        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x862, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define WINTERNAL_AUDIT_MAX_ROWS          1024

// Per-call cap for kernel R/W. METHOD_BUFFERED allocates a single non-paged
// buffer of this size, so keep it modest. Scripts that need more should chunk.
#define WINTERNAL_KMEM_MAX_BYTES          (1u * 1024u * 1024u)

//
// ---- Version ----
//
typedef struct _WINTERNAL_VERSION {
    UINT32 Major;
    UINT32 Minor;
    UINT32 BuildTime;       // unix-ish, populated by driver
    UINT32 Reserved;
} WINTERNAL_VERSION, *PWINTERNAL_VERSION;

//
// ---- PID enumeration (DKOM cross-check) ----
//
typedef struct _WINTERNAL_PID_ENTRY {
    UINT32  Pid;
    UINT32  ParentPid;        // best-effort, may be 0 on platforms where unavailable
    CHAR    ImageFileName[16];
} WINTERNAL_PID_ENTRY, *PWINTERNAL_PID_ENTRY;

typedef struct _WINTERNAL_PID_LIST {
    UINT32 Count;
    UINT32 Reserved;
    WINTERNAL_PID_ENTRY Entries[1];
} WINTERNAL_PID_LIST, *PWINTERNAL_PID_LIST;

//
// ---- Kernel R/W ----
//
// READ:   in  = {Address, Length};   out = raw bytes (Length bytes on success)
// WRITE:  in  = {Address, Length, Data[Length]};   out = (none)
//
typedef struct _WINTERNAL_KMEM_READ_IN {
    UINT64 Address;
    UINT32 Length;
    UINT32 Reserved;
} WINTERNAL_KMEM_READ_IN, *PWINTERNAL_KMEM_READ_IN;

typedef struct _WINTERNAL_KMEM_WRITE_IN {
    UINT64 Address;
    UINT32 Length;
    UINT32 Reserved;
    UCHAR  Data[1];        // Length bytes
} WINTERNAL_KMEM_WRITE_IN, *PWINTERNAL_KMEM_WRITE_IN;

//
// ---- Symbol lookup (ntoskrnl exports + already-loaded kernel modules) ----
//
typedef struct _WINTERNAL_KSYM_IN {
    WCHAR  Name[64];       // NUL-terminated. ntoskrnl-exported routine name.
} WINTERNAL_KSYM_IN, *PWINTERNAL_KSYM_IN;

typedef struct _WINTERNAL_KSYM_OUT {
    UINT64 Address;        // 0 if not found
} WINTERNAL_KSYM_OUT, *PWINTERNAL_KSYM_OUT;

//
// ---- Pool alloc / free ----
//
typedef struct _WINTERNAL_KALLOC_IN {
    UINT32 Length;
    UINT32 Tag;            // 4-char ASCII tag, e.g. 'WnTl'
    UINT32 NonPaged;       // 0 = paged, 1 = non-paged
    UINT32 Reserved;
} WINTERNAL_KALLOC_IN, *PWINTERNAL_KALLOC_IN;

typedef struct _WINTERNAL_KALLOC_OUT {
    UINT64 Address;
} WINTERNAL_KALLOC_OUT, *PWINTERNAL_KALLOC_OUT;

typedef struct _WINTERNAL_KFREE_IN {
    UINT64 Address;
    UINT32 Tag;            // must match the alloc tag (or 0 for "ignore")
    UINT32 Reserved;
} WINTERNAL_KFREE_IN, *PWINTERNAL_KFREE_IN;

//
// ---- Kernel function call ----
//
// Calls (PVOID(*)(ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR))Address(a1, a2, a3, a4)
// at IRQL == PASSIVE_LEVEL inside the dispatch thread. The caller is
// responsible for argument validity; the driver wraps the call in SEH so a
// crashing target is reported as STATUS_UNSUCCESSFUL rather than bug-checking
// the queue thread (it can still bug-check the system if the target touches
// invalid memory at high IRQL).
//
typedef struct _WINTERNAL_KCALL_IN {
    UINT64 Address;
    UINT64 Args[4];
} WINTERNAL_KCALL_IN, *PWINTERNAL_KCALL_IN;

typedef struct _WINTERNAL_KCALL_OUT {
    UINT64 ReturnValue;
    UINT32 Faulted;        // non-zero if the call raised an SEH exception
    UINT32 Reserved;
} WINTERNAL_KCALL_OUT, *PWINTERNAL_KCALL_OUT;

//
// ---- Process unprotect ----
//
// Win11 24H2 (build 26100) puts EPROCESS->Protection at a known offset.
// Because that offset changes per build, callers may either:
//   * pass FieldOffset = 0 to use the driver's compiled-in default, OR
//   * pass an explicit FieldOffset and NewValue they discovered themselves
//     via kread/ksym (the "scripts can do everything" path).
//
typedef struct _WINTERNAL_UNPROTECT_IN {
    UINT32 Pid;
    UINT32 FieldOffset;    // 0 -> use driver default for current build
    UINT8  NewValue;       // typically 0 to clear PP/PPL
    UINT8  Reserved[7];
} WINTERNAL_UNPROTECT_IN, *PWINTERNAL_UNPROTECT_IN;

typedef struct _WINTERNAL_UNPROTECT_OUT {
    UINT32 FieldOffsetUsed;
    UINT8  PrevValue;
    UINT8  Reserved[3];
} WINTERNAL_UNPROTECT_OUT, *PWINTERNAL_UNPROTECT_OUT;

//
// ---- Kill (works on protected processes) ----
//
typedef struct _WINTERNAL_KILL_IN {
    UINT32 Pid;
    UINT32 ExitStatus;     // commonly 1 or STATUS_PROCESS_IS_TERMINATING
} WINTERNAL_KILL_IN, *PWINTERNAL_KILL_IN;

//
// ---- Force-protect (Ob callback lockdown) ----
//
// Driver maintains a small array of locked PIDs. On the first PROTECT_LOCK
// call it registers a single pair of pre-operation Ob callbacks (one for
// PsProcessType, one for PsThreadType). Each callback walks the locked
// list and, on match, ANDs the requested access mask with ~Strip — i.e.,
// the requested bits in Strip are silently removed before the handle is
// granted. Kernel-mode openers (Info->KernelHandle == TRUE) are skipped
// so our own driver can still operate on locked PIDs.
//
// Cap is fixed (WINTERNAL_PROTECT_MAX) so the callback can do a linear
// walk without taking a per-call allocation in the hot path.
//
#define WINTERNAL_PROTECT_MAX 32

typedef struct _WINTERNAL_PROTECT_LOCK_IN {
    UINT32 Pid;
    UINT32 Reserved;
} WINTERNAL_PROTECT_LOCK_IN, *PWINTERNAL_PROTECT_LOCK_IN;

typedef struct _WINTERNAL_PROTECT_LIST_OUT {
    UINT32 Count;
    UINT32 Reserved;
    UINT32 Pids[WINTERNAL_PROTECT_MAX];
} WINTERNAL_PROTECT_LIST_OUT, *PWINTERNAL_PROTECT_LIST_OUT;

//
// ---- Token UIAccess flip ----
//
// nt!_TOKEN has a TokenFlags ULONG with bit 0x10 = TOKEN_HAS_UI_ACCESS.
// On Win11 24H2 (build 26100) the field is at offset 0x40 from the start
// of the token object. Other builds may differ; caller can pass an
// explicit FieldOffset, or leave 0 to use the driver default.
//
typedef struct _WINTERNAL_TOKEN_UIACCESS_IN {
    UINT32 Pid;
    UINT32 Enable;          // 0 = clear, 1 = set
    UINT32 FieldOffset;     // 0 = driver default
    UINT32 Reserved;
} WINTERNAL_TOKEN_UIACCESS_IN, *PWINTERNAL_TOKEN_UIACCESS_IN;

typedef struct _WINTERNAL_TOKEN_UIACCESS_OUT {
    UINT32 PrevFlags;
    UINT32 NewFlags;
    UINT32 FieldOffsetUsed;
    UINT32 Reserved;
} WINTERNAL_TOKEN_UIACCESS_OUT, *PWINTERNAL_TOKEN_UIACCESS_OUT;

#define WINTERNAL_TOKEN_FLAG_UIACCESS         0x10
#define WINTERNAL_DEFAULT_TOKENFLAGS_OFFSET   0x40

//
// ---- EPROCESS signature level ----
//
// Win11 24H2 (build 26100) keeps SignatureLevel and SectionSignatureLevel
// as two adjacent UCHARs at offset 0x878 / 0x879. win32k checks the value
// for high z-bands (GENUINE_WINDOWS, SYSTEM_TOOLS, LOCK) and refuses the
// SetWindowBand if the level isn't Microsoft-grade. Bumping the bytes to
// SE_SIGNING_LEVEL_WINDOWS (0x0C) makes the process appear MS-signed for
// the win32k check.
//
#define IOCTL_WINTERNAL_SET_SIGLEVEL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x826, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Write into kernel CODE pages — toggles CR0.WP on the current CPU before
// the copy and reads back to detect HVCI silent rejection. Used for inline
// patches of system DLLs / drivers (e.g. neutering win32kfull's
// IAMThreadAccessGranted + IsValidBandForProcess gates for `win zbid`).
// Read-back verification means the write either applies or returns
// STATUS_NOT_SUPPORTED — no silent failures.
#define IOCTL_WINTERNAL_KCODE_PATCH   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x827, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Returns the kernel address of a small "always returns 1" stub function
// inside Winternal.sys. Used as the IAT redirect target for bypassing
// win32k!IsImmersiveBroker (and any other bool-returning gate where we
// can patch the IAT slot in .rdata instead of the function body in .text;
// .text writes are blocked by HVCI, .rdata writes go through).
#define IOCTL_WINTERNAL_GET_TRUE_STUB CTL_CODE(FILE_DEVICE_UNKNOWN, 0x828, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Returns the kernel address of EPROCESS->Win32Process (tagPROCESSINFO*)
// for a given PID, via PsGetProcessWin32Process. The CLI then kread/kwrites
// fields on it directly — pool memory, no HVCI / CR0.WP needed.
#define IOCTL_WINTERNAL_GET_W32PROC   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x829, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kernel-side equivalents of user-mode process inspection. Bypass any
// user-mode API hooks (Detours/EAT/IAT) since the underlying syscalls
// run with PreviousMode=KernelMode and the OS doesn't apply the user-mode
// detours installed by AVs/anti-cheat.
#define IOCTL_WINTERNAL_ENUM_THREADS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_K_MITIGATIONS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_K_TOKEN_INFO   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_K_MEM_QUERY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82D, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Raw read from any \\Device\\* object (typically \\Device\\HarddiskVolumeN
// for a volume, or \\Device\\PhysicalDriveN for the whole disk). The
// driver opens the object with FILE_READ_DATA and PreviousMode = Kernel,
// which routes the request straight to the device stack's lowest IRP_MJ_
// READ handler — every minifilter and user-mode hook above it is bypassed.
// This is the "ground truth" view of on-disk bytes, used by NTFS analysis
// plugins to parse MFT records without trusting NtQueryDirectoryFile.
// Caps: 1 MiB per call (raise WINTERNAL_NTFS_RAW_MAX if you need more).
// Raw byte read from any \Device\* object (volume / physical drive).
#define IOCTL_WINTERNAL_NTFS_RAW_READ   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x880, METHOD_BUFFERED, FILE_ANY_ACCESS)
// FSCTL surfaces routed through the driver so they hit NTFS with
// PreviousMode = Kernel — minifilters that filter per-process or per-
// access-mode can't intercept these.
#define IOCTL_WINTERNAL_NTFS_VOL_DATA   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x881, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_NTFS_USN_QUERY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x882, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_NTFS_USN_READ   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x883, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_NTFS_MFT_ENUM   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x884, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_NTFS_STREAMS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x885, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WINTERNAL_NTFS_RAW_MAX         (1u * 1024u * 1024u)
#define WINTERNAL_NTFS_DEV_NAME_MAX    128
#define WINTERNAL_NTFS_PATH_MAX        520
#define WINTERNAL_NTFS_USN_BUF         (64u * 1024u)

typedef struct _WINTERNAL_NTFS_RAW_READ_IN {
    WCHAR  Device[WINTERNAL_NTFS_DEV_NAME_MAX]; // e.g. L"\\Device\\HarddiskVolume3"
    UINT64 Offset;                              // byte offset (must be sector-aligned)
    UINT32 Length;                              // bytes to read; <= WINTERNAL_NTFS_RAW_MAX
    UINT32 Reserved;
} WINTERNAL_NTFS_RAW_READ_IN, *PWINTERNAL_NTFS_RAW_READ_IN;

// FSCTL_GET_NTFS_VOLUME_DATA passthrough — the driver opens the device,
// issues the FSCTL with PreviousMode=Kernel, and returns the kernel's
// NTFS_VOLUME_DATA_BUFFER (extended). Caller passes the device name;
// output is the raw struct.
typedef struct _WINTERNAL_NTFS_DEVICE_IN {
    WCHAR Device[WINTERNAL_NTFS_DEV_NAME_MAX];
} WINTERNAL_NTFS_DEVICE_IN, *PWINTERNAL_NTFS_DEVICE_IN;

typedef struct _WINTERNAL_NTFS_VOL_DATA_OUT {
    LARGE_INTEGER VolumeSerialNumber;
    LARGE_INTEGER NumberSectors;
    LARGE_INTEGER TotalClusters;
    LARGE_INTEGER FreeClusters;
    LARGE_INTEGER TotalReserved;
    UINT32        BytesPerSector;
    UINT32        BytesPerCluster;
    UINT32        BytesPerFileRecordSegment;
    UINT32        ClustersPerFileRecordSegment;
    LARGE_INTEGER MftValidDataLength;
    LARGE_INTEGER MftStartLcn;
    LARGE_INTEGER Mft2StartLcn;
    LARGE_INTEGER MftZoneStart;
    LARGE_INTEGER MftZoneEnd;
} WINTERNAL_NTFS_VOL_DATA_OUT, *PWINTERNAL_NTFS_VOL_DATA_OUT;

// FSCTL_QUERY_USN_JOURNAL passthrough.
typedef struct _WINTERNAL_NTFS_USN_JOURNAL_OUT {
    UINT64 JournalId;
    INT64  FirstUsn;
    INT64  NextUsn;
    INT64  LowestValidUsn;
    INT64  MaxUsn;
    UINT64 MaxSize;
    UINT64 AllocationDelta;
} WINTERNAL_NTFS_USN_JOURNAL_OUT, *PWINTERNAL_NTFS_USN_JOURNAL_OUT;

// FSCTL_READ_USN_JOURNAL passthrough. Output: first 8 bytes are the
// next-USN cursor (signed); the rest is a packed array of USN_RECORD_V2
// — user-mode parses them.
typedef struct _WINTERNAL_NTFS_USN_READ_IN {
    WCHAR  Device[WINTERNAL_NTFS_DEV_NAME_MAX];
    UINT64 JournalId;
    INT64  StartUsn;
    UINT32 ReasonMask;
    UINT32 WaitForFresh;       // 0 = snapshot, 1 = block until new data
} WINTERNAL_NTFS_USN_READ_IN, *PWINTERNAL_NTFS_USN_READ_IN;

// FSCTL_ENUM_USN_DATA passthrough. Output: first 8 bytes are the
// next-FRN cursor; the rest is packed USN_RECORD_V2.
typedef struct _WINTERNAL_NTFS_MFT_ENUM_IN {
    WCHAR  Device[WINTERNAL_NTFS_DEV_NAME_MAX];
    UINT64 StartFrn;
} WINTERNAL_NTFS_MFT_ENUM_IN, *PWINTERNAL_NTFS_MFT_ENUM_IN;

// FileStreamInformation passthrough. Output: packed FILE_STREAM_INFORMATION
// records; user-mode walks NextEntryOffset chain.
typedef struct _WINTERNAL_NTFS_STREAMS_IN {
    WCHAR Path[WINTERNAL_NTFS_PATH_MAX];   // NT path like L"\\??\\C:\\Users\\..."
} WINTERNAL_NTFS_STREAMS_IN, *PWINTERNAL_NTFS_STREAMS_IN;

// ---- Real-time process monitor ----
//
// Driver registers PsSetCreateProcessNotifyRoutineEx and writes
// create/exit events into an in-kernel ring. The CLI calls READ in a
// loop; the driver blocks (up to 2s) waiting for new events and returns
// however many it has. Cancelable via the CLI's Ctrl+C handler — each
// read returns within the 2-second timeout so we can rerun and check
// the abort flag.
#define IOCTL_WINTERNAL_PROC_MONITOR_START  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_PROC_MONITOR_STOP   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_PROC_MONITOR_READ   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WINTERNAL_PROC_EV_CREATE        0u
#define WINTERNAL_PROC_EV_EXIT          1u
// Fired from the NtTerminateProcess prologue hook — gives us
// attribution (CallerPid, TargetPid) before the kernel actually
// performs the termination. CallerPid lands in the existing
// `CreatingPid` field; the targeted image goes in `Image` resolved
// from the PID cache. ExitStatus lives in `Reserved`.
#define WINTERNAL_PROC_EV_TERMINATE_REQ 2u
#define WINTERNAL_PROC_IMAGE_MAX  260u
#define WINTERNAL_PROC_CMD_MAX    520u
#define WINTERNAL_PROC_RING_SIZE  256u

typedef struct _WINTERNAL_PROC_EVENT {
    UINT64 TimestampNs;        // KeQuerySystemTimePrecise (100ns units)
    UINT32 EventType;          // WINTERNAL_PROC_EV_*
    UINT32 Pid;
    UINT32 ParentPid;          // 0 on exit
    UINT32 CreatingPid;        // process that called CreateProcess; 0 on exit
    UINT32 CreatingTid;        // its thread; 0 on exit
    UINT32 Dropped;            // events lost because the ring overflowed
                               // before this one was read; non-zero only
                               // on the first event after a drop.
    UINT32 ImageLen;           // wchars including NUL, 0 if unavailable
    UINT32 CmdLen;             // wchars including NUL
    UINT32 Reserved;
    WCHAR  Image[WINTERNAL_PROC_IMAGE_MAX];
    WCHAR  CmdLine[WINTERNAL_PROC_CMD_MAX];
} WINTERNAL_PROC_EVENT, *PWINTERNAL_PROC_EVENT;

typedef struct _WINTERNAL_PROC_MON_OUT {
    UINT32 Count;
    UINT32 Reserved;
    WINTERNAL_PROC_EVENT Events[1];   // [Count]
} WINTERNAL_PROC_MON_OUT, *PWINTERNAL_PROC_MON_OUT;

// ---- Process-create block rules ----
//
// Extension of the process monitor: rule-driven IRP_MJ_CREATE-equivalent
// for process creation. The notify routine (PsSetCreateProcessNotifyRoutineEx)
// is registered once at DriverEntry and stays alive for the driver's
// lifetime — rules add/remove/clear just mutate the in-kernel rule list,
// no register churn at runtime. Patterns match the image-path the kernel
// sees on create (CreateInfo->ImageFileName, e.g. \??\C:\Windows\System32\foo.exe)
// with the same path-aware wildcard matcher the NTFS filter uses
// (`*` spans `\`, `?` one char, case-insensitive).
//
// Actions on match:
//   ALLOW (default if no rule) — pass through.
//   DENY                       — set CreateInfo->CreationStatus =
//                                STATUS_ACCESS_DENIED so the syscall
//                                fails. Audit + ring entry both fire.
//   LOG                        — audit + ring only; create proceeds.
#define IOCTL_WINTERNAL_PROC_RULE_ADD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_PROC_RULE_REMOVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_PROC_RULE_LIST   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_PROC_RULE_CLEAR  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A6, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---- Process-termination protect rules ----
//
// Rules describe images that may not be terminated. The undocumented
// NtTerminateProcess prologue hook evaluates these against the target's
// cached image at termination time; a match returns STATUS_ACCESS_DENIED
// without calling the original handler. Both taskkill (from any session,
// any privilege — including SYSTEM elevation, since it routes through
// the syscall like everything else) and any other Nt-level terminator
// are blocked. ProcessHandle == self is still allowed (we don't block
// processes from exiting voluntarily).
//
// Distinct from PROC_RULE (which blocks CREATES, not exits). Distinct
// from `protect <pid> --force` (which works at the Ob handle-open layer
// and only strips destructive access bits from new handles).
#define IOCTL_WINTERNAL_PROC_PROTECT_ADD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_PROC_PROTECT_REMOVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_PROC_PROTECT_LIST   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8A9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_PROC_PROTECT_CLEAR  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8AA, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WINTERNAL_PROC_PROTECT_MAX_RULES   64
#define WINTERNAL_PROC_PROTECT_PATTERN_MAX 260

// Flags returned in WINTERNAL_PROC_PROTECT_RULE.Flags so the CLI can tell
// the user which enforcement path is actually live for the rule they just
// added. Bit 0 is the "inline hook on NtTerminateProcess" — the only path
// capable of returning a custom NTSTATUS. When it's NOT set, the rule is
// enforced solely by ObRegisterCallbacks stripping PROCESS_TERMINATE from
// new handles, and the syscall return becomes STATUS_ACCESS_DENIED no
// matter what `Status` was configured with.
#define WINTERNAL_PROC_PROTECT_FLAG_HOOK_LIVE  0x00000001u
#define WINTERNAL_PROC_PROTECT_FLAG_OB_LIVE    0x00000002u

typedef struct _WINTERNAL_PROC_PROTECT_RULE {
    UINT32 RuleId;                                              // 0 on ADD
    UINT32 BlockCount;                                          // populated on LIST
    UINT32 Status;                                              // NTSTATUS returned to terminator
                                                                //   on match. Only honored when
                                                                //   FLAG_HOOK_LIVE is set on ADD;
                                                                //   otherwise enforcement falls
                                                                //   back to the Ob handle-strip
                                                                //   path which always yields
                                                                //   STATUS_ACCESS_DENIED.
    UINT32 Flags;                                               // see WINTERNAL_PROC_PROTECT_FLAG_*
    WCHAR  Pattern[WINTERNAL_PROC_PROTECT_PATTERN_MAX];
} WINTERNAL_PROC_PROTECT_RULE, *PWINTERNAL_PROC_PROTECT_RULE;

typedef struct _WINTERNAL_PROC_PROTECT_REMOVE_IN {
    UINT32 RuleId;
    UINT32 Reserved;
} WINTERNAL_PROC_PROTECT_REMOVE_IN, *PWINTERNAL_PROC_PROTECT_REMOVE_IN;

typedef struct _WINTERNAL_PROC_PROTECT_LIST_OUT {
    UINT32 Count;
    UINT32 Reserved;
    WINTERNAL_PROC_PROTECT_RULE Rules[1];                       // [Count]
} WINTERNAL_PROC_PROTECT_LIST_OUT, *PWINTERNAL_PROC_PROTECT_LIST_OUT;

// ---- Window rules (driver-resident storage) ----
//
// Rules live in the driver so they survive CLI restarts and so the
// shield DLL (loaded into every GUI process by `win protect`) can pull
// from a single source of truth via IOCTL instead of from a shared
// file-mapping owned by a transient guardian.
//
// Phase 1 (here): driver stores and serves rules; enforcement is still
// the user-mode shield DLL doing subclass-drop + WH_CBT abort. Phase 2
// (future): kernel inline hooks on NtUserDestroyWindow / NtUserCreate-
// WindowEx for true driver-side prohibition (HVCI-fragile, so the user-
// mode path stays as a fallback).
#define IOCTL_WINTERNAL_WIN_RULE_ADD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_WIN_RULE_REMOVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_WIN_RULE_LIST   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_WIN_RULE_CLEAR  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WINTERNAL_WIN_RULE_MAX_RULES    64
#define WINTERNAL_WIN_RULE_PATTERN_MAX  128

// Match kinds — what gets compared against r.Pattern.
#define WINTERNAL_WIN_KIND_TITLE_GLOB   1u
#define WINTERNAL_WIN_KIND_CLASS_GLOB   2u
#define WINTERNAL_WIN_KIND_PID          3u
#define WINTERNAL_WIN_KIND_IMAGE_GLOB   4u

// Action — what happens on match.
#define WINTERNAL_WIN_ACT_BLOCK_CLOSE   0u   // subclass-drop WM_CLOSE/SC_CLOSE (shield, user-mode)
#define WINTERNAL_WIN_ACT_BLOCK_CREATE  1u   // WH_CBT abort (shield, user-mode)
#define WINTERNAL_WIN_ACT_BLOCK_DESTROY 2u   // NtUserDestroyWindow kernel inline hook
                                             //   (caller-based: matches PID / IMAGE
                                             //   of the process calling DestroyWindow).
                                             //   HVCI-fragile -- the hook write may
                                             //   be rejected, in which case rules
                                             //   are stored but not enforced.

// Flags reported on ADD/LIST so the CLI can tell users whether kernel-side
// enforcement is actually engaged. Without this, an HVCI-rejected hook
// install would look identical to a successful one from user-mode.
#define WINTERNAL_WIN_FLAG_DESTROY_HOOK_LIVE  0x00000001u

typedef struct _WINTERNAL_WIN_RULE {
    UINT32 RuleId;                                          // 0 on ADD; assigned by driver
    UINT32 Kind;                                            // WINTERNAL_WIN_KIND_*
    UINT32 Action;                                          // WINTERNAL_WIN_ACT_*
    UINT32 HitCount;                                        // populated on LIST
    UINT32 Flags;                                           // WINTERNAL_WIN_FLAG_*
    UINT32 LastHookError;                                   // NTSTATUS from most recent
                                                            //   block-destroy hook-install
                                                            //   attempt (0 = ok / N/A)
    WCHAR  Pattern[WINTERNAL_WIN_RULE_PATTERN_MAX];         // glob or decimal PID
} WINTERNAL_WIN_RULE, *PWINTERNAL_WIN_RULE;

typedef struct _WINTERNAL_WIN_RULE_REMOVE_IN {
    UINT32 RuleId;
    UINT32 Reserved;
} WINTERNAL_WIN_RULE_REMOVE_IN, *PWINTERNAL_WIN_RULE_REMOVE_IN;

typedef struct _WINTERNAL_WIN_RULE_LIST_OUT {
    UINT32 Count;
    UINT32 Reserved;
    WINTERNAL_WIN_RULE Rules[1];                            // [Count]
} WINTERNAL_WIN_RULE_LIST_OUT, *PWINTERNAL_WIN_RULE_LIST_OUT;

// ---- HOOK_INSTALL_BY_RVA -----------------------------------------------
//
// CLI-driven hook install where the user-mode side has already resolved
// the target address via DbgHelp + the matching PDB for the live build.
// Driver maps `Module` to its loaded base, validates `Rva` against the
// module size, and patches at base + Rva. Decoupling locate (user-mode)
// from patch (kernel) lets us:
//   - hit non-exported symbols (xxxDestroyWindow et al.)
//   - stay build-agnostic without baking offsets into the .sys
//   - keep the driver's HTTP/PDB surface area at zero
//
// HookId selects which detour to bind. New entries here MUST match the
// dispatch table in Queue.c (g_HookDispatch).
#define WINTERNAL_HOOK_ID_DESTROY_WINDOW   1u
#define WINTERNAL_HOOK_ID_NT_LOAD_DRIVER   2u

typedef struct _WINTERNAL_HOOK_RVA_REQ {
    WCHAR  Module[64];      // file name only (e.g. "win32kfull.sys"); case-insensitive
    UINT32 Rva;             // offset from module base where the prolog starts
    UINT32 HookId;          // WINTERNAL_HOOK_ID_*
} WINTERNAL_HOOK_RVA_REQ, *PWINTERNAL_HOOK_RVA_REQ;

typedef struct _WINTERNAL_HOOK_RVA_RESP {
    UINT32 Installed;       // 1 on success, 0 on failure
    UINT32 NtStatus;        // detailed reason if Installed == 0
    UINT64 ResolvedVa;      // base + Rva (driver-side, diagnostic)
} WINTERNAL_HOOK_RVA_RESP, *PWINTERNAL_HOOK_RVA_RESP;

#define IOCTL_WINTERNAL_HOOK_INSTALL_BY_RVA  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B4, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WINTERNAL_PROC_RULE_MAX_RULES   64
#define WINTERNAL_PROC_RULE_PATTERN_MAX 260

#define WINTERNAL_PROC_ACT_ALLOW 0
#define WINTERNAL_PROC_ACT_DENY  1
#define WINTERNAL_PROC_ACT_LOG   2

typedef struct _WINTERNAL_PROC_RULE {
    UINT32 RuleId;                                          // 0 on ADD; assigned by driver
    UINT32 Action;                                          // WINTERNAL_PROC_ACT_*
    UINT32 MatchCount;                                      // populated on LIST
    UINT32 Status;                                          // when Action == DENY: NTSTATUS written
                                                            //   to CreationStatus. 0 -> default
                                                            //   STATUS_ACCESS_DENIED.
    WCHAR  Pattern[WINTERNAL_PROC_RULE_PATTERN_MAX];        // wildcard pattern
} WINTERNAL_PROC_RULE, *PWINTERNAL_PROC_RULE;

typedef struct _WINTERNAL_PROC_RULE_REMOVE_IN {
    UINT32 RuleId;
    UINT32 Reserved;
} WINTERNAL_PROC_RULE_REMOVE_IN, *PWINTERNAL_PROC_RULE_REMOVE_IN;

typedef struct _WINTERNAL_PROC_RULE_LIST_OUT {
    UINT32 Count;
    UINT32 Reserved;
    WINTERNAL_PROC_RULE Rules[1];                           // [Count]
} WINTERNAL_PROC_RULE_LIST_OUT, *PWINTERNAL_PROC_RULE_LIST_OUT;

// ---- Driver-load block rules ----
//
// Symmetric to PROC_RULE but for kernel drivers. The driver inline-hooks
// NtLoadDriver(IN PUNICODE_STRING DriverServiceName); the detour parses
// the service-name component (the leaf of
// "\Registry\Machine\System\CurrentControlSet\Services\<name>"), walks
// the rule list, and returns the rule's NTSTATUS on DENY without calling
// the original. Patterns are case-insensitive wildcards (same matcher as
// PROC_RULE) matched against the service-name leaf — e.g. `Foo`, `Foo*`,
// `*`. SCM-driven loads (services.exe -> NtLoadDriver) and direct
// ZwLoadDriver callers (our own `drv load`, third-party tools) are both
// caught since both go through the same syscall.
//
// Actions on match:
//   ALLOW (default if no rule) — pass through.
//   DENY                       — skip the original, return per-rule
//                                NTSTATUS to the caller (default
//                                STATUS_ACCESS_DENIED).
//   LOG                        — audit only; load proceeds.
//
// HVCI: same caveat as the NtTerminateProcess hook — the CR0.WP-protected
// kernel-code write may be rejected, in which case ADD returns
// STATUS_DEVICE_NOT_READY and no rules are enforceable. Status surfaced
// to the CLI via the LIST_OUT.HookLive flag.
#define IOCTL_WINTERNAL_DRV_RULE_ADD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_DRV_RULE_REMOVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_DRV_RULE_LIST   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_DRV_RULE_CLEAR  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8B8, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WINTERNAL_DRV_RULE_MAX_RULES    64
#define WINTERNAL_DRV_RULE_PATTERN_MAX  128

#define WINTERNAL_DRV_ACT_ALLOW 0
#define WINTERNAL_DRV_ACT_DENY  1
#define WINTERNAL_DRV_ACT_LOG   2

// Bits set on the first list entry's Flags telling the CLI which
// enforcement layer(s) are actually live. The driver attempts both at
// init; either alone is sufficient to enforce rules. HOOK_LIVE is the
// inline patch on NtLoadDriver -- precise (only blocks driver loads,
// not other registry tools) but rejected on HVCI / kernel-CI machines.
// CM_LIVE is the CmRegisterCallbackEx fallback -- works under any
// kernel-CI configuration but also blocks unrelated registry opens on
// the same `\Services\<denied>` key (sc query, reg query, etc.).
#define WINTERNAL_DRV_RULE_FLAG_HOOK_LIVE 0x00000001u
#define WINTERNAL_DRV_RULE_FLAG_CM_LIVE   0x00000002u

typedef struct _WINTERNAL_DRV_RULE {
    UINT32 RuleId;                                          // 0 on ADD; assigned by driver
    UINT32 Action;                                          // WINTERNAL_DRV_ACT_*
    UINT32 MatchCount;                                      // populated on LIST
    UINT32 Status;                                          // NTSTATUS returned to NtLoadDriver
                                                            //   on DENY. 0 -> default
                                                            //   STATUS_ACCESS_DENIED.
    UINT32 Flags;                                           // populated on LIST; first entry
                                                            //   carries hook-live bit.
    UINT32 Reserved;
    WCHAR  Pattern[WINTERNAL_DRV_RULE_PATTERN_MAX];         // wildcard against service name
} WINTERNAL_DRV_RULE, *PWINTERNAL_DRV_RULE;

typedef struct _WINTERNAL_DRV_RULE_REMOVE_IN {
    UINT32 RuleId;
    UINT32 Reserved;
} WINTERNAL_DRV_RULE_REMOVE_IN, *PWINTERNAL_DRV_RULE_REMOVE_IN;

typedef struct _WINTERNAL_DRV_RULE_LIST_OUT {
    UINT32 Count;
    UINT32 Flags;                                           // WINTERNAL_DRV_RULE_FLAG_*
    WINTERNAL_DRV_RULE Rules[1];                            // [Count]
} WINTERNAL_DRV_RULE_LIST_OUT, *PWINTERNAL_DRV_RULE_LIST_OUT;

// ---- NTFS filter (NtCreateFile hook + rule list) ----
//
// Each rule is { pattern, action }. Patterns use Windows wildcard syntax
// (RtlIsNameInExpression): `*` any chars, `?` one char, `<` `>` `"`
// FSD-specific wildcards. The driver intercepts NtCreateFile, walks rules
// in insertion order, and applies the first-match action. Hook is
// installed lazily on first ADD and uninstalled on CLEAR / when the last
// rule is removed.
//
// Actions:
//   DENY      -> STATUS_ACCESS_DENIED
//   NOTFOUND  -> STATUS_OBJECT_NAME_NOT_FOUND  (file appears not to exist)
//   READONLY  -> strip GENERIC_WRITE/FILE_WRITE_DATA from DesiredAccess
//                (so the open succeeds but writes fail; useful for sealing
//                 specific files without breaking processes that just want
//                 to read them).
//   LOG       -> log to audit ring, allow through (instrumentation only).
#define IOCTL_WINTERNAL_NTFS_FILTER_ADD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x886, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_NTFS_FILTER_REMOVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x887, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_NTFS_FILTER_LIST   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x888, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINTERNAL_NTFS_FILTER_CLEAR  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x889, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WINTERNAL_FILTER_MAX_RULES    64
#define WINTERNAL_FILTER_PATTERN_MAX 260

#define WINTERNAL_FILTER_ACT_DENY     0
#define WINTERNAL_FILTER_ACT_NOTFOUND 1
#define WINTERNAL_FILTER_ACT_READONLY 2
#define WINTERNAL_FILTER_ACT_LOG      3

typedef struct _WINTERNAL_FILTER_RULE {
    UINT32 RuleId;                                       // 0 on ADD; assigned by driver
    UINT32 Action;                                       // WINTERNAL_FILTER_ACT_*
    UINT32 MatchCount;                                   // populated on LIST
    UINT32 Reserved;
    WCHAR  Pattern[WINTERNAL_FILTER_PATTERN_MAX];        // RtlIsNameInExpression syntax
} WINTERNAL_FILTER_RULE, *PWINTERNAL_FILTER_RULE;

typedef struct _WINTERNAL_FILTER_REMOVE_IN {
    UINT32 RuleId;
    UINT32 Reserved;
} WINTERNAL_FILTER_REMOVE_IN, *PWINTERNAL_FILTER_REMOVE_IN;

typedef struct _WINTERNAL_FILTER_LIST_OUT {
    UINT32 Count;
    UINT32 Reserved;
    WINTERNAL_FILTER_RULE Rules[1];                      // [Count]
} WINTERNAL_FILTER_LIST_OUT, *PWINTERNAL_FILTER_LIST_OUT;

typedef struct _WINTERNAL_SIGLEVEL_IN {
    UINT32 Pid;
    UINT8  SignatureLevel;       // SE_SIGNING_LEVEL_*
    UINT8  SectionSignatureLevel;
    UINT8  Reserved[2];
    UINT32 FieldOffset;          // 0 = driver default (0x878)
    UINT32 Reserved2;
} WINTERNAL_SIGLEVEL_IN, *PWINTERNAL_SIGLEVEL_IN;

typedef struct _WINTERNAL_SIGLEVEL_OUT {
    UINT8  PrevSignatureLevel;
    UINT8  PrevSectionSignatureLevel;
    UINT8  Reserved[2];
    UINT32 FieldOffsetUsed;
} WINTERNAL_SIGLEVEL_OUT, *PWINTERNAL_SIGLEVEL_OUT;

#define WINTERNAL_DEFAULT_SIGLEVEL_OFFSET 0x878
#define WINTERNAL_SIGLEVEL_WINDOWS        0x0C
#define WINTERNAL_SIGLEVEL_WINDOWS_TCB    0x0E

//
// ---- KCODE_PATCH ----
//
// Address: kernel virtual address to patch.
// Length:  number of bytes to write (max 64 per call).
// Data:    bytes to write.
//
#define WINTERNAL_KCODE_PATCH_MAX 64

typedef struct _WINTERNAL_KCODE_PATCH_IN {
    UINT64 Address;
    UINT32 Length;
    UINT32 Reserved;
    UCHAR  Data[WINTERNAL_KCODE_PATCH_MAX];
} WINTERNAL_KCODE_PATCH_IN, *PWINTERNAL_KCODE_PATCH_IN;

typedef struct _WINTERNAL_GET_TRUE_STUB_OUT {
    UINT64 Address;
} WINTERNAL_GET_TRUE_STUB_OUT, *PWINTERNAL_GET_TRUE_STUB_OUT;

typedef struct _WINTERNAL_GET_W32PROC_IN {
    UINT32 Pid;
    UINT32 Reserved;
} WINTERNAL_GET_W32PROC_IN, *PWINTERNAL_GET_W32PROC_IN;

typedef struct _WINTERNAL_GET_W32PROC_OUT {
    UINT64 Address;       // 0 if process has no Win32Process / not a GUI thread
} WINTERNAL_GET_W32PROC_OUT, *PWINTERNAL_GET_W32PROC_OUT;

//
// ---- Kernel-side process inspection ----
//
// Each handler takes a PID and returns the relevant snapshot. The driver
// performs the actual query via the Zw* / Ke* primitive that's PreviousMode-
// aware, so user-mode IAT/EAT/inline detours don't filter the result.
//

#define WINTERNAL_MAX_THREADS_PER_PROC 1024

typedef struct _WINTERNAL_PID_IN {
    UINT32 Pid;
    UINT32 Reserved;
} WINTERNAL_PID_IN, *PWINTERNAL_PID_IN;

typedef struct _WINTERNAL_THREAD_ENTRY {
    UINT32 Tid;
    UINT32 State;            // 0..9 (Initialized, Ready, Running, ...)
    UINT32 WaitReason;       // 0..40 (Executive, FreePage, Suspended, ...)
    INT32  Priority;
    UINT64 StartAddress;     // user-mode or kernel start address
    UINT64 KernelTime100Ns;
    UINT64 UserTime100Ns;
    UINT64 CreateTimeFt;
} WINTERNAL_THREAD_ENTRY, *PWINTERNAL_THREAD_ENTRY;

typedef struct _WINTERNAL_THREADS_OUT {
    UINT32 Count;
    UINT32 Reserved;
    WINTERNAL_THREAD_ENTRY Entries[1];   // [Count]
} WINTERNAL_THREADS_OUT, *PWINTERNAL_THREADS_OUT;

#define WINTERNAL_MITIGATION_COUNT 16

typedef struct _WINTERNAL_MITIGATION_ITEM {
    UINT32 PolicyId;
    INT32  NtStatus;          // 0 = OK; ERROR_INVALID_PARAMETER → unsupported
    UINT64 Value;
} WINTERNAL_MITIGATION_ITEM, *PWINTERNAL_MITIGATION_ITEM;

typedef struct _WINTERNAL_MITIGATIONS_OUT {
    UINT32 Count;
    UINT32 Reserved;
    WINTERNAL_MITIGATION_ITEM Items[WINTERNAL_MITIGATION_COUNT];
} WINTERNAL_MITIGATIONS_OUT, *PWINTERNAL_MITIGATIONS_OUT;

#define WINTERNAL_MAX_PRIVILEGES 64

typedef struct _WINTERNAL_TOKEN_PRIV {
    UINT64 Luid;
    UINT32 Attributes;
    UINT32 Reserved;
} WINTERNAL_TOKEN_PRIV;

typedef struct _WINTERNAL_TOKEN_INFO_OUT {
    UCHAR  UserSid[256];        // raw SID, null-padded
    UCHAR  IntegritySid[64];    // raw SID, null-padded
    UINT32 IntegrityRid;        // last subauth of IntegritySid for convenience
    UINT32 ElevationType;       // 1=default 2=full 3=limited
    UINT32 Elevated;
    UINT32 UIAccess;
    UINT32 SessionId;
    UINT32 PrivCount;
    WINTERNAL_TOKEN_PRIV Privileges[WINTERNAL_MAX_PRIVILEGES];
} WINTERNAL_TOKEN_INFO_OUT, *PWINTERNAL_TOKEN_INFO_OUT;

#define WINTERNAL_MAX_MEM_REGIONS 2048

typedef struct _WINTERNAL_MEM_REGION {
    UINT64 BaseAddress;
    UINT64 RegionSize;
    UINT32 State;       // MEM_COMMIT / MEM_RESERVE / MEM_FREE
    UINT32 Protect;     // PAGE_*
    UINT32 Type;        // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
    UINT32 Reserved;
} WINTERNAL_MEM_REGION, *PWINTERNAL_MEM_REGION;

typedef struct _WINTERNAL_MEM_QUERY_OUT {
    UINT32 Count;
    UINT32 Truncated;     // 1 if hit WINTERNAL_MAX_MEM_REGIONS cap
    WINTERNAL_MEM_REGION Entries[1];   // [Count]
} WINTERNAL_MEM_QUERY_OUT, *PWINTERNAL_MEM_QUERY_OUT;

//
// ---- Kernel callbacks ----
//
// Kinds: 1=PsSetCreateProcessNotifyRoutineEx array,
//        2=PsSetLoadImageNotifyRoutine array,
//        3=PsSetCreateThreadNotifyRoutine array.
// The driver returns the routine pointer for each entry and (best effort)
// the owning module's base + name by walking PsLoadedModuleList.
//
#define WINTERNAL_CB_KIND_PROCESS   1
#define WINTERNAL_CB_KIND_IMAGE     2
#define WINTERNAL_CB_KIND_THREAD    3

typedef struct _WINTERNAL_CB_IN {
    UINT32 Kind;
    UINT32 Reserved;
} WINTERNAL_CB_IN, *PWINTERNAL_CB_IN;

typedef struct _WINTERNAL_CB_ENTRY {
    UINT64 Routine;
    UINT64 ModuleBase;
    CHAR   ModuleName[64];      // NUL-terminated, 8.3-style short name
} WINTERNAL_CB_ENTRY, *PWINTERNAL_CB_ENTRY;

typedef struct _WINTERNAL_CB_LIST {
    UINT32 Count;
    UINT32 Reserved;
    WINTERNAL_CB_ENTRY Entries[1];
} WINTERNAL_CB_LIST, *PWINTERNAL_CB_LIST;

//
// ---- Driver list (PsLoadedModuleList walk) ----
//
typedef struct _WINTERNAL_DRIVER_ENTRY {
    UINT64 ImageBase;
    UINT32 ImageSize;
    UINT32 Reserved;
    CHAR   Name[128];
} WINTERNAL_DRIVER_ENTRY, *PWINTERNAL_DRIVER_ENTRY;

typedef struct _WINTERNAL_DRIVER_LIST {
    UINT32 Count;
    UINT32 Reserved;
    WINTERNAL_DRIVER_ENTRY Entries[1];
} WINTERNAL_DRIVER_LIST, *PWINTERNAL_DRIVER_LIST;

//
// ---- SSDT (KeServiceDescriptorTable) ----
//
typedef struct _WINTERNAL_SSDT_ENTRY {
    UINT32 Index;
    UINT32 Reserved;
    UINT64 Routine;
    UINT64 ModuleBase;
    CHAR   ModuleName[64];
} WINTERNAL_SSDT_ENTRY, *PWINTERNAL_SSDT_ENTRY;

typedef struct _WINTERNAL_SSDT_LIST {
    UINT32 Count;
    UINT32 Base;          // KiServiceTable base address (for cross-checks)
    WINTERNAL_SSDT_ENTRY Entries[1];
} WINTERNAL_SSDT_LIST, *PWINTERNAL_SSDT_LIST;

//
// ---- Kernel-mode hook ----
//
typedef struct _WINTERNAL_KHOOK_INSTALL_IN {
    UINT64 Target;
    UINT64 Detour;
    UINT32 PrologueSize;     // >= 14, <= 64
    UINT32 Reserved;
} WINTERNAL_KHOOK_INSTALL_IN, *PWINTERNAL_KHOOK_INSTALL_IN;

typedef struct _WINTERNAL_KHOOK_INSTALL_OUT {
    UINT64 Trampoline;       // kernel address; jmp here to invoke original
} WINTERNAL_KHOOK_INSTALL_OUT, *PWINTERNAL_KHOOK_INSTALL_OUT;

typedef struct _WINTERNAL_KHOOK_UNINSTALL_IN {
    UINT64 Target;
} WINTERNAL_KHOOK_UNINSTALL_IN, *PWINTERNAL_KHOOK_UNINSTALL_IN;

//
// ---- Kernel-mode Lua ----
//
// Layout of the input buffer:
//     UINT32 ScriptLength;
//     UINT32 Reserved;
//     CHAR   Script[ScriptLength];     // UTF-8, not NUL-terminated
//
// Output:
//     INT32  LuaStatus;                 // LUA_OK = 0 on success
//     UINT32 OutputLength;
//     CHAR   Output[OutputLength];      // captured prints + error text
//
#define WINTERNAL_LUA_MAX_SCRIPT  (4u * 1024u * 1024u)   // 4 MiB
#define WINTERNAL_LUA_OUT_DEFAULT (256u * 1024u)         // 256 KiB

typedef struct _WINTERNAL_LUA_IN {
    UINT32 ScriptLength;
    UINT32 Reserved;
    CHAR   Script[1];      // ScriptLength bytes
} WINTERNAL_LUA_IN, *PWINTERNAL_LUA_IN;

typedef struct _WINTERNAL_LUA_OUT {
    INT32  LuaStatus;
    UINT32 OutputLength;
    CHAR   Output[1];      // OutputLength bytes
} WINTERNAL_LUA_OUT, *PWINTERNAL_LUA_OUT;

//
// ---- Lockdown / audit ----
//
typedef struct _WINTERNAL_LOCKDOWN_OUT {
    UINT32 Engaged;        // 1 if lockdown is on
    UINT32 EngagedTickMs;  // KeQueryUnbiasedInterruptTime / 10000 at engage
} WINTERNAL_LOCKDOWN_OUT, *PWINTERNAL_LOCKDOWN_OUT;

// One audit row.
typedef struct _WINTERNAL_AUDIT_ROW {
    UINT64 TimestampNs;      // KeQueryInterruptTimePrecise (100ns units)
    UINT32 IoControlCode;
    UINT32 CallerPid;
    UINT64 Target;           // primary address argument (0 if N/A)
    UINT32 Length;           // bytes affected
    INT32  Status;           // NTSTATUS returned
} WINTERNAL_AUDIT_ROW, *PWINTERNAL_AUDIT_ROW;

typedef struct _WINTERNAL_AUDIT_OUT {
    UINT32 RowCount;
    UINT32 Reserved;
    WINTERNAL_AUDIT_ROW Rows[1];
} WINTERNAL_AUDIT_OUT, *PWINTERNAL_AUDIT_OUT;

//
// ---- Force unload driver ----
//
// Name is the short driver name without the "\Driver\" prefix. The driver
// resolves the full name internally. Wide-char to match how driver names
// are stored in the kernel.
//
#define WINTERNAL_DRIVER_NAME_MAX 64
typedef struct _WINTERNAL_FORCE_UNLOAD_IN {
    WCHAR Name[WINTERNAL_DRIVER_NAME_MAX];
} WINTERNAL_FORCE_UNLOAD_IN, *PWINTERNAL_FORCE_UNLOAD_IN;

//
// ---- Kernel-level service registration ----
//
#define WINTERNAL_DRIVER_PATH_MAX 260
typedef struct _WINTERNAL_KDRV_REGISTER_IN {
    WCHAR Name[WINTERNAL_DRIVER_NAME_MAX];
    WCHAR ImagePath[WINTERNAL_DRIVER_PATH_MAX];  // NT path: \??\C:\... or %SystemRoot%\system32\drivers\...
    UINT32 StartType;          // SERVICE_DEMAND_START (3) by default
    UINT32 Reserved;
} WINTERNAL_KDRV_REGISTER_IN, *PWINTERNAL_KDRV_REGISTER_IN;

typedef struct _WINTERNAL_KDRV_NAME_IN {
    WCHAR Name[WINTERNAL_DRIVER_NAME_MAX];
} WINTERNAL_KDRV_NAME_IN, *PWINTERNAL_KDRV_NAME_IN;

typedef struct _WINTERNAL_KDRV_SET_START_IN {
    WCHAR  Name[WINTERNAL_DRIVER_NAME_MAX];
    UINT32 StartType;          // 0 boot, 1 system, 2 auto, 3 demand, 4 disabled
    UINT32 Reserved;
} WINTERNAL_KDRV_SET_START_IN, *PWINTERNAL_KDRV_SET_START_IN;
