// NT API declarations and structs not available in the public Windows SDK.
// Tries to reuse <winternl.h> where possible and only adds what's missing.
#pragma once
#include <Windows.h>
#include <winternl.h>

namespace winternal::nt {

// Status codes not in winternl.h.
constexpr LONG kStatusInfoLengthMismatch = 0xC0000004L;
constexpr LONG kStatusBufferTooSmall     = 0xC0000023L;
constexpr LONG kStatusMoreEntries        = 0x00000105L;
constexpr LONG kStatusNoMoreEntries      = 0x8000001AL;

// SYSTEM_INFORMATION_CLASS values used by this project (winternl defines a subset).
constexpr SYSTEM_INFORMATION_CLASS SystemProcessInformationClass         = static_cast<SYSTEM_INFORMATION_CLASS>(5);
constexpr SYSTEM_INFORMATION_CLASS SystemModuleInformationClass          = static_cast<SYSTEM_INFORMATION_CLASS>(11);
constexpr SYSTEM_INFORMATION_CLASS SystemHandleInformationClass          = static_cast<SYSTEM_INFORMATION_CLASS>(16);
constexpr SYSTEM_INFORMATION_CLASS SystemExtendedHandleInformationClass  = static_cast<SYSTEM_INFORMATION_CLASS>(64);

// PROCESSINFOCLASS values (winternl defines ProcessBasicInformation as 0).
constexpr PROCESSINFOCLASS ProcessBasicInformationClass = static_cast<PROCESSINFOCLASS>(0);

// OBJECT_INFORMATION_CLASS values (winternl.h defines the enum as type with
// ObjectBasicInformation=0 and ObjectTypeInformation=2; cast to add others).
constexpr OBJECT_INFORMATION_CLASS ObjectNameInformationClass     = static_cast<OBJECT_INFORMATION_CLASS>(1);
constexpr OBJECT_INFORMATION_CLASS ObjectTypeInformationClass     = static_cast<OBJECT_INFORMATION_CLASS>(2);
constexpr OBJECT_INFORMATION_CLASS ObjectAllTypesInformationClass = static_cast<OBJECT_INFORMATION_CLASS>(3);

// Minimal type-information record (just the name; the rest of the struct
// involves POOL_TYPE which is kernel-only — we don't need those fields).
struct OBJECT_TYPE_INFORMATION_MIN {
    UNICODE_STRING TypeName;
    BYTE Reserved[88];   // padding so the next aligned record is at expected offset
};

// SYSTEM_PROCESS_INFORMATION (extended layout used by SystemProcessInformation).
struct SYSTEM_THREAD_INFORMATION_X {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
};

struct SYSTEM_PROCESS_INFORMATION_X {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION_X Threads[1];
};

// RTL_PROCESS_MODULES (kernel module list).
struct RTL_PROCESS_MODULE_INFORMATION_X {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};

struct RTL_PROCESS_MODULES_X {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION_X Modules[1];
};

// SYSTEM_HANDLE_INFORMATION_EX
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_X {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SYSTEM_HANDLE_INFORMATION_EX_X {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_X Handles[1];
};

// OBJECT_DIRECTORY_INFORMATION
struct OBJECT_DIRECTORY_INFORMATION_X {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
};

// Functions in ntdll not declared by winternl.h.
extern "C" {
NTSTATUS NTAPI NtSuspendProcess(HANDLE);
NTSTATUS NTAPI NtResumeProcess(HANDLE);
NTSTATUS NTAPI NtOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NTAPI NtQueryDirectoryObject(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);
} // extern "C"

constexpr ACCESS_MASK kDirQuery    = 0x0001;
constexpr ACCESS_MASK kDirTraverse = 0x0002;

constexpr ULONG kDuplicateCloseSource = 0x00000001;
constexpr ULONG kDuplicateSameAccess  = 0x00000002;

inline VOID InitializeObjectAttributesX(POBJECT_ATTRIBUTES p, PUNICODE_STRING n, ULONG attr, HANDLE root, PSECURITY_DESCRIPTOR sd) {
    p->Length = sizeof(OBJECT_ATTRIBUTES);
    p->RootDirectory = root;
    p->ObjectName = n;
    p->Attributes = attr;
    p->SecurityDescriptor = sd;
    p->SecurityQualityOfService = nullptr;
}

} // namespace winternal::nt
