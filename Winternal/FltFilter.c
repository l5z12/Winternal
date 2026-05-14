// FltFilter.c — minifilter framework wrapper for the NTFS file-open
// filter. Compiled as a SEPARATE TU because <fltKernel.h> pulls in
// <ntifs.h>, which redefines PEPROCESS/PETHREAD etc. relative to the
// KMDF/ntddk.h-flavored definitions Queue.c uses. Keeping them in
// different TUs lets each TU pick the right view of the kernel types.
//
// Bridge to the rest of the driver:
//   * The rule list + IOCTL handlers live in Queue.c.
//   * Queue.c exposes WinternalFilterEvaluate(name, &ruleId) which
//     consults the spinlock-protected rule list and returns the action
//     to apply (deny / notfound / readonly / log / -1 = no match).
//   * Queue.c exposes WinternalFilterAudit(ruleId, action) to bridge
//     to the audit ring.
//   * Queue.c calls WinternalFilterRegister/Unregister to install or
//     tear down the minifilter as rules come and go.
//
// HVCI-compatibility: FltRegisterFilter / FltStartFiltering go through
// the documented fltmgr.sys path. No CR0.WP toggle, no kernel-code
// writes — the hypervisor allows it.

#include <fltKernel.h>

#include "../Winternal/Public.h"  // WINTERNAL_FILTER_ACT_* + IOCTL codes

// --- bridges into Queue.c (linked from the other TU) ----------------------
extern UINT32 WinternalFilterEvaluate(_In_ PUNICODE_STRING Name, _Out_ UINT32* outRuleId);
extern VOID   WinternalFilterAudit(UINT32 ruleId, NTSTATUS action);

// --- minifilter state -----------------------------------------------------
static PFLT_FILTER g_FilterHandle   = NULL;
static BOOLEAN     g_FilterMfActive = FALSE;

// --- callbacks ------------------------------------------------------------

static FLT_PREOP_CALLBACK_STATUS FLTAPI
WinternalFltPreCreate(_Inout_ PFLT_CALLBACK_DATA Data,
                      _In_    PCFLT_RELATED_OBJECTS FltObjects,
                      _Outptr_result_maybenull_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Resolve the file name for matching. NORMALIZED form gives the
    // canonical \Device\HarddiskVolume...\path layout we want to match
    // against; QUERY_DEFAULT means use the filesystem's default I/O
    // path (faster than ALWAYS_ALLOW_CACHE_LOOKUP and good enough for
    // pre-create).
    PFLT_FILE_NAME_INFORMATION fni = NULL;
    NTSTATUS s = FltGetFileNameInformation(Data,
                    FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                    &fni);
    if (!NT_SUCCESS(s) || !fni) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    (void)FltParseFileNameInformation(fni);

    UINT32 ruleId = 0;
    UINT32 action = WinternalFilterEvaluate(&fni->Name, &ruleId);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "[winternal] flt.PreCreate: %wZ -> action=%u\n",
               &fni->Name, action);
    FltReleaseFileNameInformation(fni);

    if (action == (UINT32)-1) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    WinternalFilterAudit(ruleId, (NTSTATUS)action);

    if (action == WINTERNAL_FILTER_ACT_LOG) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (action == WINTERNAL_FILTER_ACT_READONLY) {
        // Strip write-side bits from the create's security context so
        // the open succeeds with read-only access. Read attempts go
        // through; writes get STATUS_ACCESS_DENIED at the FSD.
        if (Data->Iopb->Parameters.Create.SecurityContext) {
            ACCESS_MASK* access =
                &Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
            *access &= ~(FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
                         FILE_WRITE_EA   | DELETE           | WRITE_DAC | WRITE_OWNER |
                         GENERIC_WRITE   | GENERIC_ALL);
            FltSetCallbackDataDirty(Data);
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // DENY / NOTFOUND — short-circuit the IRP with the chosen NTSTATUS.
    Data->IoStatus.Status      = (action == WINTERNAL_FILTER_ACT_NOTFOUND)
                                    ? STATUS_OBJECT_NAME_NOT_FOUND
                                    : STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static NTSTATUS FLTAPI
WinternalFltUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle   = NULL;
        g_FilterMfActive = FALSE;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS FLTAPI
WinternalFltInstanceSetupCallback(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                                  _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                                  _In_ DEVICE_TYPE VolumeDeviceType,
                                  _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[winternal] flt.InstanceSetup: deviceType=0x%x fsType=%d\n",
               VolumeDeviceType, VolumeFilesystemType);
    // Accept all volumes — the rule list itself decides what's filtered.
    return STATUS_SUCCESS;
}

static const FLT_OPERATION_REGISTRATION g_FilterOps[] = {
    { IRP_MJ_CREATE, 0, WinternalFltPreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                                      // Flags
    NULL,                                   // ContextRegistration
    g_FilterOps,                            // OperationRegistration
    WinternalFltUnloadCallback,             // FilterUnloadCallback
    WinternalFltInstanceSetupCallback,      // InstanceSetupCallback
    NULL,                                   // InstanceQueryTeardownCallback
    NULL,                                   // InstanceTeardownStartCallback
    NULL,                                   // InstanceTeardownCompleteCallback
};

// --- exports for Queue.c --------------------------------------------------

NTSTATUS WinternalFilterRegister(_In_ PDRIVER_OBJECT DriverObject)
{
    if (g_FilterMfActive) return STATUS_SUCCESS;
    if (!DriverObject)    return STATUS_DRIVER_INTERNAL_ERROR;

    NTSTATUS s = FltRegisterFilter(DriverObject,
                                   &g_FilterRegistration,
                                   &g_FilterHandle);
    if (!NT_SUCCESS(s)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[winternal] FltRegisterFilter -> 0x%08X. Need the Instances\n"
                   "  registry key under Services\\Winternal — `winternal install`\n"
                   "  sets it up. Reinstall if you're seeing STATUS_FLT_NOT_INITIALIZED.\n",
                   s);
        g_FilterHandle = NULL;
        return s;
    }
    s = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(s)) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return s;
    }
    g_FilterMfActive = TRUE;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
               "[winternal] minifilter registered + FltStartFiltering OK\n");
    return STATUS_SUCCESS;
}

VOID WinternalFilterUnregister(VOID)
{
    if (!g_FilterMfActive) return;
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }
    g_FilterMfActive = FALSE;
}

BOOLEAN WinternalFilterIsActive(VOID)
{
    return g_FilterMfActive;
}
