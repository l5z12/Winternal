/*++

Module Name:

    driver.c

Abstract:

    DriverEntry + driver-context cleanup. Winternal is a *non-PnP* KMDF
    driver: there's no hardware to enumerate, the .sys is loaded via SCM
    (`sc start`), and the control device is allocated immediately from
    DriverEntry rather than from an EvtDeviceAdd callback that would
    never fire under non-PnP load.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "driver.tmh"

// Defined in Queue.c. Forward-declared here so DriverContextCleanup can call
// it at unload time, after which any in-flight detour code would dangle.
VOID WinternalKhookUninstallAll(VOID);

// Defined in Queue.c. Hands the protect/Ob path our own DRIVER_OBJECT so it
// can patch the loader's "forced integrity" flag bit before calling
// ObRegisterCallbacks (which would otherwise STATUS_ACCESS_DENY any caller
// whose loader entry lacks that bit).
VOID WinternalProtectSetSelf(PDRIVER_OBJECT Self);

// Minifilter — registers at DriverEntry so FltMgr does the volume
// attachment dance at the right time. Implementation in FltFilter.c.
NTSTATUS WinternalFilterRegister(PDRIVER_OBJECT DriverObject);
VOID     WinternalFilterUnregister(VOID);

// Defined in Device.c.
NTSTATUS WinternalCreateControlDevice(_In_ WDFDRIVER Driver);

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, WinternalEvtDriverContextCleanup)
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver;
    NTSTATUS status;

    WPP_INIT_TRACING(DriverObject, RegistryPath);
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    // Hand our own DriverObject to the protect/Ob path so it can flip the
    // loader's "forced integrity" bit before any ObRegisterCallbacks call.
    WinternalProtectSetSelf(DriverObject);

    // Register the minifilter early — FltStartFiltering needs to run
    // during driver load for the Filter Manager to attach instances to
    // already-mounted volumes. Late registration from an IOCTL handler
    // registers but doesn't attach; pre-create then never fires. We
    // tolerate a failure here (other features still work) but log it.
    {
        NTSTATUS fltStatus = WinternalFilterRegister(DriverObject);
        if (!NT_SUCCESS(fltStatus)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                       "[winternal] minifilter init failed 0x%08X — "
                       "`ntfs filter` will be inert until reinstalled.\n",
                       fltStatus);
        }
    }

    //
    // Non-PnP framework driver. The control device is created below in
    // WinternalCreateControlDevice; we don't supply an EvtDeviceAdd.
    //
    // EvtDriverUnload is REQUIRED here for SCM `sc stop` to work: without
    // it, KMDF's non-PnP scaffolding never sets DriverObject->DriverUnload,
    // and ControlService(STOP) bounces with ERROR_INVALID_SERVICE_CONTROL
    // (1052). Setting it wires the framework's DriverUnload chain, which
    // calls WinternalEvtDriverUnload before tearing the queue down.
    //
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags = WdfDriverInitNonPnpDriver;
    config.DriverPoolTag   = 'WnTl';
    config.EvtDriverUnload = WinternalEvtDriverUnload;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = WinternalEvtDriverContextCleanup;

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, &driver);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WdfDriverCreate failed %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    status = WinternalCreateControlDevice(driver);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WinternalCreateControlDevice failed %!STATUS!", status);
        // The framework will tear down the driver object; cleanup callback runs.
        WPP_CLEANUP(DriverObject);
        return status;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit OK");
    return STATUS_SUCCESS;
}

VOID
WinternalEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    // Uninstall every kernel inline hook before our image disappears.
    WinternalKhookUninstallAll();

    WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)DriverObject));
}
