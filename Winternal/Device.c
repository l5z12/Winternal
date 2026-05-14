/*++

Module Name:

    device.c

Abstract:

    Control-device creation. Called once from DriverEntry. Because Winternal
    is non-PnP, this is where the only WDFDEVICE in the driver is set up.

    Wiring:
      1. WdfControlDeviceInitAllocate (with SDDL restricting opens to
         SYSTEM + Administrators)
      2. WdfDeviceInitAssignName so user mode can CreateFile(L"\\\\.\\Winternal")
      3. WdfDeviceCreate
      4. WdfDeviceCreateSymbolicLink for the DOS-namespace alias
      5. WinternalQueueInitialize to wire the IOCTL queue
      6. WdfControlFinishInitializing — REQUIRED for control devices,
         otherwise user-mode opens block waiting for "PnP start"

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "device.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, WinternalCreateControlDevice)
#endif

NTSTATUS
WinternalCreateControlDevice(
    _In_ WDFDRIVER Driver
    )
{
    PWDFDEVICE_INIT deviceInit = NULL;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    PDEVICE_CONTEXT deviceContext;
    WDFDEVICE device;
    NTSTATUS status;

    DECLARE_CONST_UNICODE_STRING(deviceName, WINTERNAL_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(symLink,    WINTERNAL_SYMLINK_NAME);
    DECLARE_CONST_UNICODE_STRING(sddl,       WINTERNAL_DEVICE_SDDL);

    PAGED_CODE();

    //
    // Allocate a control-device init block. The SDDL passed here is the
    // canonical access mask resolved by the I/O manager when user-mode
    // calls CreateFile on the symbolic link — anything below
    // Builtin Administrators fails at open with ERROR_ACCESS_DENIED.
    //
    deviceInit = WdfControlDeviceInitAllocate(Driver, &sddl);
    if (deviceInit == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetExclusive(deviceInit, FALSE);

    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        // On failure WdfDeviceCreate consumes deviceInit only on success;
        // when it fails we must free it explicitly.
        if (deviceInit) WdfDeviceInitFree(deviceInit);
        return status;
    }

    deviceContext = DeviceGetContext(device);
    deviceContext->PrivateDeviceData = 0;

    status = WdfDeviceCreateSymbolicLink(device, &symLink);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WinternalQueueInitialize(device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // CRITICAL for control devices. Without this, the framework blocks
    // user-mode opens waiting for a PnP start that will never come.
    WdfControlFinishInitializing(device);

    return STATUS_SUCCESS;
}
