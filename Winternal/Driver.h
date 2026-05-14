/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>

#include "device.h"
#include "queue.h"
#include "trace.h"

EXTERN_C_START

//
// WDFDRIVER events. Winternal is a *non-PnP* control-device driver — it
// has no hardware behind it and is loaded via SCM (`sc start`). DriverEntry
// allocates the control device directly via WdfControlDeviceInitAllocate
// instead of waiting for an EvtDeviceAdd that would never fire.
//
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_OBJECT_CONTEXT_CLEANUP WinternalEvtDriverContextCleanup;

EXTERN_C_END
