/*++

Module Name:

    queue.h

Abstract:

    This file contains the queue definitions.

Environment:

    Kernel-mode Driver Framework

--*/

EXTERN_C_START

//
// This is the context that can be placed per queue
// and would contain per queue information.
//
typedef struct _QUEUE_CONTEXT {

    ULONG PrivateDeviceData;  // just a placeholder

} QUEUE_CONTEXT, *PQUEUE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUEUE_CONTEXT, QueueGetContext)

NTSTATUS
WinternalQueueInitialize(
    _In_ WDFDEVICE Device
    );

NTSTATUS
WinternalEnumProcessIds(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWritten
    );

//
// Events from the IoQueue object
//
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL WinternalEvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_STOP WinternalEvtIoStop;

// EvtDriverUnload: SCM `sc stop` path. Sets the dispatch gate, waits for
// in-flight IOCTLs to drain, uninstalls every kernel inline hook. Wiring
// this callback is what makes SCM advertise SERVICE_ACCEPT_STOP — KMDF
// only sets DriverObject->DriverUnload on non-PnP drivers that opt in.
EVT_WDF_DRIVER_UNLOAD WinternalEvtDriverUnload;

EXTERN_C_END
