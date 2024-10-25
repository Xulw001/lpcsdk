#include <ntifs.h>
#include <stdio.h>
#include <wdm.h>
//
#include "lpc_user.h"

HANDLE hThread = NULL;
bool g_thread_stop = false;

VOID FilterUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    if (hThread) {
        g_thread_stop = false;
        ZwWaitForSingleObject(hThread, FALSE, NULL);
        ZwClose(hThread);
    }
    LOG("Driver UnLoad\n");
}

static VOID LPCWorkThreadRoutine(PVOID pStartContext) {
    UNREFERENCED_PARAMETER(pStartContext);
    int times = 1;
    while (g_thread_stop) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10 * 1000 * 1000;
        timeout.QuadPart *= 5;
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
        CHAR buffer[260];
        sprintf_s(buffer, "Hi Mon, I need your help at %d!", times++);
        SIZE_T responselen = 0;
        if (lpc::LPC_ERROR_SUCCESS == lpc::LPCIoctl(0x1, (PUINT8)buffer, strlen(buffer), (PUINT8)buffer, &responselen)) {
            LOG("[User Response]:%s", buffer);
        }
    }
    g_thread_stop = false;
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID StartLpcWork() {
    g_thread_stop = true;
    NTSTATUS status = PsCreateSystemThread(&hThread, 0, NULL, NtCurrentProcess(), NULL, LPCWorkThreadRoutine, NULL);
    if (!NT_SUCCESS(status)) {
        LOG("PsCreateSystemThread failed at %ld\n", status);
        return;
    }
}

//
// DriverEntry
//
_Function_class_(DRIVER_INITIALIZE)
    _IRQL_requires_same_
    _IRQL_requires_(PASSIVE_LEVEL)
EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject,
                              _In_ PUNICODE_STRING pusRegistryPath) {
    // Enable POOL_NX_OPTIN
    // Set NonPagedPool
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
    UNREFERENCED_PARAMETER(pusRegistryPath);

    //
    // Init global data
    //
    BOOLEAN fSuccess = FALSE;
    __try {
        pDriverObject->DriverUnload = FilterUnload;
        StartLpcWork();
        LOG("Driver Load\n");
        fSuccess = true;
    } __finally {
        if (!fSuccess) {
            FilterUnload(pDriverObject);
        }
    }

    return STATUS_SUCCESS;
}