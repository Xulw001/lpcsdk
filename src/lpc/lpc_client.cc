#include <wdm.h>
//
#include "lpc.hpp"
#include "lpc_client.hpp"
#include "lpc_user.h"

namespace lpc {

typedef struct _ZwLPCFuncTable {
    pFuncZwConnectPort ZwConnectPort;
    pFuncZwRequestWaitReplyPort ZwRequestWaitReplyPort;
} ZwLPCFuncTable;

static UNICODE_STRING LpcPortName = RTL_CONSTANT_STRING(LPC_PORT_NAME);
static UNICODE_STRING ustrZwConnectPort = RTL_CONSTANT_STRING(L"ZwConnectPort");
static UNICODE_STRING ustrZwRequestWaitReplyPort = RTL_CONSTANT_STRING(L"ZwRequestWaitReplyPort");

static ZwLPCFuncTable lpc_table_;
#define ZwConnectPort lpc_table_.ZwConnectPort
#define ZwRequestWaitReplyPort lpc_table_.ZwRequestWaitReplyPort

/// @brief 初始化LPC函数表
/// @return
static bool InitLPCLibrary() {
    if (NULL == ZwConnectPort || NULL == ZwRequestWaitReplyPort) {
        ZwConnectPort = (pFuncZwConnectPort)MmGetSystemRoutineAddress(&ustrZwConnectPort);
        ZwRequestWaitReplyPort = (pFuncZwRequestWaitReplyPort)MmGetSystemRoutineAddress(&ustrZwRequestWaitReplyPort);
        if (ZwConnectPort == NULL || ZwRequestWaitReplyPort == NULL) {
            LOG("InitLPCLibrary failed!");
            return false;
        }
    }

    return true;
}

/// @brief 连接默认的LPC端口
/// @param pConnInfo LPC连接信息
/// @return
static bool ConnectPort(PCONN_INFO pConnInfo) {
    NTSTATUS status;
    HANDLE SectionHandle = NULL;
    LARGE_INTEGER SectionSize;
    SectionSize.QuadPart = LARGE_MESSAGE_SIZE;
    // 创建用于数据映射的内存节
    status = ZwCreateSection(&SectionHandle,
                             SECTION_MAP_READ | SECTION_MAP_WRITE,
                             NULL,  // Backed by the pagefile
                             &SectionSize,
                             PAGE_READWRITE,
                             SEC_COMMIT,
                             NULL);
    if (!NT_SUCCESS(status)) {
        LOG("ZwCreateSection failed at 0x%x!", status);
        return false;
    }

    HANDLE hConnectionPort;
    SECURITY_QUALITY_OF_SERVICE sqos;
    PORT_VIEW ClientView;
    REMOTE_PORT_VIEW ServerView;
    ULONG MaxMessageLength;

    sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    sqos.ImpersonationLevel = SecurityImpersonation;
    sqos.EffectiveOnly = FALSE;
    sqos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    ClientView.Length = sizeof(PORT_VIEW);
    ClientView.SectionHandle = SectionHandle;
    ClientView.SectionOffset = 0;
    ClientView.ViewSize = LARGE_MESSAGE_SIZE;
    ClientView.ViewBase = 0;
    ServerView.Length = sizeof(REMOTE_PORT_VIEW);
    ServerView.ViewBase = 0;
    ServerView.ViewSize = 0;

    // 连接LPC端口
    status = ZwConnectPort(
        &hConnectionPort,
        &LpcPortName,
        &sqos,
        &ClientView,
        &ServerView,
        (PULONG)&MaxMessageLength,
        NULL,
        NULL);
    if (NT_SUCCESS(status)) {
        pConnInfo->hPort = hConnectionPort;
        pConnInfo->pInData = (PUINT8)ClientView.ViewBase;
        pConnInfo->pOutData = (PUINT8)ServerView.ViewBase;
        pConnInfo->hSection = SectionHandle;

        return true;
    } else {
        LOG("ZwConnectPort failed at 0x%x!", status);
        ZwClose(SectionHandle);
        SectionHandle = NULL;
    }

    return false;
}

/// @brief 释放LPC连接资源
/// @param pConnInfo LPC连接信息
/// @return
static void ClosePort(IN PCONN_INFO pConnInfo) {
    if (pConnInfo->hPort) {
        ZwClose(pConnInfo->hPort);
        pConnInfo->hPort = NULL;
    }

    if (pConnInfo->hSection) {
        ZwClose(pConnInfo->hSection);
        pConnInfo->hSection = NULL;
        pConnInfo->pInData = NULL;
        pConnInfo->pOutData = NULL;
    }
}

/// @brief 构建LPC请求消息
/// @param pRequest 指向LPC请求消息的缓冲区
/// @param pConnInfo LPC连接信息
/// @param cmd 通信指令
/// @param request 请求消息的缓冲区
/// @param requestLen 请求消息长度
static void BuildLPCRequestMessage(PLPC_MSG pRequest, PCONN_INFO pConnInfo, ULONG cmd, UINT8* request, SIZE_T requestLen) {
    if (requestLen > MAX_LPC_DATA_LENGTH) {
        InitializeMessageHeader(&pRequest->Header, sizeof(LPC_MSG), 0);
        pRequest->Command = cmd;
        pRequest->DataSize = (ULONG)requestLen;
        pRequest->UseSection = true;
        if (request) {
            RtlCopyMemory(pConnInfo->pInData, request, requestLen);
        }
    } else {
        InitializeMessageHeader(&pRequest->Header, sizeof(LPC_MSG) + requestLen, 0);
        pRequest->Command = cmd;
        pRequest->DataSize = (ULONG)requestLen;
        pRequest->UseSection = false;
        if (request) {
            RtlCopyMemory(pRequest->Content, request, requestLen);
        }
    }
}

static PVOID Alloc(size_t nSize, POOL_TYPE ePoolType) {
    nSize = (nSize != 0) ? nSize : 1;
    PVOID result = ExAllocatePoolWithTag(ePoolType, nSize, 'gttm');
    if (result) {
        RtlZeroMemory(result, nSize);
    }
    return result;
}

static VOID Free(PVOID pObject) {
    if (pObject) {
        ExFreePool(pObject);
    }
}

LPC_ERROR LPCIoctl(ULONG cmd, UINT8* request, SIZE_T requestLen, UINT8* response, SIZE_T* responseLen) {
    CONN_INFO ConnInfo = {NULL, NULL, NULL, NULL};
    PLPC_MSG pRequest = NULL, pResponse = NULL;

    __try {
        // 检测输入输出参数
        if ((NULL == request && 0 != requestLen) || (NULL == response && 0 != responseLen)) {
            return LPC_ERROR_INVALID_PARAMETER;
        }

        if (!InitLPCLibrary()) {
            return LPC_ERROR_INTERNAL;
        }

        // 创建接受和发送缓冲区
        pRequest = (PLPC_MSG)Alloc(MAX_LPC_MESSAGE_LENGTH, NonPagedPool);
        pResponse = (PLPC_MSG)Alloc(MAX_LPC_MESSAGE_LENGTH, NonPagedPool);
        if (NULL == pRequest || NULL == pResponse) {
            return LPC_ERROR_INTERNAL;
        }

        // 连接LPC
        if (!ConnectPort(&ConnInfo)) {
            return LPC_ERROR_CONNECTED_FAILED;
        }

        BuildLPCRequestMessage(pRequest, &ConnInfo, cmd, request, requestLen);

        // 发送消息等待回复
        NTSTATUS status = ZwRequestWaitReplyPort(ConnInfo.hPort, (PPORT_MESSAGE)pRequest, (PPORT_MESSAGE)pResponse);
        if (!NT_SUCCESS(status)) {
            LOG("ZwRequestWaitReplyPort failed at 0x%x!", status);
            return LPC_ERROR_DISCONNECTED;
        }

        if (pResponse->Command == (ULONG)-1) {
            return LPC_ERROR_COMMAND_UNSUPPORT;
        }

        if (pResponse->DataSize == (ULONG)-1) {
            return LPC_ERROR_INVALID_PARAMETER;
        }

        if (pResponse->DataSize < (*responseLen) ? (*responseLen) : pResponse->DataSize) {
            (*responseLen) = pResponse->DataSize;
        }

        if (response) {
            if (pResponse->UseSection) {
                if (ConnInfo.pOutData) {
                    RtlCopyMemory(response, ConnInfo.pOutData, *responseLen);
                }
            } else {
                RtlCopyMemory(response, pResponse->Content, *responseLen);
            }
        }

        return LPC_ERROR_SUCCESS;

    } __finally {
        if (pRequest) {
            Free(pRequest);
        }

        if (pResponse) {
            Free(pResponse);
        }

        ClosePort(&ConnInfo);
    }
}

}  // namespace lpc
