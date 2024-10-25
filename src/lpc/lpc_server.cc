#ifndef _NTDDK_
#include "lpc_server.hpp"

#include "lpc.hpp"
#include "lpc_user.h"

namespace lpc {

LPCServer& LPCServer::GetInstance() {
    static LPCServer instance;
    return instance;
}

/// @brief 创建LPC通信端口
/// @return LPC通信端口的句柄
static HANDLE CreatePort() {
    NTSTATUS status;
    UNICODE_STRING unicodePortName;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE hPort = INVALID_HANDLE_VALUE;

    RtlInitUnicodeString(&unicodePortName, LPC_PORT_NAME);
    InitializeObjectAttributes(
        &objectAttributes,
        &unicodePortName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    // 创建LPC端口
    status = NtCreatePort(&hPort,
                          &objectAttributes,
                          sizeof(PORT_MESSAGE),
                          MAX_LPC_MESSAGE_LENGTH,
                          0);
    if (!NT_SUCCESS(status)) {
        LOG("NtCreatePort failed at 0x%x", status);
    }

    return hPort;
}

/// @brief 获取LPC消息类型
/// @param request 指向LPC消息的缓冲区
/// @return LPC消息类型
static USHORT GetMessageType(PLPC_MSG request) {
    return request->Header.u2.s2.Type;
}

/// @brief 处理LPC连接请求
/// @param request 指向LPC消息的缓冲区
/// @param Accept 是否拒绝连接
/// @param pConnInfo 指向LPC连接信息的缓冲区
/// @return
static bool HandlerConnection(PLPC_MSG request, BOOLEAN Accept, PCONN_INFO pConnInfo) {
    NTSTATUS status;
    HANDLE SectionHandle = NULL;
    LARGE_INTEGER SectionSize = {LARGE_MESSAGE_SIZE};
    // 创建用于数据映射的内存节
    status = NtCreateSection(&SectionHandle,
                             SECTION_MAP_READ | SECTION_MAP_WRITE,
                             NULL,  // Backed by the pagefile
                             &SectionSize,
                             PAGE_READWRITE,
                             SEC_COMMIT,
                             NULL);
    if (!NT_SUCCESS(status)) {
        LOG("NtCreateSection failed at 0x%x", status);
        return false;
    }

    REMOTE_PORT_VIEW ClientView = {};
    PORT_VIEW ServerView = {};
    ServerView.Length = sizeof(PORT_VIEW);
    ServerView.SectionHandle = SectionHandle;
    ServerView.SectionOffset = 0;
    ServerView.ViewSize = LARGE_MESSAGE_SIZE;
    ClientView.Length = sizeof(REMOTE_PORT_VIEW);
    // 接受或者拒绝LPC连接请求
    status = NtAcceptConnectPort(
        &pConnInfo->hPort,
        NULL,
        (PPORT_MESSAGE)&request->Header,
        Accept,
        &ServerView,
        &ClientView);
    if (!NT_SUCCESS(status)) {
        LOG("NtAcceptConnectPort failed at 0x%x", status);
        NtClose(SectionHandle);
        SectionHandle = NULL;
        return false;
    }

    // 完成LPC连接请求
    status = NtCompleteConnectPort(pConnInfo->hPort);
    if (!NT_SUCCESS(status)) {
        LOG("NtCompleteConnectPort failed at 0x%x", status);
        NtClose(SectionHandle);
        SectionHandle = NULL;
        NtClose(pConnInfo->hPort);
        pConnInfo->hPort = NULL;
        return false;
    }

    pConnInfo->hSection = SectionHandle;
    // 接收缓冲区
    pConnInfo->pInData = (PUINT8)ClientView.ViewBase;
    // 发送缓冲区
    pConnInfo->pOutData = (PUINT8)ServerView.ViewBase;
    return true;
}

/// @brief 响应LPC消息
/// @param hReplyPort LPC连接端口
/// @param replyBuffer LPC响应消息
/// @return
bool ReplyMessage(HANDLE hReplyPort, PLPC_MSG replyBuffer) {
    NTSTATUS status = NtReplyPort(hReplyPort, (PPORT_MESSAGE)replyBuffer);
    if (!NT_SUCCESS(status)) {
        LOG("NtReplyPort failed at 0x%x", status);
        return false;
    }

    return true;
}

/// @brief 释放LPC连接资源
/// @param pConnInfo LPC连接信息
/// @return
static bool CloseConnection(PCONN_INFO pConnInfo) {
    NTSTATUS status;
    if (pConnInfo->hSection) {
        status = NtClose(pConnInfo->hSection);
        if (!NT_SUCCESS(status)) {
            ;
        }
    }
    if (pConnInfo->hPort) {
        status = NtClose(pConnInfo->hPort);
        if (!NT_SUCCESS(status)) {
            ;
        }
    }
    pConnInfo->hPort = NULL;
    pConnInfo->hSection = NULL;
    return true;
}

bool LPCServer::Start() {
    lpc_server_ = CreatePort();
    if (lpc_server_ == NULL) {
        return false;
    }
    monitor_ = true;
    lpc_main_ = std::thread(std::bind(&LPCServer::LPCServerMain, this));
    return true;
}

void LPCServer::Stop() {
    if (monitor_) {
        monitor_ = false;
    }

    if (lpc_main_.joinable()) {
        lpc_main_.join();
    }

    if (lpc_server_) {
        CloseHandle(lpc_server_);
        lpc_server_ = NULL;
    }
}

void LPCServer::InstallCallback(ULONG cmd, LPCCallback cb) {
    auto it = callback_.find(cmd);
    if (it != callback_.end()) {
        LOG("register lpc callback failed at 0x%x", cmd);
        return;
    }

    callback_.emplace(cmd, cb);
}

/// @brief 构建LPC响应消息
/// @param pResponse 指向LPC响应消息的缓冲区
/// @param ClientId 本次通信的客户端Id
/// @param MessageId 本次通信的消息Id
/// @param cmd 本次通信的指令
/// @param reply 实际响应消息的缓冲区
/// @param replyLen 响应消息长度
static void BuildResponseMessage(PLPC_MSG pResponse, MY_CLIENT_ID ClientId, ULONG MessageId, ULONG cmd, UINT8* reply, SIZE_T replyLen) {
    // 若数据长度超过LPC消息限制 使用内存节
    if (replyLen > MAX_LPC_DATA_LENGTH) {
        InitializeMessageHeader(&pResponse->Header, sizeof(LPC_MSG), 0);
        pResponse->Header.ClientId = ClientId;
        pResponse->Header.MessageId = MessageId;
        pResponse->Command = cmd;
        pResponse->DataSize = (ULONG)replyLen;
        pResponse->UseSection = true;
    } else {
        InitializeMessageHeader(&pResponse->Header, sizeof(LPC_MSG) + replyLen, 0);
        pResponse->Header.ClientId = ClientId;
        pResponse->Header.MessageId = MessageId;
        pResponse->Command = cmd;
        pResponse->DataSize = (ULONG)replyLen;
        pResponse->UseSection = false;
        RtlCopyMemory(pResponse->Content, reply, replyLen);
    }
}

void LPCServer::LPCServerMain() {
    UINT8 buffer[MAX_LPC_MESSAGE_LENGTH] = {0};
    std::unordered_map<HANDLE, CONN_INFO> connection;
    PLPC_MSG pRequest = (PLPC_MSG)buffer;
    PLPC_MSG pResponse = (PLPC_MSG)buffer;
    while (monitor_) {
        HANDLE lpc_client;
        // 等待LPC连接
        NTSTATUS status = NtReplyWaitReceivePort(
            lpc_server_,
            &lpc_client,
            NULL,
            (PPORT_MESSAGE)pRequest);
        if (status == 0xC0000002L || status == STATUS_INVALID_HANDLE) {
            break;
        }

        if (!NT_SUCCESS(status)) {
            Sleep(3000);
            continue;
        }

        CONN_INFO connInfo = {0, 0, 0};
        bool IsExist = false;
        // 检测LPC连接是否接入
        auto it = connection.find(lpc_client);
        if (it != connection.end()) {
            connInfo = it->second;
            IsExist = true;
        }

        USHORT msgType = GetMessageType(pRequest);
        switch (msgType) {
            case LPC_CONNECTION_REQUEST: {
                if (IsExist) {
                    // 拒绝重复的LPC连接
                    HandlerConnection(pRequest, FALSE, &connInfo);
                } else {
                    if (HandlerConnection(pRequest, TRUE, &connInfo)) {
                        connection.emplace(connInfo.hPort, connInfo);
                    }
                }
            } break;
            case LPC_PORT_CLOSED:
            case LPC_CLIENT_DIED:
                if (IsExist) {
                    CloseConnection(&connInfo);
                    connection.erase(it);
                } else {
                    NtClose(lpc_client);
                }
                break;
            case LPC_REQUEST:
            case LPC_DATAGRAM:
                if (IsExist) {
                    void* data = NULL;
                    if (pRequest->UseSection) {
                        data = connInfo.pInData;
                    } else {
                        data = pRequest->Content;
                    }

                    int reply_len = 0;
                    auto it = callback_.find(pRequest->Command);
                    if (it != callback_.end()) {
                        reply_len = it->second(data, pRequest->DataSize, connInfo.pOutData, LARGE_MESSAGE_SIZE);
                    } else {
                        pRequest->Command = (ULONG)kCmdError;
                    }

                    BuildResponseMessage(pResponse, pRequest->Header.ClientId, pRequest->Header.MessageId,
                                         pRequest->Command, connInfo.pOutData, reply_len);

                    ReplyMessage(connInfo.hPort, pResponse);
                } else {
                    BuildResponseMessage(pResponse, pRequest->Header.ClientId, pRequest->Header.MessageId,
                                         pRequest->Command, NULL, 0);
                    ReplyMessage(lpc_client, pResponse);
                }
                break;
            default:
                break;
        }
    }
}

}  // namespace lpc

#endif