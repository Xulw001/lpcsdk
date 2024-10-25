#ifndef _NTDDK_
#include "lpc_server.hpp"

#include "lpc.hpp"
#include "lpc_user.h"

namespace lpc {

LPCServer& LPCServer::GetInstance() {
    static LPCServer instance;
    return instance;
}

/// @brief ����LPCͨ�Ŷ˿�
/// @return LPCͨ�Ŷ˿ڵľ��
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
    // ����LPC�˿�
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

/// @brief ��ȡLPC��Ϣ����
/// @param request ָ��LPC��Ϣ�Ļ�����
/// @return LPC��Ϣ����
static USHORT GetMessageType(PLPC_MSG request) {
    return request->Header.u2.s2.Type;
}

/// @brief ����LPC��������
/// @param request ָ��LPC��Ϣ�Ļ�����
/// @param Accept �Ƿ�ܾ�����
/// @param pConnInfo ָ��LPC������Ϣ�Ļ�����
/// @return
static bool HandlerConnection(PLPC_MSG request, BOOLEAN Accept, PCONN_INFO pConnInfo) {
    NTSTATUS status;
    HANDLE SectionHandle = NULL;
    LARGE_INTEGER SectionSize = {LARGE_MESSAGE_SIZE};
    // ������������ӳ����ڴ��
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
    // ���ܻ��߾ܾ�LPC��������
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

    // ���LPC��������
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
    // ���ջ�����
    pConnInfo->pInData = (PUINT8)ClientView.ViewBase;
    // ���ͻ�����
    pConnInfo->pOutData = (PUINT8)ServerView.ViewBase;
    return true;
}

/// @brief ��ӦLPC��Ϣ
/// @param hReplyPort LPC���Ӷ˿�
/// @param replyBuffer LPC��Ӧ��Ϣ
/// @return
bool ReplyMessage(HANDLE hReplyPort, PLPC_MSG replyBuffer) {
    NTSTATUS status = NtReplyPort(hReplyPort, (PPORT_MESSAGE)replyBuffer);
    if (!NT_SUCCESS(status)) {
        LOG("NtReplyPort failed at 0x%x", status);
        return false;
    }

    return true;
}

/// @brief �ͷ�LPC������Դ
/// @param pConnInfo LPC������Ϣ
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

/// @brief ����LPC��Ӧ��Ϣ
/// @param pResponse ָ��LPC��Ӧ��Ϣ�Ļ�����
/// @param ClientId ����ͨ�ŵĿͻ���Id
/// @param MessageId ����ͨ�ŵ���ϢId
/// @param cmd ����ͨ�ŵ�ָ��
/// @param reply ʵ����Ӧ��Ϣ�Ļ�����
/// @param replyLen ��Ӧ��Ϣ����
static void BuildResponseMessage(PLPC_MSG pResponse, MY_CLIENT_ID ClientId, ULONG MessageId, ULONG cmd, UINT8* reply, SIZE_T replyLen) {
    // �����ݳ��ȳ���LPC��Ϣ���� ʹ���ڴ��
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
        // �ȴ�LPC����
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
        // ���LPC�����Ƿ����
        auto it = connection.find(lpc_client);
        if (it != connection.end()) {
            connInfo = it->second;
            IsExist = true;
        }

        USHORT msgType = GetMessageType(pRequest);
        switch (msgType) {
            case LPC_CONNECTION_REQUEST: {
                if (IsExist) {
                    // �ܾ��ظ���LPC����
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