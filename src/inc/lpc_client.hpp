#ifndef __LPC_CLIENT_H
#define __LPC_CLIENT_H
#ifdef _NTDDK_

namespace lpc {

typedef enum {
    LPC_ERROR_SUCCESS,
    LPC_ERROR_INVALID_PARAMETER,
    LPC_ERROR_CONNECTED_FAILED,
    LPC_ERROR_DISCONNECTED,
    LPC_ERROR_COMMAND_UNSUPPORT,
    LPC_ERROR_INTERNAL = 99,
} LPC_ERROR;

LPC_ERROR LPCIoctl(ULONG cmd, UINT8* request, SIZE_T requestLen, UINT8* response, SIZE_T* responseLen);

}  // namespace lpc

#endif
#endif