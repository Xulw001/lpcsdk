#ifndef __LPC_USER_H
#define __LPC_USER_H

#ifdef _NTDDK_
#include "lpc_client.hpp"
#else
#include "lpc_server.hpp"
#endif

#define LPC_PORT_NAME L"\\{ED73A181-60B9-4EF6-A022-BCD6C0AA4CDC}"

typedef enum {
    kCmdError = -1
} Cmd;

#ifdef _NTDDK_
#define LOG(fmt, ...) DbgPrint(fmt, ##__VA_ARGS__)
#else
#define LOG(fmt, ...)                       \
    char _buffer[1024];                     \
    sprintf_s(_buffer, fmt, ##__VA_ARGS__); \
    OutputDebugStringA(_buffer);
#endif

#endif