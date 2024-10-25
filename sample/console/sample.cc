#include <stdio.h>

#include <iostream>

#include "lpc_user.h"

int times = 1;
int TestWork(void* buffer, size_t len1, void* response, size_t len2) {
    if (buffer == NULL || len1 == 0) {
        return 0;
    }

    LOG("[Kernel Request]:%s", (LPSTR)buffer);
    CHAR data[260];
    sprintf_s(data, "Hi Mon, I finish your request at %d!", times++);
    memcpy(response, data, strlen(data));
    return (int)strlen(data);
}

int main() {
    lpc::LPCServer::GetInstance().Start();
    lpc::LPCServer::GetInstance().InstallCallback(0x01, TestWork);

    WCHAR buffer[MAX_PATH] = {0};
    while (true) {
        memset(buffer, 0x00, sizeof(buffer));
        std::wcin >> buffer;
        if (wcscmp(buffer, L"q") == 0) {
            break;
        }
    }
    lpc::LPCServer::GetInstance().Stop();
}