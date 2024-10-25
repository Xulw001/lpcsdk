#ifndef __LPC_SERVER_H
#define __LPC_SERVER_H
#ifndef _NTDDK_
#include <Windows.h>

#include <functional>
#include <thread>
#include <unordered_map>

namespace lpc {

typedef std::function<int(void*, size_t, void*, size_t)> LPCCallback;

class LPCServer {
   public:
    static LPCServer& GetInstance();

    /// @brief 启动LPC服务
    /// @return
    bool Start();
    /// @brief 停止LPC服务
    void Stop();
    /// @brief 为LPC指令注册回调函数
    /// @param cmd LPC指令
    /// @param cb LPC回调函数指针
    void InstallCallback(ULONG cmd, LPCCallback cb);

   private:
    LPCServer() {
        monitor_ = false;
        lpc_server_ = NULL;
    }

    ~LPCServer() { ; }

    void LPCServerMain();

   private:
    std::unordered_map<ULONG, LPCCallback> callback_;
    std::thread lpc_main_;
    bool monitor_;
    HANDLE lpc_server_;
};

#define GInstallCallback(cmd, func)                \
    lpc::LPCServer::GetInstance().InstallCallback( \
        cmd, std::bind(func, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4))

};  // namespace lpc
#endif
#endif
