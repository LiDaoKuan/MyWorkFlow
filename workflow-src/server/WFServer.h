//
// Created by ldk on 12/19/25.
//

/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Xie Han (xiehan@sogou-inc.com)
           Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#ifndef MYWORKFLOW_WFSERVER_H
#define MYWORKFLOW_WFSERVER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <cerrno>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <openssl/ssl.h>
#include "EndpointParams.h"
#include "WFTaskFactory.h"

struct WFServerParams {
    TransportType transport_type; // 传输层协议类型 (TCP/UDP/SCTP等)
    size_t max_connections;       // 服务器最大并发连接数
    int peer_response_timeout;    // 单次读/写操作的超时时间(毫秒)  控制底层socket操作的阻塞时间
    int receive_timeout;          // 接收完整消息的总超时时间(毫秒) -1表示无限制, 由应用层协议控制
    int keep_alive_timeout;       // 保持连接活跃的空闲超时时间(毫秒)
    size_t request_size_limit;    // 请求体的最大允许大小(字节)
    int ssl_accept_timeout;       // SSL/TLS握手超时时间(毫秒)  非SSL服务器会忽略此参数
};

// 服务器默认参数配置
static constexpr struct WFServerParams SERVER_PARAMS_DEFAULT =
{
    .transport_type = TT_TCP,           // 默认使用TCP传输
    .max_connections = 2000,            // 默认最大2000个并发连接
    .peer_response_timeout = 10 * 1000, // 10秒单次IO操作超时
    .receive_timeout = -1,              // 无总接收超时限制
    .keep_alive_timeout = 60 * 1000,    // 60秒Keep-Alive超时
    .request_size_limit = (size_t)-1,   // 无请求大小限制 (使用size_t最大值)
    .ssl_accept_timeout = 10 * 1000,    // 10秒SSL握手超时
};

/**
 * @brief 服务器基类，提供通用服务器功能
 *
 * 设计要点:
 * 1. 保护性继承CommService，隐藏底层通信细节
 * 2. 提供统一的服务器生命周期管理(start/stop)
 * 3. 支持SSL/TLS, 通过虚函数提供扩展点
 * 4. 线程安全的连接计数和资源管理
 * 5. 支持优雅关闭和文件描述符继承(用于平滑重启) */
class WFServerBase : protected CommService {
public:
    explicit WFServerBase(const struct WFServerParams *params) :
        conn_count(0) {
        this->params = (params == nullptr ? SERVER_PARAMS_DEFAULT : *params);
        this->unbind_finish = false; // 标记未解绑
        this->listen_fd = -1;        // 监听文件描述符默认为-1
    }

public:
    /* 以下是一系列重载的start()方法, 提供灵活的服务器启动方式 */

    /* 使用IPv4和指定端口启动. */
    int start(unsigned short port) {
        return start(AF_INET, nullptr, port, nullptr, nullptr);
    }

    /* 指定地址族(AF_INET/AF_INET6)和端口启动. */
    int start(int family, unsigned short port) {
        return start(family, nullptr, port, nullptr, nullptr);
    }

    /* 通过主机名和端口启动(会进行DNS解析). */
    int start(const char *host, unsigned short port) {
        return start(AF_INET, host, port, nullptr, nullptr);
    }

    /* 指定地址族、主机名和端口启动. */
    int start(int family, const char *host, unsigned short port) {
        return start(family, host, port, nullptr, nullptr);
    }

    /* 通过预定义的套接字地址启动. */
    int start(const struct sockaddr *bind_addr, socklen_t addrlen) {
        return start(bind_addr, addrlen, nullptr, nullptr);
    }

    /* 下面是 SSL/TLS服务器启动接口(需要证书和私钥文件). */

    int start(unsigned short port, const char *cert_file, const char *key_file) {
        return start(AF_INET, nullptr, port, cert_file, key_file);
    }

    int start(int family, unsigned short port,
              const char *cert_file, const char *key_file) {
        return start(family, nullptr, port, cert_file, key_file);
    }

    int start(const char *host, unsigned short port,
              const char *cert_file, const char *key_file) {
        return start(AF_INET, host, port, cert_file, key_file);
    }

    int start(int family, const char *host, unsigned short port,
              const char *cert_file, const char *key_file);

    /* 通用启动函数, 处理SSL配置. */
    int start(const struct sockaddr *bind_addr, socklen_t addrlen,
              const char *cert_file, const char *key_file);

    /* 通过预定义的监听文件描述符启动(用于平滑重启或SCTP服务器). */
    int serve(const int listen_fd_) {
        return serve(listen_fd_, nullptr, nullptr);
    }

    /**@brief 通过预定义的监听套接字启动服务器(带加密)
     * 适用场景:
     *  1. 优雅重启(继承父进程的监听套接字)
     *  2. 需要特殊配置的套接字(SCTP, 自定义socket选项等)
     * @return 0 成功
     * @return 1 失败 */
    int serve(int listen_fd, const char *cert_file, const char *key_file);

    /* 阻塞式停止服务器(先关闭监听, 然后等待所有连接完成). */
    void stop() {
        this->shutdown();
        this->wait_finish();
    }

    /* Nonblocking terminating the server. For stopping multiple servers.
     * Typically, call shutdown() and then wait_finish().
     * But indeed wait_finish() can be called before shutdown(), even before
     * start() in another thread. */
    /**@brief 非阻塞式关闭服务器
     * 设计说明:
     * 1. shutdown()可立即返回, 实际关闭在后台进行
     * 2. wait_finish()可由任意线程调用, 包括在start()前调用
     * 3. 支持多个服务器实例的并行关闭
     * 4. 典型用法: 先调用shutdown(), 然后在适当时候调用wait_finish() */
    void shutdown();

    /* 阻塞等待服务器完全停止 */
    void wait_finish();

public:
    // 获取当前活跃链接数
    [[nodiscard]] size_t get_conn_count() const { return this->conn_count; }

    /* Get the listening address. This is often used after starting
     * server on a random port (start() with port == 0). */
    /**@brief 获取监听地址信息, 通过参数指针传出. 常用于随机端口启动后(端口=0), 获取实际分配的端口号
     * @return -1 表示函数执行失败 */
    int get_listen_addr(struct sockaddr *addr, socklen_t *addrlen) const {
        if (this->listen_fd >= 0) {
            return getsockname(this->listen_fd, addr, addrlen);
        }
        errno = ENOTCONN; // 未连接状态
        return -1;
    }

    /* 获取服务器配置参数(只读) */
    [[nodiscard]] const struct WFServerParams *get_params() const {
        return &this->params;
    }

protected:
    /* Override this function to create the initial SSL CTX of the server */
    /**创建服务器SSL上下文, 子类可重写自定义SSL配置
     * @return 成功返回SSL_CTX指针, 失败返回 nullptr */
    virtual SSL_CTX *new_ssl_ctx(const char *cert_file, const char *key_file);

    /* Override this function to implement server that supports TLS SNI.
     * "servername" will be NULL if client does not set a host name.
     * Returning NULL to indicate that servername is not supported. */

    /**@brief SNI(Server Name Indication)回调. 子类可以重写该方法.\n
     * SNI 是 TLS 的扩展, 这允许在握手过程开始时通过客户端告诉它正在连接的服务器的主机名称
     * @param servername 客户端请求的主机名, 可能为nullptr
     * @return 默认返回全局SSL_CTX上下文, 返回nullptr表示不支持该主机名. 子类可以重写以支持多证书 */
    virtual SSL_CTX *get_server_ssl_ctx(const char *servername) {
        return this->get_ssl_ctx();
    }

    /* This can be used by the implementation of 'new_ssl_ctx'. */
    /**@brief SSL回调函数, 可被 new_ssl_ctx 调用
     * @return SSL_TLSEXT_ERR_NOACK 拒绝不支持的主机名
     * @return SSL_TLSEXT_ERR_OK 成功 */
    static int ssl_ctx_callback(SSL *ssl, int *al, void *arg);

protected:
    WFServerParams params; // 服务器配置参数

    /* 重写CommService的虚函数 */
protected:
    // 创建监听套接字
    int create_listen_fd() override;
    // 创建新连接对象
    WFConnection *new_connection(int accept_fd) override;
    // 删除连接(内部使用)
    void delete_connection(WFConnection *conn);

private:
    // 内部初始化函数, 处理地址绑定和SSL配置.
    int init(const struct sockaddr *bind_addr, socklen_t addrlen,
             const char *cert_file, const char *key_file);
    // CommService的解绑回调, 用于通知上层.
    void handle_unbound() override;

protected:
    std::atomic<size_t> conn_count; // 连接计数器. 原子变量

private:
    int listen_fd;
    bool unbind_finish; // 服务器解绑完成标志

    std::mutex mutex;
    std::condition_variable cond; // 用于等待服务器完全关闭

    class CommScheduler *scheduler; // 任务调度器（前向声明）
};

/**@brief 模板化服务器实现, 处理特定类型的请求和响应
 * @tparam REQ 请求类型 (如HttpRequest, RedisRequest等)
 * @tparam RESP 响应类型 (如HttpResponse, RedisResponse等) */
template <class REQ, class RESP>
class WFServer : public WFServerBase {
public:
    WFServer(const struct WFServerParams *params, std::function<void (WFNetworkTask<REQ, RESP> *)> proc) :
        WFServerBase(params), process(std::move(proc)) {}

    explicit WFServer(std::function<void (WFNetworkTask<REQ, RESP> *)> proc) :
        WFServerBase(&SERVER_PARAMS_DEFAULT), process(std::move(proc)) {}

protected:
    CommSession *new_session(long long seq, CommConnection *conn) override;

protected:
    // 业务逻辑函数（策略模式）
    std::function<void (WFNetworkTask<REQ, RESP> *)> process;
};

template <class REQ, class RESP>
CommSession *WFServer<REQ, RESP>::new_session(long long seq, CommConnection *conn) {
    using factory = WFNetworkTaskFactory<REQ, RESP>; // 工厂类型别名
    // 创建服务器任务, 绑定处理函数
    WFNetworkTask<REQ, RESP> *task = factory::create_server_task(this, this->process);
    // 设置保活时间
    task->set_keep_alive(this->params.keep_alive_timeout);
    // 设置接收超时
    task->set_receive_timeout(this->params.receive_timeout);
    // 设置请求大小限制
    task->get_req()->set_size_limit(this->params.request_size_limit);

    return task; // 返回Session对象, 框架接管所有权
}

#endif