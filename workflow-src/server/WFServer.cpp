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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <cerrno>
#include <unistd.h>
#include <cstdio>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <openssl/ssl.h>
#include "CommScheduler.h"
#include "EndpointParams.h"
#include "WFConnection.h"
#include "WFGlobal.h"
#include "WFServer.h"

#define PORT_STR_MAX	5

// 服务器专用连接类, 管理连接计数.
// 与WFServerBase协同工作, 实现连接数限制.
// 在析构时自动递减服务器的连接计数器.
class WFServerConnection : public WFConnection {
public:
    explicit WFServerConnection(std::atomic<size_t> *conn_count) {
        this->conn_count = conn_count;
    }

    ~WFServerConnection() override {
        --(*this->conn_count);
    }

private:
    std::atomic<size_t> *conn_count; // 指向 WFServerBase 内的 conn_count
};

int WFServerBase::ssl_ctx_callback(SSL *ssl, int *al, void *arg) {
    auto *server = static_cast<WFServerBase *>(arg);
    // 从SSL对象中获取客户端请求的主机名
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    // 通过虚函数获取对应主机名的SSL上下文（支持SNI）
    SSL_CTX *ssl_ctx = server->get_server_ssl_ctx(servername);

    if (!ssl_ctx) {
        return SSL_TLSEXT_ERR_NOACK; // 拒绝不支持的主机名
    }

    // 如果获取的上下文与默认不同, 动态切换SSL连接使用的上下文
    if (ssl_ctx != server->get_ssl_ctx()) {
        SSL_set_SSL_CTX(ssl, ssl_ctx);
    }

    return SSL_TLSEXT_ERR_OK; // 成功
}

SSL_CTX *WFServerBase::new_ssl_ctx(const char *cert_file, const char *key_file) {
    SSL_CTX *ssl_ctx = WFGlobal::new_ssl_server_ctx(); // 创建基础SSL上下文

    if (!ssl_ctx) {
        return nullptr;
    }

    // 配置证书、私钥和SNI回调
    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) > 0 &&            // 配置证书
        SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) > 0 &&  // 加载PEM格式私钥
        SSL_CTX_check_private_key(ssl_ctx) > 0 &&                                // 验证私钥与证书匹配
        SSL_CTX_set_tlsext_servername_callback(ssl_ctx, ssl_ctx_callback) > 0 && // 配置SNI回调
        SSL_CTX_set_tlsext_servername_arg(ssl_ctx, this) > 0)                    // 传入对象指针
    {
        return ssl_ctx; // 全部成功
    }
    // 存在失败情况. 释放SSL上下文
    SSL_CTX_free(ssl_ctx);
    return nullptr;
}

/**@brief 服务器内部初始化函数 \n
 * 主要工作: \n
 *  1. 计算最终超时值（取peer_response_timeout和receive_timeout的较小值）
 *  2. 验证SSL参数（如需要）
 *  3. 初始化底层通信服务
 *  4. 配置SSL（如需要）
 *  5. 获取调度器引用
 * @return 0 成功
 * @return -1 失败 */
int WFServerBase::init(const struct sockaddr *bind_addr, socklen_t addrlen,
                       const char *cert_file, const char *key_file) {
    int timeout = this->params.peer_response_timeout;
    // 计算操作超时: 取单次IO超时和总接收超时的较小值
    if (this->params.receive_timeout >= 0) {
        // 无符号比较避免负数问题
        if (static_cast<unsigned int>(timeout) > static_cast<unsigned int>(this->params.receive_timeout)) {
            timeout = this->params.receive_timeout;
        }
    }

    // 验证SSL参数: SSL传输类型必须提供证书和私钥
    if (this->params.transport_type == TT_TCP_SSL ||
        this->params.transport_type == TT_SCTP_SSL) {
        if (!cert_file || !key_file) {
            errno = EINVAL; // 参数无效
            return -1;
        }
    }

    // 初始化底层通信服务
    if (this->CommService::init(bind_addr, addrlen, -1, timeout) < 0) {
        return -1;
    }

    // SSL配置: 仅当提供证书/私钥且非UDP时启用
    if (cert_file && key_file && this->params.transport_type != TT_UDP) {
        SSL_CTX *ssl_ctx = this->new_ssl_ctx(cert_file, key_file);

        if (!ssl_ctx) {
            this->deinit(); // 初始化失败, 清理资源
            return -1;
        }
        // 设置SSL握手上下文和握手延时
        this->set_ssl(ssl_ctx, this->params.ssl_accept_timeout);
    }
    // 获取全局调度器, 用于任务分发
    this->scheduler = WFGlobal::get_scheduler();
    return 0;
}

int WFServerBase::create_listen_fd() {
    if (this->listen_fd < 0) {
        // 需要创建新套接字
        const struct sockaddr *bind_addr;
        socklen_t addrlen;
        int type, protocol;
        constexpr int reuse = 1; // SO_REUSEADDR选项值

        // 根据传输类型设置套接字参数
        switch (this->params.transport_type) {
        case TT_TCP:
        case TT_TCP_SSL: type = SOCK_STREAM;
            protocol = 0; // 默认协议
            break;
        case TT_UDP: type = SOCK_DGRAM;
            protocol = 0;
            break;
#ifdef IPPROTO_SCTP
        case TT_SCTP:
        case TT_SCTP_SSL: type = SOCK_STREAM;
            protocol = IPPROTO_SCTP; // 显式指定SCTP协议
            break;
#endif
        default:
            errno = EPROTONOSUPPORT; // 不支持的协议
            return -1;
        }

        // 获取绑定地址
        this->get_addr(&bind_addr, &addrlen);
        // 创建套接字
        this->listen_fd = socket(bind_addr->sa_family, type, protocol);
        if (this->listen_fd >= 0) {
            // 设置地址重用, 避免TIME_WAIT问题
            setsockopt(this->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
        }
    } else {
        // 复用外部提供的监听套接字
        this->listen_fd = dup(this->listen_fd); // 复制fd, 避免原始fd关闭影响
    }

    return this->listen_fd;
}

WFConnection *WFServerBase::new_connection(const int accept_fd) {
    // 递增连接计数, 检查是否超过限制
    if (++this->conn_count <= this->params.max_connections ||
        this->drain(1) == 1) // 超限时尝试排空一个连接
    {
        // 设置 SO_REUSEADDR 避免端口耗尽问题（对客户端连接也有用）
        constexpr int reuse = 1;
        setsockopt(accept_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
        // 创建带计数管理的专用连接对象
        return new WFServerConnection(&this->conn_count);
    }

    // 拒绝连接: 回滚计数并返回错误
    --this->conn_count;
    errno = EMFILE; // 超过文件描述符限制
    return nullptr;
}

// 安全删除连接对象
void WFServerBase::delete_connection(WFConnection *conn) {
    // 由于C++多态特性, 基类指针实际指向派生类对象
    // 必须显式转换为派生类指针再删除, 确保调用正确的析构函数
    delete (WFServerConnection *)conn;
}

// 处理解绑完成通知
void WFServerBase::handle_unbound() {
    this->mutex.lock();
    this->unbind_finish = true; // 设置解绑完成标志
    this->cond.notify_one();    // 唤醒等待线程
    this->mutex.unlock();
}

// 启动服务器（底层实现）
int WFServerBase::start(const struct sockaddr *bind_addr, socklen_t addrlen,
                        const char *cert_file, const char *key_file) {
    SSL_CTX *ssl_ctx;
    // 初始化
    if (this->init(bind_addr, addrlen, cert_file, key_file) >= 0) {
        // 将服务器绑定到调度器
        if (this->scheduler->bind(this) >= 0) {
            return 0;
        }
        // 绑定失败, 清理资源
        ssl_ctx = this->get_ssl_ctx();
        this->deinit();
        if (ssl_ctx) {
            SSL_CTX_free(ssl_ctx);
        }
    }
    // 启动失败
    this->listen_fd = -1; // 重置监听fd
    return -1;
}

/**@brief 通过主机名和端口启动服务器\n
 * 功能:
 * 1. 将主机名/端口解析为地址结构
 * 2. 调用底层start函数
 * 3. 处理DNS解析错误
 * @return 0 成功
 * @return 1 失败 */
int WFServerBase::start(int family, const char *host, unsigned short port,
                        const char *cert_file, const char *key_file) {
    const struct addrinfo hints = {
        .ai_flags = AI_PASSIVE,     // 用于服务器绑定
        .ai_family = family,        // 地址族
        .ai_socktype = SOCK_STREAM, // 流式套接字
    };
    struct addrinfo *addrinfo;
    char port_str[PORT_STR_MAX + 1]; // 端口字符串缓冲区
    int ret;

    // 将端口号转换为字符串
    snprintf(port_str, PORT_STR_MAX + 1, "%d", port);
    // DNS解析（如果host为nullptr，addrinfo里得到的ip就是0.0.0.0）
    ret = getaddrinfo(host, port_str, &hints, &addrinfo);
    if (ret == 0) {
        // 使用解析结果绑定启动服务器
        ret = start(addrinfo->ai_addr, (socklen_t)addrinfo->ai_addrlen, cert_file, key_file);
        freeaddrinfo(addrinfo); // 释放解析结果
    } else {
        // 处理DNS错误
        if (ret != EAI_SYSTEM) {
            // 非系统错误转换为EINVAL
            errno = EINVAL;
        }
        ret = -1;
    }

    return ret;
}

int WFServerBase::serve(int listen_fd, const char *cert_file, const char *key_file) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof ss;

    // 获取套接字绑定地址
    if (getsockname(listen_fd, reinterpret_cast<struct sockaddr *>(&ss), &len) < 0) {
        return -1;
    }

    // 保存fd
    this->listen_fd = listen_fd;
    // 通过标准流程启动
    return start(reinterpret_cast<struct sockaddr *>(&ss), len, cert_file, key_file);
}

void WFServerBase::shutdown() {
    this->listen_fd = -1;          // 标记文件描述符为无效值
    this->scheduler->unbind(this); // 通知调度器解绑
}

// 阻塞等待服务器完全停止
void WFServerBase::wait_finish() {
    SSL_CTX *ssl_ctx = this->get_ssl_ctx(); // 保存SSL上下文引用
    std::unique_lock<std::mutex> lock(this->mutex);

    // 等待解绑完成
    while (!this->unbind_finish) {
        this->cond.wait(lock);
    }

    // 清理底层资源
    this->deinit();
    this->unbind_finish = false; // 重置状态
    lock.unlock();               // 先释放锁后再释放SSL资源（避免潜在死锁）
    // 安全释放SSL上下文
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
}