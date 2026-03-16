//
// Created by ldk on 10/25/25.
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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#ifndef MYWORKFLOW_ROUTEMANAGER_H
#define MYWORKFLOW_ROUTEMANAGER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string>
#include <mutex>
#include <openssl/ssl.h>
#include "rbtree.h"
#include "WFConnection.h"
#include "EndpointParams.h"
#include "CommScheduler.h"

// 负责核心路由管理
class RouteManager {
public:
    // 轻量级的容器, 用于承载 get 方法的查询结果
    class RouteResult {
    public:
        // 用户自定义的上下文指针.？？？ 它通常会在目标服务器发生状态变化(如从不可用变为可用)时, 通过 notify_available 等回调函数传回给用户代码.
        // 这使得用户可以基于路由状态实现自定义的逻辑, 例如记录日志或触发特定操作
        void *cookie;

        // request_object: 路由结果的核心, 指向一个可被调度的连接对象. 具体可能是两种类型:
        // - CommSchedTarget: 当 DNS 解析结果只有一个 IP 地址时, 它直接代表一个具体的服务器目标. 同时内部又拥有连接池，可以复用已有连接
        // - CommSchedGroup: 当 DNS 解析结果有多个 IP 地址(即多个目标)时, 它是一个负载均衡组, 内部根据策略(小顶堆)，选择一个低负载CommSchedTarget向目标发起连接
        CommSchedObject *request_object;

        RouteResult() : cookie(nullptr), request_object(nullptr) {}

        void clear() {
            cookie = nullptr;
            request_object = nullptr;
        }
    };

    // 是框架与操作系统 Socket API 之间的桥梁. 亮点是对 SSL/TLS 连接生命周期的精细管理
    class RouteTarget : public CommSchedTarget {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        // init()方法和deinit()方法并不是多态, 因为基类的两个对应函数不是虚函数。为什么不用多态？？？
    public:
        int init(const sockaddr *addr, socklen_t addrlen, SSL_CTX *ssl_ctx,
                 int connect_timeout, int ssl_connect_timeout, int response_timeout, size_t max_connections) {
            // 先进行父类的初始化
            int ret = this->CommSchedTarget::init(addr, addrlen, ssl_ctx, connect_timeout, ssl_connect_timeout, response_timeout, max_connections);
            if (ret >= 0 && ssl_ctx) {
                SSL_CTX_up_ref(ssl_ctx); // 增加SSL上下文引用计数
            }
            return ret;
        }

        void deinit() {
            SSL_CTX *ssl_ctx = this->get_ssl_ctx();
            this->CommSchedTarget::deinit(); // 先释放父类资源
            if (ssl_ctx) {
                SSL_CTX_free(ssl_ctx); // 安全释放SSL上下文
            }
        }
#endif

    public:
        int state;

    private:
        // 重写工厂方法
        WFConnection *new_connection(int connect_fd) override {
            return new WFConnection;
        }

    public:
        RouteTarget() : state(0) {}
    };

public:
    int get(TransportType type, const addrinfo *addrinfo, const std::string &other_info, const EndpointParams *ep_params,
            const std::string &hostname, SSL_CTX *ssl_ctx, RouteResult &result);

    RouteManager() { cache_.rb_node = nullptr; }
    ~RouteManager();

private:
    std::mutex mutex_;
    rb_root cache_{};

public:
    // 熔断机制的接口

    // 标记某个目标为熔断状态
    static void notify_unavailable(void *cookie, CommTarget *target);
    // 标记某个已熔断的目标现在可用
    static void notify_available(void *cookie, CommTarget *target);
};

#endif //MYWORKFLOW_ROUTEMANAGER_H