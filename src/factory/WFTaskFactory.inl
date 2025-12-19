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

  Authors: Xie Han (xiehan@sogou-inc.com)
           Wu Jiaxu (wujiaxu@sogou-inc.com)
           Li Yingxin (liyingxin@sogou-inc.com)
*/
#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <cerrno>
#include <ctime>
#include <netdb.h>
#include <cstdio>
#include <string>
#include <functional>
#include <utility>
#include <atomic>
#include <openssl/ssl.h>
#include "WFGlobal.h"
#include "Workflow.h"
#include "WFTask.h"
#include "RouteManager.h"
#include "URIParser.h"
#include "WFTaskError.h"
#include "EndpointParams.h"
#include "WFNameService.h"

class __WFDynamicTask : public WFDynamicTask {
protected:
    void dispatch() override {
        series_of(this)->push_front(this->create(this)); // 创建任务, 添加到任务流中(头插)
        this->WFDynamicTask::dispatch();
    }

protected:
    std::function<SubTask *(WFDynamicTask *)> create; // 用于创建任务的函数, 类初始化时由外部传入. 将创建任务的逻辑委托给外部, 在合适的时候调用, 实现控制反转.

public:
    explicit __WFDynamicTask(std::function<SubTask *(WFDynamicTask *)> &&create) :
        create(std::move(create)) {}
};

inline WFDynamicTask *WFTaskFactory::create_dynamic_task(dynamic_create_t create) {
    return new __WFDynamicTask(std::move(create));
}

template <>
int WFTaskFactory::send_by_name(const std::string &, void *const *, size_t);

template <typename T>
int WFTaskFactory::send_by_name(const std::string &mailbox_name, T *const msg[], size_t max) {
    // 将T类型的消息转换为 void * const 类型的消息发送
    return WFTaskFactory::send_by_name(mailbox_name, static_cast<void *const *>(msg), max);
}

template <>
int WFTaskFactory::signal_by_name(const std::string &, void *const *, size_t);

template <typename T>
int WFTaskFactory::signal_by_name(const std::string &cond_name, T *const msg[], size_t max) {
    return WFTaskFactory::signal_by_name(cond_name, (void *const *)msg, max);
}

/**创建复杂网络客户端任务的模板基类.
 * @param REQ: 请求协议类型（例如 protocol::HttpRequest）.
 * @param RESP: 响应协议类型（例如 protocol::HttpResponse）.
 * @param ctx: 任务上下文类型. 用于在任务执行过程中携带和传递用户自定义的上下文信息, 实现更复杂的状态管理. 默认为bool型 */
template <class REQ, class RESP, typename CTX = bool>
class WFComplexClientTask : public WFClientTask<REQ, RESP> {
protected:
    using task_callback_t = std::function<void (WFNetworkTask<REQ, RESP> *)>;

public:
    WFComplexClientTask(const int retry_max, task_callback_t &&cb) :
        WFClientTask<REQ, RESP>(NULL, WFGlobal::get_scheduler(), std::move(cb)) //
    {
        type_ = TT_TCP; // 设置默认的传输类型为 TCP
        ssl_ctx_ = nullptr;
        fixed_addr_ = false;
        fixed_conn_ = false;
        retry_max_ = retry_max;
        retry_times_ = 0; // 初始化重试计数器
        redirect_ = false;
        ns_policy_ = nullptr;
        router_task_ = nullptr;
    }

    // new api for children 生命周期钩子 子类可通过重写这些方法在关键节点（初始化成功/失败、发送请求前）插入自定义逻辑
protected:
    virtual bool init_success() { return true; } // 初始化成功后的回调, 默认返回 true
    virtual void init_failed() {} // 初始化失败的回调
    virtual bool check_request() { return true; } // 在发送请求前被调用. 子类可以在此检查参数是否合法
    virtual WFRouterTask *route(); // 生成并返回一个 WFRouterTask. 决定了如何找到目标服务器（比如是查 DNS 还是查一致性哈希环）

    // 一次网络交互结束（无论成功失败）后调用.
    // 如果返回 true, 表示任务彻底结束，回调用户 callback.
    // 如果返回 false, 框架会尝试进行重试或重定向逻辑.
    virtual bool finish_once() { return true; }

public:
    // 通过URI初始化（拷贝版本）
    void init(const ParsedURI &uri) {
        uri_ = uri; // 拷贝操作
        init_with_uri();
    }

    // 通过URI初始化（移动版本）
    void init(ParsedURI &&uri) {
        uri_ = std::move(uri); // 移动操作
        init_with_uri();
    }

    // 手动指定 IP 和端口进行初始化, 不经过域名解析
    void init(enum TransportType type, const struct sockaddr *addr, socklen_t addrlen, const std::string &info);

    void set_transport_type(enum TransportType type) {
        type_ = type;
    }

    [[nodiscard]] TransportType get_transport_type() const { return type_; }

    void set_ssl_ctx(SSL_CTX *ssl_ctx) { ssl_ctx_ = ssl_ctx; }

    [[nodiscard]] virtual const ParsedURI *get_current_uri() const { return &uri_; }

    // 当需要重定向时调用(通常在内部逻辑中使用), 它会重置任务状态并指向新的 URI
    void set_redirect(const ParsedURI &uri) {
        redirect_ = true;
        init(uri);
    }

    // 当需要重定向时调用
    void set_redirect(enum TransportType type, const struct sockaddr *addr, socklen_t addrlen, const std::string &info) {
        redirect_ = true;
        init(type, addr, addrlen, info);
    }

    [[nodiscard]] bool is_fixed_addr() const { return this->fixed_addr_; }

    [[nodiscard]] bool is_fixed_conn() const { return this->fixed_conn_; }

protected:
    void set_fixed_addr(int fixed) { this->fixed_addr_ = fixed; }

    void set_fixed_conn(int fixed) { this->fixed_conn_ = fixed; }

    void set_info(const std::string &info) {
        info_.assign(info);
    }

    void set_info(const char *info) {
        info_.assign(info);
    }

protected:
    void dispatch() override;
    SubTask *done() override;

    // 用于重试机制
    // 在重试之前, 必须清空上一次失败或错误的响应对象 (resp), 重新构造一个新的 RESP 对象, 同时保留协议头信息.
    // 这通过显式调用析构函数和 placement new 实现
    void clear_resp() {
        protocol::ProtocolMessage head(std::move(this->resp)); // 保留原协议头
        this->resp.~RESP(); // 显式调用析构函数
        new(&this->resp) RESP; // 使用placement new
        *static_cast<protocol::ProtocolMessage *>(&this->resp) = std::move(head); //
    }

    // 将 retry_times_ 设置为最大值, 强制停止后续的自动重试
    void disable_retry() {
        retry_times_ = retry_max_;
    }

protected:
    enum TransportType type_; // 传输层协议类型（如 TCP、TCP_SSL、SCTP、UDP）
    ParsedURI uri_; // 解析后的URI对象
    std::string info_; // 通常用于存储通过 URI 无法完全表达的额外连接信息, 或者用于区分相同地址下的不同资源(例如数据库的用户名/密码, 或者特定服务的标识字符串). 在负载均衡中可作为 key 使用
    SSL_CTX *ssl_ctx_; // ssl上下文. 若为空则表示使用非加密通道
    bool fixed_addr_; // 固定地址模式标志. 若为true, 任务将跳过DNS解析和负载均衡, 直接连接init时指定的ip地址
    bool fixed_conn_; // 固定连接模式标志. 若为true, 任务尝试复用一个特定的连接(常用于事务性任务或需要绑定连接的场景), 而不是新建或从连接池获取
    bool redirect_; // 标志位, 表示当前任务是否处于“重定向”状态. 如果发生了重定向, uri_ 会被更新
    CTX ctx_; // 用户定义的上下文变量(由模板参数决定)
    int retry_max_; // 最大重试次数
    int retry_times_; // 当前已重试次数
    WFNSPolicy *ns_policy_; // 指向名字服务策略(Naming Service Policy)的指针. 指定如何从域名获取目标节点（例如使用 DNS, 还是使用 Consul/Etcd 等服务发现）
    WFRouterTask *router_task_; // 路由子任务. 这是一个异步任务, 负责执行 DNS 解析和负载均衡选择目标节点的过程
    RouteManager::RouteResult route_result_; // 存储经过路由选择后的目标 IP、Port、Cookie 等信息
    WFNSTracing tracing_; // 用于名字服务（NS）的追踪数据结构, 可能用于统计 DNS 解析耗时、路由耗时等监控指标

public:
    // 返回 ctx_ 的指针, 允许派生类修改上下文状态
    CTX *get_mutable_ctx() { return &ctx_; }

private:
    void clear_prev_state();
    //
    void init_with_uri();
    // 设置端口. 如果端口已经被设置, 判断端口是否合法. 如果没有设置端口, 则根据协议设置默认端口
    bool set_port();
    // 路由回调函数
    void router_callback(void *t);
    // 任务生命周期的终结阶段处理的回调函数. 参数t是为了和框架其他回调函数统一, 函数内部并未使用
    void switch_callback(void *t);
};

// 清除之前请求的所有状态
template <class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::clear_prev_state() {
    this->ns_policy_ = nullptr; // 重置命名服务策略（Naming Service Policy）. 重定向后的新地址（URI）可能属于完全不同的域名或服务。例如, 从 service-a.sogou 重定向到 external.example.com. 之前的域名解析策略（如 Consul 策略）可能不再适用, 需要重新根据新域名获取对应的策略
    this->route_result_.clear(); // 清空之前的路由结果
    if (this->tracing_.deleter) {
        this->tracing_.deleter(tracing_.data); // 手动释放追踪数据的内存
        this->tracing_.deleter = nullptr;
    }
    this->tracing_.data = nullptr;
    this->retry_times_ = 0; // 重置重试次数
    this->state = WFT_STATE_UNDEFINED; // 表示任务尚未开始执行
    this->error = 0;
    this->timeout_reason = TOR_NOT_TIMEOUT; // 重置超时原因. 父类中该变量的默认值也是TOR_NOT_TIMEOUT, 此处与父类保持一致, 避免父类函数读取到错误状态
}

template <class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::init(enum TransportType type, const struct sockaddr *addr, socklen_t addrlen, const std::string &info) {
    if (redirect_) {
        clear_prev_state(); // 重定向状态清理
    }

    this->type_ = type; // 设置传输类型
    this->info_.assign(info);
    // 将用户传入的 sockaddr 封装进 addrinfo 中
    addrinfo addrinfo = {};
    addrinfo.ai_family = addr->sa_family;
    addrinfo.ai_addr = const_cast<sockaddr *>(addr);
    addrinfo.ai_addrlen = addrlen;

    auto params = WFGlobal::get_global_settings()->endpoint_params; // 获取全局默认的端点参数（如连接超时时间、最大连接数等）
    // 为什么设为 false? 因为这个函数是基于 IP 地址 初始化的, 没有域名信息. TLS 握手时通常不会发送 IP 作为 SNI, 因此这里显式关闭 SNI, 避免底层 SSL 库报错或发送错误信息
    params.use_tls_sni = false; // 关键点. SNI (Server Name Indication) 是 TLS 协议的扩展， 允许客户端在握手时告诉服务器它想访问哪个域名
    // Workflow 的连接池是挂在路由表项（Route Entry）下的. 即使是固定 IP, 也需要生成一个 RouteResult 对象, 作为获取连接的“凭证” (Key)
    // 注意这里调用的是 get 而不是异步的 route. 因为 IP 已知, 不需要网络 I/O, 这是一个同步操作, 直接构建并返回路由结果
    if (WFGlobal::get_route_manager()->get(type, &addrinfo, info_, &params, "", ssl_ctx_, route_result_) < 0) {
        this->state = WFT_STATE_SYS_ERROR;
        this->error = errno;
    }
    // 如果路由获取成功, 则调用此虚函数. 子类行为: 例如 WFHttpTask 会在这里初始化 HTTP 解析器；WFRedisTask 会初始化 Redis 协议结构
    else if (this->init_success()) {
        return;
    }

    this->init_failed();
}

template <class REQ, class RESP, typename CTX>
bool WFComplexClientTask<REQ, RESP, CTX>::set_port() {
    if (uri_.port) {
        const int port = atoi(uri_.port);
        // 严格检查端口号是否在 TCP/UDP 有效范围内 (1-65535)
        if (port <= 0 || port > 65535) {
            this->state = WFT_STATE_TASK_ERROR; // 无效端口时设置任务状态为 WFT_STATE_TASK_ERROR
            this->error = WFT_ERR_URI_PORT_INVALID; // this->error = WFT_ERR_URI_PORT_INVALID;
            return false;
        }
        return true;
    }

    if (uri_.scheme) {
        // 根据协议获取默认端口
        const char *port_str = WFGlobal::get_default_port(uri_.scheme);
        if (port_str) {
            uri_.port = strdup(port_str); // 复制默认端口字符串
            if (uri_.port) {
                return true;
            }
            this->state = WFT_STATE_SYS_ERROR; // 系统错误
            this->error = errno;
            return false;
        }
    }

    this->state = WFT_STATE_TASK_ERROR;
    this->error = WFT_ERR_URI_SCHEME_INVALID;
    return false;
}

template <class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::init_with_uri() {
    // 重定向处理
    if (redirect_) {
        clear_prev_state(); // 清除之前的请求的所有状态
        ns_policy_ = WFGlobal::get_dns_resolver(); // 重新获取全局dns解析器
    }
    // URI解析成功
    if (uri_.state == URI_STATE_SUCCESS) {
        // 验证端口合法性
        if (this->set_port()) {
            // 调用初始化成功回调
            if (this->init_success()) {
                return;
            }
        }
    }
    // URI解析失败
    else if (uri_.state == URI_STATE_ERROR) {
        this->state = WFT_STATE_SYS_ERROR;
        this->error = uri_.error;
    }
    // 其他未明确指定的状态
    else {
        this->state = WFT_STATE_TASK_ERROR;
        this->error = WFT_ERR_URI_PARSE_FAILED;
    }
    // 初始化失败, 调用失败回调
    this->init_failed();
}

// 创建路由任务, 实现客户端请求的目标服务器选择逻辑
template <class REQ, class RESP, typename CTX>
WFRouterTask *WFComplexClientTask<REQ, RESP, CTX>::route() {
    // 创建路由完成回调
    auto &&cb = std::bind(&WFComplexClientTask::router_callback, this, std::placeholders::_1);
    // 构建路由参数
    const struct WFNSParams params = {
        .type = type_,
        .uri = uri_,
        .info = info_.c_str(),
        .ssl_ctx = ssl_ctx_,
        .fixed_addr = fixed_addr_,
        .fixed_conn = fixed_conn_,
        .retry_times = retry_times_,
        .tracing = &tracing_,
    };
    // 获取命名服务策略
    if (!ns_policy_) {
        WFNameService *ns = WFGlobal::get_name_service();
        ns_policy_ = ns->get_policy(uri_.host ? uri_.host : "");
    }
    // 创建并返回路由任务（策略模式应用: 委托具体策略对象创建任务）
    return ns_policy_->create_router_task(&params, std::move(cb));
}

template <class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::router_callback(void *t) {
    auto *task = static_cast<WFRouterTask *>(t); // 使用 static_cast 而非 dynamic_cast 表明框架确保类型安全
    // 将子任务(路由任务)的状态传递给父任务(客户端任务)
    this->state = task->get_state();
    if (this->state == WFT_STATE_SUCCESS) {
        this->route_result_ = std::move(*task->get_result());
    } else if (this->state == WFT_STATE_UNDEFINED) {
        /* 未定义状态 should not happen */
        this->state = WFT_STATE_SYS_ERROR;
        this->error = ENOSYS;
    } else {
        // 保留路由任务的原始错误码
        this->error = task->get_error();
    }
}

template <class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::dispatch() {
    switch (this->state) //
    {
    case WFT_STATE_UNDEFINED: // 未定义状态.
        if (this->check_request()) // 检查参数是否合法
        {
            if (this->route_result_.request_object) // 检查是否已有有效的请求对象
            {
                // 以上两步都为true, 则穿透到成功状态
            case WFT_STATE_SUCCESS: //
                this->set_request_object(this->route_result_.request_object);
                // 职责分离: 基类处理通用网络逻辑, 派生类处理路由等高级特性
                this->WFClientTask<REQ, RESP>::dispatch(); // 委托父类处理实际的网络请求
                return;
            }
            // 没有有效的请求对象, 创建路由任务
            router_task_ = this->route();
            series_of(this)->push_front(this); // 将当前任务放入序列
            series_of(this)->push_front(router_task_); // 将路由任务放在当前任务之前
        }
    default: break;
    }
    this->subtask_done();
}

template <class REQ, class RESP, typename CTX>
void WFComplexClientTask<REQ, RESP, CTX>::switch_callback(void *t) {
    // 非重定向路径处理
    if (!redirect_) {
        // SSL错误转换
        if (this->state == WFT_STATE_SYS_ERROR && this->error < 0) {
            this->state = WFT_STATE_SSL_ERROR;
            this->error = -this->error;
        }
        // 追踪数据 清理
        if (tracing_.deleter) {
            tracing_.deleter(tracing_.data);
            tracing_.deleter = nullptr;
        }
        // 用于回调执行
        if (this->callback) {
            this->callback(this);
        }
    }
    // 重定向路径
    if (redirect_) {
        redirect_ = false; // 重定向状态重置
        clear_resp(); // 清除上一次的响应对象
        this->target = NULL; //
        series_of(this)->push_front(this);
    } else {
        // 任务自我销毁
        delete this;
    }
}

template <class REQ, class RESP, typename CTX>
SubTask *WFComplexClientTask<REQ, RESP, CTX>::done() {
    SeriesWork *series = series_of(this);
    // 路由任务清理
    if (router_task_) {
        // 存在未处理的路由任务时, 直接清理并返回序列中下一个任务
        router_task_ = nullptr;
        return series->pop();
    }
    // 任务状态标记
    const bool is_user_request = this->finish_once(); // 判断是否需要回调
    // 服务发现反馈
    if (ns_policy_) {
        if (this->state == WFT_STATE_SYS_ERROR || this->state == WFT_STATE_DNS_ERROR) {
            ns_policy_->failed(&route_result_, &tracing_, this->target); // 当出现系统错误或DNS错误时, 通知策略服务节点不可用
        } else if (route_result_.request_object) {
            ns_policy_->success(&route_result_, &tracing_, this->target); // 当请求成功时，通知策略服务节点健康
        }
    }
    // 请求成功
    if (this->state == WFT_STATE_SUCCESS) {
        if (!is_user_request) {
            return this; // 非用户请求（重试/重定向）成功时, 直接返回当前任务
        }
    }
    // 系统错误
    else if (this->state == WFT_STATE_SYS_ERROR) {
        // 仅在重试次数未达上限时重试
        if (retry_times_ < retry_max_) {
            redirect_ = true;
            if (ns_policy_) {
                route_result_.clear(); // 清除路由结果, 强制重新路由
            }
            this->state = WFT_STATE_UNDEFINED; // 重置任务状态为未定义
            this->error = 0; // 清除错误码
            this->timeout_reason = 0; // 清除超时原因
            retry_times_++;
        }
    }

    // 线程安全回调调度
    // 线程切换触发条件: 无目标地址 (!this->target)，或者 无活跃连接
    /* When the target or the connection is NULL, it's likely that we are
     * in the caller's thread. Running a timer will switch callback function to
     * a handler thread, and this can prevent stack overflow. */
    if (!this->target || !this->CommSession::get_connect()) {
        // 创建计时器任务, 令回调函数在计时器任务中执行。（计时器任务会在一个单独的线程中执行, 避免调用者线程栈溢出）
        auto &&cb = std::bind(&WFComplexClientTask::switch_callback, this, std::placeholders::_1);
        WFTimerTask *timer = WFTaskFactory::create_timer_task(std::move(cb));
        series->push_front(timer);
    } else {
        // 直接调用回调
        this->switch_callback(nullptr);
    }
    // 返回序列中下一个任务
    return series->pop();
}

/**********Template Network Factory**********/

template <class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_client_task(enum TransportType type, const std::string &host, unsigned short port,
                                                    int retry_max, std::function<void (WFNetworkTask<REQ, RESP> *)> callback) {
    auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, std::move(callback));

    char port_buf[32];
    sprintf(port_buf, "%u", port); // 将 port 转为 char* 字符串类型

    ParsedURI uri;
    uri.scheme = strdup("scheme");
    uri.host = strdup(host.c_str());
    uri.port = strdup(port_buf);
    if (!uri.scheme || !uri.host || !uri.port) {
        // 有资源内存分配失败(strdup出现了问题), 设置错误状态和错误码, 方便诊断
        uri.state = URI_STATE_ERROR;
        uri.error = errno;
    } else {
        uri.state = URI_STATE_SUCCESS;
    }

    task->init(std::move(uri));
    task->set_transport_type(type);
    return task;
}

template <class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_client_task(enum TransportType type, const std::string &url,
                                                    int retry_max, std::function<void (WFNetworkTask<REQ, RESP> *)> callback) {
    auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, std::move(callback));

    ParsedURI uri;
    // 解析URI. 在创建时解析, 而不是在任务执行时解析: 无效URI在创建时就暴露, 但增加了创建开销
    if (URIParser::parse(url, uri) < 0) {
        // URI解析失败, 释放内存并返回nullptr
        delete task;
        return nullptr;
    }
    task->init(std::move(uri));
    task->set_transport_type(type); // 是否与 ParsedURI.scheme 重复？？？
    return task;
}

template <class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_client_task(enum TransportType type, const ParsedURI &uri,
                                                    int retry_max, std::function<void (WFNetworkTask<REQ, RESP> *)> callback) {
    auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, std::move(callback));

    task->init(uri);
    task->set_transport_type(type);
    return task;
}

template <class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_client_task(enum TransportType type, const struct sockaddr *addr, socklen_t addrlen,
                                                    int retry_max, std::function<void (WFNetworkTask<REQ, RESP> *)> callback) {
    auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, std::move(callback));

    task->init(type, addr, addrlen, "");
    return task;
}

template <class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_client_task(enum TransportType type, const struct sockaddr *addr, socklen_t addrlen,
                                                    SSL_CTX *ssl_ctx, int retry_max,
                                                    std::function<void (WFNetworkTask<REQ, RESP> *)> callback) {
    auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, std::move(callback));

    task->set_ssl_ctx(ssl_ctx);
    task->init(type, addr, addrlen, "");
    return task;
}

template <class REQ, class RESP>
WFNetworkTask<REQ, RESP> *
WFNetworkTaskFactory<REQ, RESP>::create_server_task(CommService *service,
                                                    std::function<void (WFNetworkTask<REQ, RESP> *)> &process) {
    return new WFServerTask<REQ, RESP>(service, WFGlobal::get_scheduler(), process);
}

/**********Server Factory**********/

class WFServerTaskFactory {
public:
    static WFDnsTask *create_dns_task(CommService *service, std::function<void (WFDnsTask *)> &process);

    static WFHttpTask *create_http_task(CommService *service, std::function<void (WFHttpTask *)> &process);

    // static WFMySQLTask *create_mysql_task(CommService *service, std::function<void (WFMySQLTask *)> &process);
};

/************Go Task Factory************/

// 协程？？？
class __WFGoTask : public WFGoTask {
public:
    void set_go_func(std::function<void ()> func) {
        this->go = std::move(func);
    }

protected:
    void execute() override {
        this->go(); //
    }

protected:
    std::function<void ()> go; // 保存任意可调用对象

public:
    __WFGoTask(ExecQueue *queue, Executor *executor, std::function<void ()> &&func) :
        WFGoTask(queue, executor), // 基类初始化
        go(std::move(func)) // 移动语义避免拷贝
    {}
};

// 带定时的协程？？？
class __WFTimedGoTask : public __WFGoTask {
protected:
    void dispatch() override;
    SubTask *done() override;

protected:
    void handle(int state, int error) override;

protected:
    static void timer_callback(WFTimerTask *timer);

protected:
    time_t seconds;
    long nanoseconds;
    std::atomic<int> ref;

public:
    __WFTimedGoTask(const time_t seconds, const long nanoseconds,
                    ExecQueue *queue, Executor *executor,
                    std::function<void ()> &&func) :
        __WFGoTask(queue, executor, std::move(func)),
        ref(4) // 引用计数初始化为4, 表示生命周期分为四个阶段:
    // Go 任务执行：用户函数的执行
    // 定时器任务：等待指定时间
    // 协调任务 1：定时器超时后触发 Go 任务
    // 协调任务 2：Go 任务完成后清理资源
    {
        this->seconds = seconds;
        this->nanoseconds = nanoseconds;
    }
};

// 创建GO任务, 传入队列名
template <class FUNC, class... ARGS>
WFGoTask *WFTaskFactory::create_go_task(const std::string &queue_name, FUNC &&func, ARGS &&... args) {
    auto &&tmp = std::bind(std::forward<FUNC>(func), std::forward<ARGS>(args)...);
    return new __WFGoTask(WFGlobal::get_exec_queue(queue_name),
                          WFGlobal::get_compute_executor(),
                          std::move(tmp));
}

// 创建带定时的GO任务, 通过队列名
template <class FUNC, class... ARGS>
WFGoTask *WFTaskFactory::create_timedgo_task(time_t seconds, long nanoseconds,
                                             const std::string &queue_name,
                                             FUNC &&func, ARGS &&... args) {
    auto &&tmp = std::bind(std::forward<FUNC>(func), std::forward<ARGS>(args)...);
    return new __WFTimedGoTask(seconds, nanoseconds,
                               WFGlobal::get_exec_queue(queue_name),
                               WFGlobal::get_compute_executor(),
                               std::move(tmp));
}

// 创建GO任务, 直接传入任务的执行单元的任务的队列
template <class FUNC, class... ARGS>
WFGoTask *WFTaskFactory::create_go_task(ExecQueue *queue, Executor *executor,
                                        FUNC &&func, ARGS &&... args) {
    auto &&tmp = std::bind(std::forward<FUNC>(func), std::forward<ARGS>(args)...);
    return new __WFGoTask(queue, executor, std::move(tmp));
}

// 创建带定时的GO任务, 直接传入任务的执行单元的任务的队列
template <class FUNC, class... ARGS>
WFGoTask *WFTaskFactory::create_timedgo_task(time_t seconds, long nanoseconds,
                                             ExecQueue *queue, Executor *executor,
                                             FUNC &&func, ARGS &&... args) {
    auto &&tmp = std::bind(std::forward<FUNC>(func), std::forward<ARGS>(args)...);
    return new __WFTimedGoTask(seconds, nanoseconds, queue, executor, std::move(tmp));
}

// 重置已有 Go 任务的执行函数
template <class FUNC, class... ARGS>
void WFTaskFactory::reset_go_task(WFGoTask *task, FUNC &&func, ARGS &&... args) {
    auto &&tmp = std::bind(std::forward<FUNC>(func), std::forward<ARGS>(args)...);
    dynamic_cast<__WFGoTask *>(task)->set_go_func(std::move(tmp));
}

/**********Create go task with nullptr func**********/

/**为什么需要提供创建空任务的接口？
 * 相比于上方的模板接口, 下方的特化版本: 无std::bind()调用, 无函数对象构造 ,无移动语义开销 */

// 创建空的GO任务
template <> inline
WFGoTask *WFTaskFactory::create_go_task(const std::string &queue_name,
                                        std::nullptr_t &&) {
    return new __WFGoTask(WFGlobal::get_exec_queue(queue_name),
                          WFGlobal::get_compute_executor(),
                          nullptr);
}

template <> inline
WFGoTask *WFTaskFactory::create_timedgo_task(time_t seconds, long nanoseconds,
                                             const std::string &queue_name,
                                             std::nullptr_t &&) {
    return new __WFTimedGoTask(seconds, nanoseconds,
                               WFGlobal::get_exec_queue(queue_name),
                               WFGlobal::get_compute_executor(),
                               nullptr);
}

template <> inline
WFGoTask *WFTaskFactory::create_go_task(ExecQueue *queue, Executor *executor,
                                        std::nullptr_t &&) {
    return new __WFGoTask(queue, executor, nullptr);
}

template <> inline
WFGoTask *WFTaskFactory::create_timedgo_task(time_t seconds, long nanoseconds,
                                             ExecQueue *queue, Executor *executor,
                                             std::nullptr_t &&) {
    return new __WFTimedGoTask(seconds, nanoseconds, queue, executor, nullptr);
}

template <> inline
void WFTaskFactory::reset_go_task(WFGoTask *task, std::nullptr_t &&) {
    dynamic_cast<__WFGoTask *>(task)->set_go_func(nullptr);
}

/**********Template Thread Task Factory**********/

template <class INPUT, class OUTPUT>
class __WFThreadTask : public WFThreadTask<INPUT, OUTPUT> {
protected:
    void execute() override {
        this->routine(&this->input, &this->output); // 执行业务逻辑
    }

protected:
    std::function<void (INPUT *, OUTPUT *)> routine; // 主要业务逻辑函数

public:
    __WFThreadTask(ExecQueue *queue, Executor *executor,
                   std::function<void (INPUT *, OUTPUT *)> &&rt,
                   std::function<void (WFThreadTask<INPUT, OUTPUT> *)> &&cb) :
        WFThreadTask<INPUT, OUTPUT>(queue, executor, std::move(cb)),
        routine(std::move(rt)) {}
};

template <class INPUT, class OUTPUT>
class __WFTimedThreadTask : public __WFThreadTask<INPUT, OUTPUT> {
protected:
    void dispatch() override;
    SubTask *done() override;

protected:
    // 任务完成回调
    void handle(int state, int error) override;

protected:
    // 定时器超时后的回调
    static void timer_callback(WFTimerTask *timer);

protected:
    time_t seconds;
    long nanoseconds;
    std::atomic<int> ref; // 引用计数, 用于管理生命周期: 1次: 任务对象自身, 1次: 线程执行上下文, 1次: 定时器任务, 1次: 完成回调处理

public:
    __WFTimedThreadTask(time_t seconds, long nanoseconds,
                        ExecQueue *queue, Executor *executor,
                        std::function<void (INPUT *, OUTPUT *)> &&rt,
                        std::function<void (WFThreadTask<INPUT, OUTPUT> *)> &&cb) :
        __WFThreadTask<INPUT, OUTPUT>(queue, executor, std::move(rt), std::move(cb)),
        ref(4) // 初始化为4, 代表生命周期的四次
    {
        this->seconds = seconds;
        this->nanoseconds = nanoseconds;
    }
};

template <class INPUT, class OUTPUT>
void __WFTimedThreadTask<INPUT, OUTPUT>::dispatch() {
    WFTimerTask *timer = WFTaskFactory::create_timer_task(this->seconds, this->nanoseconds, __WFTimedThreadTask::timer_callback);
    timer->user_data = this; // 将任务对象的指针传递给定时器, 方便定时器在超时时通过指针访问任务对象

    this->ExecRequest::dispatch(); // 将任务交给线程池
    timer->start(); // 启动定时器. 如果先启动定时器, 可能在任务准备完成前就超时
}

template <class INPUT, class OUTPUT>
SubTask *__WFTimedThreadTask<INPUT, OUTPUT>::done() {
    if (this->callback) {
        this->callback(this);
    }
    return series_of(this)->pop();
}

template <class INPUT, class OUTPUT>
void __WFTimedThreadTask<INPUT, OUTPUT>::handle(int state, int error) {
    if (--this->ref == 3) {
        // --ref == 3 说明, 任务先完成(或者执行过程中出错),
        // 定时器尚未超时（timer_callback()尚未被调用）
        // 此时记录任务状态, 然后调用subtask_done()继续后续任务
        this->state = state;
        this->error = error;
        this->SubTask::subtask_done();
    }
    // 如果没有进入上面的if语句, 则说明定时器已经超时, 任务在定时器的回调函数timer_callback中已经被标记完成

    if (--this->ref == 0) {
        // --ref == 0
        delete this;
    }
}

template <class INPUT, class OUTPUT>
void __WFTimedThreadTask<INPUT, OUTPUT>::timer_callback(WFTimerTask *timer) {
    auto *task = static_cast<__WFTimedThreadTask<INPUT, OUTPUT> *>(timer->user_data);

    if (--task->ref == 3) {
        // --ref == 3 说明, 定时器先超时（或者被取消，又或者系统资源耗尽导致定时器设置失败）, 任务还没有完成
        if (timer->get_state() == WFT_STATE_SUCCESS) {
            // 定时器是真正的超时
            task->state = WFT_STATE_SYS_ERROR;
            task->error = ETIMEDOUT;
        } else {
            // 定时器被取消，或者系统资源耗尽，或者系统时间被回拨（例如从2022年调回2020年）, 或者其他非正常超时情况
            task->state = timer->get_state();
            task->error = timer->get_error();
        }
        // 令该任务提前完成, 无论任务此时是何状态
        task->subtask_done();
    }

    if (--task->ref == 0) {
        delete task;
    }
}

template <class INPUT, class OUTPUT>
WFThreadTask<INPUT, OUTPUT> *
WFThreadTaskFactory<INPUT, OUTPUT>::create_thread_task(const std::string &queue_name,
                                                       std::function<void (INPUT *, OUTPUT *)> routine,
                                                       std::function<void (WFThreadTask<INPUT, OUTPUT> *)> callback) {
    return new __WFThreadTask<INPUT, OUTPUT>(WFGlobal::get_exec_queue(queue_name),
                                             WFGlobal::get_compute_executor(),
                                             std::move(routine),
                                             std::move(callback));
}

template <class INPUT, class OUTPUT>
WFThreadTask<INPUT, OUTPUT> *
WFThreadTaskFactory<INPUT, OUTPUT>::create_thread_task(time_t seconds, long nanoseconds,
                                                       const std::string &queue_name,
                                                       std::function<void (INPUT *, OUTPUT *)> routine,
                                                       std::function<void (WFThreadTask<INPUT, OUTPUT> *)> callback) {
    return new __WFTimedThreadTask<INPUT, OUTPUT>(seconds, nanoseconds,
                                                  WFGlobal::get_exec_queue(queue_name),
                                                  WFGlobal::get_compute_executor(),
                                                  std::move(routine),
                                                  std::move(callback));
}

template <class INPUT, class OUTPUT>
WFThreadTask<INPUT, OUTPUT> *
WFThreadTaskFactory<INPUT, OUTPUT>::create_thread_task(ExecQueue *queue, Executor *executor,
                                                       std::function<void (INPUT *, OUTPUT *)> routine,
                                                       std::function<void (WFThreadTask<INPUT, OUTPUT> *)> callback) {
    return new __WFThreadTask<INPUT, OUTPUT>(queue, executor, std::move(routine), std::move(callback));
}

template <class INPUT, class OUTPUT>
WFThreadTask<INPUT, OUTPUT> *
WFThreadTaskFactory<INPUT, OUTPUT>::create_thread_task(time_t seconds, long nanoseconds,
                                                       ExecQueue *queue, Executor *executor,
                                                       std::function<void (INPUT *, OUTPUT *)> routine,
                                                       std::function<void (WFThreadTask<INPUT, OUTPUT> *)> callback) {
    return new __WFTimedThreadTask<INPUT, OUTPUT>(seconds, nanoseconds,
                                                  queue, executor,
                                                  std::move(routine),
                                                  std::move(callback));
}