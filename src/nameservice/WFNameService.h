//
// Created by ldk on 11/26/25.
//

/*
  Copyright (c) 2020 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef MYWORKFLOW_WFNAMESERVICE_H
#define MYWORKFLOW_WFNAMESERVICE_H

#include <pthread.h>
#include <functional>
#include <utility>
#include "rbtree.h"
#include "Communicator.h"
#include "Workflow.h"
#include "WFTask.h"
#include "RouteManager.h"
#include "URIParser.h"
#include "EndpointParams.h"

// 路由解析. 异步获取路由结果（如 DNS 解析、负载均衡选择）
class WFRouterTask : public WFGenericTask {
public:
    RouteManager::RouteResult *get_result() { return &this->result; }

public:
    void set_state(const int state) { this->state = state; }
    void set_error(const int error) { this->error = error; }

protected:
    RouteManager::RouteResult result; // 存储路由解析的结果, 例如选择的具体目标服务器地址（addrinfo）或负载均衡组
    std::function<void (WFRouterTask *)> callback; // 当路由任务完成（无论成功或失败）后, 框架会自动执行此回调, 通知调用方任务已结束

protected:
    // 任务的最终环节, 由框架在任务执行完毕后调用
    SubTask *done() override {
        SeriesWork *series = series_of(this); // 获取所属的任务流

        if (this->callback) {
            this->callback(this); // 执行回调函数
        }

        delete this; // 释放自身内存
        return series->pop(); // 返回任务流中下一个任务
    }

public:
    explicit WFRouterTask(std::function<void (WFRouterTask *)> &&cb) : callback(std::move(cb)) {}
};

// 追踪数据容器. 比如用于请求链路追踪
class WFNSTracing {
public:
    void *data; // 指向实际追踪数据的指针
    void (*deleter)(void *); // 负责释放data所指内存的函数指针

public:
    WFNSTracing() {
        this->data = nullptr;
        this->deleter = nullptr;
    }
};

// 技巧--关注点分离: WFNSParams 负责描述请求, 而 WFNSTracing 负责记录过程

// 命名服务请求的完整描述
struct WFNSParams {
    TransportType type; // 协议类型
    ParsedURI &uri; // 通信目标
    const char *info; // 用于传递调试ID或标签, 或者其他信息
    SSL_CTX *ssl_ctx; // 是否加密以及如何加密
    bool fixed_addr; // 用于优化与控制. 例如: 在测试或处理已知IP的服务时, 设置 fixed_addr 为 true 可以跳过DNS查询. 提升性能
    bool fixed_conn; // 用于优化与控制. 可能用于需要隔离连接的特殊场景
    int retry_times; // 自动重试次数
    WFNSTracing *tracing; // 通过传入一个非空的 WFNSTracing 对象, 调用者可以收集到此次命名解析过程的内部详细日志、耗时等诊断信息.
};

using router_callback_t = std::function<void (WFRouterTask *)>;

// 策略模式抽象基类: 命名服务与路由管理的核心算法骨架
class WFNSPolicy {
public:
    // 根据参数创建特定的路由任务. 子类必须实现该方法
    virtual WFRouterTask *create_router_task(const struct WFNSParams *params, router_callback_t callback) = 0;

    // 成功回调. 标记目标可用
    virtual void success(RouteManager::RouteResult *result, WFNSTracing *tracing, CommTarget *target) {
        RouteManager::notify_available(result->cookie, target);
    }

    // 失败回调. 标记目标不可用
    virtual void failed(RouteManager::RouteResult *result, WFNSTracing *tracing, CommTarget *target) {
        if (target) {
            RouteManager::notify_unavailable(result->cookie, target);
        }
    }

public:
    virtual ~WFNSPolicy() = default;
};

class WFNameService {
public:
    int add_policy(const char *name, WFNSPolicy *policy);
    WFNSPolicy *get_policy(const char *name);
    WFNSPolicy *del_policy(const char *name);

public:
    // 获取默认策略
    [[nodiscard]] WFNSPolicy *get_default_policy() const {
        return this->default_policy;
    }

    // 设置默认策略
    void set_default_policy(WFNSPolicy *policy) {
        this->default_policy = policy;
    }

private:
    WFNSPolicy *default_policy; // 默认策略指针. 当通过 get_policy未找到指定名称的策略时, 回退到此默认策略, 确保总有策略可用
    rb_root root; // 存储所有注册的策略条目
    pthread_rwlock_t rwlock; // 读写锁

private:
    // 内部查找器. 执行红黑树查找, 返回策略条目, 用于内部管理
    struct WFNSPolicyEntry *get_policy_entry(const char *name) const;

public:
    explicit WFNameService(WFNSPolicy *default_policy) : rwlock(PTHREAD_RWLOCK_INITIALIZER), root{nullptr} {
        this->default_policy = default_policy;
    }

    virtual ~WFNameService();
};

#endif //MYWORKFLOW_WFNAMESERVICE_H