//
// Created by ldk on 12/20/25.
//

/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Liu Kai (liukaidx@sogou-inc.com)
*/

#include <string>
#include <atomic>
#include "dns_types.h"
#include "DnsMessage.h"
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "WFServer.h"

using namespace protocol;

// DNS连接默认保活时间（60秒）
#define DNS_KEEPALIVE_DEFAULT	(60 * 1000)

/**********Client**********/

/**
 * @brief DNS客户端任务
 *
 * 处理DNS查询的核心逻辑, 支持：
 * - UDP/TCP自动切换（当响应被截断时）
 * - DNS over SSL (dnss://)
 * - 智能重试与重定向
 */
class ComplexDnsTask : public WFComplexClientTask<DnsRequest,
                                                  DnsResponse,
                                                  std::function<void (WFDnsTask *)> > // 回调类型
{
    static struct addrinfo hints;   // 静态addrinfo提示（用于getaddrinfo）
    static std::atomic<size_t> seq; // 全局请求ID生成器（原子计数器）

public:
    /**
     * @param retry_max 最大重试次数
     * @param cb 用户回调函数
     */
    ComplexDnsTask(int retry_max, dns_callback_t &&cb) :
        WFComplexClientTask(retry_max, std::move(cb)) {
        this->set_transport_type(TT_UDP); // DNS默认使用UDP传输
    }

protected:
    CommMessageOut *message_out() override;

    bool init_success() override;

    bool finish_once() override;

private:
    bool need_redirect();
};

// addrinfo静态初始化（数字服务+数字主机模式）
struct addrinfo ComplexDnsTask::hints =
{
    .ai_flags = AI_NUMERICSERV | AI_NUMERICHOST, // 仅解析数字地址/端口
    .ai_family = AF_UNSPEC,                      // 支持IPv4/IPv6
    .ai_socktype = SOCK_STREAM                   // 流式套接字（TCP）
};

// 全局DNS请求ID种子（避免冲突）
std::atomic<size_t> ComplexDnsTask::seq(0);

/**
 * @brief 消息序列化（准备发送的数据包）
 *
 * 关键处理：
 * 1. 生成唯一请求ID（避免冲突）
 * 2. 同步请求/响应的单包标志（影响DNS分片处理）
 * 3. 透传到基类序列化
 *
 * @return 待发送的消息对象
 */
CommMessageOut *ComplexDnsTask::message_out() {
    DnsRequest *req = this->get_req();
    DnsResponse *resp = this->get_resp();
    enum TransportType type = this->get_transport_type();

    // 生成唯一请求ID（避免0值）
    if (req->get_id() == 0) {
        // 原子递增+哈希扰动（减少冲突概率）
        req->set_id(++ComplexDnsTask::seq * 99991 % 65535 + 1);
    }
    // 同步响应ID（用于匹配请求-响应）
    resp->set_request_id(req->get_id());
    resp->set_request_name(req->get_question_name());

    // 设置单包标志（UDP必须单包，TCP可分片）
    req->set_single_packet(type == TT_UDP);
    resp->set_single_packet(type == TT_UDP);

    // 透传到基类完成序列化
    return this->WFClientTask::message_out();
}

/**
 * @brief 任务初始化验证
 *
 * 核心检查：
 * 1. 验证URI scheme（dns/dnss）
 * 2. 解析DNS服务器地址
 * 3. 集成Workflow路由系统
 *
 * @return bool true=初始化成功
 */
bool ComplexDnsTask::init_success() {
    // 验证URI scheme
    if (uri_.scheme && strcasecmp(uri_.scheme, "dnss") == 0) {
        // DNS over SSL 强制使用TCP+SSL
        this->WFComplexClientTask::set_transport_type(TT_TCP_SSL);
    }
    // 无效scheme
    else if (!uri_.scheme || strcasecmp(uri_.scheme, "dns") != 0) {
        this->state = WFT_STATE_TASK_ERROR;
        this->error = WFT_ERR_URI_SCHEME_INVALID;
        return false;
    }

    // 地址解析与路由
    if (!this->route_result_.request_object) {
        enum TransportType type = this->get_transport_type();
        struct addrinfo *addr;
        int ret;

        // 解析DNS服务器地址（数字模式，避免递归DNS查询）
        ret = getaddrinfo(uri_.host, uri_.port, &hints, &addr);
        if (ret != 0) {
            this->state = WFT_STATE_DNS_ERROR;
            this->error = ret;
            return false;
        }

        // 集成Workflow路由系统
        auto *ep = &WFGlobal::get_global_settings()->dns_server_params;
        ret = WFGlobal::get_route_manager()->get(
            type,            // 传输类型
            addr,            // 服务器地址
            this->info_,     // 连接信息
            ep,              // 端点参数
            this->uri_.host, // 目标主机
            this->ssl_ctx_,  // SSL上下文
            route_result_    // 路由结果（输出）
            );
        freeaddrinfo(addr);
        if (ret < 0) {
            this->state = WFT_STATE_SYS_ERROR;
            this->error = errno;
            return false;
        }
    }

    return true;
}

/**
 * @brief 单次请求完成处理
 *
 * 决策逻辑：
 * 1. 检查是否需要协议切换（UDP->TCP）
 * 2. 处理用户重定向请求
 * 3. 重试次数耗尽时回调用户
 *
 * @return bool true=继续任务流程
 */
bool ComplexDnsTask::finish_once() {
    // 检查协议切换/重定向
    if (this->state == WFT_STATE_SUCCESS) {
        if (need_redirect()) {
            // 触发重定向（如UDP截断时切换TCP）
            this->set_redirect(uri_);
        } else if (this->state != WFT_STATE_SUCCESS) {
            // 非成功状态禁用重试
            this->disable_retry();
        }
    }

    /* If retry times meet retry max and there is no redirect,
     * we ask the client for a retry or redirect.
     */
    // 当重试次数达到上限且无重定向时, 回调用户处理
    if (retry_times_ == retry_max_ && !redirect_ && *this->get_mutable_ctx()) {
        this->set_transport_type(TT_UDP); // 重置为UDP（为可能的重定向准备）
        (*this->get_mutable_ctx())(this); // 用户回调决定后续（可能手动重试/重定向）
    }

    return true;
}

/**
 * @brief 检查是否需要重定向
 *
 * 触发条件：
 * - UDP传输时响应被截断（TC标志=1）
 *
 * @return bool true=需要重定向
 */
bool ComplexDnsTask::need_redirect() {
    DnsResponse *client_resp = this->get_resp();
    enum TransportType type = this->get_transport_type();

    // UDP截断时切换到TCP（RFC标准要求）
    if (type == TT_UDP && client_resp->get_tc() == 1) {
        this->set_transport_type(TT_TCP); // 切换传输协议
        return true;
    }

    return false;
}

/**********Client Factory**********/

/**
 * @brief 创建DNS客户端任务（字符串URL）
 *
 * @param url DNS查询URL（格式：dns://server/name）
 * @param retry_max 最大重试次数
 * @param callback 完成回调
 * @return WFDnsTask* 任务对象
 */
WFDnsTask *WFTaskFactory::create_dns_task(const std::string &url, int retry_max,
                                          dns_callback_t callback) {
    ParsedURI uri;
    // 解析URL（自动处理编码等）
    URIParser::parse(url, uri);
    return WFTaskFactory::create_dns_task(uri, retry_max, std::move(callback));
}

/**
 * @brief 创建DNS客户端任务（预解析URI）
 *
 * @param uri 预解析的URI对象
 * @param retry_max 最大重试次数
 * @param callback 完成回调
 * @return WFDnsTask* 任务对象
 */
WFDnsTask *WFTaskFactory::create_dns_task(const ParsedURI &uri, int retry_max,
                                          dns_callback_t callback) {
    // 创建任务对象
    ComplexDnsTask *task = new ComplexDnsTask(retry_max, std::move(callback));
    const char *name;

    // 提取查询域名（处理路径格式：/example.com）
    if (uri.path && uri.path[0] && uri.path[1]) {
        name = uri.path + 1; // 跳过开头的'/'
    } else {
        name = "."; // 根域
    }

    // 设置DNS查询问题（A记录/IN类）
    DnsRequest *req = task->get_req();
    req->set_question(name, DNS_TYPE_A, DNS_CLASS_IN);

    // 初始化任务（设置目标服务器等）
    task->init(uri);
    // 设置连接保活时间
    task->set_keep_alive(DNS_KEEPALIVE_DEFAULT);
    return task;
}


/**********Server**********/

/**
 * @brief DNS服务端任务类
 *
 * 适配Workflow服务器模型, 处理:
 * 1. 请求/响应分片标志设置
 * 2. 响应头自动生成
 * 3. 传输类型适配
 */
class WFDnsServerTask : public WFServerTask<DnsRequest, DnsResponse> {
public:
    WFDnsServerTask(CommService *service, std::function<void (WFDnsTask *)> &proc) :
        WFServerTask(service, WFGlobal::get_scheduler(), proc) {
        // 从服务参数获取传输类型（UDP/TCP）
        this->type = reinterpret_cast<WFServerBase *>(service)->get_params()->transport_type;
    }

protected:
    // 消息反序列化（接收时处理）
    CommMessageIn *message_in() override {
        // 设置请求单包标志（影响分片处理）
        this->get_req()->set_single_packet(this->type == TT_UDP);
        return this->WFServerTask::message_in();
    }

    // 消息序列化（发送前处理）
    CommMessageOut *message_out() override {
        // 设置响应单包标志
        this->get_resp()->set_single_packet(this->type == TT_UDP);
        return this->WFServerTask::message_out();
    }

    void handle(int state, int error) override;

protected:
    enum TransportType type; // 服务传输类型
};

/**
 * @brief 服务端任务状态处理
 *
 * 关键状态处理：
 * - WFT_STATE_TOREPLY: 构造标准DNS响应头
 *
 * @param state 任务状态
 * @param error 错误码
 */
void WFDnsServerTask::handle(int state, int error) {
    // 构造响应头（仅当需要回复时）
    if (state == WFT_STATE_TOREPLY) {
        DnsRequest *req = this->get_req();
        DnsResponse *resp = this->get_resp();

        // 复制请求关键字段
        resp->set_question_name(req->get_question_name());
        resp->set_question_type(req->get_question_type());
        resp->set_question_class(req->get_question_class());
        resp->set_opcode(req->get_opcode());
        resp->set_id(req->get_id()); // 匹配请求ID
        resp->set_rd(req->get_rd()); // 递归期望标志
        resp->set_qr(1);
        // resp->set_ra(1);
    }
    // 透传到基类完成后续处理
    return WFServerTask::handle(state, error);
}

/**********Server Factory**********/

/**
 * @brief 创建DNS服务端任务
 *
 * @param service 通信服务对象
 * @param proc 业务处理器
 * @return WFDnsTask* 任务对象
 */
WFDnsTask *WFServerTaskFactory::create_dns_task(CommService *service, std::function<void (WFDnsTask *)> &proc) {
    return new WFDnsServerTask(service, proc);
}