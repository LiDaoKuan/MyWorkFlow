//
// Created by ldk on 11/27/25.
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
#include <vector>
#include <atomic>
#include "URIParser.h"
#include "StringUtil.h"
#include "dns_types.h"
#include "DnsMessage.h"
#include "WFDnsClient.h"

using namespace protocol;

using DnsCtx = std::function<void (WFDnsTask *)>;
using ComplexTask = WFComplexClientTask<DnsRequest, DnsResponse, DnsCtx>;

class DnsParams {
public:
    struct dns_params {
        std::vector<ParsedURI> uris;          // DNS服务器URI列表 (如 dns://8.8.8.8)
        std::vector<std::string> search_list; // DNS搜索域列表 (如 example.com)
        int ndots;                            // 决定是否使用搜索域的点数阈值
        int attempts;                         // 每个查询的最大尝试次数
        bool rotate;                          // 是否轮询DNS服务器
    };

public:
    DnsParams() {
        this->ref = new std::atomic<size_t>(1); // 原子引用计数，确保线程安全
        this->params = new dns_params();        // 分配参数存储空间
    }

    DnsParams(const DnsParams &p) {
        this->ref = p.ref;       // 共享同一个引用计数器
        this->params = p.params; // 共享同一个参数对象
        this->incref();          // 增加引用计数
    }

    DnsParams &operator=(const DnsParams &p) {
        // 防止自赋值
        if (this != &p) {
            this->decref();          // 减少当前对象的引用计数，可能触发释放
            this->ref = p.ref;       // 指向新的引用计数器
            this->params = p.params; // 指向新的参数对象
            this->incref();          // 增加新参数的引用计数
        }
        return *this;
    }

    ~DnsParams() { this->decref(); }

    [[nodiscard]] const dns_params *get_params() const { return this->params; }
    dns_params *get_params() { return this->params; }

private:
    // 增加引用计数
    void incref() {
        ++(*this->ref);
    }

    // 减少引用计数, 如果为0则释放资源
    void decref() {
        if (--(*this->ref) == 0) {
            delete this->params;
            delete this->ref;
        }
    }

private:
    dns_params *params;       // 指向实际DNS参数的指针
    std::atomic<size_t> *ref; // 引用计数指针, 方便两个对象使用同一个引用计数
};

// DNS查询状态枚举，控制原始域名的尝试策略
enum {
    DNS_STATUS_TRY_ORIGIN_DONE = 0,  // 已尝试原始域名
    DNS_STATUS_TRY_ORIGIN_FIRST = 1, // 第一次尝试原始域名（在搜索域之前）
    DNS_STATUS_TRY_ORIGIN_LAST = 2   // 最后尝试原始域名（在搜索域之后）
};

// DNS查询状态结构，跟踪查询过程中的中间状态
struct DnsStatus {
    std::string origin_name;  // 原始查询名称
    std::string current_name; // 当前尝试的完整域名
    size_t next_server;       // 下一个要尝试的DNS服务器索引
    size_t last_server;       // 最后一个要尝试的DNS服务器索引
    size_t next_domain;       // 下一个要尝试的搜索域索引
    int attempts_left;        // 剩余尝试次数
    int try_origin_state;     // 原始域名尝试状态
};

// 计算字符串中点('.')的数量, 用于决定是否应用搜索域
static int __get_ndots(const std::string &str) {
    int ndots = 0;
    for (const char ch : str) {
        ndots += (ch == '.'); // 累加 "." 的数量
    }
    return ndots;
}

// 根据DNS规则生成下一个要尝试的域名
static bool __has_next_name(const DnsParams::dns_params *p, struct DnsStatus *s) {
    // 尝试原始域名（如果状态设置为FIRST）
    if (s->try_origin_state == DNS_STATUS_TRY_ORIGIN_FIRST) {
        s->current_name = s->origin_name;
        s->try_origin_state = DNS_STATUS_TRY_ORIGIN_DONE;
        return true;
    }

    // 尝试所有搜索域（search_list）
    if (s->next_domain < p->search_list.size()) {
        s->current_name = s->origin_name;
        s->current_name.push_back('.');                         // 添加点分隔符
        s->current_name.append(p->search_list[s->next_domain]); // 添加搜索域
        s->next_domain++;                                       // 移动到下一个搜索域
        return true;
    }

    // 3. 最后尝试原始域名（如果状态设置为LAST）
    if (s->try_origin_state == DNS_STATUS_TRY_ORIGIN_LAST) {
        s->current_name = s->origin_name;
        s->try_origin_state = DNS_STATUS_TRY_ORIGIN_DONE;
        return true;
    }

    // 4. 无更多域名可尝试
    return false;
}

// DNS查询的内部回调函数, 处理重试逻辑和错误恢复
static void __callback_internal(WFDnsTask *task, const DnsParams &params, struct DnsStatus &dns_status) {
    ComplexTask *ctask = static_cast<ComplexTask *>(task); // 为什么不使用dynamic_cast???
    const int state = task->get_state();                   // 获取任务状态（成功/失败）
    DnsRequest *req = task->get_req();                     // 获取请求对象
    DnsResponse *resp = task->get_resp();                  // 获取响应对象
    const auto *p = params.get_params();                   // 获取DNS参数
    const int rcode = resp->get_rcode();                   // 获取DNS响应码

    // 决定是否需要尝试下一个服务器
    const bool try_next_server = state != WFT_STATE_SUCCESS ||         // 任务失败
                                 rcode == DNS_RCODE_SERVER_FAILURE ||  // 服务器故障
                                 rcode == DNS_RCODE_NOT_IMPLEMENTED || // 服务器未实现对应请求类型
                                 rcode == DNS_RCODE_REFUSED;           // 服务器拒绝查询

    // 决定是否需要尝试下一个域名
    const bool try_next_name = rcode == DNS_RCODE_FORMAT_ERROR || // 格式错误
                               rcode == DNS_RCODE_NAME_ERROR ||   // 名称错误
                               resp->get_ancount() == 0;          // 或没有回答记录】
    // 服务器重试逻辑
    if (try_next_server) {
        // 如果已尝试完一轮服务器, 减少尝试次数
        if (dns_status.last_server == dns_status.next_server) {
            dns_status.attempts_left--;
        }
        // 检查是否还有剩余尝试次数
        if (dns_status.attempts_left <= 0) {
            return;
        }
        // 移动到下一个服务器（循环）
        dns_status.next_server = (dns_status.next_server + 1) % p->uris.size();
        // 重定向到新服务器
        ctask->set_redirect(p->uris[dns_status.next_server]);
        return;
    }
    // 域名重试逻辑
    if (try_next_name && __has_next_name(p, &dns_status)) {
        // 更新请求中的问题名称
        req->set_question_name(dns_status.current_name);
        // 重定向到当前服务器（可能需要重试同一服务器）
        ctask->set_redirect(p->uris[dns_status.next_server]);
        return;
    }
}

// 简化版初始化, 使用默认参数
int WFDnsClient::init(const std::string &url) {
    return this->init(url, "", 1, 2, false); // 默认: 无搜索域, ndots=1, 尝试2次, 不轮询
}

/**
 * @brief   初始化DNS客户端配置. 包含所有可选参数
 * @param[in] url          DNS服务器列表(逗号分隔), 支持格式:
 *                         - dns://host:port (UDP)
 *                         - dnss://host:port (DNS-over-TLS)
 *                         - 纯IP/主机名（自动添加dns://前缀）
 *                         示例: "8.8.8.8,114.114.114.114" 或 "dns://1.1.1.1,dnss://[2606:4700:4700::1111]"
 * @param[in] search_list  域名搜索列表(逗号分隔), 用于短域名补全
 *                         示例: "example.com,corp.local"
 * @param[in] ndots        域名中点的数量阈值(0-15):
 *                         - 当查询域名包含少于ndots个点时，先尝试搜索域
 *                         - 例如：ndots=1时, "example"会先查"example.search.domain"
 *                         - 有效范围: 0-15(超出自动限制为15)
 * @param[in] attempts     单个DNS查询最大尝试次数(1-5):
 *                         - 每个服务器尝试attempts次后切换下一服务器
 *                         - 有效范围: 1-5（超出自动限制为5）
 * @param[in] rotate       服务器轮询策略:
 *                         - true: 在多个DNS服务器间轮询请求（负载均衡）
 *                         - false: 顺序尝试（主备模式，按配置顺序尝试）
 * @return    是否成功初始化
 * @retval    0   成功
 * @retval    -1  失败（errno设置为错误码，如EINVAL）
 * @note      线程不安全：应在单线程环境初始化
 *            重置内部任务ID计数器（this->id = 0）
 *            自动限制参数范围：ndots(0-15), attempts(1-5)
 *            内存分配失败时（new DnsParams）可能抛出std::bad_alloc
 * @warning   重复调用会导致资源泄漏，应先调用deinit()清理
 *            纯IP地址需确保格式正确（IPv6地址必须用[]包裹）
 *            不验证DNS服务器可达性，仅做格式检查
 */
int WFDnsClient::init(const std::string &url, const std::string &search_list,
                      int ndots, int attempts, bool rotate) {
    std::vector<std::string> hosts;
    std::vector<ParsedURI> uris;
    std::string host;
    ParsedURI uri;

    this->id = 0; // 重置任务ID计数器

    // 拆分URL列表（多个服务器用逗号分隔）
    hosts = StringUtil::split_filter_empty(url, ',');
    for (const auto &i : hosts) {
        host = i;
        // 确保URL有协议前缀
        if (strncasecmp(host.c_str(), "dns://", 6) != 0 && strncasecmp(host.c_str(), "dnss://", 7) != 0) {
            host += "dns://"; // 添加默认协议
        }
        // 解析URI
        if (URIParser::parse(host, uri) != 0) {
            return -1; // 解析失败
        }
        uris.emplace_back(std::move(uri));
    }
    // URI数量验证
    if (uris.empty() || ndots < 0 || attempts < 1) {
        errno = EINVAL;
        return -1;
    }
    // 创建并初始化参数对象
    this->params = new DnsParams;
    DnsParams::dns_params *dns_params_ = static_cast<DnsParams *>(this->params)->get_params();
    // 设置参数（带边界检查）
    dns_params_->uris = std::move(uris);                                         //设置服务器列表
    dns_params_->search_list = StringUtil::split_filter_empty(search_list, ','); // 拆分搜索域
    dns_params_->ndots = ndots > 15 ? 15 : ndots;                                // 限制ndots最大值为15
    dns_params_->attempts = attempts > 5 ? 5 : attempts;                         // 限制尝试次数最大为15
    dns_params_->rotate = rotate;                                                // 设置轮询标志

    return 0;
}

void WFDnsClient::deinit() {
    delete static_cast<DnsParams *>(this->params); // 释放指针
    this->params = nullptr;                        // 防止指针悬空
}

// 创建DNS查询任务
WFDnsTask *WFDnsClient::create_dns_task(const std::string &name, dns_callback_t callback) {
    const DnsParams::dns_params *dns_params_ = static_cast<DnsParams *>(this->params)->get_params();
    struct DnsStatus status;
    size_t next_server;
    WFDnsTask *task;
    DnsRequest *req;

    // 确定起始服务器（轮询或固定）
    next_server = dns_params_->rotate ? this->id++ % dns_params_->uris.size() : 0;

    // 初始化查询状态
    status.origin_name = name;                             // 保存原始查询名
    status.next_domain = 0;                                // 从第一个搜索域开始
    status.attempts_left = dns_params_->attempts;          // 设置最大尝试次数
    status.try_origin_state = DNS_STATUS_TRY_ORIGIN_FIRST; // 初始尝试原始域名

    // 特殊情况处理
    // 如果名称以点结尾, 表示完全限定域名, 跳过搜索域
    if (!name.empty() && name.back() == '.') {
        status.next_domain = dns_params_->search_list.size();
    }
    // 如果名称中点数少于ndots阈值, 最后尝试原始域名
    else if (__get_ndots(name) < dns_params_->ndots) {
        status.try_origin_state = DNS_STATUS_TRY_ORIGIN_LAST;
    }

    // 获取第一个要尝试的域名
    __has_next_name(dns_params_, &status);

    // 创建DNS任务
    task = WFTaskFactory::create_dns_task(dns_params_->uris[next_server], 0, std::move(callback));
    // 设置服务器范围
    status.next_server = next_server;
    status.last_server = (next_server + dns_params_->uris.size() - 1) % dns_params_->uris.size();

    // 配置DNS请求
    req = task->get_req();
    req->set_question(status.current_name.c_str(), DNS_TYPE_A, DNS_CLASS_IN); // A记录查询
    req->set_rd(1);                                                           // 设置递归查询标志

    /** 为什么使用static_cast而非dynamic_cast?
     * 1. 性能考虑：static_cast无运行时开销，dynamic_cast需要RTTI检查
     * 2. 设计保证：WFTaskFactory::create_dns_task保证返回ComplexTask类型
     * 3. 框架约定：在此上下文中类型是已知的，不需要动态检查
     * 4. 无继承层次: ComplexTask是最终类型，无多态需求 */

    ComplexTask *ctask = static_cast<ComplexTask *>(task);

    // 设置内部回调
    // 绑定内部回调, 捕获当前参数和状态
    *ctask->get_mutable_ctx() = std::bind(__callback_internal, std::placeholders::_1,
                                          *static_cast<DnsParams *>(params), status);

    return task; // 返回创建好的任务, 由外部启动
}