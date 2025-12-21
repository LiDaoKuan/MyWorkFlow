//
// Created by ldk on 12/20/25.
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

  Authors: Xie Han (xiehan@sogou-inc.com)
           Liu Kai (liukaidx@sogou-inc.com)
           Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cerrno>
#include <netdb.h>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cctype>
#include <utility>
#include <string>
#include "EndpointParams.h"
#include "RouteManager.h"
#include "WFGlobal.h"
#include "WFTaskFactory.h"
#include "WFResourcePool.h"
#include "WFNameService.h"
#include "DnsCache.h"
#include "DnsUtil.h"
#include "WFDnsClient.h"
#include "WFDnsResolver.h"

#define HOSTS_LINEBUF_INIT_SIZE	128     // hosts文件行缓冲区初始大小
#define PORT_STR_MAX			5       // 端口号最大字符串长度(65535+1)

/**@brief DNS查询输入参数
 *
 * 封装DNS查询所需的所有输入信息，支持多种查询模式 */
class DnsInput {
public:
    DnsInput() :
        port_(0), numeric_host_(false),
        family_(AF_UNSPEC) // AF_UNSPEC: 可以代表任何域
    {}

    /**@brief
     * @param host 主机名或IP地址字符串
     * @param port 端口号
     * @param numeric_host 主机名 host 是否为IP地址
     * @param family 地址族（AF_INET, AF_INET6等） */
    DnsInput(const std::string &host, unsigned short port, bool numeric_host, int family) :
        host_(host),
        port_(port),
        numeric_host_(numeric_host),
        family_(family) {}

    /**@brief 重置为简单查询模式
     * @param host 主机名
     * @param port 端口号 */
    void reset(const std::string &host, unsigned short port) {
        host_.assign(host);
        port_ = port;
        numeric_host_ = false;
        family_ = AF_UNSPEC;
    }

    /**@brief 重置为完整查询模式
     * @param host 主机名或IP地址
     * @param port 端口号
     * @param numeric_host 主机名 host 是否为IP地址
     * @param family 地址族 */
    void reset(const std::string &host, unsigned short port, bool numeric_host, int family) {
        host_.assign(host);
        port_ = port;
        numeric_host_ = numeric_host;
        family_ = family;
    }

    [[nodiscard]] const std::string &get_host() const { return this->host_; }
    [[nodiscard]] unsigned short get_port() const { return this->port_; }
    [[nodiscard]] bool is_numeric_host() const { return this->numeric_host_; }

protected:
    std::string host_;
    unsigned short port_;
    bool numeric_host_;
    int family_; // 地址族（AF_INET, AF_INET6, AF_UNIX等）

    friend class DnsRoutine;
};

/**
 * @brief DNS查询输出结果
 *
 * 封装DNS查询的结果，负责资源管理。
 * 注意：默认会自动释放addrinfo资源，除非调用 move_addrinfo() */
class DnsOutput {
public:
    DnsOutput() :
        error_(0),
        addrinfo_(nullptr) {}

    ~DnsOutput() {
        if (addrinfo_) {
            if (addrinfo_->ai_flags) {
                // 系统分配的addrinfo (通过getaddrinfo获取)
                freeaddrinfo(addrinfo_);
            } else {
                // 自定义分配的addrinfo (通过malloc手动创建)
                free(addrinfo_);
            }
        }
    }

    [[nodiscard]] int get_error() const { return error_; }
    [[nodiscard]] const struct addrinfo *get_addrinfo() const { return addrinfo_; }

    //if DONOT want DnsOutput release addrinfo, use move_addrinfo in callback
    /**@brief 转移addrinfo所有权
     *
     * 将addrinfo指针的所有权转移给调用者，防止DnsOutput析构时释放
     * @return addrinfo指针
     */
    struct addrinfo *move_addrinfo() {
        struct addrinfo *p = addrinfo_;
        addrinfo_ = nullptr;
        return p;
    }

protected:
    int error_; // 错误码（0表示成功, 非0为EAI_*错误码）
    struct addrinfo *addrinfo_;

    friend class DnsRoutine;
};

/**@brief DNS解析核心逻辑
 *
 * 提供DNS解析的静态方法，支持多种地址类型：
 * 1. 普通主机名解析
 * 2. UNIX域套接字路径处理
 * 3. IP地址直接转换 */
class DnsRoutine {
public:
    static void run(const DnsInput *in, DnsOutput *out);

    /**@brief 创建DNS输出
     *
     * 用于自定义DNS解析结果的创建
     * @param out 输出对象指针
     * @param error 错误码
     * @param addr_info 地址信息指针 */
    static void create(DnsOutput *out, int error, struct addrinfo *addr_info) {
        if (out->addrinfo_) {
            if (out->addrinfo_->ai_flags) {
                freeaddrinfo(out->addrinfo_);
            } else {
                free(out->addrinfo_);
            }
        }

        out->error_ = error;
        out->addrinfo_ = addr_info;
    }

private:
    static void run_local_path(const std::string &path, DnsOutput *out);
};

/**@brief 处理UNIX域套接字路径
 *
 * 专门处理以'/'开头的本地路径, 创建AF_UNIX类型的地址信息, 并封装为addrinfo
 * @param path UNIX套接字路径
 * @param out DNS输出结果 */
void DnsRoutine::run_local_path(const std::string &path, DnsOutput *out) {
    struct sockaddr_un *sun = nullptr;
    // 检查路径长度是否超过UNIX套接字路径限制
    if (path.size() + 1 <= sizeof(sun->sun_path)) {
        size_t size = sizeof(struct addrinfo) + sizeof(struct sockaddr_un);
        // 分配addrinfo和sockaddr_un联合内存
        out->addrinfo_ = static_cast<struct addrinfo *>(calloc(size, 1)); // 分配size个字节的内存
        if (out->addrinfo_) {
            sun = reinterpret_cast<struct sockaddr_un *>(out->addrinfo_ + 1); // 向后偏移sizeof(addrinfo)字节
            sun->sun_family = AF_UNIX;
            memcpy(sun->sun_path, path.c_str(), path.size()); // 拷贝path
            // 设置addrinfo结构
            out->addrinfo_->ai_family = AF_UNIX;
            out->addrinfo_->ai_socktype = SOCK_STREAM;
            out->addrinfo_->ai_addr = reinterpret_cast<struct sockaddr *>(sun);
            size = offsetof(struct sockaddr_un, sun_path) + path.size() + 1;
            out->addrinfo_->ai_addrlen = size;
            out->error_ = 0;
            return;
        }
    } else {
        errno = EINVAL; // 路径过长
    }
    out->error_ = EAI_SYSTEM; // 系统错误
}

/**
 * @brief 执行DNS解析
 *
 * 根据输入参数执行适当的DNS解析策略
 * @param in DNS输入参数
 * @param out DNS输出结果
 */
void DnsRoutine::run(const DnsInput *in, DnsOutput *out) {
    // 处理UNIX域套接字路径
    if (in->host_[0] == '/') {
        run_local_path(in->host_, out);
        return;
    }
    // 设置getaddrinfo参数
    struct addrinfo hints = {
        .ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV, // 仅返回可用地址类型, 端口为数值
        .ai_family = in->family_,                   // 地址族
        .ai_socktype = SOCK_STREAM,                 // 流式套接字
    };
    char port_str[PORT_STR_MAX + 1]; // 端口字符串缓冲区
    // 如果是IP地址, 设置AI_NUMERICHOST标志
    if (in->is_numeric_host()) {
        hints.ai_flags |= AI_NUMERICHOST;
    }
    // 执行DNS解析
    snprintf(port_str, PORT_STR_MAX + 1, "%u", in->port_);
    out->error_ = getaddrinfo(in->host_.c_str(), port_str, &hints, &out->addrinfo_); // DNS解析
    if (out->error_ == 0) {
        out->addrinfo_->ai_flags = 1;
    }
}

// Dns Thread task. For internal usage only.
using ThreadDnsTask = WFThreadTask<DnsInput, DnsOutput>;
using thread_dns_callback_t = std::function<void (ThreadDnsTask *)>;

/**@brief DNS上下文结构
 *
 * 用于并行DNS查询（IPv4/IPv6）时保存中间状态 */
struct DnsContext {
    unsigned short port;        // 端口号
    int eai_error;              // EAI_*错误码
    struct addrinfo *addr_info; // 地址信息指针
};

/**@brief 检测系统默认地址族
 *
 * 探测系统支持的网络协议栈，用于优化DNS查询
 * @return AF_INET（仅IPv4）, AF_INET6（仅IPv6）, AF_UNSPEC（双栈）
 */
static int __default_family() {
    struct addrinfo hints = {
        .ai_flags = AI_ADDRCONFIG,  // 仅返回系统配置的地址类型
        .ai_family = AF_UNSPEC,     // 不限制地址族
        .ai_socktype = SOCK_STREAM, // 流式套接字
    };
    struct addrinfo *res;
    struct addrinfo *cur;
    int family = AF_UNSPEC; // 默认双栈
    bool v4 = false;        // IPv4支持标志
    bool v6 = false;        // IPv6支持标志

    // 获取本地地址配置
    if (getaddrinfo(nullptr, "1", &hints, &res) == 0) {
        for (cur = res; cur; cur = cur->ai_next) {
            if (cur->ai_family == AF_INET) {
                v4 = true;
            } else if (cur->ai_family == AF_INET6) {
                v6 = true;
            }
        }
        freeaddrinfo(res); // 释放本地地址信息
        // 如果只支持一种协议栈, 优化查询
        if (v4 ^ v6) {
            family = v4 ? AF_INET : AF_INET6;
        }
    }
    return family;
}

// hosts line format: IP canonical_name [aliases...] [# Comment]
/**@brief 解析hosts文件单行
 *
 * 解析/etc/hosts格式的单行, 提取IP和主机名映射
 * 格式: IP canonical_name [aliases...] [# Comment]
 *
 * @param p 行内容指针
 * @param name 要查找的主机名
 * @param port 端口号字符串
 * @param hints getaddrinfo提示
 * @param res 结果指针（输出参数）
 * @return 0 成功
 * @return 1 失败
 */
static int __readaddrinfo_line(char *p, const char *name, const char *port,
                               const struct addrinfo *hints, struct addrinfo **res) {
    const char *ip = nullptr;
    char *start;

    // 移除行尾注释
    start = p;
    while (*start != '\0' && *start != '#') {
        start++;
    }
    *start = '\0';

    // 逐字段解析
    while (true) {
        // 跳过空白
        while (isspace(*p)) {
            p++;
        }

        start = p;
        // 找到字段结束
        while (*p != '\0' && !isspace(*p)) {
            p++;
        }

        // start == p, 说明两者都指向行尾, 该行没有剩余字段, 退出
        if (start == p) {
            break;
        }

        // 终止当前字段
        if (*p != '\0') {
            *p++ = '\0'; // 当前位置添加'\0', 标记字符串结束. 并且指针p后移
        }

        // 第一个字段是IP地址
        if (ip == nullptr) {
            ip = start;
            continue;
        }

        // 检查主机名匹配
        if (strcasecmp(name, start) == 0) {
            if (getaddrinfo(ip, port, hints, res) == 0) {
                return 0;
            }
        }
    }

    return 1;
}

/**@brief 从hosts文件读取地址信息
 *
 * 模拟getaddrinfo()行为, 但数据源为指定的hosts文件
 *
 * @param path hosts文件路径
 * @param name 主机名
 * @param port 端口号
 * @param hints getaddrinfo提示
 * @param res 结果指针（输出参数）
 * @return EAI_*错误码
 */
static int __readaddrinfo(const char *path, const char *name, unsigned short port,
                          const struct addrinfo *hints, struct addrinfo **res) {
    char port_str[PORT_STR_MAX + 1];
    size_t bufsize = 0;
    char *line = nullptr;
    int count = 0;
    int errno_bak;
    FILE *fp;
    int ret;

    fp = fopen(path, "r"); // 打开文件
    if (!fp) {
        return EAI_SYSTEM; // 系统错误
    }

    snprintf(port_str, PORT_STR_MAX + 1, "%u", port);

    errno_bak = errno; // 备份errno
    // 循环获取每一行, 然后调用单行解析函数进行解析
    while ((ret = getline(&line, &bufsize, fp)) > 0) {
        if (__readaddrinfo_line(line, name, port_str, hints, res) == 0) {
            count++;
            res = &(*res)->ai_next; // 移动到下一个结果
        }
    }

    ret = ferror(fp) ? EAI_SYSTEM : EAI_NONAME; // 错误处理
    free(line);                                 // 释放由getline()函数分配的内存
    fclose(fp);                                 // 关闭文件
    if (count != 0) {
        errno = errno_bak; // 恢复errno
        return 0;          // 成功找到至少一个匹配
    }

    return ret;
}

/**@brief 创建DNS线程任务
 *
 * 创建一个在独立线程中执行DNS解析的任务
 *
 * @param host 主机名
 * @param port 端口号
 * @param family 地址族
 * @param callback 完成回调
 * @return ThreadDnsTask指针
 */
static ThreadDnsTask *__create_thread_dns_task(const std::string &host, unsigned short port, int family,
                                               thread_dns_callback_t callback) {
    auto *task = WFThreadTaskFactory<DnsInput, DnsOutput>::
        create_thread_task(WFGlobal::get_dns_queue(),
                           WFGlobal::get_dns_executor(),
                           DnsRoutine::run,
                           std::move(callback));

    task->get_input()->reset(host, port, false, family);
    return task;
}

/**@brief 生成DNS缓存键
 *
 * 根据主机名和地址族生成唯一的缓存键
 *
 * @param hostname 主机名
 * @param family 地址族
 * @return 缓存键字符串
 */
static std::string __get_cache_host(const std::string &hostname,
                                    int family) {
    char c;

    // 根据地址族添加后缀
    if (family == AF_UNSPEC) {
        c = '*';
    } else if (family == AF_INET) {
        c = '4';
    } else if (family == AF_INET6) {
        c = '6';
    } else {
        c = '?';
    }

    return hostname + c;
}

/**@brief 生成任务守卫名称
 *
 * 生成用于防止重复DNS查询的守卫名称
 *
 * @param cache_host 缓存键
 * @param port 端口号
 * @return 守卫名称
 */
static std::string __get_guard_name(const std::string &cache_host,
                                    unsigned short port) {
    std::string guard_name("INTERNAL-dns:");
    guard_name.append(cache_host).append(":");
    guard_name.append(std::to_string(port));
    return guard_name;
}

void WFResolverTask::dispatch() {
    // 检查错误状态
    if (this->msg_) {
        this->state = WFT_STATE_DNS_ERROR;
        this->error = reinterpret_cast<intptr_t>(msg_);
        this->subtask_done();
        return;
    }

    // 解析URI
    const ParsedURI &uri = ns_params_.uri;
    this->host_ = uri.host ? uri.host : "";
    port_ = uri.port ? atoi(uri.port) : 0;

    // 检查DNS缓存
    DnsCache *dns_cache = WFGlobal::get_dns_cache();
    const DnsCache::DnsHandle *addr_handle;
    std::string hostname = this->host_;
    int family = ep_params_.address_family;
    std::string cache_host = __get_cache_host(hostname, family);

    // 根据重试策略选择缓存类型
    if (ns_params_.retry_times == 0) {
        addr_handle = dns_cache->get_ttl(cache_host, port_); // 获取DNS宽松缓存
    } else {
        addr_handle = dns_cache->get_confident(cache_host, port_); // 获取DNS严格缓存（实时性更好）
    }

    // 如果在guard中且缓存不可用, 发起DNS查询
    if (in_guard_ && (addr_handle == nullptr || addr_handle->value.delayed())) {
        if (addr_handle) {
            dns_cache->release(addr_handle);
        }
        this->request_dns();
        return;
    }

    // 处理缓存命中
    if (addr_handle) {
        RouteManager *route_manager = WFGlobal::get_route_manager();
        struct addrinfo *addr_info = addr_handle->value.addrinfo;
        struct addrinfo first = *addr_info; // 注意此处是拷贝赋值;

        // 固定地址模式: 只使用第一个地址
        if (ns_params_.fixed_addr && addr_info->ai_next) {
            first.ai_next = nullptr;
            addr_info = &first; // 令addr_info指向新创建的值
        }

        // 创建路由任务, 路由结果放在 this->result 中
        if (route_manager->get(ns_params_.type, addr_info, ns_params_.info,
                               &ep_params_, hostname, ns_params_.ssl_ctx,
                               this->result) < 0) {
            this->state = WFT_STATE_SYS_ERROR;
            this->error = errno;
        } else {
            this->state = WFT_STATE_SUCCESS;
        }

        dns_cache->release(addr_handle); // 释放引用（与前面调用 get_xxx() 方法获取 addr_handle 对应）
        this->subtask_done();            // 该任务完成
        return;
    }

    // 检查是否为ip地址(ip地址无需DNS解析)
    if (*this->host_) {
        const char front = this->host_[0];
        const char back = this->host_[hostname.size() - 1];
        struct in6_addr addr;
        int ret;

        // 检查地址类型
        if (strchr(this->host_, ':')) // strchr(str, c): 返回str中c第一次出现的位置的地址(返回char*类型)
        {
            // inet_pton: 将点分十进制的ip地址转化为用于网络传输的数值格式, 适用于ipv4和ipv6. 成功则返回1
            ret = inet_pton(AF_INET6, this->host_, &addr); // ipv6地址
        } else if (isdigit(back) && isdigit(front)) {
            ret = inet_pton(AF_INET, this->host_, &addr); // ipv4
        } else if (front == '/') {
            ret = 1; // UNIX域套接字
        } else {
            ret = 0; // 主机名
        }

        // 成功
        if (ret == 1) {
            // 'true' means numeric host
            // 直接解析IP地址
            DnsInput dns_in(hostname, port_, true, AF_UNSPEC);
            DnsOutput dns_out;

            DnsRoutine::run(&dns_in, &dns_out);
            dns_callback(&dns_out, (unsigned int)-1, (unsigned int)-1);
            this->subtask_done();
            return;
        }
    }

    // 检查host文件
    const char *hosts = WFGlobal::get_global_settings()->hosts_path;
    if (hosts) {
        struct addrinfo hints = {
            .ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_NUMERICHOST,
            .ai_family = this->ep_params_.address_family,
            .ai_socktype = SOCK_STREAM,
        };
        struct addrinfo *ai;
        int ret;

        ret = __readaddrinfo(hosts, this->host_, port_, &hints, &ai);
        if (ret == 0) {
            DnsOutput out;
            DnsRoutine::create(&out, ret, ai);
            dns_callback(&out, dns_ttl_default_, dns_ttl_min_);
            this->subtask_done();
            return;
        }
    }

    // 创建命名条件任务防止重复DNS查询
    std::string guard_name = __get_guard_name(cache_host, port_);
    WFConditional *guard = WFTaskFactory::create_guard(guard_name, this, &msg_);

    in_guard_ = true;
    has_next_ = true;

    series_of(this)->push_front(guard);
    this->subtask_done();
}

/**@brief 发起DNS查询请求
 *
 * 根据配置选择适当的DNS查询策略：
 * 1. 线程内查询（阻塞式）
 * 2. 网络查询（异步非阻塞）
 * 3. 并行查询（多DNS服务器） */
void WFResolverTask::request_dns() {
    WFDnsClient *client = WFGlobal::get_dns_client();
    if (client) {
        static int default_family = __default_family();        // 检测系统默认协议栈
        WFResourcePool *respool = WFGlobal::get_dns_respool(); // DNS资源池

        int family = ep_params_.address_family;
        if (family == AF_UNSPEC) {
            family = default_family; // 使用系统默认协议族
        }

        if (family == AF_INET || family == AF_INET6) {
            // 单协议栈查询
            auto &&cb = std::bind(&WFResolverTask::dns_single_callback,
                                  this, std::placeholders::_1);
            WFDnsTask *dns_task = client->create_dns_task(this->host_, std::move(cb));

            if (family == AF_INET6) {
                dns_task->get_req()->set_question_type(DNS_TYPE_AAAA); // IPv6查询
            }

            WFConditional *cond = respool->get(dns_task); // 从资源池获取配额
            series_of(this)->push_front(cond);            //
        } else {
            // 双协议栈并行查询
            auto *dns_context = new struct DnsContext[2]; // 为IPv4和IPv6分配上下文
            WFDnsTask *task_v4;
            WFDnsTask *task_v6;
            ParallelWork *pwork;

            dns_context[0].addr_info = nullptr;
            dns_context[1].addr_info = nullptr;
            dns_context[0].port = this->port_;
            dns_context[1].port = this->port_;

            // 创建IPv4任务
            task_v4 = client->create_dns_task(this->host_, dns_partial_callback);
            task_v4->user_data = dns_context;

            // 创建IPv6任务
            task_v6 = client->create_dns_task(this->host_, dns_partial_callback);
            task_v6->get_req()->set_question_type(DNS_TYPE_AAAA);
            task_v6->user_data = dns_context + 1;

            // 创建并行工作流
            auto &&cb = std::bind(&WFResolverTask::dns_parallel_callback,
                                  this, std::placeholders::_1);

            pwork = Workflow::create_parallel_work(std::move(cb));
            pwork->set_context(dns_context);

            WFConditional *cond_v4 = respool->get(task_v4);
            WFConditional *cond_v6 = respool->get(task_v6);
            pwork->add_series(Workflow::create_series_work(cond_v4, nullptr));
            pwork->add_series(Workflow::create_series_work(cond_v6, nullptr));

            series_of(this)->push_front(pwork);
        }
    } else {
        // 使用线程DNS任务（后备任务）
        ThreadDnsTask *dns_task;
        auto &&cb = std::bind(&WFResolverTask::thread_dns_callback,
                              this, std::placeholders::_1);
        dns_task = __create_thread_dns_task(this->host_, this->port_, this->ep_params_.address_family, std::move(cb));
        series_of(this)->push_front(dns_task);
    }

    has_next_ = true;
    this->subtask_done();
}

SubTask *WFResolverTask::done() {
    SeriesWork *series = series_of(this);

    if (!has_next_) {
        task_callback();
    } else {
        has_next_ = false;
    }

    return series->pop();
}

/**@brief DNS输出结果处理
 *
 * 处理DNS查询结果, 更新路由信息
 * @param dns_output DNS查询输出
 * @param ttl_default 默认TTL
 * @param ttl_min 最小TTL
 */
void WFResolverTask::dns_callback(void *dns_output, unsigned int ttl_default, unsigned int ttl_min) {
    auto *dns_out = static_cast<DnsOutput *>(dns_output);
    const int dns_error = dns_out->get_error();
    // 处理错误
    if (dns_error) {
        if (dns_error == EAI_SYSTEM) {
            this->state = WFT_STATE_SYS_ERROR;
            this->error = errno;
        } else {
            this->state = WFT_STATE_DNS_ERROR;
            this->error = dns_error;
        }
    } else {
        // 处理成功结果
        RouteManager *route_manager = WFGlobal::get_route_manager();
        DnsCache *dns_cache = WFGlobal::get_dns_cache();
        struct addrinfo *addrinfo = dns_out->move_addrinfo(); // 转移所有权
        const DnsCache::DnsHandle *addr_handle;
        const std::string hostname = this->host_;
        const int family = this->ep_params_.address_family;
        const std::string cache_host = __get_cache_host(hostname, family); // 生成缓存键

        // 将DNS解析结果存入缓存池, 得到handle指针
        addr_handle = dns_cache->put(cache_host, this->port_, addrinfo, (unsigned int)ttl_default, (unsigned int)ttl_min);
        // 创建路由任务
        if (route_manager->get(ns_params_.type, addrinfo, ns_params_.info,
                               &ep_params_, hostname, ns_params_.ssl_ctx,
                               this->result) < 0) {
            this->state = WFT_STATE_SYS_ERROR;
            this->error = errno;
        } else {
            this->state = WFT_STATE_SUCCESS;
        }
        // 释放handle, 与 put() 对应
        dns_cache->release(addr_handle);
    }
}

/**@brief 单DNS服务器查询回调
 *
 * 处理对单个DNS服务器的查询结果
 * @param net_dns_task 网络DNS任务指针
 */
void WFResolverTask::dns_single_callback(void *net_dns_task) {
    auto *dns_task = static_cast<WFDnsTask *>(net_dns_task);
    WFGlobal::get_dns_respool()->post(nullptr); // 释放资源池配额. 通过归还空资源

    if (dns_task->get_state() == WFT_STATE_SUCCESS) {
        struct addrinfo *ai = nullptr;
        // 转换DNS响应为addrinfo
        const int ret = protocol::DnsUtil::getaddrinfo(dns_task->get_resp(), port_, &ai);
        DnsOutput out;
        DnsRoutine::create(&out, ret, ai);
        dns_callback(&out, dns_ttl_default_, dns_ttl_min_);
    } else {
        this->state = WFT_STATE_DNS_ERROR;
        this->error = EAI_AGAIN; // 临时错误, 可重试
    }

    task_callback();
}

/**@brief 部分DNS响应回调（静态方法）
 *
 * 用于处理部分DNS响应，作为C风格回调的适配器
 * @param net_dns_task 网络DNS任务指针
 */
void WFResolverTask::dns_partial_callback(void *net_dns_task) {
    auto *dns_task = static_cast<WFDnsTask *>(net_dns_task);
    WFGlobal::get_dns_respool()->post(nullptr); // 释放资源池配额

    auto *ctx = static_cast<struct DnsContext *>(dns_task->user_data);

    ctx->addr_info = nullptr;
    if (dns_task->get_state() == WFT_STATE_SUCCESS) {
        // 转换DNS响应为addrinfo
        protocol::DnsResponse *resp = dns_task->get_resp();
        ctx->eai_error = protocol::DnsUtil::getaddrinfo(resp, ctx->port, &ctx->addr_info);
    } else {
        ctx->eai_error = EAI_AGAIN; // 临时错误
    }
}

/**@brief 并行DNS查询回调
 *
 * 处理并行查询多个DNS服务器的结果
 * @param parallel 并行任务指针
 */
void WFResolverTask::dns_parallel_callback(const void *parallel) {
    const auto *pwork = static_cast<const ParallelWork *>(parallel);
    const auto *c4 = static_cast<struct DnsContext *>(pwork->get_context());
    const struct DnsContext *c6 = c4 + 1;

    // 检查是否有成功结果
    if (c4->eai_error == 0 || c6->eai_error == 0) {
        struct addrinfo *ai = nullptr;
        struct addrinfo **pai = &ai;
        DnsOutput out;

        // 合并IPv4和IPv6结果
        *pai = c4->addr_info;
        while (*pai) {
            pai = &(*pai)->ai_next;
        }

        *pai = c6->addr_info;
        DnsRoutine::create(&out, 0, ai);
        dns_callback(&out, dns_ttl_default_, dns_ttl_min_);
    } else {
        // 处理失败情况
        int eai_error = c4->eai_error;

        if (c6->eai_error == EAI_AGAIN) {
            eai_error = EAI_AGAIN; // 优先临时错误
        }

        this->state = WFT_STATE_DNS_ERROR;
        this->error = eai_error;
    }

    delete []c4; // 释放上下文内存
    task_callback();
}

/**@brief 线程DNS查询回调
 *
 * 处理在独立线程中执行的DNS查询结果
 * @param thrd_dns_task 线程DNS任务指针
 */
void WFResolverTask::thread_dns_callback(void *thrd_dns_task) {
    auto *dns_task = static_cast<ThreadDnsTask *>(thrd_dns_task);

    if (dns_task->get_state() == WFT_STATE_SUCCESS) {
        DnsOutput *out = dns_task->get_output();
        dns_callback(out, dns_ttl_default_, dns_ttl_min_);
    } else {
        this->state = dns_task->get_state();
        this->error = dns_task->get_error();
    }

    task_callback();
}

/**@brief 任务完成回调处理函数
 *
 * 统一处理任务完成逻辑, 设置状态和错误码
 */
void WFResolverTask::task_callback() {
    if (this->in_guard_) {
        const int family = ep_params_.address_family;
        const std::string cache_host = __get_cache_host(this->host_, family);
        const std::string guard_name = __get_guard_name(cache_host, this->port_);

        if (this->state == WFT_STATE_DNS_ERROR) {
            this->msg_ = reinterpret_cast<void *>(static_cast<intptr_t>(this->error));
        }

        // 释放条件变量(guard_name), 可能唤醒其他任务
        WFTaskFactory::release_guard_safe(guard_name, this->msg_);
    }
    // 执行用户回调
    if (this->callback) {
        this->callback(this);
    }
    delete this;
}

WFRouterTask *WFDnsResolver::create_router_task(const struct WFNSParams *params, router_callback_t callback) {
    const struct WFGlobalSettings *settings = WFGlobal::get_global_settings();
    unsigned int dns_ttl_default = settings->dns_ttl_default;
    unsigned int dns_ttl_min = settings->dns_ttl_min;
    const struct EndpointParams *ep_params = &settings->endpoint_params;
    return new WFResolverTask(params, dns_ttl_default, dns_ttl_min, ep_params, std::move(callback));
}