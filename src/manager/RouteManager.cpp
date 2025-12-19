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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <chrono>
#include <mutex>
#include <vector>
#include <string>
#include <algorithm>
#include <openssl/ssl.h>
#include "list.h"
#include "rbtree.h"
#include "WFGlobal.h"
#include "CommScheduler.h"
#include "EndpointParams.h"
#include "RouteManager.h"
#include "StringUtil.h"

// 获取系统启动后经过的秒数
#define GET_CURRENT_SECOND	std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()
// 平均修复时间
#define MTTR_SECOND			30

using RouteTargetTCP = RouteManager::RouteTarget;

// 用于创建无连接的UDP数据报套接字. 模板方法模式的典型应用
class RouteTargetUDP : public RouteManager::RouteTarget {
private:
    int create_connect_fd() override {
        const struct sockaddr *addr;
        socklen_t addrlen;

        this->get_addr(&addr, &addrlen); // 通过 this->get_addr(&addr, &addrlen) 获取基类中设置的地址族(如IPv4的 AF_INET或IPv6的 AF_INET6), 确保套接字与预设地址兼容
        return socket(addr->sa_family, SOCK_DGRAM, 0); // 使用 SOCK_DGRAM 参数创建数据报套接字, 这是UDP协议的典型特征
    }
};

// 用于创建面向连接的SCTP流套接字. 兼具TCP的可靠性和UDP的多路复用特性. 模板方法模式的典型应用
class RouteTargetSCTP : public RouteManager::RouteTarget {
private:
#ifdef IPPROTO_SCTP
    int create_connect_fd() override {
        const struct sockaddr *addr;
        socklen_t addrlen;

        this->get_addr(&addr, &addrlen); // 获取基类中设置的地址族
        // 创建SCTP套接字. 注意后面协议参数是: IPPROTO_SCTP
        return socket(addr->sa_family, SOCK_STREAM, IPPROTO_SCTP);
    }
#else
    // 在不支持SCTP的系统上, 函数返回-1并设置 errno 为 EPROTONOSUPPORT, 使调用方能正确处理协议不支持的情况
    virtual int create_connect_fd() {
        errno = EPROTONOSUPPORT;
        return -1;
    }
#endif
};

using RouteTargetTCP_SSL = RouteTargetTCP;

/* To support TLS SNI(服务器名称指示). */
class RouteTargetTCP_TLS_SNI : public RouteTargetTCP_SSL {
private:
    int init_ssl(SSL *ssl) override {
        // SSL_set_tlsext_host_name: 在TLS握手的 ClientHello 消息中插入一个特殊的扩展字段.
        // 告诉服务器：“我打算访问的域名是 this->hostname.c_str()”
        if (SSL_set_tlsext_host_name(ssl, this->hostname.c_str()) > 0) {
            return 0;
        } else {
            return -1;
        }
    }

    /**SNI 要解决的核心问题源于现代Web服务器架构. 一个物理服务器 (同一个IP地址) 上常常会托管多个不同的域名(虚拟主机).
     * 当客户端通过TLS连接此服务器时, 服务器需要在握手初期就知道客户端到底想连接哪个具体的域名, 以便返回与之匹配的正确证书.
     *
     * 如果客户端不告知域名信息, 服务器可能只能返回一个默认证书, 极有可能导致客户端在证书验证时发现证书中的域名与它实际想访问的域名不匹配, 从而中断连接,
     * 报错信息可能类似 SSL_ERROR_BAD_CERT_DOMAIN.
     *
     * 而 SSL_set_tlsext_host_name 这个函数的作用, 正是在TLS握手的 ClientHello 消息中插入一个特殊的扩展字段,
     * 明确地告诉服务器：“我打算访问的域名是 this->hostname.c_str()”
     * 这样, 服务器就能精准地选择并返回对应域名的证书, 确保后续的证书验证流程能够顺利通过. */

private:
    std::string hostname;

public:
    explicit RouteTargetTCP_TLS_SNI(const std::string &name) :
        hostname(name) {}
};

using RouteTargetSCTP_SSL = RouteTargetSCTP;

/**SNI 是一个位于TLS层的特性, 其机制与底层传输协议 (TCP或SCTP) 无关.
 * 因此, 无论是基于TCP的HTTPS, 还是基于SCTP的某些安全服务,
 * 只要使用了TLS/SSL进行加密, 都需要在握手阶段正确设置SNI信息, 才能可靠地访问基于域名共享IP的虚拟主机 */

// 用于支持 TLS SNI（服务器名称指示）功能
class RouteTargetSCTP_TLS_SNI : public RouteTargetSCTP_SSL {
private:
    int init_ssl(SSL *ssl) override {
        if (SSL_set_tlsext_host_name(ssl, this->hostname.c_str()) > 0) {
            return 0;
        } else {
            return -1;
        }
    }

private:
    std::string hostname;

public:
    explicit RouteTargetSCTP_TLS_SNI(const std::string &name) :
        hostname(name) {}
};

//  protocol_name\n user\n pass\n dbname\n ai_addr ai_addrlen \n....
//

// 集中定义创建一条路由所需的所有参数, 如传输协议、目标地址、SSL上下文、超时设置等
struct RouteParams {
    enum TransportType transport_type; // 指定传输层协议(如TCP、UDP或SCTP). 这是路由的基础类型
    const struct addrinfo *addrinfo; // 指向一个由DNS解析得到的地址信息链表, 包含一个或多个目标服务器的IP地址和端口.
    uint64_t key; // 用于唯一标识此路由条目的缓存键, 通常由目标主机名、端口和协议类型等信息哈希生成.
    SSL_CTX *ssl_ctx; // SSL/TLS上下文指针. 如果连接需要使用TLS加密, 此字段必须有效; 否则为nullptr.
    size_t max_connections; // 允许到目标服务器的最大并发连接数, 用于连接池管理, 防止过度消耗服务器资源
    int connect_timeout; // 建立TCP连接的超时时间 (通常以毫秒为单位)
    int response_timeout; // 等待服务器响应的超时时间.
    int ssl_connect_timeout; // 完成SSL/TLS握手的超时时间, 可能长于普通的连接超时
    bool use_tls_sni; // 是否在TLS握手时启用 SNI (服务器名称指示) 扩展. 对于虚拟主机场景, 此选项必须开启.
    const std::string &hostname; // 要访问的目标主机名. 用于SNI扩展或HTTP请求头中的Host字段
};

// 路由条目管理器: 保存状态，管理路由条目的生命周期、多个目标之间的负载均衡以及熔断状态
class RouteResultEntry {
public:
    rb_node rb{}; // 用于将本条目插入到红黑树中, 实现基于key的高效查找、插入和删除
    CommSchedObject *request_object; // 核心调度对象. 可能是单个CommSchedTarget, 也可能是一个负责负载均衡的CommSchedGroup
    CommSchedGroup *group; // 当addrinfo包含多个地址时, 此指针指向管理这些目标的负载均衡组
    std::mutex mutex;
    std::vector<RouteManager::RouteTarget *> targets; // 存储由此条目管理的所有具体目标(RouteTarget对象)
    list_head breaker_list; // 一个链表头, 链接了当前所有处于熔断状态(不可用)的目标
    uint64_t key{0}; // 与此条目关联的缓存, 与RouteParams中的key对应
    int nleft; // 当前可用的目标数量(未熔断的目标数)
    int nbreak; // 当前不可用的目标数量(已熔断的目标数)

    RouteResultEntry() :
        request_object(nullptr), group(nullptr), nleft(0), nbreak(0),
        breaker_list(&this->breaker_list, &this->breaker_list) {}

public:
    int init(const struct RouteParams *params);
    void deinit();

    void notify_unavailable(RouteManager::RouteTarget *target);
    void notify_available(RouteManager::RouteTarget *target);
    void check_breaker();

private:
    void free_list(); // 暂未实现
    static RouteManager::RouteTarget *create_target(const struct RouteParams *params, const struct addrinfo *addrinfo);
    int add_group_targets(const struct RouteParams *params);
};

// 记录“哪个目标”出了故障以及“何时可尝试恢复”
struct __breaker_node {
    RouteManager::RouteTarget *target; // 出现故障的目标
    int64_t timeout; // 预计尝试修复的时间点
    struct list_head breaker_list; // 用于将节点链接在熔断列表中
};

// 根据传入的params和addr构建target
RouteManager::RouteTarget *RouteResultEntry::create_target(const struct RouteParams *params, const struct addrinfo *addr) {
    RouteManager::RouteTarget *target;
    // 根据transport_type决定具体创建哪种路由目标对象（如TCP、UDP等）
    switch (params->transport_type) {
    case TT_TCP: target = new RouteTargetTCP();
        break;
    case TT_UDP: target = new RouteTargetUDP();
        break;
    case TT_SCTP: target = new RouteTargetSCTP();
        break;
    case TT_TCP_SSL:
        // use_tls_sni: TLS SNI功能开关, 当协议为SSL/TLS时, 决定是否创建支持SNI扩展的专用对象
        if (params->use_tls_sni) {
            target = new RouteTargetTCP_TLS_SNI(params->hostname);
        } else {
            target = new RouteTargetTCP_SSL;
        }
        break;
    case TT_SCTP_SSL: if (params->use_tls_sni) {
            target = new RouteTargetSCTP_TLS_SNI(params->hostname);
        } else {
            target = new RouteTargetSCTP_SSL;
        }
        break;
    default:
        errno = EINVAL;
        return nullptr;
    }

    if (target->init(addr->ai_addr, addr->ai_addrlen, params->ssl_ctx,
                     params->connect_timeout, params->ssl_connect_timeout,
                     params->response_timeout, params->max_connections) < 0) {
        delete target;
        target = nullptr;
    }

    return target;
}

// 根据 RouteParams 中的 addrinfo 链表, 为每个地址调用 create_target 方法创建对应的 RouteTarget 对象
// 如果存在多个目标, 则会创建 CommSchedGroup 来实现负载均衡. 此方法完成了从参数到可调度对象的转换
int RouteResultEntry::init(const struct RouteParams *params) {
    const struct addrinfo *addr = params->addrinfo;
    RouteManager::RouteTarget *target;

    if (addr == nullptr) // 链表为空
    {
        errno = EINVAL;
        return -1;
    }

    if (addr->ai_next == nullptr) // addrinfo链表中只有一个节点
    {
        target = RouteResultEntry::create_target(params, addr); // 创建对应的 RouteTarget 对象
        if (target) {
            this->targets.push_back(target); // 将创建的 RouteTarget 对象添加到vector中
            this->request_object = target; // 设置请求对象
            this->key = params->key; // 记录唯一key
            return 0;
        }
        return -1;
    }

    // addrinfo链表中不止一个节点
    this->group = new CommSchedGroup(); // 创建调度组以实现负载均衡
    if (this->group->init() >= 0) {
        if (this->add_group_targets(params) >= 0) {
            this->request_object = this->group; // 设置请求对象
            this->key = params->key; // 记录唯一key
            return 0;
        }
        // 向调度组添加调度目标时出错, 销毁调度组
        this->group->deinit();
    }

    delete this->group; // 出现错误, 释放对象内存
    return -1;
}

int RouteResultEntry::add_group_targets(const struct RouteParams *params) {
    RouteManager::RouteTarget *target;
    const struct addrinfo *addr;

    for (addr = params->addrinfo; addr != nullptr; addr = addr->ai_next) {
        target = RouteResultEntry::create_target(params, addr); // 根据当前的addrinfo创建对象
        if (target) {
            if (this->group->add(target) >= 0) {
                this->targets.push_back(target); // 将目标也添加到vector中
                this->nleft++; // 可用目标数量+1
                continue;
            }
            // 向调度组添加目标失败, 销毁目标
            target->deinit();
            delete target;
        }
        // 如果存在添加目标失败的情况, 才会执行下面for循环, 否则不会执行下面for循环(因为前面有continue)
        // 将所有已经添加的target删除
        for (auto *route_target : this->targets) {
            this->group->remove(route_target);
            route_target->deinit();
            delete route_target;
        }
        // 这种"全有或全无"的策略确保了资源管理的严谨性, 避免了部分成功部分失败导致的复杂状态
        return -1;
    }

    return 0;
}

// 释放资源
void RouteResultEntry::deinit() {
    for (auto *target : this->targets) {
        if (this->group) {
            this->group->remove(target);
        }

        target->deinit();
        delete target;
    }

    if (this->group) {
        this->group->deinit();
        delete this->group;
    }

    struct list_head *pos, *tmp;
    __breaker_node *node;

    list_for_each_safe(pos, tmp, &this->breaker_list) {
        node = list_entry(pos, __breaker_node, breaker_list);
        list_del(pos);
        delete node;
    }
}

// 熔断
void RouteResultEntry::notify_unavailable(RouteManager::RouteTarget *target) {
    if (this->targets.size() <= 1) { return; } // 全局目标数检查

    int errno_bak = errno; // 备份错误码
    std::lock_guard<std::mutex> lock(this->mutex);

    if (this->nleft <= 1) { return; } // 当前可用目标数检查

    /**确保系统始终保留至少一个可用的目标. 如果将所有目标都熔断, 会导致服务完全不可用.
     * 这两重检查(第一重在锁外快速判断, 第二重在锁内精确判断)有效防止了这种情况的发生, 是熔断机制中的韧性设计 */

    // 从调度组移除
    if (this->group->remove(target) < 0) {
        errno = errno_bak; // 恢复错误码
        return;
    }

    // 创建并记录熔断节点
    auto *node = new __breaker_node;

    node->target = target;
    node->timeout = GET_CURRENT_SECOND + MTTR_SECOND; // 计算恢复时间点
    list_add_tail(&node->breaker_list, &this->breaker_list); // 加入熔断链表
    // 更新状态计数器
    this->nbreak++;
    this->nleft--;
}

// 将之前不可用的路由目标重新标记为可用？？？或者 将目标target标记为可用
void RouteResultEntry::notify_available(RouteManager::RouteTarget *target) {
    if (this->targets.size() <= 1 || this->nbreak == 0) { return; }

    int errno_bak = errno; // 备份错误码
    std::lock_guard<std::mutex> lock(this->mutex);

    if (this->group->add(target) == 0) {
        // 添加成功, 可用目标+1
        this->nleft++;
        // 为什么没有减少熔断目标数量nbreak？？？
        // 对 nbreak 的递减操作可能由另一个专门的清理线程/函数在从熔断链表(breaker_list)中移除目标时一并处理, 以确保状态的一致性
    } else {
        // 添加失败, 恢复错误码. 确保不干扰调用方
        errno = errno_bak;
    }
}

// 定期任务, 用于检查break_list中的目标是否已过熔断超时时间, 并在超时后尝试恢复它们
void RouteResultEntry::check_breaker() {
    // 如果系统总共就一个节点(this->targets.size() <= 1), 那么现在一定不存在熔断节点(系统至少保留一个可用节点), 不需要检查
    // 如果当前根本没有熔断的节点(this->nbreak == 0), 那么不需要检查
    // 以上两种情况直接返回可以节省系统开销
    if (this->targets.size() <= 1 || this->nbreak == 0) { return; }

    list_head *pos, *tmp;
    __breaker_node *node;
    int errno_bak = errno; // 备份错误码
    int64_t cur_time = GET_CURRENT_SECOND; // 获取当前时间
    std::lock_guard<std::mutex> lock(this->mutex);

    list_for_each_safe(pos, tmp, &this->breaker_list) {
        node = list_entry(pos, __breaker_node, breaker_list);
        // 到达恢复时间, 尝试恢复
        if (cur_time >= node->timeout) {
            if (this->group->add(node->target) == 0) {
                this->nleft++; // 恢复成功
            } else {
                errno = errno_bak; // 恢复失败, 但是还原错误码, 确保调用方不被干扰
            }

            list_del(pos); // 从熔断链表中删除被恢复的节点
            delete node; // 释放节点空间
            this->nbreak--; // 熔断数量-1
        }
    }
}

/**@brief 比较两个 addrinfo 结构体中网络地址是否相同的函数. 暂时不关心协议族是否相同（暂未实现协议族比较）
 * @return -1（x < y）; 0（x = y）; 1（x > y）
 */
static inline int addr_cmp(const addrinfo *x, const addrinfo *y) {
    // todo ai_protocol
    // 先比较地址长度 (ai_addrlen), 长度相同再逐字节比较地址内容 (ai_addr)
    if (x->ai_addrlen == y->ai_addrlen) {
        return memcmp(x->ai_addr, y->ai_addr, x->ai_addrlen); // 逐字节比较地址内容
    }
    if (x->ai_addrlen < y->ai_addrlen) {
        return -1;
    }
    return 1;
}

// 判断地址x是否在排序上小于地址y
static inline bool addr_less(const struct addrinfo *x, const struct addrinfo *y) {
    return addr_cmp(x, y) < 0;
}

// FNV-1a哈希算法64bit版
static uint64_t fnv_hash(const unsigned char *data, size_t size) {
    uint64_t hash = 14695981039346656037ULL; // 14695981039346656037ULL - 64位FNV算法的标准初始值

    // 该算法通过交替进行异或和乘法操作, 对输入数据的每个字节进行扩散, 确保即使微小的输入变化也会产生显著不同的哈希值
    while (size) {
        hash ^= static_cast<const uint64_t>(*(data++)); // 先异或当前字节. 注意后置++是先取值, 再进行++！！！
        hash *= 1099511628211ULL; // 再乘以质数. 1099511628211ULL - 精心选择的质数, 提供良好的扩散特性
        size--; // 剩余字节数
    }

    return hash;
}

static uint64_t generate_key(enum TransportType type, const struct addrinfo *addrinfo, const std::string &other_info,
                             const struct EndpointParams *ep_params, const std::string &hostname, SSL_CTX *ssl_ctx) {
    // 先序列化所有影响连接特性的参数, 再将序列化后的值作为哈希算法的输入进行哈希
    // 整数数组内存拷贝
    const int params[] = {
        ep_params->address_family, static_cast<int>(ep_params->max_connections),
        ep_params->connect_timeout, ep_params->response_timeout
    };
    // TransportType: 内存拷贝
    std::string buf(reinterpret_cast<const char *>(&type), sizeof(enum TransportType));

    if (!other_info.empty()) { buf += other_info; }

    buf.append(reinterpret_cast<const char *>(params), sizeof params);
    if (type == TT_TCP_SSL || type == TT_SCTP_SSL) {
        // 内存拷贝: 指针值序列化, 区分不同的SSL配置上下文
        buf.append(reinterpret_cast<const char *>(ssl_ctx), sizeof(void *));
        // 内存拷贝: 整数值序列化, 避免SSL握手超时影响连接行为
        buf.append(reinterpret_cast<const char *>(&ep_params->ssl_connect_timeout), sizeof(int));
        // 字符串追加, 支持虚拟主机和SNI扩展
        if (ep_params->use_tls_sni) {
            buf += hostname;
            buf += '\n';
        }
    }
    if (addrinfo->ai_next) {
        // 多个addrinfo: 排序后序列化, 确保地址顺序无关性.
        /**假设域名 api.example.com 通过DNS轮询解析到三个完全相同的服务器, 但有两个不同的DNS响应, 其 addrinfo 链表中的IP地址顺序不同：
         * - 响应A的顺序：192.0.2.10-> 192.0.2.20-> 192.0.2.30
         * - 响应B的顺序：192.0.2.30-> 192.0.2.10-> 192.0.20
         * 虽然这两个响应包含的服务器集合是完全相同的, 但由于IP地址的排列顺序不同, 如果直接序列化, 会产生不同的字节流, 进而导致哈希值不同.
         * 排序后保证顺序统一, 就能解决这个问题 */

        // 将addrinfo链表转换为vector, 方便排序
        std::vector<const struct addrinfo *> sorted_addr;
        sorted_addr.push_back(addrinfo);
        addrinfo = addrinfo->ai_next;
        do {
            sorted_addr.push_back(addrinfo);
            addrinfo = addrinfo->ai_next;
        } while (addrinfo);
        // 对vector进行排序
        std::sort(sorted_addr.begin(), sorted_addr.end(), addr_less); // 排序
        for (const struct addrinfo *p : sorted_addr) {
            // 对排序后的数据逐个序列化
            buf.append(reinterpret_cast<const char *>(&p->ai_addrlen), sizeof(socklen_t));
            buf.append(reinterpret_cast<const char *>(p->ai_addr), p->ai_addrlen);
        }
    } else {
        // 单个addrinfo: 直接序列化地址长度和内容
        buf.append(reinterpret_cast<const char *>(&addrinfo->ai_addrlen), sizeof(socklen_t));
        buf.append(reinterpret_cast<const char *>(addrinfo->ai_addr), addrinfo->ai_addrlen);
    }
    // 对序列化后的值进行哈希
    return fnv_hash(reinterpret_cast<const unsigned char *>(buf.c_str()), buf.size());
}

RouteManager::~RouteManager() {
    RouteResultEntry *entry;
    // 只要红黑树不为空就继续清理
    while (cache_.rb_node) {
        entry = rb_entry(cache_.rb_node, RouteResultEntry, rb); // 获取rb_node所在的RouteResultEntry
        rb_erase(cache_.rb_node, &cache_); // 从红黑树中删除rb_node
        entry->deinit(); // 销毁rb_node所在的entry
        delete entry;
    }
}

// 根据连接参数来查找或创建路由条目
int RouteManager::get(enum TransportType type, const struct addrinfo *addrinfo, const std::string &other_info,
                      const struct EndpointParams *ep_params, const std::string &hostname, SSL_CTX *ssl_ctx,
                      RouteResult &result) {
    if (type == TT_TCP_SSL || type == TT_SCTP_SSL) {
        // 当调用方未显式提供ssl_ctx(即为nullptr)时, 函数会自动获取框架预配置的全局SSL客户端上下文. 这确保了即使调用方不熟悉SSL配置, 也能建立安全的加密连接
        static SSL_CTX *global_client_ctx = WFGlobal::get_ssl_client_ctx();
        if (ssl_ctx == nullptr) {
            ssl_ctx = global_client_ctx; // 使用全局默认SSL上下文
        }
    } else {
        // 非SSL协议, 置空
        ssl_ctx = nullptr;
    }
    // 获取唯一key
    uint64_t key = generate_key(type, addrinfo, other_info, ep_params, hostname, ssl_ctx);
    rb_node **p = &cache_.rb_node;
    rb_node *parent = nullptr;
    RouteResultEntry *bound = nullptr;
    RouteResultEntry *entry = nullptr;
    std::lock_guard<std::mutex> lock(mutex_);

    while (*p) {
        parent = *p;
        entry = rb_entry(*p, RouteResultEntry, rb); // 获取*p指向的rb_node所在的entry
        if (key <= entry->key) {
            bound = entry;
            p = &(*p)->rb_left;
        } else {
            p = &(*p)->rb_right;
        }
    }

    if (bound && bound->key == key) {
        // 缓存命中
        entry = bound;
        entry->check_breaker(); // 检查并可能恢复之前被熔断的目标
    } else {
        // 缓存未命中, 创建新条目
        struct RouteParams params = {
            .transport_type = type,
            .addrinfo = addrinfo,
            .key = key,
            .ssl_ctx = ssl_ctx,
            .max_connections = ep_params->max_connections,
            .connect_timeout = ep_params->connect_timeout,
            .response_timeout = ep_params->response_timeout,
            .ssl_connect_timeout = ep_params->ssl_connect_timeout,
            .use_tls_sni = ep_params->use_tls_sni,
            .hostname = hostname,
        };

        entry = new RouteResultEntry;
        if (entry->init(&params) >= 0) {
            // 初始化成功，将新条目插入树中
            rb_link_node(&entry->rb, parent, p);
            rb_insert_color(&entry->rb, &cache_);
        } else {
            // 初始化失败, 清理资源
            delete entry;
            return -1;
        }
    }

    // cookie作为唯一标识符, 在后续的网络操作中, 框架可以通过这个指针准确地找到是哪个路由条目产生了特定的事件(如连接成功/失败)
    // 当目标服务器的可用性状态发生变化时(如从不可用变为可用), 框架可以通过这个 cookie 调用相应的通知函数(如 notify_available 或 notify_unavailable), 从而更新路由条目的内部状态
    result.cookie = entry;
    result.request_object = entry->request_object; // 调用方获得 request_object 后, 就可以直接使用它来创建连接或发送请求, 而无需关心底层是单个目标还是一组目标
    return 0;
}

void RouteManager::notify_unavailable(void *cookie, CommTarget *target) {
    if (cookie && target) {
        static_cast<RouteResultEntry *>(cookie)->notify_unavailable(dynamic_cast<RouteTarget *>(target));
    }
}

void RouteManager::notify_available(void *cookie, CommTarget *target) {
    if (cookie && target) {
        static_cast<RouteResultEntry *>(cookie)->notify_available(dynamic_cast<RouteTarget *>(target));
    }
}