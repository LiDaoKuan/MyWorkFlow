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

#ifndef MYWORKFLOW_DNSCACHE_H
#define MYWORKFLOW_DNSCACHE_H

#include <netdb.h>
#include <cstdint>
#include <string>
#include <mutex>
#include <utility>
#include "LRUCache.h"
#include "DnsUtil.h"

// 标识一种宽松的缓存查询模式. 此模式下, 只要缓存项未超过其绝对过期时间 (expire_time), 则仍被视为有效而被返回
#define GET_TYPE_TTL		0
// 标识一种严格的缓存查询模式. 此模式下, 要求缓存项必须处于置信时间 (confident_time) 之内才被视为有效, 适用于对数据实时性要求高的场景
#define GET_TYPE_CONFIDENT	1

// 当缓存项超过"置信时间"但未超过"绝对过期时间"时, 虽然它可能不再是"最新"的, 但在某些场景下(如网络不稳定时)仍可被使用以保证服务的基本可用性

// 包含两个超时时间和一个ip地址链表，用于在缓存系统中作为value记录域名key的过期时间？
struct DnsCacheValue {
    struct addrinfo *addrinfo; // 指向一个链表. 这个链表包含了域名解析后得到的一个或多个IP地址（例如，一个域名可能对应多个IPv4或IPv6地址）以及相关的套接字地址信息
    int64_t confident_time;
    int64_t expire_time;

    // 用于检查该缓存记录是否被标记为"延迟处理"
    [[nodiscard]] bool delayed() const {
        return addrinfo->ai_flags & 2; // 通过检查 addrinfo->ai_flags 是否包含特定标志来实现
    }
};

// RAII: NO. Release handle by user
// Thread safety: YES
// MUST call release when handle no longer used
class DnsCache {
public:
    using HostPort = std::pair<std::string, unsigned short>;
    using DnsHandle = LRUHandle<HostPort, DnsCacheValue>;

public:
    // get handler
    // Need call release when handle no longer needed
    //Handle *get(const KEY &key);

    // 标准查询模式
    const DnsHandle *get(const HostPort &host_port);

    const DnsHandle *get(const std::string &host, unsigned short port) {
        return get(HostPort(host, port));
    }

    const DnsHandle *get(const char *host, unsigned short port) {
        return get(std::string(host), port);
    }

    // 宽松查询模式
    const DnsHandle *get_ttl(const HostPort &host_port) {
        return get_inner(host_port, GET_TYPE_TTL);
    }

    const DnsHandle *get_ttl(const std::string &host, unsigned short port) {
        return get_ttl(HostPort(host, port));
    }

    const DnsHandle *get_ttl(const char *host, unsigned short port) {
        return get_ttl(std::string(host), port);
    }

    // 严格查询模式
    const DnsHandle *get_confident(const HostPort &host_port) {
        return get_inner(host_port, GET_TYPE_CONFIDENT);
    }

    const DnsHandle *get_confident(const std::string &host, unsigned short port) {
        return get_confident(HostPort(host, port));
    }

    const DnsHandle *get_confident(const char *host, unsigned short port) {
        return get_confident(std::string(host), port);
    }

    const DnsHandle *put(const HostPort &host_port, addrinfo *addrinfo,
                         unsigned int dns_ttl_default, unsigned int dns_ttl_min);

    const DnsHandle *put(const std::string &host, unsigned short port, addrinfo *addrinfo,
                         unsigned int dns_ttl_default, unsigned int dns_ttl_min) {
        return put(HostPort(host, port), addrinfo, dns_ttl_default, dns_ttl_min);
    }

    const DnsHandle *put(const char *host, unsigned short port, addrinfo *addrinfo,
                         unsigned int dns_ttl_default, unsigned int dns_ttl_min) {
        return put(std::string(host), port, addrinfo, dns_ttl_default, dns_ttl_min);
    }

    // release handle by get/put
    void release(const DnsHandle *handle);

    // delete from cache, deleter delay called when all inuse-handle release.
    void del(const HostPort &key);

    void del(const std::string &host, unsigned short port) {
        del(HostPort(host, port));
    }

    void del(const char *host, unsigned short port) {
        del(std::string(host), port);
    }

private:
    const DnsHandle *get_inner(const HostPort &host_port, int type);

    std::mutex mutex_;

    // 自定义删除器, 负责安全且正确地释放 addrinfo 结构体占用的内存, 防止泄漏
    class ValueDeleter {
    public:
        void operator()(const DnsCacheValue &value) const {
            struct addrinfo *ai = value.addrinfo;

            if (ai) {
                if (ai->ai_flags & 1) {
                    // 当DNS查询通过操作系统标准的 getaddrinfo 函数完成时, 它会在堆上分配一个可能包含多个 addrinfo 节点的链表.
                    // 释放它必须使用对应的 freeaddrinfo, 否则会导致内存泄漏或崩溃
                    ::freeaddrinfo(ai);
                } else {
                    // 释放通过框架内部接口构建的addrinfo结构
                    protocol::DnsUtil::freeaddrinfo(ai);
                }
            }
        }
    };

    // HostPort本身是一个pair<string, unsigned short>类型, 它在LRUCache中作为key, 对应的value为DnsCacheValue（）
    LRUCache<HostPort, DnsCacheValue, ValueDeleter> cache_pool_;

public:
    // To prevent inline calling LRUCache's constructor and deconstructor.
    DnsCache();
    ~DnsCache();
};

#endif //MYWORKFLOW_DNSCACHE_H