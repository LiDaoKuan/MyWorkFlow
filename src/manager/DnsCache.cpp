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
           Xie Han (xiehan@sogou-inc.com)
*/

#include <cstdint>
#include <chrono>
#include "DnsCache.h"

// 用于获取系统启动后经过的秒数(从纪元时间点开始计算), 返回一个整数秒值. 它不依赖系统墙钟, 适合测量时间间隔
// std::chrono::steady_clock: 一个稳定、单调递增的时钟, 即使系统时间被手动调整, 其计时也不会回退或跳跃, 非常适合测量耗时、间隔或超时
// time_since_epoch(): 返回从该时钟的固定起点(通常为系统启动时刻)到当前时间点的 duration 对象(表示时间长度)
// std::chrono::duration_cast<T>: 将持续时间转换为以T为单位的精度. 这是一个类型安全的转换操作
// count(): 提取持续时间对象中的整数值(此处即: 秒数), 类型通常为 int64_t
#define GET_CURRENT_SECOND	std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count()

// 用于表示 TTL 的增量值(即: 延长期)
#define	TTL_INC				5

// 当一个热点域名的缓存过期时, 可能会有大量并发请求同时到达并发现缓存失效, 导致它们都去触发DNS查询, 造成缓存雪崩或DNS服务器压力激增.
// 通过为已过期的缓存项设置一个短暂的延长期(TTL_INC, 例如5秒)并标记为"已延迟", 后续的请求在该延长期内依然会认为该缓存项已过期(因为时间戳再次被检查),
// 但由于已被标记, 它们不会重复执行延长操作, 从而将回源压力分散开

// 带延迟标记的缓存查询函数. 根据指定的查询类型(GET_TYPE_TTL 或 GET_TYPE_CONFIDENT)来检查并返回有效的DNS缓存项
const DnsCache::DnsHandle *DnsCache::get_inner(const HostPort &host_port, int type) {
    int64_t cur = GET_CURRENT_SECOND;
    std::lock_guard<std::mutex> lock(mutex_); // 获取互斥锁, 确保在检查缓存状态和进行后续操作时, 缓存池不会被其他线程修改
    const DnsHandle *handle = cache_pool_.get(host_port);

    if (handle && ((type == GET_TYPE_TTL && cur > handle->value.expire_time) || // 检查当前时间 cur 是否超过了该缓存项的绝对过期时间(expire_time). 这是缓存有效性的最终底线
                   (type == GET_TYPE_CONFIDENT && cur > handle->value.confident_time) // 检查当前时间 cur是否超过了该缓存项的置信时间(confident_time). 这个时间通常比绝对过期时间要早, 用于实现渐进式更新
        )) // 此函数在 GET_TYPE_CONFIDENT 模式下, 一旦超时就认为缓存无效, 适用于对数据实时性要求高的场景
    {
        // 当缓存项已过期时, 并非立即从缓存中删除它, 而是执行一套延迟更新逻辑:
        if (!handle->value.delayed()) // 如果该缓存项尚未被标记为"延迟更新"
        {
            auto *h = const_cast<DnsHandle *>(handle); // 需要修改句柄值, 去除const属性
            if (type == GET_TYPE_TTL) {
                h->value.expire_time += TTL_INC; // 延长绝对过期时间
            } else {
                h->value.confident_time += TTL_INC; // 延长置信时间
            }

            h->value.addrinfo->ai_flags |= 2; // 设置延迟标记
        }
        // 释放已经过期的缓存项
        cache_pool_.release(handle);
        return nullptr;
    }

    return handle;
}

/**
 * @brief 将 DNS 解析结果存入缓存池
 * @param host_port 缓存的键, 通常是域名和端口的组合, 用于唯一标识一个缓存条目
 * @param addrinfo DNS解析结果, 包含一个或多个IP地址(如IPv4或IPv6)及套接字地址信息
 * @param dns_ttl_default 默认的存活时间. 如果DNS响应中没有提供TTL, 或者作为计算缓存绝对过期时间的基础
 * @param dns_ttl_min 最小存活时间. 主要有两个作用: 1)确保TTL不会设置得过短; 2)用于计算置信时间, 即缓存数据被认为"高度可信"的时间段
 * @return
 */
const DnsCache::DnsHandle *DnsCache::put(const HostPort &host_port, struct addrinfo *addrinfo,
                                         unsigned int dns_ttl_default, unsigned int dns_ttl_min) {
    int64_t expire_time;
    int64_t confident_time;
    int64_t cur_time = GET_CURRENT_SECOND;

    if (dns_ttl_min > dns_ttl_default) {
        // 确保用于计算confident_time的dns_ttl_min不会大于用于计算expire_time的dns_ttl_default.
        // 如果用户配置错误，函数会自动修正，防止产生逻辑上矛盾的时间戳（即置信时间晚于绝对过期时间）
        dns_ttl_min = dns_ttl_default;
    }

    if (dns_ttl_min == (unsigned int)-1) {
        confident_time = INT64_MAX; // 将 (unsigned int)-1 转换为 INT64_MAX 是一种特殊处理, 意味着该缓存条目永不过期, 适用于某些极其稳定的记录
    } else {
        // 如果 dns_ttl_min 不是 (unsigned int) -1 (表示无穷大)
        // 则 confident_time = cur_time + dns_ttl_min.
        // 这个时间点早于绝对过期时间, 在此时间点之前, 缓存数据被认为是高度可信的
        confident_time = cur_time + dns_ttl_min;
    }

    if (dns_ttl_default == (unsigned int)-1) {
        expire_time = INT64_MAX; // 永不过期
    } else {
        // 如果 dns_ttl_default 不是 (unsigned int)-1, 则 expire_time = cur_time + dns_ttl_default.
        // 这是缓存有效性的最终底线, 超过此时间, 缓存条目会因过期而被淘汰
        expire_time = cur_time + dns_ttl_default;
    }

    std::lock_guard<std::mutex> lock(mutex_); // 确保在多线程环境下对缓存池的修改是原子性的
    return cache_pool_.put(host_port, {addrinfo, confident_time, expire_time});
}

const DnsCache::DnsHandle *DnsCache::get(const DnsCache::HostPort &host_port) {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_pool_.get(host_port);
}

void DnsCache::release(const DnsCache::DnsHandle *handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_pool_.release(handle);
}

void DnsCache::del(const DnsCache::HostPort &key) {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_pool_.del(key);
}

DnsCache::DnsCache() {}

DnsCache::~DnsCache() {}