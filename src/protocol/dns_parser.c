//
// Created by ldk on 10/25/25.
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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "dns_types.h"
#include "dns_parser.h"

#define DNS_LABELS_MAX			63
#define DNS_NAMES_MAX			256
#define DNS_MSGBASE_INIT_SIZE	514 // 512 + 2(leading length)
#define MAX(x, y) ((x) <= (y) ? (y) : (x))

struct __dns_record_entry {
    struct list_head entry_list;
    struct dns_record record;
};

static inline uint8_t __dns_parser_uint8(const char *ptr) {
    return (unsigned char)ptr[0];
}

// 将2字节的大端序数据转换为主机字节序的16位整数
static inline uint16_t __dns_parser_uint16(const char *ptr) {
    const unsigned char *p = (const unsigned char *)ptr;
    // 将高位字节左移8位, 与低位字节相加
    return ((uint16_t)p[0] << 8) + ((uint16_t)p[1]);
}

// 将4字节的大端序数据转换为主机字节序的32位整数
static inline uint32_t __dns_parser_uint32(const char *ptr) {
    const unsigned char *p = (const unsigned char *)ptr;
    // 将四个字节分别左移24、16、8、0位后相加
    return ((uint32_t)p[0] << 24) +
           ((uint32_t)p[1] << 16) +
           ((uint32_t)p[2] << 8) +
           ((uint32_t)p[3]);
}

/*
 * Parse a single <domain-name>.
 * <domain-name> is a domain name represented as a series of labels, and
 * terminated by a label with zero length.
 *
 * phost must point to a char array with at least DNS_NAMES_MAX+1 size
 */

/**@brief 用于解析DNS报文的域名
 * @param phost 输出参数，指向一个足够大（至少 DNS_NAMES_MAX+1）的字符数组，用于存储解析出的域名字符串（如 "www.example.com."）
 * @param parser 解析器上下文，包含原始DNS报文数据（msg_buf和 msg_size）及当前解析位置（cur）
 * @return 成功返回0, 失败返回-2
 */
static int __dns_parser_parse_host(char *phost, dns_parser_t *parser) {
    uint8_t len;
    uint16_t pointer;

    const char *msgend = (const char *)parser->msg_buf + parser->msg_size; // msgend指向报文缓冲区的结束位置，用于在解析过程中防止越界
    const char **cur = &(parser->cur); // 当前解析位置
    const char *curbackup = NULL; // backup cur when host label is pointer
    size_t hcur = 0; // 跟踪 phost 缓冲区的当前写入位置

    // 确保解析起始位置是有效的
    if (*cur >= msgend) {
        return -2;
    }

    while (*cur < msgend) {
        len = __dns_parser_uint8(*cur);
        // 长度字节的最高两位为 00 时, 这是一个普通的标签. len & 11000000, 获得最高两位
        if ((len & 0xC0) == 0) {
            (*cur)++; // 解析位置后移
            if (len == 0) {
                break; // 零长度标签表示域名结束
            }
            // 长度不合法 || 没有足够的剩余报文数据 || 输出缓冲区不够用
            if (len > DNS_LABELS_MAX || *cur + len > msgend || hcur + len + 1 > DNS_NAMES_MAX) {
                return -2;
            }
            memcpy(phost + hcur, *cur, len); // 复制标签内容
            *cur += len;
            hcur += len;
            phost[hcur++] = '.'; // 将标签内容（如 "www"）复制到 phost，后追加点号（.），形成 "www."
        } else if ((len & 0xC0) == 0xC0) {
            // 最高两位为 11 表示这是一个指针(指针偏移为14位，即 len & 0x3FFF)
            pointer = __dns_parser_uint16(*cur) & 0x3FFF; // 指针指向报文中同一域名的另一个出现位置(避免重复传输)
            // 检查指针值有效性：不能超出报文范围，且不能指向当前解析位置之后（防止循环引用）
            if (pointer >= parser->msg_size || (const char *)parser->msg_base + pointer >= *cur) {
                return -2;
            }
            *cur += 2; // 解析位置后移两个字节
            if (curbackup == NULL) {
                curbackup = *cur; // 备份当前指针，以便后续恢复
            }
            *cur = (const char *)parser->msg_base + pointer; // 跳转到指针指向的位置. 实现了递归解析而不复制数据
        } else {
            return -2; // 长度字节最高两位不是00或11，报文格式错误
        }
    }
    // 如果解析过程中遇到过指针压缩, 此时将当前解析位置恢复为之前备份的位置. 这是因为指针跳转只用于读取域名部分, 主报文解析需在指针后继续
    if (curbackup != NULL) { *cur = curbackup; }
    // 若域名以点号结尾（如 "www.example.com."），去除最后一个点号（除非域名本身是根域）
    if (hcur > 1 && phost[hcur - 1] == '.') { hcur--; }
    // 如果域名为空(无标签), 添加根域点号(".")
    if (hcur == 0) {
        phost[hcur++] = '.';
    }
    phost[hcur] = '\0'; // 添加C字符串终止符

    return 0;
}

// 用于安全释放DNS记录内存的清理函数
static void __dns_parser_free_record(struct __dns_record_entry *r) {
    // 根据不同的DNS记录类型，有针对性地释放其内部动态分配的资源，最终销毁记录对象本身
    switch (r->record.type) {
    // SOA（起始授权机构）记录
    case DNS_TYPE_SOA: {
        struct dns_record_soa *soa;
        soa = (struct dns_record_soa *)(r->record.rdata);
        free(soa->mname);
        free(soa->rname);
        break;
    }
    // SRV（服务定位）记录
    case DNS_TYPE_SRV: {
        struct dns_record_srv *srv;
        srv = (struct dns_record_srv *)(r->record.rdata);
        free(srv->target);
        break;
    }
    // MX（邮件交换）记录
    case DNS_TYPE_MX: {
        struct dns_record_mx *mx;
        mx = (struct dns_record_mx *)(r->record.rdata);
        free(mx->exchange);
        break;
    }
    }
    free(r->record.name);
    free(r);
}

// 用于安全释放整个DNS记录链表
static void __dns_parser_free_record_list(struct list_head *head) {
    struct list_head *pos, *tmp;
    struct __dns_record_entry *entry;

    list_for_each_safe(pos, tmp, head) {
        entry = list_entry(pos, struct __dns_record_entry, entry_list);
        list_del(pos);
        __dns_parser_free_record(entry);
    }
}

/*
 * A RDATA format, from RFC 1035:
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ADDRESS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * ADDRESS: A 32 bit Internet address.
 * Hosts that have multiple Internet addresses will have multiple A records.
 */
static int __dns_parser_parse_a(struct __dns_record_entry **r, uint16_t rdlength, dns_parser_t *parser) {
    // 检查传入的rdlength（数据长度）是否严格等于struct in_addr的大小, 在IPv4中，这固定为4字节（32位）
    if (sizeof(struct in_addr) != rdlength) { return -2; }

    const char **cur = &(parser->cur); // 指向解析器当前读取位置的指针的指针, 用于读取数据并推进解析位置
    // 计算需要分配的总内存大小, 即: 结构体大小 + IPv4地址数据大小
    const size_t entry_size = sizeof(struct __dns_record_entry) + sizeof(struct in_addr);
    struct __dns_record_entry *entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }

    // entry->record.rdata指针被设置为 entry + 1.
    // 这意味着它指向紧接在 __dns_record_entry 结构体之后的内存地址, 也就是分配的内存块中专门留给IPv4地址数据的那部分
    entry->record.rdata = (void *)(entry + 1);
    // 复制IPV4地址: 将报文数据中当前指针（*cur）位置开始的 rdlength（4字节）字节数据, 复制到刚才设置好的 rdata 指向的位置
    memcpy(entry->record.rdata, *cur, rdlength);
    *cur += rdlength; // 解析位置后移4字节
    *r = entry;

    return 0;
}

/*
 * AAAA RDATA format, from RFC 3596:
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ADDRESS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * ADDRESS: A 128 bit Internet address.
 * Hosts that have multiple addresses will have multiple AAAA records.
 */
static int __dns_parser_parse_aaaa(struct __dns_record_entry **r, uint16_t rdlength, dns_parser_t *parser) {
    // 检查传入的rdlength（数据长度）是否严格等于struct in6_addr的大小, 在IPv6中，这固定为16字节（128位）
    if (sizeof(struct in6_addr) != rdlength) {
        return -2; // 如果长度不匹配, 说明DNS报文可能已损坏或格式错误
    }

    const char **cur = &(parser->cur);
    size_t entry_size = sizeof(struct __dns_record_entry) + sizeof(struct in6_addr);
    struct __dns_record_entry *entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }

    entry->record.rdata = (void *)(entry + 1);
    memcpy(entry->record.rdata, *cur, rdlength); // 复制ipv6地址
    *cur += rdlength; // 解析位置后移16字节
    *r = entry;

    return 0;
}

/*
 * Parse any <domain-name> record.
 */
// 处理通用域名记录(如 CNAME, NS, PTR 等)
static int __dns_parser_parse_names(struct __dns_record_entry **r, uint16_t rdlength, dns_parser_t *parser) {
    char name[DNS_NAMES_MAX + 2];

    const char **cur = &(parser->cur);
    const char *rcdend = *cur + rdlength; // 计算出该记录数据区域的结束位置 rcdend
    int ret = __dns_parser_parse_host(name, parser); // 域名解析
    if (ret < 0) { return ret; } // 检查域名解析是否出错
    // 检查解析后位置是否恰好等于记录末尾. 如果不等, 说明实际解析消耗的数据长度与报文头中声明的 rdlength 不匹配, 表明报文可能已损坏, 立即返回错误 -2
    if (*cur != rcdend) { return -2; }

    const size_t name_len = strlen(name);
    // 计算需要分配的总内存大小, 包括 __dns_record_entry 结构体本身、域名字符串长度以及字符串终止符 \0 的空间
    const size_t entry_size = sizeof(struct __dns_record_entry) + name_len + 1;
    struct __dns_record_entry *entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }
    // 将 entry->record.rdata 指针设置为 entry + 1, 这意味着它指向紧接在 __dns_record_entry 结构体之后的内存地址.
    // 接着, 使用 memcpy 将临时缓冲区 name 中的域名字符串(包括终止符 \0)复制到这个位置
    entry->record.rdata = (void *)(entry + 1);
    memcpy(entry->record.rdata, name, name_len + 1);
    *r = entry;

    return 0;
}

/*
 * SOA RDATA format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                     MNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                     RNAME                     /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    SERIAL                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    REFRESH                    |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     RETRY                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    EXPIRE                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    MINIMUM                    |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * MNAME: <domain-name>
 * RNAME: <domain-name>
 * SERIAL: The unsigned 32 bit version number.
 * REFRESH: A 32 bit time interval.
 * RETRY: A 32 bit time interval.
 * EXPIRE: A 32 bit time value.
 * MINIMUM: The unsigned 32 bit integer.
 */
// 用于解析DNS SOA（Start of Authority，起始授权机构）记录
static int __dns_parser_parse_soa(struct __dns_record_entry **r, uint16_t rdlength, dns_parser_t *parser) {
    char mname[DNS_NAMES_MAX + 2];
    char rname[DNS_NAMES_MAX + 2];

    const char **cur = &(parser->cur);
    const char *rcdend = *cur + rdlength;
    int ret = __dns_parser_parse_host(mname, parser); // 解析主域名服务器（MNAME）
    if (ret < 0) { return ret; }
    ret = __dns_parser_parse_host(rname, parser); // 解析管理员邮箱（RNAME）
    if (ret < 0) { return ret; }
    // 确保在解析完两个域名后, 剩余的报文数据长度恰好为20字节.
    // 这20字节用于存储SOA记录中的5个32位整数参数（序列号、刷新间隔、重试间隔、过期时间、最小TTL）
    if (*cur + 20 != rcdend) { return -2; }
    // 将记录头 (__dns_record_entry) 和SOA数据 (dns_record_soa) 存放在一块连续内存中
    const size_t entry_size = sizeof(struct __dns_record_entry) + sizeof(struct dns_record_soa);
    struct __dns_record_entry *entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }

    entry->record.rdata = (void *)(entry + 1);
    struct dns_record_soa *soa = (struct dns_record_soa *)(entry->record.rdata);

    soa->mname = strdup(mname);
    soa->rname = strdup(rname);
    soa->serial = __dns_parser_uint32(*cur);
    soa->refresh = __dns_parser_uint32(*cur + 4);
    soa->retry = __dns_parser_uint32(*cur + 8);
    soa->expire = __dns_parser_uint32(*cur + 12);
    soa->minimum = __dns_parser_uint32(*cur + 16);
    // 若strdup调用失败(内存不足), 函数会回滚所有已分配的资源, 防止内存泄漏
    if (!soa->mname || !soa->rname) {
        free(soa->mname);
        free(soa->rname);
        free(entry);
        return -1;
    }

    *cur += 20; // 解析位置后移
    *r = entry;

    return 0;
}

/*
 * SRV RDATA format, from RFC 2782:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                   PRIORITY                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    WEIGHT                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     PORT                      |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                    TARGET                     /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * PRIORITY: A 16 bit unsigned integer in network byte order.
 * WEIGHT: A 16 bit unsigned integer in network byte order.
 * PORT: A 16 bit unsigned integer in network byte order.
 * TARGET: <domain-name>
 */
// 用于处理 SRV 记录(Service Record，服务记录)
static int __dns_parser_parse_srv(struct __dns_record_entry **r, uint16_t rdlength, dns_parser_t *parser) {
    const char *rcdend;
    const char **cur;
    struct __dns_record_entry *entry;
    struct dns_record_srv *srv;
    size_t entry_size;
    char target[DNS_NAMES_MAX + 2];
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
    int ret;

    cur = &(parser->cur);
    rcdend = *cur + rdlength; // 当前记录数据结束边界, 防止解析过程中越界
    // 检查报文剩余数据是否足够容纳 SRV 记录固定的头部（6字节）
    if (*cur + 6 > rcdend) { return -2; }

    priority = __dns_parser_uint16(*cur); // 优先级
    weight = __dns_parser_uint16(*cur + 2); // 权重
    port = __dns_parser_uint16(*cur + 4); // 端口
    *cur += 6; // 解析位置后移

    ret = __dns_parser_parse_host(target, parser); // 目标主机名解析
    if (ret < 0) { return ret; }
    if (*cur != rcdend) { return -2; } // 检查当前指针是否恰好到达记录末尾, 确保没有多余或缺失数据

    entry_size = sizeof(struct __dns_record_entry) + sizeof(struct dns_record_srv);
    entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }

    entry->record.rdata = (void *)(entry + 1); // rdata指向紧接在entry之后的内存
    srv = (struct dns_record_srv *)(entry->record.rdata);

    srv->priority = priority;
    srv->weight = weight;
    srv->port = port;
    srv->target = strdup(target);

    // strdup失败(内存不足), 会立即释放之前分配的 entry 内存
    if (!srv->target) {
        free(entry);
        return -1;
    }

    *r = entry;

    return 0;
}

// 用于处理 MX 记录（邮件交换记录）
static int __dns_parser_parse_mx(struct __dns_record_entry **r,
                                 uint16_t rdlength,
                                 dns_parser_t *parser) {
    const char *rcdend;
    const char **cur;
    struct __dns_record_entry *entry;
    struct dns_record_mx *mx;
    size_t entry_size;
    char exchange[DNS_NAMES_MAX + 2];
    int16_t preference;
    int ret;

    cur = &(parser->cur);
    rcdend = *cur + rdlength;

    // 检查剩余数据是否足够2字节，防止越界访问. MX记录中的优先级是一个16位整数, 数值越小优先级越高
    if (*cur + 2 > rcdend) { return -2; }
    preference = __dns_parser_uint16(*cur); // 解析优先级
    *cur += 2;

    ret = __dns_parser_parse_host(exchange, parser); // 解析邮件服务器域名
    if (ret < 0) { return ret; }
    if (*cur != rcdend) { return -2; } // 检查当前解析位置是否恰好到达记录末尾, 确保没有多余或缺失数据.

    entry_size = sizeof(struct __dns_record_entry) + sizeof(struct dns_record_mx);
    entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }

    entry->record.rdata = (void *)(entry + 1);
    mx = (struct dns_record_mx *)(entry->record.rdata);
    mx->exchange = strdup(exchange); // 为邮件服务器域名创建独立副本, 因为exchange是函数内的数组, 函数结束后会释放
    mx->preference = preference; //

    if (!mx->exchange) {
        free(entry);
        return -1;
    }

    *r = entry;

    return 0;
}

static int __dns_parser_parse_others(struct __dns_record_entry **r, uint16_t rdlength, dns_parser_t *parser) {
    const char **cur;
    struct __dns_record_entry *entry;
    size_t entry_size;

    cur = &(parser->cur);
    entry_size = sizeof(struct __dns_record_entry) + rdlength;
    entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }

    entry->record.rdata = (void *)(entry + 1);
    // 将DNS报文中的原始记录数据 (从当前解析位置 *cur开始, 长度为 rdlength) 复制到刚才设置好的 rdata 指向的内存中.
    // 然后, 将解析器的当前指针向前推进 rdlength 字节, 确保解析器能够继续处理报文中后续的记录
    memcpy(entry->record.rdata, *cur, rdlength);
    *cur += rdlength;
    *r = entry;

    return 0;
}

/*
 * RR format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                      NAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      TYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      CLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                       TTL                     |
 *  |                                               |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    RDLENGTH                   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  /                      RDATA                    /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
// 记录分发与解析调度: 根据传入的索引 idx处理 DNS 响应报文中三个不同部分的资源记录: 回答记录(Answer), 权威记录(Authority)和附加记录(Additional)
static int __dns_parser_parse_record(int idx, dns_parser_t *parser) {
    uint16_t i;
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    uint16_t count;
    const char *msgend;
    const char **cur;
    int ret;
    struct __dns_record_entry *entry;
    char host[DNS_NAMES_MAX + 2];
    struct list_head *list;

    // 通过 idx 参数区分处理哪一部分记录
    switch (idx) {
    case 0: // 回答记录
        count = parser->header.ancount;
        list = &parser->answer_list;
        break;
    case 1: // 权威记录
        count = parser->header.nscount;
        list = &parser->authority_list;
        break;
    case 2: // 附加记录
        count = parser->header.arcount;
        list = &parser->additional_list;
        break;
    default: return -2;
    }

    msgend = (const char *)parser->msg_buf + parser->msg_size;
    cur = &(parser->cur);

    for (i = 0; i < count; i++) {
        ret = __dns_parser_parse_host(host, parser); // 解析域名
        if (ret < 0) { return ret; }

        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10
        if (*cur + 10 > msgend) { return -2; }
        // 解析每个记录的公共头部
        type = __dns_parser_uint16(*cur); // 记录类型（如A、AAAA、MX）
        rclass = __dns_parser_uint16(*cur + 2); // 记录类（通常为IN，表示Internet）
        ttl = __dns_parser_uint32(*cur + 4); // 生存时间（缓存有效期）
        rdlength = __dns_parser_uint16(*cur + 8); // 数据部分长度
        *cur += 10;
        if (*cur + rdlength > msgend) { return -2; } // 确保报文数据完整且不会越界

        entry = NULL;
        // 根据 type 调用对应的解析函数
        switch (type) {
        case DNS_TYPE_A: ret = __dns_parser_parse_a(&entry, rdlength, parser);
            break;
        case DNS_TYPE_AAAA: ret = __dns_parser_parse_aaaa(&entry, rdlength, parser);
            break;
        case DNS_TYPE_NS:
        case DNS_TYPE_CNAME:
        case DNS_TYPE_PTR: ret = __dns_parser_parse_names(&entry, rdlength, parser);
            break;
        case DNS_TYPE_SOA: ret = __dns_parser_parse_soa(&entry, rdlength, parser);
            break;
        case DNS_TYPE_SRV: ret = __dns_parser_parse_srv(&entry, rdlength, parser);
            break;
        case DNS_TYPE_MX: ret = __dns_parser_parse_mx(&entry, rdlength, parser);
            break;
        default: ret = __dns_parser_parse_others(&entry, rdlength, parser); // 未知记录类型
        }

        if (ret < 0) { return ret; }

        entry->record.name = strdup(host);
        if (!entry->record.name) {
            __dns_parser_free_record(entry);
            return -1;
        }

        entry->record.type = type;
        entry->record.rclass = rclass;
        entry->record.ttl = ttl;
        entry->record.rdlength = rdlength;
        // 将新记录添加到对应段的链表中
        list_add_tail(&entry->entry_list, list);
    }

    return 0;
}

/*
 * Question format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                     QNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QTYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QCLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * The query name is encoded as a series of labels, each represented
 * as a one-byte length (maximum 63) followed by the text of the
 * label.  The list is terminated by a label of length zero (which can
 * be thought of as the root domain).
 */
// 用于处理查询问题部分(Question Section): 从接收到的 DNS 报文数据中, 提取出客户端想要查询的域名, 查询类型 和 查询类别
static int __dns_parser_parse_question(dns_parser_t *parser) {
    uint16_t qtype;
    uint16_t qclass;
    const char *msgend;
    const char **cur;
    int ret;
    char host[DNS_NAMES_MAX + 2];

    msgend = (const char *)parser->msg_buf + parser->msg_size; // 计算解析边界
    cur = &(parser->cur);

    // question count != 1 is an error
    // 虽然DNS协议理论上允许一个报文中包含多个Question, 但在实际应用中, 绝大多数标准的DNS查询只包含一个Question.
    // 此检查简化了解析逻辑, 如果遇到不常见的多Question报文, 则直接报错, 确保解析器专注于处理最常见的场景
    if (parser->header.qdcount != 1) { return -2; }

    // parse qname
    ret = __dns_parser_parse_host(host, parser); // 解析 QNAME 字段
    if (ret < 0) { return ret; }

    // parse qtype and qclass
    if (*cur + 4 > msgend) { return -2; }

    // 读取2字节的QTYPE 和2字节的QCLASS
    qtype = __dns_parser_uint16(*cur);
    qclass = __dns_parser_uint16(*cur + 2);
    *cur += 4;

    // 先检查并释放之前可能已经存在的qname，防止内存泄漏
    if (parser->question.qname) {
        free(parser->question.qname);
    }
    // 创建副本
    parser->question.qname = strdup(host);
    if (parser->question.qname == NULL) { return -1; }

    parser->question.qtype = qtype;
    parser->question.qclass = qclass;

    return 0;
}

//  DNS 解析器的初始化
void dns_parser_init(dns_parser_t *parser) {
    parser->msg_buf = NULL;
    parser->msg_base = NULL;
    parser->cur = NULL;
    parser->msg_size = 0;
    parser->buf_size = 0;
    parser->complete = 0;
    parser->single_packet = 0;
    memset(&parser->header, 0, sizeof(struct dns_header));
    memset(&parser->question, 0, sizeof(struct dns_question));
    INIT_LIST_HEAD(&parser->answer_list);
    INIT_LIST_HEAD(&parser->authority_list);
    INIT_LIST_HEAD(&parser->additional_list);
}

// 设置查询问题(Question)部分
int dns_parser_set_question(const char *name, uint16_t qtype, uint16_t qclass, dns_parser_t *parser) {
    const int ret = dns_parser_set_question_name(name, parser); // 设置域名
    if (ret < 0) { return ret; }

    parser->question.qtype = qtype; // 设置查询类型（如A记录、MX记录）
    parser->question.qclass = qclass; // 设置查询类别（通常为IN，代表Internet）
    parser->header.qdcount = 1; // 标记解析器头部的问题计数为1

    return 0;
}

// 设置查询的域名
int dns_parser_set_question_name(const char *name, dns_parser_t *parser) {
    size_t len = strlen(name); // 计算输入的域名的长度
    char *newname = (char *)malloc(len + 1); // 为域名分配内存（+1用于存储空字符）

    if (!newname) { return -1; }

    memcpy(newname, name, len + 1); // 将输入域名复制到新分配的内存中
    // Remove trailing dot, except name is "."
    // 规范化处理: 移除末尾的点号, 但保留根域"."的特殊情况
    if (len > 1 && newname[len - 1] == '.') { newname[len - 1] = '\0'; }

    // 释放旧的域名内存, 防止泄漏
    if (parser->question.qname) { free(parser->question.qname); }
    parser->question.qname = newname; // 更新解析器中的域名指针

    return 0;
}

void dns_parser_set_id(uint16_t id, dns_parser_t *parser) {
    parser->header.id = id;
}

// DNS 解析器的总控调度
int dns_parser_parse_all(dns_parser_t *parser) {
    parser->complete = 1; // 标记解析开始
    parser->cur = (const char *)parser->msg_base; // 将当前解析指针指向报文数据起始处
    struct dns_header *h = &parser->header;
    // 检查报文长度是否至少能容纳一个DNS头部
    if (parser->msg_size < sizeof(struct dns_header)) { return -2; }

    memcpy(h, parser->msg_base, sizeof(struct dns_header));
    // 将下面这些字段从网络字节序转换为主机字节序
    h->id = ntohs(h->id);
    h->qdcount = ntohs(h->qdcount);
    h->ancount = ntohs(h->ancount);
    h->nscount = ntohs(h->nscount);
    h->arcount = ntohs(h->arcount);
    parser->cur += sizeof(struct dns_header);

    int ret = __dns_parser_parse_question(parser); // 解析查询问题
    if (ret < 0) { return ret; }

    for (int i = 0; i < 3; i++) {
        ret = __dns_parser_parse_record(i, parser); // 循环解析资源记录: 回答记录, 权威记录, 附加记录
        if (ret < 0) { return ret; }
    }

    return 0;
}

int dns_parser_append_message(const void *buf, size_t *n, dns_parser_t *parser) {
    if (parser->complete) {
        // 如果解析已完成, 则忽略新数据, 直接返回1. 这确保了函数不会对已经处理完毕的报文进行重复操作
        *n = 0;
        return 1;
    }

    // if-else语句: 确保获得了一个完整的DNS报文段
    if (!parser->single_packet) {
        // 流模式(single_packet = 0), 适用于 DNS over TCP.
        // 由于TCP是字节流协议, 一次 recv 调用可能无法收到完整的DNS报文(尤其是报文前面有2字节的长度字段), 因此需要多次调用本函数来累积数据
        // 同时, TCP流式传输需要解决TCP粘包和数据完整性问题

        size_t msgsize_bak = parser->msg_size; // 备份已经接收到的字节数

        // 检查当前缓冲区是否足以容纳新数据.
        if (parser->msg_size + *n > parser->buf_size) {
            // 如果不够, 则使用 realloc进行扩容, 策略是至少扩大到当前缓冲区的2倍, 直到能满足 parser->msg_size + *n 的需求
            size_t new_size = MAX(DNS_MSGBASE_INIT_SIZE, 2 * parser->buf_size);
            while (new_size < parser->msg_size + *n) {
                new_size *= 2;
            }
            void *new_buf = realloc(parser->msg_buf, new_size);
            if (!new_buf) { return -1; }

            parser->msg_buf = new_buf;
            parser->buf_size = new_size;
        }
        // 新数据被 memcpy 到缓冲区的末尾.
        memcpy((char *)parser->msg_buf + parser->msg_size, buf, *n);
        parser->msg_size += *n;
        // 检查已累积的数据是否足够解析出TCP DNS报文的2字节长度前缀.
        if (parser->msg_size < 2) {
            return 0; // 如果不足(<2), 则返回0, 表示需要接收更多数据
        }
        // 解析出长度前缀 total
        size_t total = __dns_parser_uint16((char *)parser->msg_buf);

        // 检查已累积的数据是否达到了 total + 2字节 (即整个报文的完整长度)(2字节是total本身在报文段中的长度)
        if (parser->msg_size < total + 2) {
            return 0; // 如果不足, 同样返回0.
        }
        // 只有当数据足够时, 才计算本次实际需要消费的数据量 (*n = total + 2 - msgsize_bak). 告诉调用者: 本次实际消耗了多少数据（解决TCP粘包问题）
        *n = total + 2 - msgsize_bak; // 解决TCP粘包问题的核心
        // 设置 msg_base 指向有效DNS数据的开始位置(跳过2字节长度前缀)
        parser->msg_size = total + 2;
        parser->msg_base = (char *)parser->msg_buf + 2;
    } else {
        // 单包模式(single_packet = 1): 适用于 DNS over UDP
        // 接为传入的数据分配一块新内存并完整拷贝, 然后设置 msg_base指向数据开头, msg_size等于数据长度.
        // 这是因为UDP报文是自包含的, 没有额外的长度前缀
        parser->msg_buf = malloc(*n);
        memcpy(parser->msg_buf, buf, *n);
        parser->msg_base = parser->msg_buf;
        parser->msg_size = *n;
        parser->buf_size = *n;
    }
    // 能执行到这里, 一定已经获得了完整的DNS报文段, 如果不完整, 会在if语句中提前return
    int ret = dns_parser_parse_all(parser); // 执行实际的DNS解析
    if (ret < 0) { return ret; }

    return 1;
}

// 销毁DNS解析器
void dns_parser_deinit(dns_parser_t *parser) {
    free(parser->msg_buf);
    free(parser->question.qname);

    __dns_parser_free_record_list(&parser->answer_list);
    __dns_parser_free_record_list(&parser->authority_list);
    __dns_parser_free_record_list(&parser->additional_list);
}


int dns_record_cursor_next(struct dns_record **record, dns_record_cursor_t *cursor) {
    // 判断当前节点的下一个节点（cursor->next->next）是否不是链表的头节点（cursor->head）
    if (cursor->next->next != cursor->head) {
        cursor->next = cursor->next->next; // 令游标指向下一个节点
        struct __dns_record_entry *e = list_entry(cursor->next, struct __dns_record_entry, entry_list); // 获取下一个节点所在的entry
        *record = &e->record; // 通过输出参数返回该记录的指针
        return 0;
    }
    return 1;
}

// 查找特定域名的CNAME记录
int dns_record_cursor_find_cname(const char *name, const char **cname, dns_record_cursor_t *cursor) {
    struct __dns_record_entry *e = NULL;

    if (!name || !cname) { return 1; } // 检查输入参数的有效性, 防止空指针访问

    cursor->next = cursor->head; // 将游标的next指针重置到链表的头节点
    while (cursor->next->next != cursor->head) {
        cursor->next = cursor->next->next;
        e = list_entry(cursor->next, struct __dns_record_entry, entry_list);
        // strcasecmp: 不区分大小写的比较
        if (e->record.type == DNS_TYPE_CNAME && strcasecmp(name, e->record.name) == 0) {
            *cname = (const char *)e->record.rdata; // 将输出参数cname指向记录中的目标域名
            return 0;
        }
    }

    return 1;
}

// 向DNS记录链表中添加原始资源记录(Resource Record). 调用者必须确保传入的 rdata 长度与 rlen 严格一致, 且 list 是一个已初始化的链表头
int dns_add_raw_record(const char *name, uint16_t type, uint16_t rclass,
                       uint32_t ttl, uint16_t rlen, const void *rdata,
                       struct list_head *list) {
    struct __dns_record_entry *entry;
    size_t entry_size = sizeof(struct __dns_record_entry) + rlen;

    entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }

    entry->record.name = strdup(name); // 为域名创建独立副本
    if (!entry->record.name) {
        free(entry);
        return -1;
    }

    entry->record.type = type; // 记录类型
    entry->record.rclass = rclass; // 记录类别
    entry->record.ttl = ttl;
    entry->record.rdlength = rlen; // 数据长度
    entry->record.rdata = (void *)(entry + 1);
    memcpy(entry->record.rdata, rdata, rlen); // 将外部传入的记录数据(如IPv4地址、域名等)复制到预先分配好的 rdata区域
    list_add_tail(&entry->entry_list, list);

    return 0;
}

// 向DNS记录链表中添加原始资源记录. string接口
int dns_add_str_record(const char *name, uint16_t type, uint16_t rclass,
                       uint32_t ttl, const char *rdata,
                       struct list_head *list) {
    size_t rlen = strlen(rdata);
    // record.rdlength has no meaning for parsed record types, ignore its
    // correctness, same for soa/srv/mx record
    // record.rdlength对于已解析的记录类型没有意义，忽略其正确性
    return dns_add_raw_record(name, type, rclass, ttl, rlen + 1, rdata, list);
}

// 构建一个SOA记录对象, 并将其添加到指定的DNS记录链表中
int dns_add_soa_record(const char *name, uint16_t rclass, uint32_t ttl, const char *mname,
                       const char *rname, uint32_t serial, int32_t refresh,
                       int32_t retry, int32_t expire, uint32_t minimum, struct list_head *list) {
    struct __dns_record_entry *entry;
    struct dns_record_soa *soa;
    size_t entry_size;
    char *pname, *pmname, *prname;

    entry_size = sizeof(struct __dns_record_entry) + sizeof(struct dns_record_soa);

    entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }

    entry->record.rdata = (void *)(entry + 1);
    entry->record.rdlength = 0; // 可能意味着这个函数创建的记录主要用于内部表示或缓存, 而非直接用于网络报文序列化. 如果需要用于网络传输, 则需要正确计算并设置此长度
    soa = (struct dns_record_soa *)(entry->record.rdata);

    pname = strdup(name);
    pmname = strdup(mname);
    prname = strdup(rname);

    if (!pname || !pmname || !prname) {
        free(pname);
        free(pmname);
        free(prname);
        free(entry);
        return -1;
    }

    soa->mname = pmname;
    soa->rname = prname;
    soa->serial = serial; // 序列号
    soa->refresh = refresh; // 刷新间隔
    soa->retry = retry;
    soa->expire = expire;
    soa->minimum = minimum;

    entry->record.name = pname;
    entry->record.type = DNS_TYPE_SOA; // 设置记录的类型
    entry->record.rclass = rclass;
    entry->record.ttl = ttl;
    list_add_tail(&entry->entry_list, list);

    return 0;
}

// 构建一个 DNS SRV记录(服务定位记录), 并将其添加到指定的链表中
int dns_add_srv_record(const char *name, uint16_t rclass, uint32_t ttl, uint16_t priority,
                       uint16_t weight, uint16_t port, const char *target, struct list_head *list) {
    size_t entry_size = sizeof(struct __dns_record_entry) + sizeof(struct dns_record_srv);
    struct __dns_record_entry *entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }

    entry->record.rdata = (void *)(entry + 1);
    entry->record.rdlength = 0;
    struct dns_record_srv *srv = (struct dns_record_srv *)(entry->record.rdata);

    char *pname, *ptarget;
    pname = strdup(name);
    ptarget = strdup(target);

    if (!pname || !ptarget) {
        free(pname);
        free(ptarget);
        free(entry);
        return -1;
    }

    srv->priority = priority;
    srv->weight = weight;
    srv->port = port;
    srv->target = ptarget;

    entry->record.name = pname;
    entry->record.type = DNS_TYPE_SRV; // 标记记录类型为SRV
    entry->record.rclass = rclass;
    entry->record.ttl = ttl;
    list_add_tail(&entry->entry_list, list);

    return 0;
}

// 创建并添加DNS MX记录(邮件交换记录)
int dns_add_mx_record(const char *name, uint16_t rclass, uint32_t ttl, int16_t preference,
                      const char *exchange, struct list_head *list) {
    size_t entry_size = sizeof(struct __dns_record_entry) + sizeof(struct dns_record_mx);

    struct __dns_record_entry *entry = (struct __dns_record_entry *)malloc(entry_size);
    if (!entry) { return -1; }

    entry->record.rdata = (void *)(entry + 1);
    entry->record.rdlength = 0;
    struct dns_record_mx *mx = (struct dns_record_mx *)(entry->record.rdata);

    char *pname, *pexchange;
    pname = strdup(name);
    pexchange = strdup(exchange);

    if (!pname || !pexchange) {
        free(pname);
        free(pexchange);
        free(entry);
        return -1;
    }

    mx->preference = preference;
    mx->exchange = pexchange;

    entry->record.name = pname;
    entry->record.type = DNS_TYPE_MX;
    entry->record.rclass = rclass;
    entry->record.ttl = ttl;
    list_add_tail(&entry->entry_list, list);

    return 0;
}

// DNS记录类型转换
const char *dns_type2str(int type) {
    switch (type) {
    case DNS_TYPE_A: return "A";
    case DNS_TYPE_NS: return "NS";
    case DNS_TYPE_MD: return "MD";
    case DNS_TYPE_MF: return "MF";
    case DNS_TYPE_CNAME: return "CNAME";
    case DNS_TYPE_SOA: return "SOA";
    case DNS_TYPE_MB: return "MB";
    case DNS_TYPE_MG: return "MG";
    case DNS_TYPE_MR: return "MR";
    case DNS_TYPE_NULL: return "NULL";
    case DNS_TYPE_WKS: return "WKS";
    case DNS_TYPE_PTR: return "PTR";
    case DNS_TYPE_HINFO: return "HINFO";
    case DNS_TYPE_MINFO: return "MINFO";
    case DNS_TYPE_MX: return "MX";
    case DNS_TYPE_AAAA: return "AAAA";
    case DNS_TYPE_SRV: return "SRV";
    case DNS_TYPE_TXT: return "TXT";
    case DNS_TYPE_AXFR: return "AXFR";
    case DNS_TYPE_MAILB: return "MAILB";
    case DNS_TYPE_MAILA: return "MAILA";
    case DNS_TYPE_ALL: return "ALL";
    default: return "Unknown";
    }
}

const char *dns_class2str(int dnsclass) {
    switch (dnsclass) {
    case DNS_CLASS_IN: return "IN";
    case DNS_CLASS_CS: return "CS";
    case DNS_CLASS_CH: return "CH";
    case DNS_CLASS_HS: return "HS";
    case DNS_CLASS_ALL: return "ALL";
    default: return "Unknown";
    }
}

const char *dns_opcode2str(int opcode) {
    switch (opcode) {
    case DNS_OPCODE_QUERY: return "QUERY";
    case DNS_OPCODE_IQUERY: return "IQUERY";
    case DNS_OPCODE_STATUS: return "STATUS";
    default: return "Unknown";
    }
}

const char *dns_rcode2str(int rcode) {
    switch (rcode) {
    case DNS_RCODE_NO_ERROR: return "NO_ERROR";
    case DNS_RCODE_FORMAT_ERROR: return "FORMAT_ERROR";
    case DNS_RCODE_SERVER_FAILURE: return "SERVER_FAILURE";
    case DNS_RCODE_NAME_ERROR: return "NAME_ERROR";
    case DNS_RCODE_NOT_IMPLEMENTED: return "NOT_IMPLEMENTED";
    case DNS_RCODE_REFUSED: return "REFUSED";
    default: return "Unknown";
    }
}