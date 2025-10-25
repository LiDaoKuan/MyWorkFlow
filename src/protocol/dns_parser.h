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

#ifndef MYWORKFLOW_DNS_PARSER_H
#define MYWORKFLOW_DNS_PARSER_H

#include <sys/types.h>
#include <stdint.h>
#include "list.h"

/**
 * dns_header_t is a struct to describe the header of a dns
 * request or response packet, but the byte order is not
 * transformed.
 */
#pragma pack(1)
struct dns_header {
    uint16_t id; // 标识符: 一个随机生成的16位数字, 用于将DNS请求和其对应的响应关联起来
#if __BYTE_ORDER == __LITTLE_ENDIAN
    // __LITTLE_ENDIAN: 小段序平台, 字段从低位到高位(从右向左)定义.
    // 例如, rd : 1表示占用最低位的第0位. tc : 2表示占用最低位的第2位
    uint8_t rd : 1; // 期望递归: 1位标志. 由客户端设置, 若为1, 请求服务器进行递归查询
    uint8_t tc : 1; // 截断标志: 1位标志. 若为1, 表示报文因超长而被截断
    uint8_t aa : 1; // 权威回答: 1位标志, 仅在响应中有效. 若为1, 表示响应来自管理该域名的权威服务器
    uint8_t opcode : 4; // 操作码: 4位字段, 定义查询类型. 0代表标准查询, 1代表反向查询等
    uint8_t qr : 1; // 查询/响应: 1位标志. 0表示这是一个查询报文, 1表示这是一个响应报文

    uint8_t rcode : 4; // 响应码: 4位字段, 在响应中表示处理状态. 0表示成功, 3表示域名不存在等
    uint8_t z : 3;
    uint8_t ra : 1; // 递归可用: 1位标志, 在响应中设置. 若为1, 表示服务器支持递归查询
#elif __BYTE_ORDER == __BIG_ENDIAN
    // 大端序平台: 字段从高位到低位(从左向右)定义.
    // 例如, qr : 1表示占用最高位的第15位. opcode : 4表示占用最高位的第14～11位
    uint8_t qr : 1;
    uint8_t opcode : 4;
    uint8_t aa : 1;
    uint8_t tc : 1;
    uint8_t rd : 1;

    uint8_t ra : 1;
    uint8_t z : 3;
    uint8_t rcode : 4;
#else
# error "unknown byte order"
#endif
    uint16_t qdcount; // 问题数
    uint16_t ancount; // 回答数
    uint16_t nscount; // 授权记录数
    uint16_t arcount; // 附加记录数
};
#pragma pack()

struct dns_question {
    char *qname; // 指向查询的域名
    // 这是结构中最复杂的一个字段. 在网络上传输时, 域名并非我们日常看到的www.example.com这样的点分字符串, 而是遵循一套特定的标签化编码规则
    // 每个部分（如 www, example, com) 被称为一个"标签". 每个标签前会有一个字节表示该标签的长度, 最后以一个零字节表示域名结束
    // 以 www.example.com为例, 其编码后的十六进制形式大致为: 03 77 77 77 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00.
    // 这可以解读为: 长度3 + "www" + 长度7 + "example" + 长度3 + "com" + 结束符0

    uint16_t qtype; // 查询类型
    uint16_t qclass; // 查询类. 在当今的互联网环境中，几乎所有的DNS查询都属于 IN(Internet) 类, 其值为1. 其他类别如 CHAOS(3) 或 HESIOD(4) 已非常罕见或用于特定系统
};

// SOA(Start of Authority)记录是每个DNS区域的必备记录, 它定义了区域的全局参数和权威来源
struct dns_record_soa {
    char *mname; // 该区域主权威DNS服务器的域名. 辅助服务器会从这个服务器获取区域数据的更新
    char *rname; // 该区域的管理员的电子邮件地址. 注意, 这里的格式比较特殊, 邮箱中的@符号被替换为一个点"."。例如, admin.example.com实际表示admin@example.com
    uint32_t serial; // 区域的版本号. 每次区域数据发生变化时, 都必须递增这个号码. 辅助服务器通过比较序列号来判断是否需要从主服务器同步新数据(即区域传输)
    int32_t refresh; // 辅助服务器等待多久(秒)后, 向主服务器查询SOA记录, 检查序列号是否有更新
    int32_t retry; // 当辅助服务器尝试从主服务器获取更新失败后, 等待多久(秒)进行重试. 通常这个值比refresh小
    int32_t expire; // 如果辅助服务器在此时间段(秒)内一直无法与主服务器取得联系, 则会认为自身的区域数据已过期并停止提供该区域的权威解析服务
    uint32_t minimum; // 为此区域中所有资源记录设置的默认缓存时间(秒), 如果某条记录没有单独设置TTL, 则使用这个值. 它告诉递归服务器可以将查询结果缓存多久
};

// SRV记录用于定位支持特定服务的服务器, 它提供了比A记录或CNAME记录更丰富的服务发现信息
struct dns_record_srv {
    uint16_t priority; // 数值越小, 优先级越高(0-65535)
    uint16_t weight; // 当多个服务器的priority相同时, weight用于在这些服务器间进行负载均衡. 权重值越高, 被分配到的流量比例就越大. 如果不需要负载均衡, 可以设置为0
    uint16_t port; // 服务所在的TCP或UDP端口号(如HTTP通常是80, HTTPS是443)
    char *target; // 提供该服务的服务器的域名. 这个域名必须能够通过A记录或AAAA记录解析为IP地址
};

// MX记录专门用于电子邮件系统, 它告诉发送方的邮件服务器应该将邮件投递到哪台服务器
struct dns_record_mx {
    int16_t preference; // 数值越小优先级越高. 发送方会优先尝试将邮件发送到偏好值最小的邮件服务器. 如果失败, 则会尝试偏好值更大的备用服务器
    char *exchange; // 接收邮件的服务器域名. 请注意: 根据RFC规定, MX记录的exchange字段必须直接指向一个具有A记录或AAAA记录的主机名, 不能指向CNAME记录
};

// 用于存储 DNS 协议中资源记录. DNS 响应报文中的答案部分、授权部分和附加部分都使用这种格式来承载具体的解析结果
struct dns_record {
    char *name; // 指向查询的域名. 域名采用特殊的“标签序列”格式编码.
    uint16_t type; // 指定资源记录的类型, 表明 rdata 字段中数据的格式和用途.
    // 常用类型有：A记录(IPv4地址，值1)、CNAME记录(别名，值5)、MX记录(邮件交换，值15)、AAAA记录(IPv6地址，值28)
    uint16_t rclass; // 指定记录的协议族, 绝大多数情况下为 1，代表 IN (Internet), 即互联网地址
    uint32_t ttl; // 生存时间, 以秒为单位. 指示此记录在被查询后, 可以在缓存中保存多久. 过期后需要重新查询权威服务器以获取最新数据
    uint16_t rdlength; // 指明 rdata 字段数据的长度(字节数). 用于正确解析变长的 rdata内容
    void *rdata; // 指向与记录类型对应的具体数据. 这是一个“多态”指针, 其具体含义和结构完全由 type 字段决定
};

// 在整个DNS解析过程中负责维护从原始网络数据到结构化DNS信息的完整上下文
typedef struct dns_parser {
    void *msg_buf; // 指向原始报文数据缓冲区的起始位置. 如果DNS基于TCP协议(DNS over TLS（DoT）), 这个缓冲区开头可能包含2字节的报文长度前缀, 随后才是真正的DNS数据
    void *msg_base; // 指向纯粹DNS报文数据的起始位置. 对于TCP, msg_base通常是 msg_buf + 2, 跳过了长度前缀. 对于UDP, 则 msg_base 很可能等于 msg_buf
    const char *cur; // 指向当前解析位置
    size_t msg_size; // 已接收到的有效DNS报文数据的总长度
    size_t buf_size; // 表示 msg_buf 所指向的缓冲区的总容量. 它可能大于 msg_size, 为接收更多数据(如TCP分片传输时)预留空间
    char complete; // 一个布尔标志, 表示当前报文是否已完全解析
    char single_packet; // 指示此解析器是否用于处理UDP报文, DNS over UDP 通常在一个数据包内完成交互, 而DNS over TCP 可能需要处理分片. 此标志可能影响解析器对数据完整性的判断逻辑
    struct dns_header header; // 存储解析后的DNS报文头部信息, 包括事务ID、标志位(QR, OPCODE, AA, TC, RD, RA, RCODE等)以及各部分的记录数量(QDCOUNT, ANCOUNT等)
    struct dns_question question; // 存储查询问题部分的信息
    struct list_head answer_list; // 用于链接解析出的回答记录
    struct list_head authority_list; // 用于链接解析出的权威名称服务器记录
    struct list_head additional_list; // 用于链接解析出的附加信息记录
} dns_parser_t;

typedef struct __dns_record_cursor {
    const struct list_head *head;
    const struct list_head *next;
} dns_record_cursor_t;

#ifdef __cplusplus
extern "C" {
#endif

void dns_parser_init(dns_parser_t *parser);

void dns_parser_set_id(uint16_t id, dns_parser_t *parser);
int dns_parser_set_question(const char *name, uint16_t qtype,
                            uint16_t qclass, dns_parser_t *parser);
int dns_parser_set_question_name(const char *name, dns_parser_t *parser);

int dns_parser_parse_all(dns_parser_t *parser);
int dns_parser_append_message(const void *buf, size_t *n, dns_parser_t *parser);

void dns_parser_deinit(dns_parser_t *parser);

int dns_record_cursor_next(struct dns_record **record, dns_record_cursor_t *cursor);

int dns_record_cursor_find_cname(const char *name, const char **cname, dns_record_cursor_t *cursor);

int dns_add_raw_record(const char *name, uint16_t type, uint16_t rclass, uint32_t ttl,
                       uint16_t rlen, const void *rdata, struct list_head *list);

int dns_add_str_record(const char *name, uint16_t type, uint16_t rclass,
                       uint32_t ttl, const char *rdata, struct list_head *list);

int dns_add_soa_record(const char *name, uint16_t rclass, uint32_t ttl,
                       const char *mname, const char *rname,
                       uint32_t serial, int32_t refresh,
                       int32_t retry, int32_t expire, uint32_t minimum,
                       struct list_head *list);

int dns_add_srv_record(const char *name, uint16_t rclass, uint32_t ttl, uint16_t priority,
                       uint16_t weight, uint16_t port, const char *target, struct list_head *list);

int dns_add_mx_record(const char *name, uint16_t rclass, uint32_t ttl,
                      int16_t preference, const char *exchange, struct list_head *list);

const char *dns_type2str(int type);
const char *dns_class2str(int dnsclass);
const char *dns_opcode2str(int opcode);
const char *dns_rcode2str(int rcode);

#ifdef __cplusplus
}
#endif

static inline void dns_answer_cursor_init(dns_record_cursor_t *cursor, const dns_parser_t *parser) {
    cursor->head = &parser->answer_list;
    cursor->next = cursor->head;
}

static inline void dns_authority_cursor_init(dns_record_cursor_t *cursor, const dns_parser_t *parser) {
    cursor->head = &parser->authority_list;
    cursor->next = cursor->head;
}

static inline void dns_additional_cursor_init(dns_record_cursor_t *cursor, const dns_parser_t *parser) {
    cursor->head = &parser->additional_list;
    cursor->next = cursor->head;
}

// 空实现？？？
static inline void dns_record_cursor_deinit(dns_record_cursor_t *cursor) {}

#endif //MYWORKFLOW_DNS_PARSER_H