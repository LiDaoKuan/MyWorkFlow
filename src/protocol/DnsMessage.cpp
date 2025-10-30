//
// Created by ldk on 10/28/25.
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

#include <arpa/inet.h>
#include <cerrno>
#include "dns_types.h"
#include "dns_parser.h"
#include "DnsMessage.h"

#define DNS_LABELS_MAX				63
#define DNS_MESSAGE_MAX_UDP_SIZE	512

namespace protocol {
    // 将 uint8_t 类型的数据以二进制形式追加到 std::string 中
    static inline void _append_uint8(std::string &s, uint8_t tmp) {
        // 将tmp转换为C风格字符串(取地址后转为const char*), 然后插入
        s.append(reinterpret_cast<const char *>(&tmp), sizeof(uint8_t));
    }

    // 将 uint16_t 类型的数据以二进制形式追加到 std::string 中
    static inline void _append_uint16(std::string &s, uint16_t tmp) {
        tmp = htons(tmp); // 将主机字节序的16位整数转换为网络字节序
        s.append(reinterpret_cast<const char *>(&tmp), sizeof(uint16_t));
    }

    // 将 uint32_t 类型的数据以二进制形式追加到 std::string 中
    static inline void _append_uint32(std::string &s, uint32_t tmp) {
        tmp = htonl(tmp); // 将主机字节序的32位整数转换为网络字节序
        s.append(reinterpret_cast<const char *>(&tmp), sizeof(uint32_t));
    }

    // 将点分格式的域名(如 "www.example.com")编码为DNS协议标准格式
    static inline int _append_name(std::string &s, const char *p) {
        const char *name;
        size_t len;

        while (*p) {
            name = p; // 记录当前标签的起始位置
            while (*p && *p != '.') { p++; } // 找到当前标签的结尾（点号或字符串结尾）

            len = p - name; // 计算当前标签的长度
            // len > DNS_LABELS_MAX: 确保每个标签的长度不超过DNS协议规定的63字节上限(DNS_LABELS_MAX通常定义为63)
            // len == 0 && *p && *(p + 1): 此条件用于检测连续两个点号(如 "example..com")形成的空标签, 在DNS编码中, 空标签是非法的（根域名的空标签由最后的零字节单独表示）
            if (len > DNS_LABELS_MAX || (len == 0 && *p && *(p + 1))) {
                errno = EINVAL;
                return -1;
            }

            if (len > 0) {
                _append_uint8(s, len); // 先写入1字节的长度前缀
                s.append(name, len); // 再写入标签的实际内容
            }

            if (*p == '.') { p++; } // 后移, 方便寻找下一个"."
        }

        len = 0;
        _append_uint8(s, len); // 写入一个长度为0的字节

        return 0;
    }

    // DNS记录序列化
    static inline int _append_record_list(std::string &s, int *count, dns_record_cursor_t *cursor) {
        int cnt = 0;
        dns_record *record;
        std::string record_buf; //
        std::string rdata_buf;
        int ret;

        // 遍历记录集合
        while (dns_record_cursor_next(&record, cursor) == 0) {
            record_buf.clear();
            // 序列化所有记录类型共有的部分(即DNS资源记录的头部)
            ret = _append_name(record_buf, record->name); // 将记录名（如 "example.com"）转换为DNS协议特殊的标签序列格式
            if (ret < 0) { return ret; }

            _append_uint16(record_buf, record->type); // 类型
            _append_uint16(record_buf, record->rclass); // 类
            _append_uint32(record_buf, record->ttl); // TTL

            // 按记录类型分治处理rdata
            switch (record->type) {
            default: // encode unknown types as raw record
            case DNS_TYPE_A:
            case DNS_TYPE_AAAA:
                // A记录、AAAA记录及未知类型:
                // 这些记录的 rdata 是固定长度的二进制数据(如IPv4地址为4字节), 函数直接写入长度和原始数据
                _append_uint16(record_buf, record->rdlength); // 写入长度
                record_buf.append(static_cast<const char *>(record->rdata), record->rdlength); // 写入原始数据
                break;
            case DNS_TYPE_NS:
            case DNS_TYPE_CNAME:
            case DNS_TYPE_PTR:
                // NS、CNAME、PTR记录:
                // 这些记录的 rdata 是一个域名. 函数需要递归调用 _append_name 将这个域名(如权威服务器名、别名或指针目标)进行编码, 然后写入编码后域名的长度和内容
                rdata_buf.clear();
                ret = _append_name(rdata_buf, static_cast<const char *>(record->rdata));
                if (ret < 0) { return ret; }

                _append_uint16(record_buf, rdata_buf.size());
                record_buf.append(rdata_buf);
                break;
            case DNS_TYPE_SOA:
                // SOA记录:
                // 包含两个域名（主服务器mname和管理员邮箱rname）和五个时间参数（序列号、刷新间隔等）。函数按固定顺序依次序列化这些字段
            {
                auto *soa = static_cast<struct dns_record_soa *>(record->rdata);
                rdata_buf.clear();
                ret = _append_name(rdata_buf, soa->mname);
                if (ret < 0) { return ret; }
                ret = _append_name(rdata_buf, soa->rname);
                if (ret < 0) { return ret; }

                _append_uint32(rdata_buf, soa->serial);
                _append_uint32(rdata_buf, soa->refresh);
                _append_uint32(rdata_buf, soa->retry);
                _append_uint32(rdata_buf, soa->expire);
                _append_uint32(rdata_buf, soa->minimum);

                _append_uint16(record_buf, rdata_buf.size()); // 先写入总长度
                record_buf.append(rdata_buf); // 再写入全部数据
                break;
            }

            case DNS_TYPE_SRV:
                // SRV记录
                // 包含优先级、权重、端口和一个目标域名。同样需要先序列化数值字段，再序列化目标域名
            {
                auto *srv = static_cast<struct dns_record_srv *>(record->rdata);

                rdata_buf.clear();
                _append_uint16(rdata_buf, srv->priority);
                _append_uint16(rdata_buf, srv->weight);
                _append_uint16(rdata_buf, srv->port);
                ret = _append_name(rdata_buf, srv->target);
                if (ret < 0) { return ret; }

                _append_uint16(record_buf, rdata_buf.size());
                record_buf.append(rdata_buf);
                break;
            }

            case DNS_TYPE_MX:
                // 处理方式与SRV记录类似
            {
                auto *mx = static_cast<struct dns_record_mx *>(record->rdata);

                rdata_buf.clear();
                _append_uint16(rdata_buf, mx->preference);
                ret = _append_name(rdata_buf, mx->exchange);
                if (ret < 0) { return ret; }

                _append_uint16(record_buf, rdata_buf.size());
                record_buf.append(rdata_buf);
                break;
            }
            }

            cnt++; // 计数器 cnt 增1
            s.append(record_buf);
        }

        if (count) { *count = cnt; } // 告诉调用者成功处理的记录总数

        return 0;
    }

    DnsMessage::DnsMessage(DnsMessage &&msg) noexcept : ProtocolMessage(std::move(msg)) {
        this->parser = msg.parser;
        msg.parser = nullptr;

        this->cur_size = msg.cur_size;
        msg.cur_size = 0;
    }

    DnsMessage &DnsMessage::operator =(DnsMessage &&msg) noexcept {
        if (&msg != this) {
            *static_cast<ProtocolMessage *>(this) = static_cast<ProtocolMessage>(std::move(msg));

            if (this->parser) {
                dns_parser_deinit(this->parser);
                delete this->parser;
            }

            this->parser = msg.parser;
            msg.parser = nullptr;

            this->cur_size = msg.cur_size;
            msg.cur_size = 0;
        }
        return *this;
    }

    inline list_head *DnsMessage::get_section(int section) const {
        switch (section) {
        case DNS_ANSWER_SECTION: return &parser->answer_list;
        case DNS_AUTHORITY_SECTION: return &parser->authority_list;
        case DNS_ADDITIONAL_SECTION: return &parser->additional_list;
        default:
            errno = EINVAL;
            return nullptr;
        }
    }

    int DnsMessage::add_a_record(int section, const char *name,
                                 uint16_t rclass, uint32_t ttl,
                                 const void *data) {
        list_head *list = get_section(section);

        if (!list) { return -1; }

        return dns_add_raw_record(name, DNS_TYPE_A, rclass, ttl, 4, data, list);
    }

    int DnsMessage::add_aaaa_record(int section, const char *name,
                                    uint16_t rclass, uint32_t ttl,
                                    const void *data) {
        list_head *list = get_section(section);

        if (!list) { return -1; }

        return dns_add_raw_record(name, DNS_TYPE_AAAA, rclass, ttl, 16, data, list);
    }

    int DnsMessage::add_ns_record(int section, const char *name,
                                  uint16_t rclass, uint32_t ttl,
                                  const char *data) {
        list_head *list = get_section(section);

        if (!list) { return -1; }

        return dns_add_str_record(name, DNS_TYPE_NS, rclass, ttl, data, list);
    }

    int DnsMessage::add_cname_record(int section, const char *name,
                                     uint16_t rclass, uint32_t ttl,
                                     const char *data) {
        list_head *list = get_section(section);

        if (!list) { return -1; }

        return dns_add_str_record(name, DNS_TYPE_CNAME, rclass, ttl, data, list);
    }

    int DnsMessage::add_ptr_record(int section, const char *name, uint16_t rclass,
                                   uint32_t ttl, const char *data) {
        list_head *list = get_section(section);

        if (!list) { return -1; }

        return dns_add_str_record(name, DNS_TYPE_PTR, rclass, ttl, data, list);
    }

    int DnsMessage::add_soa_record(int section, const char *name, uint16_t rclass,
                                   uint32_t ttl, const char *mname, const char *rname,
                                   uint32_t serial, int32_t refresh, int32_t retry,
                                   int32_t expire, uint32_t minimum) {
        list_head *list = get_section(section);

        if (!list) { return -1; }

        return dns_add_soa_record(name, rclass, ttl, mname, rname, serial,
                                  refresh, retry, expire, minimum, list);
    }

    int DnsMessage::add_srv_record(int section, const char *name, uint16_t rclass,
                                   uint32_t ttl, uint16_t priority, uint16_t weight,
                                   uint16_t port, const char *target) {
        list_head *list = get_section(section);

        if (!list) { return -1; }

        return dns_add_srv_record(name, rclass, ttl, priority, weight, port, target, list);
    }

    int DnsMessage::add_mx_record(int section, const char *name, uint16_t rclass,
                                  uint32_t ttl, int16_t preference, const char *exchange) {
        list_head *list = get_section(section);

        if (!list) { return -1; }

        return dns_add_mx_record(name, rclass, ttl, preference, exchange, list);
    }

    int DnsMessage::add_raw_record(int section, const char *name, uint16_t type, uint16_t rclass,
                                   uint32_t ttl, const void *data, uint16_t dlen) {
        list_head *list = get_section(section);

        if (!list) { return -1; }

        return dns_add_raw_record(name, type, rclass, ttl, dlen, data, list);
    }

    int DnsMessage::encode_reply() {
        dns_record_cursor_t cursor;
        dns_header h{};
        std::string tmp_buf;
        const char *p;
        int ancount;
        int nscount;
        int arcount;
        int ret;

        msgbuf.clear();
        msgsize = 0;

        // TODO
        // this is an incomplete and inefficient way, compress not used,
        // pointers can only be used for occurrences of a domain name where
        // the format is not class specific
        dns_answer_cursor_init(&cursor, this->parser);
        ret = _append_record_list(tmp_buf, &ancount, &cursor);
        dns_record_cursor_deinit(&cursor);
        if (ret < 0) { return ret; }

        dns_authority_cursor_init(&cursor, this->parser);
        ret = _append_record_list(tmp_buf, &nscount, &cursor);
        dns_record_cursor_deinit(&cursor);
        if (ret < 0) { return ret; }

        dns_additional_cursor_init(&cursor, this->parser);
        ret = _append_record_list(tmp_buf, &arcount, &cursor);
        dns_record_cursor_deinit(&cursor);
        if (ret < 0) { return ret; }

        h = this->parser->header;
        h.id = htons(h.id);
        h.qdcount = htons(1);
        h.ancount = htons(ancount);
        h.nscount = htons(nscount);
        h.arcount = htons(arcount);

        msgbuf.append(reinterpret_cast<const char *>(&h), sizeof(struct dns_header));
        p = parser->question.qname ? parser->question.qname : ".";
        ret = _append_name(msgbuf, p);
        if (ret < 0) { return ret; }

        _append_uint16(msgbuf, parser->question.qtype);
        _append_uint16(msgbuf, parser->question.qclass);

        msgbuf.append(tmp_buf);

        if (msgbuf.size() >= (1 << 16)) {
            errno = EOVERFLOW;
            return -1;
        }

        msgsize = htons(msgbuf.size());

        return 0;
    }

    int DnsMessage::encode(struct iovec vectors[], int) {
        iovec *p = vectors;

        if (this->encode_reply() < 0) { return -1; }

        // TODO
        // if this is a request, it won't exceed the 512 bytes UDP limit
        // if this is a response and exceed 512 bytes, we need a TrunCation reply

        if (!this->is_single_packet()) {
            p->iov_base = &this->msgsize;
            p->iov_len = sizeof(uint16_t);
            p++;
        }

        p->iov_base = static_cast<void *>(this->msgbuf.data());
        p->iov_len = msgbuf.size();
        return p - vectors + 1;
    }

    int DnsMessage::append(const void *buf, size_t *size) {
        int ret = dns_parser_append_message(buf, size, this->parser);

        if (ret >= 0) {
            this->cur_size += *size;
            if (this->cur_size > this->size_limit) {
                errno = EMSGSIZE;
                ret = -1;
            }
        } else if (ret == -2) {
            errno = EBADMSG;
            ret = -1;
        }

        return ret;
    }

    int DnsResponse::append(const void *buf, size_t *size) {
        int ret = this->DnsMessage::append(buf, size);
        const char *qname = this->parser->question.qname;

        if (ret >= 1 && (this->request_id != this->get_id() || strcasecmp(this->request_name.c_str(), qname) != 0)) {
            if (!this->is_single_packet()) {
                errno = EBADMSG;
                ret = -1;
            } else {
                dns_parser_deinit(this->parser);
                dns_parser_init(this->parser);
                ret = 0;
            }
        }

        return ret;
    }
}