//
// Created by ldk on 10/31/25.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string>
#include "dns_types.h"
#include "DnsUtil.h"

namespace protocol {
    // 将原始的DNS协议响应数据(DnsResponse)转换为标准的 addrinfo 结构链表
    int DnsUtil::getaddrinfo(const DnsResponse *resp, unsigned short port, addrinfo **addrinfo) {
        int ancount = resp->get_ancount(); // DNS回答记录数
        int rcode = resp->get_rcode(); // DNS响应码
        int status = 0;
        struct addrinfo *res = nullptr; // 结果链表头指针
        struct addrinfo **pres = &res; // 指向当前链表末尾的指针
        dns_record *record;
        struct addrinfo *addr_info;
        std::string qname;
        const char *cname;
        int family;
        int addrlen;

        // 检查DNS响应头中的RCODE，并将其转换为标准的EAI_*错误码
        switch (rcode) {
        case DNS_RCODE_NAME_ERROR: status = EAI_NONAME; // 域名不存在
            break;
        case DNS_RCODE_SERVER_FAILURE: status = EAI_AGAIN; // 服务器临时故障
            break;
        case DNS_RCODE_FORMAT_ERROR:
        case DNS_RCODE_NOT_IMPLEMENTED:
        case DNS_RCODE_REFUSED: status = EAI_FAIL; // 其他不可恢复的错误
            break;
        default: ;
        }

        qname = resp->get_question_name(); // 获取查询的域名
        cname = qname.c_str();

        DnsResultCursor cursor(resp);
        cursor.reset_answer_cursor();
        /* Forbid loop in cname chain */
        while (cursor.find_cname(cname, &cname) && ancount-- > 0) {}

        // 如果响应码rcode为成功且没有回答记录
        if (rcode == DNS_RCODE_NO_ERROR && ancount <= 0) { status = EAI_NODATA; }
        if (status != 0) { return status; }

        // 重置游标
        cursor.reset_answer_cursor();
        while (cursor.next(&record)) {
            if (!(record->rclass == DNS_CLASS_IN // 必须是Internet类记录
                  && (record->type == DNS_TYPE_A || record->type == DNS_TYPE_AAAA) // 必须是A和AAAA记录
                  && strcasecmp(record->name, cname) == 0)) // 记录名必须与目标名匹配
            {
                continue;
            }

            if (record->type == DNS_TYPE_A) {
                // ipv4记录处理
                family = AF_INET;
                addrlen = sizeof(sockaddr_in);
            } else {
                // ipv6记录处理
                family = AF_INET6;
                addrlen = sizeof(sockaddr_in6);
            }
            // 将addrinfo结构体和其后的套接字地址结构（sockaddr_in或sockaddr_in6）分配在连续的内存块中，简化了内存管理
            addr_info = static_cast<struct addrinfo *>(calloc(sizeof(struct addrinfo) + addrlen, 1));
            if (addr_info == nullptr) {
                if (res) {
                    DnsUtil::freeaddrinfo(res);
                }
                return EAI_MEMORY;
            }

            addr_info->ai_family = family;
            addr_info->ai_addrlen = addrlen;
            addr_info->ai_addr = reinterpret_cast<sockaddr *>(addr_info + 1); // ai_addr指向addr_info后面的 sockaddr_in或sockaddr_in6 部分
            addr_info->ai_addr->sa_family = family;

            if (family == AF_INET) {
                // ipv4协议
                auto *in = reinterpret_cast<struct sockaddr_in *>(addr_info->ai_addr);
                in->sin_port = htons(port);
                memcpy(&in->sin_addr, record->rdata, sizeof(in_addr));
            } else {
                // ipv6协议
                auto *in = reinterpret_cast<struct sockaddr_in6 *>(addr_info->ai_addr);
                in->sin6_port = htons(port);
                memcpy(&in->sin6_addr, record->rdata, sizeof(in6_addr));
            }

            *pres = addr_info; // 将 pres 当前所指向的那个“位置”的值, 设置为新节点 addr_info 的地址
            pres = &addr_info->ai_next; // 将指针 pres 移动到新刚刚添加到链表末尾的这个节点（addr_info）的 ai_next字段的地址上
        }

        // 如果res为nullptr，那么说明while循环没找到符合条件的ip地址记录。因为pres最初指向res，res会随着*pres的第一次改变而改变
        if (res == nullptr) { return EAI_NODATA; }

        // cname可能为空，比如: 在DNS查询过程中没有发生CNAME重定向, 或者某些错误情况下
        if (cname) {
            res->ai_canonname = strdup(cname); // 设置返回的地址信息的规范主机名
        }

        *addrinfo = res; // 通过传入的指针参数返回结果

        return 0;
    }

    // 释放addrinfo链表
    void DnsUtil::freeaddrinfo(addrinfo *ai) {
        addrinfo *p;

        while (ai != nullptr) {
            p = ai;
            ai = ai->ai_next;
            free(p->ai_canonname);
            free(p);
        }
    }
}