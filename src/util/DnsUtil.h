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

#ifndef MYWORKFLOW_DNSUTIL_H
#define MYWORKFLOW_DNSUTIL_H

#include <netdb.h>
#include "DnsMessage.h"

namespace protocol {
    // 工具类
    class DnsUtil {
    public:
        static int getaddrinfo(const DnsResponse *resp, unsigned short port, addrinfo **res);
        static void freeaddrinfo(addrinfo *ai);
    };

    // 迭代器类: 封装了对DNS响应中不同章节（回答、权威、附加）记录的遍历和查找操作
    class DnsResultCursor {
    public:
        explicit DnsResultCursor(const DnsResponse *resp) : parser(resp->get_parser()) {
            dns_answer_cursor_init(&cursor, parser);
            record = nullptr;
        }

        // 显式地删除了移动构造函数和移动赋值运算符.
        // 因为该类内部包含指向其他对象（parser）的指针.
        // 如果允许移动, 一个被移动后的 DnsResultCursor 对象可能会处于一种状态不明确的情况, 容易引发难以追踪的错误
        // 禁用移动操作是一种防御性编程措施, 确保了对象的完整性和可预测性
        DnsResultCursor(DnsResultCursor &&move) = delete;
        DnsResultCursor &operator=(DnsResultCursor &&move) = delete;

        virtual ~DnsResultCursor() = default;

        void reset_answer_cursor() {
            dns_answer_cursor_init(&cursor, parser);
        }

        void reset_authority_cursor() {
            dns_authority_cursor_init(&cursor, parser);
        }

        void reset_additional_cursor() {
            dns_additional_cursor_init(&cursor, parser);
        }

        /**
         * @param next_record 作为输出参数使用. 当函数成功获取到记录时, 会将当前记录的地址通过这个参数返回给调用者
         * @return true: 成功获取到下一个记录. false: 遍历结束或者出现错误
         */
        bool next(dns_record **next_record) {
            int ret = dns_record_cursor_next(&record, &cursor);
            if (ret != 0) {
                // 遍历完成或者出错
                record = nullptr;
            } else {
                *next_record = record;
            }

            return ret == 0;
        }

        bool find_cname(const char *name, const char **cname) {
            return dns_record_cursor_find_cname(name, cname, &cursor) == 0;
        }

    private:
        const dns_parser_t *parser; // 指向解析的上下文
        dns_record_cursor_t cursor{nullptr, nullptr}; // 遍历用的游标
        dns_record *record;
        // record成员会被设置为指向当前 cursor位置对应的那个 dns_record结构体的指针.
        // 当 next()方法被调用并返回 true 时, record就是有效的, 调用方可以通过它访问当前记录的具体内容（如域名、类型、IP地址等）
        // 当遍历结束或出错时，它会被设为 nullptr
    };
}

#endif //MYWORKFLOW_DNSUTIL_H