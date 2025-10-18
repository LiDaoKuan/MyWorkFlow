//
// Created by ldk on 10/16/25.
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

  Authors: Xie Han (xiehan@sogou-inc.com)
           Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

#include <string>
#include <vector>
#include <algorithm>
#include "http_parser.h"
#include "HttpMessage.h"
#include "HttpUtil.h"

namespace protocol {
    HttpHeaderMap::HttpHeaderMap(const HttpMessage *message) {
        http_header_cursor_t cursor;
        HttpMessageHeader header{};
        // 初始化临时游标cursor
        http_header_cursor_init(&cursor, message->get_parser());
        // 遍历
        while (http_header_cursor_next(&header.name, &header.name_len, &header.value,
                                       &header.value_len, &cursor) == 0) {
            // 根据指向名称的指针和长度信息，构造一个 std::string 对象 key
            std::string key(static_cast<const char *>(header.name), header.name_len);
            // 使用 std::transform 算法将 key 中的所有字符转换为小写
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            // 将每个头部字段的值存储在一个unordered_map中
            header_map[key].emplace_back(static_cast<const char *>(header.value), header.value_len);
        }
        // 销毁临时游标
        http_header_cursor_deinit(&cursor);
    }

    bool HttpHeaderMap::key_exists(std::string key) {
        // 先将key转化为纯小写
        std::ranges::transform(key, key.begin(), ::tolower);
        return header_map.contains(key);
    }

    std::string HttpHeaderMap::get(std::string key) {
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        const auto it = header_map.find(key);

        if (it == header_map.end() || it->second.empty()) { return {}; }

        return it->second[0];
    }

    // 获取key对应的value, 通过引用传参
    bool HttpHeaderMap::get(std::string key, std::string &value) {
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        const auto it = header_map.find(key);

        if (it == header_map.end() || it->second.empty()) { return false; }

        value = it->second[0];
        return true;
    }

    // 获取key对应的所有value
    std::vector<std::string> HttpHeaderMap::get_strict(std::string key) {
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        return header_map[key];
    }

    // 通过引用传参获取key对应的所有value
    bool HttpHeaderMap::get_strict(std::string key, std::vector<std::string> &values) {
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        const auto it = header_map.find(key);

        if (it == header_map.end() || it->second.empty()) { return false; }

        values = it->second;
        return true;
    }

    // 解码HTTP分块传输编码
    std::string HttpUtil::decode_chunked_body(const HttpMessage *msg) {
        const void *body;
        size_t body_len;
        const void *chunk;
        size_t chunk_size;
        std::string decode_result;
        HttpChunkCursor cursor(msg);

        // 获取已解析的原始消息体指针和长度
        if (msg->get_parsed_body(&body, &body_len)) {
            // 为最终的结果字符串 decode_result 预先分配了大约 body_len 大小的内存空间.
            // 这样做的好处是, 在后续连续追加多个数据块时, 可以避免频繁的动态内存重新分配和拷贝, 从而显著提升性能, 尤其是在处理大文件时
            decode_result.reserve(body_len);
            // 获取下一个数据块到chunk中, 如果获取到, 返回true
            while (cursor.next(&chunk, &chunk_size)) {
                decode_result.append(static_cast<const char *>(chunk), chunk_size);
            }
        }

        return decode_result;
    }

    // 设置HTTP响应状态码和对应原因短语
    void HttpUtil::set_response_status(HttpResponse *resp, int status_code) {
        char buf[32];
        sprintf(buf, "%d", status_code);
        resp->set_status_code(buf);

        switch (status_code) {
        case HttpStatusContinue: resp->set_reason_phrase("Continue");
            break;

        case HttpStatusSwitchingProtocols: resp->set_reason_phrase("Switching Protocols");
            break;

        case HttpStatusProcessing: resp->set_reason_phrase("Processing");
            break;

        case HttpStatusOK: resp->set_reason_phrase("OK");
            break;

        case HttpStatusCreated: resp->set_reason_phrase("Created");
            break;

        case HttpStatusAccepted: resp->set_reason_phrase("Accepted");
            break;

        case HttpStatusNonAuthoritativeInfo: resp->set_reason_phrase("Non-Authoritative Information");
            break;

        case HttpStatusNoContent: resp->set_reason_phrase("No Content");
            break;

        case HttpStatusResetContent: resp->set_reason_phrase("Reset Content");
            break;

        case HttpStatusPartialContent: resp->set_reason_phrase("Partial Content");
            break;

        case HttpStatusMultiStatus: resp->set_reason_phrase("Multi-Status");
            break;

        case HttpStatusAlreadyReported: resp->set_reason_phrase("Already Reported");
            break;

        case HttpStatusIMUsed: resp->set_reason_phrase("IM Used");
            break;

        case HttpStatusMultipleChoices: resp->set_reason_phrase("Multiple Choices");
            break;

        case HttpStatusMovedPermanently: resp->set_reason_phrase("Moved Permanently");
            break;

        case HttpStatusFound: resp->set_reason_phrase("Found");
            break;

        case HttpStatusSeeOther: resp->set_reason_phrase("See Other");
            break;

        case HttpStatusNotModified: resp->set_reason_phrase("Not Modified");
            break;

        case HttpStatusUseProxy: resp->set_reason_phrase("Use Proxy");
            break;

        case HttpStatusSwitchProxy: resp->set_reason_phrase("Switch Proxy");
            break;

        case HttpStatusTemporaryRedirect: resp->set_reason_phrase("Temporary Redirect");
            break;

        case HttpStatusPermanentRedirect: resp->set_reason_phrase("Permanent Redirect");
            break;

        case HttpStatusBadRequest: resp->set_reason_phrase("Bad Request");
            break;

        case HttpStatusUnauthorized: resp->set_reason_phrase("Unauthorized");
            break;

        case HttpStatusPaymentRequired: resp->set_reason_phrase("Payment Required");
            break;

        case HttpStatusForbidden: resp->set_reason_phrase("Forbidden");
            break;

        case HttpStatusNotFound: resp->set_reason_phrase("Not Found");
            break;

        case HttpStatusMethodNotAllowed: resp->set_reason_phrase("Method Not Allowed");
            break;

        case HttpStatusNotAcceptable: resp->set_reason_phrase("Not Acceptable");
            break;

        case HttpStatusProxyAuthRequired: resp->set_reason_phrase("Proxy Authentication Required");
            break;

        case HttpStatusRequestTimeout: resp->set_reason_phrase("Request Timeout");
            break;

        case HttpStatusConflict: resp->set_reason_phrase("Conflict");
            break;

        case HttpStatusGone: resp->set_reason_phrase("Gone");
            break;

        case HttpStatusLengthRequired: resp->set_reason_phrase("Length Required");
            break;

        case HttpStatusPreconditionFailed: resp->set_reason_phrase("Precondition Failed");
            break;

        case HttpStatusRequestEntityTooLarge: resp->set_reason_phrase("Request Entity Too Large");
            break;

        case HttpStatusRequestURITooLong: resp->set_reason_phrase("Request-URI Too Long");
            break;

        case HttpStatusUnsupportedMediaType: resp->set_reason_phrase("Unsupported Media Type");
            break;

        case HttpStatusRequestedRangeNotSatisfiable: resp->set_reason_phrase("Requested Range Not Satisfiable");
            break;

        case HttpStatusExpectationFailed: resp->set_reason_phrase("Expectation Failed");
            break;

        case HttpStatusTeapot: resp->set_reason_phrase("I'm a teapot");
            break;

        case HttpStatusEnhanceYourCaim: resp->set_reason_phrase("Enhance Your Caim");
            break;

        case HttpStatusMisdirectedRequest: resp->set_reason_phrase("Misdirected Request");
            break;

        case HttpStatusUnprocessableEntity: resp->set_reason_phrase("Unprocessable Entity");
            break;

        case HttpStatusLocked: resp->set_reason_phrase("Locked");
            break;

        case HttpStatusFailedDependency: resp->set_reason_phrase("Failed Dependency");
            break;

        case HttpStatusTooEarly: resp->set_reason_phrase("Too Early");
            break;

        case HttpStatusUpgradeRequired: resp->set_reason_phrase("Upgrade Required");
            break;

        case HttpStatusPreconditionRequired: resp->set_reason_phrase("Precondition Required");
            break;

        case HttpStatusTooManyRequests: resp->set_reason_phrase("Too Many Requests");
            break;

        case HttpStatusRequestHeaderFieldsTooLarge: resp->set_reason_phrase("Request Header Fields Too Large");
            break;

        case HttpStatusNoResponse: resp->set_reason_phrase("No Response");
            break;

        case HttpStatusBlocked: resp->set_reason_phrase("Blocked by Windows Parental Controls");
            break;

        case HttpStatusUnavailableForLegalReasons: resp->set_reason_phrase("Unavailable For Legal Reasons");
            break;

        case HttpStatusTooLargeForNginx: resp->set_reason_phrase("Request Header Too Large");
            break;

        case HttpStatusInternalServerError: resp->set_reason_phrase("Internal Server Error");
            break;

        case HttpStatusNotImplemented: resp->set_reason_phrase("Not Implemented");
            break;

        case HttpStatusBadGateway: resp->set_reason_phrase("Bad Gateway");
            break;

        case HttpStatusServiceUnavailable: resp->set_reason_phrase("Service Unavailable");
            break;

        case HttpStatusGatewayTimeout: resp->set_reason_phrase("Gateway Timeout");
            break;

        case HttpStatusHTTPVersionNotSupported: resp->set_reason_phrase("HTTP Version Not Supported");
            break;

        case HttpStatusVariantAlsoNegotiates: resp->set_reason_phrase("Variant Also Negotiates");
            break;

        case HttpStatusInsufficientStorage: resp->set_reason_phrase("Insufficient Storage");
            break;

        case HttpStatusLoopDetected: resp->set_reason_phrase("Loop Detected");
            break;

        case HttpStatusNotExtended: resp->set_reason_phrase("Not Extended");
            break;

        case HttpStatusNetworkAuthenticationRequired: resp->set_reason_phrase("Network Authentication Required");
            break;

        default: resp->set_reason_phrase("Unknown");
            break;
        }
    }

    // 用于遍历HTTP消息头部的(name, value)的迭代器方法, 通过引用传参获取结果
    bool HttpHeaderCursor::next(std::string &name, std::string &value) {
        HttpMessageHeader header{};

        if (this->next(&header)) {
            name.assign(static_cast<const char *>(header.name), header.name_len);
            value.assign(static_cast<const char *>(header.value), header.value_len);
            return true;
        }

        return false;
    }

    // 根据name查找value
    bool HttpHeaderCursor::find(const std::string &name, std::string &value) {
        HttpMessageHeader header = {
            .name = name.c_str(),
            .name_len = name.size(),
        };

        if (this->find(&header)) {
            value.assign(static_cast<const char *>(header.value), header.value_len);
            return true;
        }

        return false;
    }

    // 根据传入的name删除键值对
    bool HttpHeaderCursor::find_and_erase(const std::string &name) {
        HttpMessageHeader header = {
            .name = name.c_str(),
            .name_len = name.size(),
        };
        return this->find_and_erase(&header);
    }

    HttpChunkCursor::HttpChunkCursor(const HttpMessage *msg) {
        if (msg->get_parsed_body(&this->body, &this->body_len)) {
            this->pos = this->body;
            this->chunked = msg->is_chunked();
            this->end = false;
        } else {
            this->body = nullptr;
            this->end = true;
        }
    }

    bool HttpChunkCursor::next(const void **chunk, size_t *size) {
        if (this->end) { return false; }

        if (!this->chunked) {
            // 没有采用分块传输, 直接返回body, 并且置end为true
            *chunk = this->body;
            *size = this->body_len;
            this->end = true;
            return true;
        }

        const char *cur = static_cast<const char *>(this->pos);
        char *_end;

        // 读取块大小(十六进制字符串转为unsigned long)
        *size = strtoul(cur, &_end, 16);
        // 检查块大小
        if (*size == 0) {
            this->end = true;
            return false;
        }
        // 定位数据块起始位置并更新游标
        cur = strchr(_end, '\r');
        *chunk = cur + 2; // 跳过 \r\n, 指向数据
        cur += *size + 4; // 移动指针：跳过块大小后的\r\n, 以及当前块的数据, 和其后的 \r\n
        this->pos = cur; // 更新内部游标，指向下一个块的开头
        return true;
    }

    // 重置游标
    void HttpChunkCursor::rewind() {
        if (this->body) {
            this->pos = this->body;
            this->end = false;
        }
    }
}