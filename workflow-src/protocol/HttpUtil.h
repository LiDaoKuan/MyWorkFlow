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

#ifndef MYWORKFLOW_HTTPUTIL_H
#define MYWORKFLOW_HTTPUTIL_H

#include <string>
#include <vector>
#include <unordered_map>
#include "http_parser.h"
#include "HttpMessage.h"

#define HttpMethodGet		"GET"
#define HttpMethodHead		"HEAD"
#define HttpMethodPost		"POST"
#define HttpMethodPut		"PUT"
#define HttpMethodPatch		"PATCH"
#define HttpMethodDelete	"DELETE"
#define HttpMethodConnect	"CONNECT"
#define HttpMethodOptions	"OPTIONS"
#define HttpMethodTrace		"TRACE"

// clang-format off
enum {
    HttpStatusContinue           = 100, // RFC 7231, 6.2.1      继续
	HttpStatusSwitchingProtocols = 101, // RFC 7231, 6.2.2      切换协议
	HttpStatusProcessing         = 102, // RFC 2518, 10.1       处理中

	HttpStatusOK                   = 200, // RFC 7231, 6.3.1    成功
	HttpStatusCreated              = 201, // RFC 7231, 6.3.2    已创建
	HttpStatusAccepted             = 202, // RFC 7231, 6.3.3
	HttpStatusNonAuthoritativeInfo = 203, // RFC 7231, 6.3.4
	HttpStatusNoContent            = 204, // RFC 7231, 6.3.5    无内容
	HttpStatusResetContent         = 205, // RFC 7231, 6.3.6
	HttpStatusPartialContent       = 206, // RFC 7233, 4.1      部分内容
	HttpStatusMultiStatus          = 207, // RFC 4918, 11.1
	HttpStatusAlreadyReported      = 208, // RFC 5842, 7.1
	HttpStatusIMUsed               = 226, // RFC 3229, 10.4.1

	HttpStatusMultipleChoices       = 300, // RFC 7231, 6.4.1
	HttpStatusMovedPermanently      = 301, // RFC 7231, 6.4.2   永久移动
	HttpStatusFound                 = 302, // RFC 7231, 6.4.3   临时移动
	HttpStatusSeeOther              = 303, // RFC 7231, 6.4.4
	HttpStatusNotModified           = 304, // RFC 7232, 4.1     未修改
	HttpStatusUseProxy              = 305, // RFC 7231, 6.4.5
    HttpStatusSwitchProxy           = 306,
	HttpStatusTemporaryRedirect     = 307, // RFC 7231, 6.4.7
	HttpStatusPermanentRedirect     = 308, // RFC 7538, 3       永久重定向

	HttpStatusBadRequest                   = 400, // RFC 7231, 6.5.1        错误请求
	HttpStatusUnauthorized                 = 401, // RFC 7235, 3.1          未授权
	HttpStatusPaymentRequired              = 402, // RFC 7231, 6.5.2
	HttpStatusForbidden                    = 403, // RFC 7231, 6.5.3        禁止访问
	HttpStatusNotFound                     = 404, // RFC 7231, 6.5.4        未找到
	HttpStatusMethodNotAllowed             = 405, // RFC 7231, 6.5.5
	HttpStatusNotAcceptable                = 406, // RFC 7231, 6.5.6
	HttpStatusProxyAuthRequired            = 407, // RFC 7235, 3.2
	HttpStatusRequestTimeout               = 408, // RFC 7231, 6.5.7
	HttpStatusConflict                     = 409, // RFC 7231, 6.5.8
	HttpStatusGone                         = 410, // RFC 7231, 6.5.9
	HttpStatusLengthRequired               = 411, // RFC 7231, 6.5.10
	HttpStatusPreconditionFailed           = 412, // RFC 7232, 4.2
	HttpStatusRequestEntityTooLarge        = 413, // RFC 7231, 6.5.11
	HttpStatusRequestURITooLong            = 414, // RFC 7231, 6.5.12
	HttpStatusUnsupportedMediaType         = 415, // RFC 7231, 6.5.13
	HttpStatusRequestedRangeNotSatisfiable = 416, // RFC 7233, 4.4
	HttpStatusExpectationFailed            = 417, // RFC 7231, 6.5.14
	HttpStatusTeapot                       = 418, // RFC 7168, 2.3.3
	HttpStatusEnhanceYourCaim              = 420, // Twitter Search
	HttpStatusMisdirectedRequest           = 421, // RFC 7540, 9.1.2
	HttpStatusUnprocessableEntity          = 422, // RFC 4918, 11.2
	HttpStatusLocked                       = 423, // RFC 4918, 11.3
	HttpStatusFailedDependency             = 424, // RFC 4918, 11.4
	HttpStatusTooEarly                     = 425, // RFC 8470, 5.2.
	HttpStatusUpgradeRequired              = 426, // RFC 7231, 6.5.15
	HttpStatusPreconditionRequired         = 428, // RFC 6585, 3
	HttpStatusTooManyRequests              = 429, // RFC 6585, 4            请求过多
	HttpStatusRequestHeaderFieldsTooLarge  = 431, // RFC 6585, 5
	HttpStatusNoResponse                   = 444, // Nginx
	HttpStatusBlocked                      = 450, // Windows
	HttpStatusUnavailableForLegalReasons   = 451, // RFC 7725, 3
	HttpStatusTooLargeForNginx             = 494, // Nginx

	HttpStatusInternalServerError           = 500, // RFC 7231, 6.6.1       服务器内部错误
	HttpStatusNotImplemented                = 501, // RFC 7231, 6.6.2       网关错误
	HttpStatusBadGateway                    = 502, // RFC 7231, 6.6.3       服务不可用
	HttpStatusServiceUnavailable            = 503, // RFC 7231, 6.6.4
	HttpStatusGatewayTimeout                = 504, // RFC 7231, 6.6.5       网关超时
	HttpStatusHTTPVersionNotSupported       = 505, // RFC 7231, 6.6.6
	HttpStatusVariantAlsoNegotiates         = 506, // RFC 2295, 8.1
	HttpStatusInsufficientStorage           = 507, // RFC 4918, 11.5
	HttpStatusLoopDetected                  = 508, // RFC 5842, 7.2
	HttpStatusNotExtended                   = 510, // RFC 2774, 7
	HttpStatusNetworkAuthenticationRequired = 511, // RFC 6585, 6
};
// clang-format on

namespace protocol {
    // HTTP 协议处理工具类
    class HttpUtil {
    public:
        static void set_response_status(HttpResponse *resp, int status_code);
        // 将HTTP分块传输编码的正文解码成连续的字节流
        static std::string decode_chunked_body(const HttpMessage *msg);
    };

    // 管理 HTTP 头部信息
    class HttpHeaderMap {
    public:
        explicit HttpHeaderMap(const HttpMessage *message);

        bool key_exists(std::string key);
        std::string get(std::string key);
        bool get(std::string key, std::string &value);
        // 专门用于处理 HTTP 协议中允许一个字段名对应多个值的情况
        std::vector<std::string> get_strict(std::string key);
        bool get_strict(std::string key, std::vector<std::string> &values);

    private:
        std::unordered_map<std::string, std::vector<std::string>> header_map;
    };

    // 遍历和操作 HTTP 消息头部的类
    class HttpHeaderCursor {
    public:
        explicit HttpHeaderCursor(const HttpMessage *message);
        virtual ~HttpHeaderCursor();

    public:
        bool next(HttpMessageHeader *header);
        bool find(HttpMessageHeader *header);
        bool erase();
        bool find_and_erase(HttpMessageHeader *header);
        void rewind();

        /* std::string interface */
    public:
        bool next(std::string &name, std::string &value);
        bool find(const std::string &name, std::string &value);
        bool find_and_erase(const std::string &name);

    protected:
        http_header_cursor_t cursor{nullptr, nullptr};
    };

    // 用于遍历HTTP分块传输编码(chunked transfer encoding)消息体
    class HttpChunkCursor {
    public:
        explicit HttpChunkCursor(const HttpMessage *message);
        virtual ~HttpChunkCursor() = default;

    public:
        // 获取下一个数据块
        bool next(const void **chunk, size_t *size);
        void rewind();

    protected:
        const void *body; // 指向整个HTTP消息体的起始位置
        size_t body_len{0}; // 消息体的总长度（如果已知且未使用分块编码）
        const void *pos; // 游标当前位置, 指向下一个待解析或读取的数据块起始处
        bool chunked; // 标志位, 指示消息体是否采用分块传输编码
        bool end; // 标志位，指示游标是否已到达消息体的末尾
    };

    inline HttpHeaderCursor::HttpHeaderCursor(const HttpMessage *message) {
        http_header_cursor_init(&this->cursor, message->get_parser());
    }

    inline HttpHeaderCursor::~HttpHeaderCursor() {
        http_header_cursor_deinit(&this->cursor);
    }

    inline bool HttpHeaderCursor::next(HttpMessageHeader *header) {
        return http_header_cursor_next(&header->name, &header->name_len, &header->value,
                                       &header->value_len, &this->cursor) == 0;
    }

    inline bool HttpHeaderCursor::find(HttpMessageHeader *header) {
        return http_header_cursor_find(header->name, header->name_len, &header->value,
                                       &header->value_len, &this->cursor) == 0;
    }

    inline bool HttpHeaderCursor::erase() {
        return http_header_cursor_erase(&this->cursor) == 0;
    }

    inline bool HttpHeaderCursor::find_and_erase(HttpMessageHeader *header) {
        if (this->find(header)) { return this->erase(); }
        return false;
    }

    inline void HttpHeaderCursor::rewind() {
        http_header_cursor_rewind(&this->cursor);
    }
}

#endif //MYWORKFLOW_HTTPUTIL_H