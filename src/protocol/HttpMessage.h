//
// Created by ldk on 10/14/25.
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

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef MYWORKFLOW_HTTPMESSAGE_H
#define MYWORKFLOW_HTTPMESSAGE_H

#include <cstdlib>
#include <cstring>
#include <utility>
#include <string>
#include "list.h"
#include "ProtocolMessage.h"
#include "http_parser.h"

namespace protocol {
    struct HttpMessageHeader {
        const void *name;
        size_t name_len;
        const void *value;
        size_t value_len;
    };

    class HttpMessage : public ProtocolMessage {
    public:
        explicit HttpMessage(bool is_resp) : parser(new http_parser_t) {
            http_parser_init(is_resp, this->parser);
            INIT_LIST_HEAD(&this->output_body);
            this->output_body_size = 0;
            this->cur_size = 0;
        }

        ~HttpMessage() override {
            this->clear_output_body();
            if (this->parser) {
                http_parser_deinit(this->parser);
                delete this->parser;
            }
        }

        HttpMessage(HttpMessage &&msg) noexcept;
        HttpMessage &operator=(HttpMessage &&msg) noexcept;

    public:
        [[nodiscard]] const char *get_http_version() const {
            return http_parser_get_version(this->parser);
        }

        bool set_http_version(const char *version) {
            return http_parser_set_version(version, this->parser) == 0;
        }

        // 是否使用分块传输编码
        [[nodiscard]] bool is_chunked() const {
            return http_parser_chunked(this->parser);
        }

        // 是否保持长连接
        [[nodiscard]] bool is_keep_alive() const {
            return http_parser_keep_alive(this->parser);
        }

        // 添加头部字段(允许同名字段共存)
        bool add_header(const HttpMessageHeader *header) {
            return http_parser_add_header(header->name, header->name_len, header->value, header->value_len, this->parser) == 0;
        }

        bool add_header_pair(const char *name, const char *value) {
            return http_parser_add_header(name, strlen(name), value, strlen(value), this->parser) == 0;
        }

        // 设置头部字段(如果同名字段已经存在, 则会覆盖旧值)
        bool set_header(const struct HttpMessageHeader *header) {
            return http_parser_set_header(header->name, header->name_len, header->value, header->value_len, this->parser) == 0;
        }

        bool set_header_pair(const char *name, const char *value) {
            return http_parser_set_header(name, strlen(name), value, strlen(value), this->parser) == 0;
        }

        bool get_parsed_body(const void **body, size_t *size) const {
            return http_parser_get_body(body, size, this->parser) == 0;
        }

        /* Output body is for sending. Want to transfer a message received, maybe:
         * msg->get_parsed_body(&body, &size);
         * msg->append_output_body_nocopy(body, size); */

        // 零拷贝或单次拷贝优化的HTTP消息体追加函数
        bool append_output_body(const void *buf, size_t size);
        // 将数据拷贝到新分配的内存中，然后添加到输出链表
        bool append_output_body(const char *buf) {
            return this->append_output_body(buf, strlen(buf));
        }

        // 直接将外部数据块的指针添加到输出链表，不进行内存拷贝
        bool append_output_body_nocopy(const void *buf, size_t size);

        bool append_output_body_nocopy(const char *buf) {
            return this->append_output_body_nocopy(buf, strlen(buf));
        }

        [[nodiscard]] size_t get_output_body_size() const {
            return this->output_body_size;
        }

        // 获取输出消息体所有数据块的指针和长度数组，用于分散写入（如 writev系统调用）
        size_t get_output_body_blocks(const void *buf[], size_t size[], size_t max) const;

        bool get_output_body_merged(void *buf, size_t *size) const;

        // 清空输出消息体链表，释放相关资源
        void clear_output_body();

        /* std::string interfaces */
    public:
        bool get_http_version(std::string &version) const {
            const char *str = this->get_http_version();
            if (str) {
                version.assign(str);
                return true;
            }
            return false;
        }

        bool set_http_version(const std::string &version) {
            return this->set_http_version(version.c_str());
        }

        bool add_header_pair(const std::string &name, const std::string &value) {
            return http_parser_add_header(name.c_str(), name.size(),
                                          value.c_str(), value.size(), this->parser) == 0;
        }

        bool set_header_pair(const std::string &name, const std::string &value) {
            return http_parser_set_header(name.c_str(), name.size(),
                                          value.c_str(), value.size(), this->parser) == 0;
        }

        bool append_output_body(const std::string &buf) {
            return this->append_output_body(buf.c_str(), buf.size());
        }

        bool append_output_body_nocopy(const std::string &buf) {
            return this->append_output_body_nocopy(buf.c_str(), buf.size());
        }

        bool get_output_body_merged(std::string &body) const {
            size_t size = this->output_body_size;
            body.resize(size);
            return this->get_output_body_merged((void *)body.data(), &size);
        }

        /* for http task implementations. */
    public:
        // 检查HTTP头部是否已完全解析
        [[nodiscard]] bool is_header_complete() const {
            return is_http_parser_header_complete(this->parser);
        }

        [[nodiscard]] bool has_connection_header() const {
            return http_parser_has_connection(this->parser);
        }

        [[nodiscard]] bool has_content_length_header() const {
            return http_parser_has_content_length(this->parser);
        }

        [[nodiscard]] bool has_keep_alive_header() const {
            return http_parser_has_keep_alive(this->parser);
        }

        // 主动结束消息解析过程
        void end_parsing() {
            http_parser_close_message(this->parser);
        }

        /* for header cursor implementations. */
        [[nodiscard]] const http_parser_t *get_parser() const {
            return this->parser;
        }

    protected:
        int encode(iovec io_vecs[], int max) override;
        int append(const void *buf, size_t *size) override;

    protected:
        http_parser_t *parser; // 负责解析传入的原始HTTP数据，并存储解析出的状态和信息(如头部、版本)
        size_t cur_size; // 动态记录当前已累积或准备处理的数据总量. 是一个反映当前进度的“快照”

    private:
        list_head *combine_from(list_head *pos, size_t size);

    private:
        // 使用一个链表来管理可能由多个不连续数据块组成的完整HTTP消息体, 非常适合流式处理大量数据或多次追加数据的场景
        list_head output_body; // 以链表形式管理待发送的消息体数据块，支持零拷贝操作
        size_t output_body_size; // 记录链表中所存数据的总长度（即: 当前消息体的总长度）, 用于生成 Content-Length头部
    };

    class HttpRequest : public HttpMessage {
    public:
        HttpRequest() : HttpMessage(false) {}
        HttpRequest(HttpRequest &&http_req) = default;
        HttpRequest &operator =(HttpRequest &&req) = default;

        [[nodiscard]] const char *get_method() const {
            return http_parser_get_method(this->parser);
        }

        [[nodiscard]] const char *get_request_uri() const {
            return http_parser_get_uri(this->parser);
        }

        bool set_method(const char *method) {
            return http_parser_set_method(method, this->parser) == 0;
        }

        bool set_request_uri(const char *uri) {
            return http_parser_set_uri(uri, this->parser) == 0;
        }

        /* std::string interfaces */
    public:
        bool get_method(std::string &method) const {
            const char *str = this->get_method();
            if (str) {
                method.assign(str);
                return true;
            }
            return false;
        }

        bool get_request_uri(std::string &uri) const {
            const char *str = this->get_request_uri();
            if (str) {
                uri.assign(str);
                return true;
            }
            return false;
        }

        bool set_method(const std::string &method) {
            return this->set_method(method.c_str());
        }

        bool set_request_uri(const std::string &uri) {
            return this->set_request_uri(uri.c_str());
        }

    protected:
        int append(const void *buf, size_t *size) override;

    private:
        int handle_expect_continue();
    };

    class HttpResponse : public HttpMessage {
    public:
        HttpResponse() : HttpMessage(true) {}
        HttpResponse(HttpResponse &&resp) = default;
        HttpResponse &operator =(HttpResponse &&resp) = default;

    public:
        [[nodiscard]] const char *get_status_code() const {
            return http_parser_get_code(this->parser);
        }

        [[nodiscard]] const char *get_reason_phrase() const {
            return http_parser_get_phrase(this->parser);
        }

        bool set_status_code(const char *code) {
            return http_parser_set_code(code, this->parser) == 0;
        }

        bool set_reason_phrase(const char *phrase) {
            return http_parser_set_phrase(phrase, this->parser) == 0;
        }

        /* std::string interfaces */
    public:
        bool get_status_code(std::string &code) const {
            const char *str = this->get_status_code();

            if (str) {
                code.assign(str);
                return true;
            }

            return false;
        }

        bool get_reason_phrase(std::string &phrase) const {
            const char *str = this->get_reason_phrase();

            if (str) {
                phrase.assign(str);
                return true;
            }

            return false;
        }

        bool set_status_code(const std::string &code) {
            return this->set_status_code(code.c_str());
        }

        bool set_reason_phrase(const std::string &phrase) {
            return this->set_reason_phrase(phrase.c_str());
        }

    public:
        /* Tell the parser, it is a HEAD response. For implementations. */
        void parse_zero_body() {
            this->parser->transfer_length = 0;
        }

    protected:
        int append(const void *buf, size_t *size) override;
    };

    class HttpMessageChunk : public ProtocolMessage {
    public:
        HttpMessageChunk() {
            this->chunk_data = nullptr;
            this->nreceived = 0;
        }

        ~HttpMessageChunk() override {
            free(this->chunk_data);
        }

        HttpMessageChunk(HttpMessageChunk &&msg) noexcept;
        HttpMessageChunk &operator =(HttpMessageChunk &&msg) noexcept;

        bool get_chunk_data(const void **chunk_data, size_t *size) const;
        bool move_chunk_data(void **chunk_data, size_t *size);
        bool set_chunk_data(const void *chunk_data, size_t size);

    protected:
        int encode(iovec io_vecs[], int max) override;
        int append(const void *buf, size_t *size) override;

    private:
        int append_chunk_line(const void *buf, size_t size);

    private:
        char chunk_line[32]{};
        void *chunk_data;
        size_t chunk_size{0};
        size_t nreceived;
    };
}
#endif //MYWORKFLOW_HTTPMESSAGE_H