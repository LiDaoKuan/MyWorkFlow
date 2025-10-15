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

#include "HttpMessage.h"

namespace protocol {
    struct HttpMessageBlock {
        list_head list;
        const void *ptr;
        size_t size;
    };

    bool HttpMessage::append_output_body(const void *buf, size_t size) {
        size_t n = sizeof(HttpMessageBlock) + size;
        // 一次性分配了足够容纳管理结构体(HttpMessageBlock)和实际数据(buf指向的内容)的连续内存
        HttpMessageBlock *msg_block = static_cast<HttpMessageBlock *>(malloc(n));
        if (msg_block) {
            memcpy(msg_block + 1, buf, size); // 1. 拷贝数据
            msg_block->ptr = msg_block + 1; // 指向新拷贝的数据区
            msg_block->size = size; // 更新数据大小
            list_add_tail(&msg_block->list, &this->output_body); // 将新创建的数据块链接到 output_body链表的尾部
            this->output_body_size += size; // 更新当前消息体的总长度
            return true;
        }
        return false;
    }

    bool HttpMessage::append_output_body_nocopy(const void *buf, size_t size) {
        size_t n = sizeof(HttpMessageBlock);
        HttpMessageBlock *msg_block = static_cast<HttpMessageBlock *>(malloc(n));
        if (msg_block) {
            msg_block->ptr = buf; // 直接指向外部数据指针
            msg_block->size = size; // 记录数据大小
            list_add_tail(&msg_block->list, &this->output_body); // 添加到链表中
            this->output_body_size += size; // 增加当前消息体的总长度
            return true;
        }
        return false;
    }

    // 获取HTTP消息体所有数据块信息
    size_t HttpMessage::get_output_body_blocks(const void *buf[], size_t size[], size_t max) const {
        HttpMessageBlock *msg_block;
        list_head *pos;
        size_t n = 0;
        list_for_each(pos, &this->output_body) {
            if (n == max) { break; } // 防止数组越界
            msg_block = list_entry(pos, HttpMessageBlock, list);
            buf[n] = msg_block->ptr;
            size[n] = msg_block->size;
            ++n;
        }
        return n;
    }

    // 将存储在链表中的多个分散数据块整合到一块连续的内存缓冲区中
    bool HttpMessage::get_output_body_merged(void *buf, size_t *size) const {
        HttpMessageBlock *msg_block;
        list_head *pos;
        // 确保 buf 有足够的空间容纳所有数据
        if (*size < this->output_body_size) {
            errno = ENOSPC; // 空间不足
            return false;
        }
        list_for_each(pos, &this->output_body) {
            msg_block = list_entry(pos, HttpMessageBlock, list);
            memcpy(buf, msg_block->ptr, msg_block->size); // 拷贝数据到buf中
            buf = static_cast<char *>(buf) + msg_block->size; // 移动buf指针
        }
        *size = this->output_body_size; // 更新buf的大小
        return true;
    }

    // 清理HTTP消息的输出体部分, 释放所有存储消息体数据的内存块
    void HttpMessage::clear_output_body() {
        HttpMessageBlock *block;
        list_head *pos, *tmp;

        list_for_each_safe(pos, tmp, &this->output_body) {
            block = list_entry(pos, struct HttpMessageBlock, list);
            list_del(pos); // 从链表中删除
            free(block); // 释放内存
        }

        this->output_body_size = 0; // 数据大小置为0
    }

    // HTTP消息体块合并工具
    list_head *HttpMessage::combine_from(list_head *pos, size_t size) {
        size_t n = sizeof(HttpMessageBlock) + size;
        // 一次性分配足以容纳管理头和所有数据的连续内存. 这种布局使得后续访问时内存局部性更好, 有利于CPU缓存命中, 提升读取效率
        HttpMessageBlock *msg_block = static_cast<HttpMessageBlock *>(malloc(n));
        HttpMessageBlock *entry;
        char *ptr;
        if (msg_block) {
            msg_block->ptr = msg_block + 1; // 让 block->ptr指向紧接在管理结构 HttpMessageBlock之后的内存地址
            msg_block->size = size;
            ptr = static_cast<char *>(const_cast<void *>(msg_block->ptr));

            do {
                entry = list_entry(pos, HttpMessageBlock, list); // 1. 获取当前数据块
                pos = pos->next; // 2. 移动遍历指针
                list_del(&entry->list); // 3. 从链表中删除当前块
                memcpy(ptr, entry->ptr, entry->size); // 4. 拷贝数据
                ptr += entry->size; // 5. 移动目标指针
                free(entry); // 6. 释放原数据块
            } while (pos != &this->output_body);
            // 将新块添加到链表的尾部
            list_add_tail(&msg_block->list, &this->output_body);
            return &msg_block->list;
        }
        return nullptr;
    }

    // HTTP消息编码器
    int HttpMessage::encode(iovec io_vecs[], int max) {
        const char *start_line[3];
        http_header_cursor_t cursor; // 用于遍历链表
        HttpMessageHeader header{};
        HttpMessageBlock *block;
        list_head *pos;
        size_t size;
        int i;

        // 获取请求方法, 如果存在, 说明是http请求, 否则是http响应
        start_line[0] = http_parser_get_method(this->parser);
        if (start_line[0]) {
            // 请求行: 方法 URI 版本
            start_line[1] = http_parser_get_uri(this->parser); //  获取uri
            start_line[2] = http_parser_get_version(this->parser); // 获取版本
        } else {
            // 状态行: 版本 状态码 原因短语
            start_line[0] = http_parser_get_version(this->parser); // 获取版本
            start_line[1] = http_parser_get_code(this->parser); // 获取状态码
            start_line[2] = http_parser_get_phrase(this->parser); // 获取响应原因
        }

        // 三个关键元素缺一不可
        if (!start_line[0] || !start_line[1] || !start_line[2]) {
            errno = EBADMSG;
            return -1;
        }

        // 通过多个独立的iovec元素来构建起始行, 避免了字符串拼接.
        // 这种"分散"存储的方式, 使得最终通过writev系统调用发送时, 内核会自动将这些分散的内存块按顺序组合成完整的起始行, 完全避免了内存拷贝开销
        io_vecs[0].iov_base = static_cast<void *>(const_cast<char *>(start_line[0]));
        io_vecs[0].iov_len = strlen(start_line[0]);
        io_vecs[1].iov_base = static_cast<void *>(const_cast<char *>(" "));
        io_vecs[1].iov_len = 1;

        io_vecs[2].iov_base = static_cast<void *>(const_cast<char *>(start_line[1]));
        io_vecs[2].iov_len = strlen(start_line[1]);
        io_vecs[3].iov_base = static_cast<void *>(const_cast<char *>(" "));
        io_vecs[3].iov_len = 1;

        io_vecs[4].iov_base = static_cast<void *>(const_cast<char *>(start_line[2]));
        io_vecs[4].iov_len = strlen(start_line[2]);
        io_vecs[5].iov_base = static_cast<void *>(const_cast<char *>("\r\n")); // 表示起始行结束
        io_vecs[5].iov_len = 2;

        // 开始构建请求头/响应头
        i = 6;
        http_header_cursor_init(&cursor, this->parser); // 遍历前初始化游标
        while (http_header_cursor_next(&header.name, &header.name_len, &header.value, &header.value_len, &cursor) == 0) {
            //
            if (i == max) { break; }
            // 将每个头部字段的名称和值作为一个完整的iovec元素
            io_vecs[i].iov_base = const_cast<void *>(header.name);
            io_vecs[i].iov_len = header.name_len + 2 + header.value_len + 2;
            i++;
        }

        http_header_cursor_deinit(&cursor); // 遍历完成后销毁游标
        if (i + 1 >= max) {
            errno = EOVERFLOW; // 请求头/响应头太长
            return -1;
        }

        io_vecs[i].iov_base = static_cast<void *>(const_cast<char *>("\r\n"));
        io_vecs[i].iov_len = 2;
        i++;

        // 开始构建请求体/响应体
        size = this->output_body_size;
        list_for_each(pos, &this->output_body) {
            if (i + 1 == max && pos != this->output_body.prev) {
                // 空间不足, 将后续多个小数据块合并为一个大块
                pos = this->combine_from(pos, size);
                if (!pos) { return -1; }
            }

            block = list_entry(pos, struct HttpMessageBlock, list);
            io_vecs[i].iov_base = const_cast<void *>(block->ptr); // 将合并后的块作为一个iovec元素
            io_vecs[i].iov_len = block->size;
            size -= block->size;
            i++;
        }

        return i;
    }

    inline int HttpMessage::append(const void *buf, size_t *size) {
        int ret = http_parser_append_message(buf, size, this->parser);

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

    HttpMessage::HttpMessage(HttpMessage &&msg) noexcept :
        ProtocolMessage(std::move(msg)) {
        this->parser = msg.parser;
        msg.parser = nullptr;

        INIT_LIST_HEAD(&this->output_body);
        list_splice_init(&msg.output_body, &this->output_body);
        this->output_body_size = msg.output_body_size;
        msg.output_body_size = 0;

        this->cur_size = msg.cur_size;
        msg.cur_size = 0;
    }

    HttpMessage &HttpMessage::operator =(HttpMessage &&msg) noexcept {
        if (&msg != this) {
            *(ProtocolMessage *)this = std::move(msg);

            if (this->parser) {
                http_parser_deinit(this->parser);
                delete this->parser;
            }

            this->parser = msg.parser;
            msg.parser = nullptr;

            this->clear_output_body();
            list_splice_init(&msg.output_body, &this->output_body);
            this->output_body_size = msg.output_body_size;
            msg.output_body_size = 0;

            this->cur_size = msg.cur_size;
            msg.cur_size = 0;
        }

        return *this;
    }

#define HTTP_100_STATUS_LINE	"HTTP/1.1 100 Continue"
#define HTTP_400_STATUS_LINE	"HTTP/1.1 400 Bad Request"
#define HTTP_413_STATUS_LINE	"HTTP/1.1 413 Request Entity Too Large"
#define HTTP_417_STATUS_LINE	"HTTP/1.1 417 Expectation Failed"
#define CONTENT_LENGTH_ZERO		"Content-Length: 0"
#define CONNECTION_CLOSE		"Connection: close"
#define CRLF					"\r\n"

#define HTTP_100_RESP			HTTP_100_STATUS_LINE CRLF \
								CRLF
#define HTTP_400_RESP			HTTP_400_STATUS_LINE CRLF \
								CONTENT_LENGTH_ZERO CRLF \
								CONNECTION_CLOSE CRLF \
								CRLF
#define HTTP_413_RESP			HTTP_413_STATUS_LINE CRLF \
								CONTENT_LENGTH_ZERO CRLF \
								CONNECTION_CLOSE CRLF \
								CRLF
#define HTTP_417_RESP			HTTP_417_STATUS_LINE CRLF \
								CONTENT_LENGTH_ZERO CRLF \
								CONNECTION_CLOSE CRLF \
								CRLF

    int HttpRequest::handle_expect_continue() {
        size_t trans_len = this->parser->transfer_length;
        int ret;

        if (trans_len != (size_t)-1) {
            if (this->parser->header_offset + trans_len > this->size_limit) {
                this->feedback(HTTP_417_RESP, strlen(HTTP_417_RESP));
                errno = EMSGSIZE;
                return -1;
            }
        }

        ret = this->feedback(HTTP_100_RESP, strlen(HTTP_100_RESP));
        if (ret != strlen(HTTP_100_RESP)) {
            if (ret >= 0) { errno = ENOBUFS; }
            return -1;
        }

        return 0;
    }

    int HttpRequest::append(const void *buf, size_t *size) {
        int ret = HttpMessage::append(buf, size);
        if (ret == 0) {
            if (this->parser->expect_continue && is_http_parser_header_complete(this->parser)) {
                this->parser->expect_continue = 0;
                ret = this->handle_expect_continue();
            }
        } else if (ret < 0) {
            if (errno == EBADMSG) {
                this->feedback(HTTP_400_RESP, strlen(HTTP_400_RESP));
            } else if (errno == EMSGSIZE) {
                this->feedback(HTTP_413_RESP, strlen(HTTP_413_RESP));
            }
        }
        return ret;
    }

    int HttpResponse::append(const void *buf, size_t *size) {
        int ret = HttpMessage::append(buf, size);

        if (ret > 0) {
            if (strcmp(http_parser_get_code(this->parser), "100") == 0) {
                http_parser_deinit(this->parser);
                http_parser_init(1, this->parser);
                ret = 0;
            }
        }

        return ret;
    }

    bool HttpMessageChunk::get_chunk_data(const void **data, size_t *size) const {
        if (this->chunk_data && this->nreceived == this->chunk_size + 2) {
            *data = this->chunk_data;
            *size = this->chunk_size;
            return true;
        } else { return false; }
    }

    bool HttpMessageChunk::move_chunk_data(void **data, size_t *size) {
        if (this->chunk_data && this->nreceived == this->chunk_size + 2) {
            *data = this->chunk_data;
            *size = this->chunk_size;
            this->chunk_data = nullptr;
            this->nreceived = 0;
            return true;
        } else { return false; }
    }

    bool HttpMessageChunk::set_chunk_data(const void *data, size_t size) {
        char *p = (char *)malloc(size + 3);

        if (p) {
            memcpy(p, data, size);
            p[size] = '\r';
            p[size + 1] = '\n';
            p[size + 2] = '\0';

            free(this->chunk_data);
            this->chunk_data = p;
            this->chunk_size = size;
            this->nreceived = size + 2;
            return true;
        } else { return false; }
    }

    int HttpMessageChunk::encode(struct iovec vectors[], int max) {
        int len = sprintf(this->chunk_line, "%zx\r\n", this->chunk_size);

        vectors[0].iov_base = this->chunk_line;
        vectors[0].iov_len = len;
        vectors[1].iov_base = this->chunk_data;
        vectors[1].iov_len = this->chunk_size + 2;

        return 2;
    }

#define MIN(x, y)	((x) <= (y) ? (x) : (y))

    int HttpMessageChunk::append_chunk_line(const void *buf, size_t size) {
        char *end;
        size_t i;

        size = MIN(size, sizeof this->chunk_line - this->nreceived);
        memcpy(this->chunk_line + this->nreceived, buf, size);
        for (i = 0; i + 1 < this->nreceived + size; i++) {
            if (this->chunk_line[i] == '\r') {
                if (this->chunk_line[i + 1] != '\n') {
                    errno = EBADMSG;
                    return -1;
                }

                this->chunk_line[i] = '\0';
                this->chunk_size = strtoul(this->chunk_line, &end, 16);
                if (end == this->chunk_line) {
                    errno = EBADMSG;
                    return -1;
                }

                if (this->chunk_size > 64 * 1024 * 1024 ||
                    this->chunk_size > this->size_limit) {
                    errno = EMSGSIZE;
                    return -1;
                }

                this->chunk_data = malloc(this->chunk_size + 3);
                if (!this->chunk_data) return -1;

                this->nreceived = i + 2;
                return 1;
            }
        }

        if (i == sizeof this->chunk_line - 1) {
            errno = EBADMSG;
            return -1;
        }

        this->nreceived += size;
        return 0;
    }

    int HttpMessageChunk::append(const void *buf, size_t *size) {
        size_t nleft;
        size_t n;
        int ret;

        if (!this->chunk_data) {
            n = this->nreceived;
            ret = this->append_chunk_line(buf, *size);
            if (ret <= 0) { return ret; }

            n = this->nreceived - n;
            this->nreceived = 0;
        } else { n = 0; }

        if (this->chunk_size != 0) {
            nleft = this->chunk_size + 2 - this->nreceived;
            if (*size - n > nleft) *size = n + nleft;

            buf = static_cast<const char *>(buf) + n;
            n = *size - n;
            memcpy(static_cast<char *>(this->chunk_data) + this->nreceived, buf, n);
            this->nreceived += n;
            if (this->nreceived == this->chunk_size + 2) {
                static_cast<char *>(this->chunk_data)[this->nreceived] = '\0';
                return 1;
            }
        } else {
            while (n < *size) {
                char c = static_cast<const char *>(buf)[n];

                if (this->nreceived == 0) {
                    if (c == '\r') this->nreceived = 1;
                    else this->nreceived = (size_t)-2;
                } else if (this->nreceived == 1) {
                    if (c == '\n') {
                        *size = n + 1;
                        this->nreceived = 2;
                        static_cast<char *>(this->chunk_data)[0] = '\r';
                        static_cast<char *>(this->chunk_data)[1] = '\n';
                        static_cast<char *>(this->chunk_data)[2] = '\0';
                        return 1;
                    } else { break; }
                } else if (this->nreceived == (size_t)-2) {
                    if (c == '\r') { this->nreceived = (size_t)-1; }
                } else /* if (this->nreceived == (size_t)-1) */
                {
                    if (c == '\n') {
                        this->nreceived = 0;
                    } else { break; }
                }

                n++;
            }

            if (n < *size) {
                errno = EBADMSG;
                return -1;
            }
        }

        return 0;
    }

    HttpMessageChunk::HttpMessageChunk(HttpMessageChunk &&msg) noexcept :
        ProtocolMessage(std::move(msg)) {
        memcpy(this->chunk_line, msg.chunk_line, sizeof this->chunk_line);
        this->chunk_data = msg.chunk_data;
        msg.chunk_data = nullptr;
        this->chunk_size = msg.chunk_size;
        this->nreceived = msg.nreceived;
        msg.nreceived = 0;
    }

    HttpMessageChunk &HttpMessageChunk::operator =(HttpMessageChunk &&msg) noexcept {
        if (&msg != this) {
            *static_cast<ProtocolMessage *>(this) = std::move(msg);

            memcpy(this->chunk_line, msg.chunk_line, sizeof this->chunk_line);
            free(this->chunk_data);
            this->chunk_data = msg.chunk_data;
            msg.chunk_data = nullptr;
            this->chunk_size = msg.chunk_size;
            this->nreceived = msg.nreceived;
            msg.nreceived = 0;
        }

        return *this;
    }
}