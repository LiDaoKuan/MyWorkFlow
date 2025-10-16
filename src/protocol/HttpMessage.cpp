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

    // HTTP消息解析的桥梁
    inline int HttpMessage::append(const void *buf, size_t *size) {
        int ret = http_parser_append_message(buf, size, this->parser);

        if (ret >= 0) {
            this->cur_size += *size; // 更新累计数据量
            if (this->cur_size > this->size_limit) {
                errno = EMSGSIZE; // 检查是否超限
                ret = -1;
            }
        } else if (ret == -2) {
            errno = EBADMSG; // 协议语法错误
            ret = -1;
        }

        return ret;
    }

    HttpMessage::HttpMessage(HttpMessage &&msg) noexcept :
        ProtocolMessage(std::move(msg)) // 转移基类部分的资源
    {
        this->parser = msg.parser; // 转移指针所有权
        msg.parser = nullptr;

        INIT_LIST_HEAD(&this->output_body); // 初始化链表
        list_splice_init(&msg.output_body, &this->output_body); // 将原链表插入新链表中
        this->output_body_size = msg.output_body_size;
        msg.output_body_size = 0;

        this->cur_size = msg.cur_size;
        msg.cur_size = 0;
    }

    HttpMessage &HttpMessage::operator =(HttpMessage &&msg) noexcept {
        // 防止将对象移动赋值给自身
        if (&msg != this) {
            *(ProtocolMessage *)this = std::move(msg); // 调用基类的移动赋值运算符，确保基类部分的资源也被正确转移

            if (this->parser) {
                // 在接管新资源前，释放当前对象已持有的解析器资源，防止内存泄漏
                http_parser_deinit(this->parser);
                delete this->parser;
            }

            this->parser = msg.parser; // 直接“窃取”源对象的解析器指针，并将源对象的指针置空
            msg.parser = nullptr;

            // 清空当前对象的输出体链表，然后将源对象的链表节点整体“拼接”过来
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

    // 处理Expect: 100-continue, 用于在接收大量数据前进行预确认
    int HttpRequest::handle_expect_continue() {
        size_t trans_len = this->parser->transfer_length;
        int ret;

        // 判断传输长度是否已知(即不是未定义状态). (size_t)-1通常用作表示“长度未知”的魔术数字, 例如在分块传输编码（chunked encoding）中
        if (trans_len != (size_t)-1) {
            // header_offset(已解析的头部长度)加上trans_len(消息体预期长度)是否超过size_limit(服务器设置的最大消息大小限制)
            if (this->parser->header_offset + trans_len > this->size_limit) {
                // 超限, 立即发送417 Expectation Failed响应, 并设置 errno为 EMSGSIZE, 告知客户端停止发送消息体
                this->feedback(HTTP_417_RESP, strlen(HTTP_417_RESP));
                errno = EMSGSIZE;
                return -1;
            }
        }
        // 长度检查通过或长度未知时, 尝试发送100 Continue响应
        ret = this->feedback(HTTP_100_RESP, strlen(HTTP_100_RESP));
        // 发送不完整(ret >= 0但小于预期长度),通常意味着输出缓冲区已满(ENOBUFS错误)
        if (ret != strlen(HTTP_100_RESP)) {
            if (ret >= 0) { errno = ENOBUFS; }
            return -1;
        }
        return 0;
    }

    // 服务器端用于处理客户端发来的HTTP请求
    int HttpRequest::append(const void *buf, size_t *size) {
        int ret = HttpMessage::append(buf, size); // 调用基类的 append方法
        // ret==0表示需要更多数据
        if (ret == 0) {
            if (this->parser->expect_continue && is_http_parser_header_complete(this->parser)) {
                // 一旦进入处理逻辑, 函数会立即将expect_continue标志重置为0, 防止重复处理
                this->parser->expect_continue = 0;
                // 处理 expect_continue
                ret = this->handle_expect_continue();
            }
        } else if (ret < 0) // ret < 0则表示在解析过程中发生了错误
        {
            if (errno == EBADMSG) {
                // 协议语法错误
                this->feedback(HTTP_400_RESP, strlen(HTTP_400_RESP));
            } else if (errno == EMSGSIZE) {
                // 请求消息（通常是消息体）的长度超过了服务器允许的限制
                this->feedback(HTTP_413_RESP, strlen(HTTP_413_RESP));
            }
        }
        return ret;
    }

    // 客户端用于处理从服务器接收到的HTTP 100 Continue响应
    int HttpResponse::append(const void *buf, size_t *size) {
        int ret = HttpMessage::append(buf, size); // 调用基类的 append方法
        if (ret > 0) {
            // 检查解析器当前解析出的HTTP状态码是否为 "100"，即 100 Continue
            if (strcmp(http_parser_get_code(this->parser), "100") == 0) {
                http_parser_deinit(this->parser); // 清理解析器的内部状态, 为解析下一个HTTP消息做准备
                http_parser_init(1, this->parser); // 重新初始化解析器. 参数1很可能表示将解析器设置为解析HTTP 响应 的模式
                // 将返回值重置为0. 这是一个非常精妙的设计.
                // 它告知调用者: “虽然我成功解析了一个完整的消息(100 Continue),但请将我视为需要更多数据的状态, 因为真正的、有意义的响应还在后面."
                ret = 0;
            }
        }
        return ret;
    }

    // HTTP分块传输编码数据块提取
    bool HttpMessageChunk::get_chunk_data(const void **data, size_t *size) const {
        // 确认chunk_data指针有效, 防止返回空指针导致调用方出现未定义行为
        // +2 极有可能用于计入HTTP chunk格式中每个数据块末尾的CRLF(\r\n)分隔符(占2字节)
        // nreceived跟踪的是从网络接收到的、包含数据体及其尾部CRLF的总字节数
        // 当 nreceived == chunk_size+2 时, 说明当前数据块(包括其结束标记)已完整接收
        if (this->chunk_data && this->nreceived == this->chunk_size + 2) {
            *data = this->chunk_data;
            *size = this->chunk_size;
            return true;
        } else {
            // 返回false告知调用方数据尚未准备就绪. 可能的原因包括: 数据块还在接收中(nreceived不足),或是chunk_data缓冲区尚未分配或已失效
            return false;
        }
    }

    // 带有所有权转移的HTTP分块数据提取. 在提供数据的同时会将数据的所有权从 HttpMessageChunk 对象转移给调用者
    bool HttpMessageChunk::move_chunk_data(void **data, size_t *size) {
        if (this->chunk_data && this->nreceived == this->chunk_size + 2) {
            *data = this->chunk_data;
            *size = this->chunk_size;
            this->chunk_data = nullptr; // 将内部指针置nullptr
            this->nreceived = 0; // 重置接收计数器
            return true;
        } else { return false; }
    }

    // 将原始数据封装成HTTP chunked格式
    bool HttpMessageChunk::set_chunk_data(const void *data, size_t size) {
        // +2: 用于存储HTTP chunk格式要求的CRLF(回车换行)结束符 \r\n
        // +1: 额外的空字符 \0, 用于C风格字符串的终止
        auto *p = static_cast<char *>(malloc(size + 3));

        if (p) {
            memcpy(p, data, size); // 拷贝原始数据
            p[size] = '\r'; // 添加回车符
            p[size + 1] = '\n'; // 添加换行符
            p[size + 2] = '\0'; // 添加字符串结束符

            free(this->chunk_data); // 释放旧数据块
            this->chunk_data = p; // 更新指针指向新数据块
            this->chunk_size = size; // 记录原始数据大小
            this->nreceived = size + 2; // 记录总接收大小（数据+CRLF）
            return true;
        } else { return false; }
    }

    // HTTP分块传输编码的组装
    int HttpMessageChunk::encode(iovec vectors[], int max) {
        // %zx: 用于正确格式化 size_t类型的值为十六进制, 确保跨平台兼容性
        const int len = sprintf(this->chunk_line, "%zx\r\n", this->chunk_size);

        vectors[0].iov_base = this->chunk_line; // 指向块大小行
        vectors[0].iov_len = len; // 块大小行的长度
        vectors[1].iov_base = this->chunk_data; // 指向数据
        vectors[1].iov_len = this->chunk_size + 2; // 数据长度 + 2字节的\r\n

        return 2; // 返回整数 2, 表示本次编码填充了两个iovec结构体元素
    }

#define MIN(x, y)	((x) <= (y) ? (x) : (y))

    // 解析每个数据块开头的大小行
    int HttpMessageChunk::append_chunk_line(const void *buf, size_t size) {
        char *end;
        size_t i;

        // 确保不会拷贝超过chunk_line缓冲区剩余空间的数据, 防止了缓冲区溢出
        size = MIN(size, sizeof this->chunk_line - this->nreceived);
        memcpy(this->chunk_line + this->nreceived, buf, size);
        // 它遍历合并后的数据（原有缓冲区内容 + 新追加的数据），寻找回车符 \r
        for (i = 0; i + 1 < this->nreceived + size; i++) {
            if (this->chunk_line[i] == '\r') {
                if (this->chunk_line[i + 1] != '\n') {
                    errno = EBADMSG; // 语法错误
                    return -1;
                }

                this->chunk_line[i] = '\0'; // 将\r替换为字符串结束符
                this->chunk_size = strtoul(this->chunk_line, &end, 16); // 解析十六进制数(当前块大小)
                // 检查是否成功解析数字
                if (end == this->chunk_line) {
                    errno = EBADMSG;
                    return -1;
                }
                // 解析出的块大小与一个硬性上限（64MB）和配置的上限（size_limit）进行比较, 防止处理过大的块消耗过多内存
                if (this->chunk_size > 64 * 1024 * 1024 || this->chunk_size > this->size_limit) {
                    errno = EMSGSIZE;
                    return -1;
                }
                // 多分配3字节
                this->chunk_data = malloc(this->chunk_size + 3);
                if (!this->chunk_data) { return -1; }

                this->nreceived = i + 2; // 更新接收计数器，跳过已处理的CRLF
                return 1;
            }
        }
        // 检查循环变量 i 是否达到了 chunk_line 缓冲区最后一个有效索引的位置
        if (i == sizeof(this->chunk_line) - 1) {
            // 这个条件为真意味着, 函数已经扫描了整个缓冲区的有效空间(从新老数据合并后的起始位置到缓冲区末尾),
            // 但依然没有找到所需的 \r字符. 这表明当前接收的数据可能不是有效的HTTP chunk-size行格式
            errno = EBADMSG;
            return -1;
        }

        // 如果缓冲区未满且未找到行结束符, 函数将新追加的数据长度size加到nreceived上. 更新解析器的内部状态
        this->nreceived += size;
        return 0;
    }

    // HTTP分块传输编码(chunked transfer encoding)的流式解析器
    int HttpMessageChunk::append(const void *buf, size_t *size) {
        size_t nleft; // 表示距离收齐当前整个数据块(含结束符)还差多少字节
        size_t n;
        int ret;

        // 如果 chunk_data 为 NULL, 说明解析器尚未解析当前数据块的块大小行, 正处于解析的起始阶段。
        // 这是因为在成功解析块大小行后, append_chunk_line 函数会为块数据分配内存并将 chunk_data 指向该区域
        if (!this->chunk_data) {
            n = this->nreceived;
            ret = this->append_chunk_line(buf, *size);
            if (ret <= 0) { return ret; }
            // 解析成功(ret > 0),计算块大小行本身占用的字节数n
            n = this->nreceived - n;
            // 将nreceived重置为0, 为接收实际的块数据做准备
            this->nreceived = 0;
        } else { n = 0; }

        if (this->chunk_size != 0) {
            nleft = this->chunk_size + 2 - this->nreceived; // 计算剩余需接收的数据量
            // *size是本次调用时输入缓冲区buf中的总数据量, n是已经用于其他用途(如解析块大小行)的字节数
            // 本次可用的数据量(*size - n)大于剩余需要的数据量(nleft), 就将本次实际处理的数据量 *size 调整为 n + nleft.
            // 这确保了后续的memcpy操作不会超出当前数据块的实际需要, 防止了缓冲区越界或读取了属于下一个数据块的数据
            if (*size - n > nleft) { *size = n + nleft; }

            // buf向后移动n个字节, 因为n字节的数据已经被用于处理块大小行等信息, 当前需要处理的是紧随其后的块数据部分
            buf = static_cast<const char *>(buf) + n;
            n = *size - n; // 剩余需要处理的字节数
            memcpy(static_cast<char *>(this->chunk_data) + this->nreceived, buf, n);
            this->nreceived += n; // 更新已经接收的总字节数
            // 当 nreceived 等于 chunk_size + 2时, 说明当前数据块(包括数据体和结尾的 \r\n)已经全部接收完毕
            if (this->nreceived == this->chunk_size + 2) {
                static_cast<char *>(this->chunk_data)[this->nreceived] = '\0'; // 在缓冲区末尾显式地添加一个空字符(\0)
                return 1;
            }
        } else {
            // 当chunk_size为0时, 表示这是最后一个块(last-chunk),函数进入结束序列的解析
            while (n < *size) {
                const char c = static_cast<const char *>(buf)[n];
                // 此处this->nreceived用于状态转移,不再用于表示“已经成功接收并拷贝到chunk_data的字节数”
                if (this->nreceived == 0) {
                    if (c == '\r') {
                        this->nreceived = 1; // 如果当前字符是'\r', 转换到状态1
                    } else { this->nreceived = (size_t)-2; }
                } else if (this->nreceived == 1) {
                    if (c == '\n') {
                        // 如果当前字符是'\n'
                        *size = n + 1; // 调整输入数据大小, 表明已成功处理到当前字符
                        this->nreceived = 2; // 标记nreceived为2, 表示chunk_data中接收了两个字符
                        static_cast<char *>(this->chunk_data)[0] = '\r';
                        static_cast<char *>(this->chunk_data)[1] = '\n';
                        static_cast<char *>(this->chunk_data)[2] = '\0';
                        return 1;
                    } else { break; }
                } else if (this->nreceived == (size_t)-2) {
                    if (c == '\r') {
                        this->nreceived = (size_t)-1;
                    }
                } else /* if (this->n2received == (size_t)-1) */ {
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
        memcpy(this->chunk_line, msg.chunk_line, sizeof(this->chunk_line));
        this->chunk_data = msg.chunk_data;
        msg.chunk_data = nullptr;
        this->chunk_size = msg.chunk_size;
        this->nreceived = msg.nreceived;
        msg.nreceived = 0;
    }

    HttpMessageChunk &HttpMessageChunk::operator =(HttpMessageChunk &&msg) noexcept {
        if (&msg != this) {
            *static_cast<ProtocolMessage *>(this) = std::move(msg);

            memcpy(this->chunk_line, msg.chunk_line, sizeof(this->chunk_line));
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