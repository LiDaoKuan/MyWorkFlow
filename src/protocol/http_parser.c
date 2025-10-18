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

#include "http_parser.h"

#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "http_parser.h"

#define MIN(x, y)	((x) <= (y) ? (x) : (y))
#define MAX(x, y)	((x) >= (y) ? (x) : (y))

// 限制 请求行或状态行 的最大长度
#define HTTP_START_LINE_MAX		8192
// 限制 单个HTTP头部字段值 的最大长度
#define HTTP_HEADER_VALUE_MAX	8192
// 限制 分块传输编码 中每个数据块的长度标识行的最大长度
#define HTTP_CHUNK_LINE_MAX		1024
// 限制位于报文主体之后的 trailer 头部中每个字段行的最大长度
#define HTTP_TRAILER_LINE_MAX	8192
// 定义用于存储消息体(body)的缓冲区的初始分配大小
#define HTTP_MSGBUF_INIT_SIZE	2048

// 用于HTTP头部解析
enum {
    HPS_START_LINE, // 解析起始行
    HPS_HEADER_NAME, // 解析头部字段名
    HPS_HEADER_VALUE, // 解析对应的字段值
    HPS_HEADER_COMPLETE // 当前头部解析完成
};

enum {
    CPS_CHUNK_DATA, // 分块数据解析状态
    CPS_TRAILER_PART, // 尾部头部解析状态
    CPS_CHUNK_COMPLETE // 分块传输完成状态
};

struct __header_line {
    struct list_head list;
    int name_len; // 字段名长度
    int value_len; // 字段值长度
    char *buf; // 指向一块动态分配的内存, 该内存存储了完整的头部字段字符串, 通常格式为"字段名: 字段值". 使用指针而非字符数组可以灵活适应不同长度的头部字段
};

// HTTP请求头字段构造器: (添加http请求头部)
static int add_message_header(const char *name, size_t name_len, const char *value, size_t value_len, http_parser_t *parser) {
    // +4字节是为HTTP头部行必需的格式字符预留的: 冒号(:)、空格( )、回车(\r)和换行(\n).
    // 这种一次分配的策略优于多次分配, 因为它:
    //      减少内存碎片: 一次分配一块连续内存，而非多个小块。
    //      提升访问效率: 所有相关数据在内存中紧密排列, 符合局部性原理, CPU缓存命中率更高
    size_t size = sizeof(struct __header_line) + name_len + value_len + 4;
    struct __header_line *line = (struct __header_line *)malloc(size);
    if (line) {
        line->buf = (char *)(line + 1); // 1. buf指向结构体末尾, 这是后续判断buf是否是独立分配内存的重要标志
        memcpy(line->buf, name, name_len); // 2. 拷贝字段名
        line->buf[name_len] = ':'; // 3. 添加冒号
        line->buf[name_len + 1] = ' '; // 填充空格
        memcpy(line->buf + name_len + 2, value, value_len); // 拷贝字段值
        line->buf[name_len + 2 + value_len] = '\r'; // 添加回车
        line->buf[name_len + 2 + value_len + 1] = '\n'; // 添加换行
        line->name_len = name_len; // 记录 字段名 长度
        line->value_len = value_len; // 记录 字段值 长度
        list_add_tail(&line->list, &parser->header_list); // 将新创建的头部行添加到解析器parser的全局头部链表中
        return 0;
    }
    return -1;
}

// 设置或更新HTTP消息头部（存在即更新，不存在则添加）
static int set_message_header(const char *name, size_t name_len, const char *value, size_t value_len, http_parser_t *parser) {
    struct __header_line *line;
    struct list_head *pos;
    char *buf;
    // 遍历链表
    list_for_each(pos, &parser->header_list) {
        // 获取pos所在__header_line
        line = list_entry(pos, struct __header_line, list);
        // strncasecmp(str1, str2, n): 比较两个字符串的前n个字符，同时忽略大小写
        // 先比较字段名长度, 只有当长度名匹配时, 才进行代价较高的不区分大小写的字符串比较
        if (line->name_len == name_len && strncasecmp(line->buf, name, name_len) == 0) {
            // 找到同名的头部之后, 首先判断新值的长度是否大于旧值, 以决定是否需要扩容
            if (value_len > line->value_len) {
                // 新值的长度大于旧值, 进行扩容
                buf = (char *)malloc(name_len + value_len + 4); // 分配足够空间
                if (!buf) { return -1; }
                // 检查原buf是否独立分配
                if (line->buf != (char *)(line + 1)) {
                    free(line->buf); // 原buf是独立分配, 释放旧内存
                }
                line->buf = buf; // 指向新内存
                memcpy(buf, name, name_len); // 拷贝名称
                buf[name_len] = ':';
                buf[name_len + 1] = ' ';
            }
            // 无论内存是否重新分配, 函数都会重新构建完整的头部行
            memcpy(line->buf + name_len + 2, value, value_len); // 拷贝字段值
            line->buf[name_len + 2 + value_len] = '\r'; // 填充回车
            line->buf[name_len + 2 + value_len + 1] = '\n'; // 填充换行
            line->value_len = value_len; // 记录字段值长度
            return 0;
        }
    }
    // 如果遍历完整个链表都没有找到同名字段，函数会优雅地降级到添加逻辑
    return add_message_header(name, name_len, value, value_len, parser);
}

// 解析和设置HTTP请求行关键信息
static int match_request_line(const char *method, size_t method_len, const char *uri, size_t uri_len,
                              const char *version, size_t version_len, http_parser_t *parser) {
    // strndup(): 创建一个字符串的副本, 但是只复制 最多 指定数量的字符。并且复制完成后在新字符串的末尾添加'\0'确保其有效
    // strndup()返回的指针是指向堆内存的, 也就是说, 需要自己手动调用free()去释放这块内存！！！
    // 为什么method自己复制了一份传给自己呢？
    // 因为传入的method可能是个栈上的临时对象的指针, 为了保证一直可用, 在堆上复制一份, 然后用完自己释放. 确保其在使用期间一直有效
    method = strndup(method, method_len);
    if (method) {
        uri = strndup(uri, uri_len);
        if (uri) {
            version = strndup(version, version_len);
            if (version) {
                // 检查HTTP版本是否为"HTTP/1.0"或"HTTP/0.x"(如HTTP/0.9). 这些早期版本的HTTP协议默认不支持持久连接(keep_alive)
                if (strcmp(version, "HTTP/1.0") == 0 || strncmp(version, "HTTP/0", 6) == 0) {
                    // 如果检测到这些版本，函数会显式地将 parser->keep_alive设置为 0
                    parser->keep_alive = 0;
                }
                // 先释放解析器中原有的字符串内存, 然后将新分配的字符串指针赋值给解析器的对应成员
                free(parser->method);
                free(parser->uri);
                free(parser->version);
                parser->method = (char *)method;
                parser->uri = (char *)uri;
                parser->version = (char *)version;
                return 0;
            }
            free((char *)uri); // 出错, 释放内存
        }
        free((char *)method); // 出错, 释放内存
    }
    return -1;
}

// 解析和设置HTTP响应状态行关键信息
static int match_status_line(const char *version, size_t version_len, const char *code, size_t code_len,
                             const char *phrase, size_t phrase_len, http_parser_t *parser) {
    version = strndup(version, version_len);
    if (version) {
        code = strndup(code, code_len);
        if (code) {
            phrase = strndup(phrase, phrase_len);
            if (phrase) {
                if (strcmp(version, "HTTP/1.0") == 0 || strncmp(version, "HTTP/0", 6) == 0) {
                    parser->keep_alive = 0; // 禁用保持连接
                }

                // 识别那些没有消息体的响应
                // 1xx状态码: 这些响应通常只有状态行和头部, 他们本身没有消息体
                // 204 (No Content): 服务器成功处理了请求, 但不需要返回任何实体内容
                // 304 (Not Modified): 用于条件GET请求，表示资源未被修改，客户端应使用缓存版本，响应中不包含消息体
                if (*code == '1' || strcmp(code, "204") == 0 || strcmp(code, "304") == 0) {
                    parser->transfer_length = 0; // 消息体长度为0
                }
                // 先释放解析器中原有的字符串内存, 然后将新分配的字符串指针赋值给解析器的对应成员
                free(parser->version);
                free(parser->code);
                free(parser->phrase);
                parser->version = (char *)version;
                parser->code = (char *)code;
                parser->phrase = (char *)phrase;
                return 0;
            }
            free((char *)code);
        }
        free((char *)version);
    }
    return -1;
}

// HTTP头部字段专用解析器
static void check_message_header(const char *name, size_t name_len, const char *value, size_t value_len, http_parser_t *parser) {
    switch (name_len) {
    case 6: // 长度为6, 一般是"Except"
        if (strncasecmp(name, "Expect", 6) == 0) {
            // 检查值是否为 100-continue
            if (value_len == 12 && strncasecmp(value, "100-continue", 12) == 0) {
                parser->expect_continue = 1; // 设置 parser->expect_continue = 1, 表示客户端期望服务器准备接收主体
            }
        }
        break;
    case 10: // 长度为10, 一般是"Connection"或者"Keep-Alive"
        if (strncasecmp(name, "Connection", 10) == 0) {
            // 设置has_connection为1, 表示消息中含有Connection字段
            parser->has_connection = 1;
            // 检查值是否为 Keep-Alive 或 close
            if (value_len == 10 && strncasecmp(value, "Keep-Alive", 10) == 0) {
                // 字段值为Keep-Alive, 保持连接
                parser->keep_alive = 1;
            } else if (value_len == 5 && strncasecmp(value, "close", 5) == 0) {
                // 字段值为close, 设置keep_alive为0, 关闭保持连接
                parser->keep_alive = 0;
            }
        } else if (strncasecmp(name, "Keep-Alive", 10) == 0) {
            parser->has_keep_alive = 1; // 设置 has_keep_alive = 1, 通知解析器连接保持参数被显式设定
        }
        break;
    case 14: // 长度为14, 一般是“Content-Length”
        if (strncasecmp(name, "Content-Length", 14) == 0) {
            //
            parser->has_content_length = 1;
            if (*value >= '0' && *value <= '9' && value_len <= 15) {
                char buf[16];
                memcpy(buf, value, value_len);
                buf[value_len] = '\0';
                parser->content_length = atol(buf);
            }
        }
        break;
    case 17: // 长度为17, 一般是"Transfer-Encoding"
        if (strncasecmp(name, "Transfer-Encoding", 17) == 0) {
            // 优先比较长度, 长度匹配再进行不区分大小写的比较
            // 若值非 identity(通常是 chunked), 则设置 parser->chunked = 1，启用分块传输解析模式
            if (value_len != 8 || strncasecmp(value, "identity", 8) != 0) {
                parser->chunked = 1; // 字段值不是identify, 则通常是"chunked", 设置启用分块传输
            } else { parser->chunked = 0; } // 字段值是identify, 关闭分块传输
        }
        break;
    }
}

// HTTP起始行(请求行/状态行)解析
static int parse_start_line(const char *ptr, size_t len, http_parser_t *parser) {
    const char *p1, *p2, *p3;
    size_t l1, l2, l3;
    size_t i;
    int ret;

    // 特殊情况: 当HTTP头部的起始行就是一个空行(即连续的回车换行符 \r\n)时, 函数会立即跳过这两个字符并返回成功
    // 通常发生在解析连续头部块时, 快速跳过头部之间的分隔空行
    if (len >= 2 && ptr[0] == '\r' && ptr[1] == '\n') {
        parser->header_offset += 2;
        return 1;
    }
    const size_t min = MIN(HTTP_START_LINE_MAX, len);
    // min是起始行的最大长度, 再min范围内检查, 可以确保访问不会超出缓冲区ptr
    for (i = 0; i < min; i++) {
        if (ptr[i] == '\r') {
            // 检查i后面还有没有有效数据
            if (i == len - 1) {
                // 如果\r恰好是缓冲区的最后一个字符, 则返回0, 表示需要接收更多数据才能判断, 这体现了对流式数据处理的支持
                return 0;
            }
            // 确保i后面是有效数据后, 再判断是不是\n
            if (ptr[i + 1] != '\n') { return -2; } // 语法错误: \r后必须接\n

            len = i;
            while (len > 0 && ptr[len - 1] == ' ') { len--; } // 修剪末尾空格，定位字段

            p1 = ptr;
            while (*p1 == ' ') { p1++; } // 跳过行首空格, 令p1指向第一个字段的开头

            p2 = p1;
            while (p2 < ptr + len && *p2 != ' ') { p2++; } // 用p2定位第一个字段的结束位置

            if (p2 == ptr + len) { return -2; } // 语法错误: 没有凑齐三个字段

            l1 = (p2++) - p1; // 计算第一个字段的长度
            while (*p2 == ' ') { p2++; } // 跳过第一个字段和第二个字段之间的空格, 令p2指向第二个字段开头

            p3 = p2;
            while (p3 < ptr + len && *p3 != ' ') { p3++; } // 用p3定位第二个字段的结束位置

            if (p3 == ptr + len) { return -2; } // 语法错误: 没有凑齐三个字段

            l2 = p3++ - p2; // 计算第二个字段的长度
            while (*p3 == ' ') { p3++; } // 跳过第二个字段和第三个字段之间的空格, 令p3指向第三个字段开头

            l3 = ptr + len - p3; // 此时可得到第三个字段长度
            if (parser->is_resp) {
                // http响应
                ret = match_status_line(p1, l1, p2, l2, p3, l3, parser);
            } else {
                // http请求
                ret = match_request_line(p1, l1, p2, l2, p3, l3, parser);
            }

            if (ret < 0) { return ret; }

            parser->header_offset += i + 2; // 移动全局偏移量，跳过已解析的行
            parser->header_state = HPS_HEADER_NAME; // 状态机转移到“解析头部名”阶段
            return 1;
        }

        if (ptr[i] == '\0') { return -2; } // 语法错误, 没有遇到'\r'
    }

    if (i == HTTP_START_LINE_MAX) { return -2; } // HTTP起始行过长, 超出了解析器能安全处理的范围

    return 0;
}

// HTTP头部字段名称的解析
static int parse_header_name(const char *ptr, size_t len, http_parser_t *parser) {
    size_t min = MIN(HTTP_HEADER_NAME_MAX, len);
    size_t i;

    if (len >= 2 && ptr[0] == '\r' && ptr[1] == '\n') {
        // 遇到回车换行, 标志着请求头或者响应头的结束, 后续不再有新的头部字段.
        parser->header_offset += 2;
        parser->header_state = HPS_HEADER_COMPLETE;
        return 1;
    }
    //
    for (i = 0; i < min; i++) {
        if (ptr[i] == ':') {
            // 找到冒号后的处理
            if (i == 0) { return -2; } // 开头不能是冒号

            parser->name_buf[i] = '\0'; // 添加字符串结束符, 便于后续使用strcmp等函数进行比较
            parser->header_offset += i + 1; // 移动全局偏移量
            parser->header_state = HPS_HEADER_VALUE; // 状态转移: 下一个阶段应该开始解析这个头部字段对应的值了
            return 1;
        }

        // 过滤掉不允许在字段名中出现的控制字符(如ASCII值小于或等于空格的字符)
        // HTTP头部字段名应由可打印字符组成, 出现控制字符视为协议格式错误
        if ((signed char)ptr[i] <= ' ') { return -2; }
        // 累积字符到缓冲区
        parser->name_buf[i] = ptr[i];
    }
    if (i == HTTP_HEADER_NAME_MAX) return -2;
    return 0;
}

// 处理HTTP协议中可能出现的头部值跨行折叠情况
static int parse_header_value(const char *ptr, size_t len, http_parser_t *parser) {
    char header_value[HTTP_HEADER_VALUE_MAX];
    const char *end = ptr + len;
    const char *begin = ptr;
    size_t i = 0;
    int ret;

    while (1) {
        while (1) {
            if (ptr == end) { return 0; }
            // 跳过行首的空格和制表符
            if (*ptr == ' ' || *ptr == '\t') {
                ptr++;
            } else {
                break;
            }
        }
        // 逐个字符读取, 直到行尾(遇到'\r')
        while (1) {
            if (i == HTTP_HEADER_VALUE_MAX) { return -2; }

            header_value[i] = *ptr++;
            if (ptr == end) { return 0; }

            if (header_value[i] == '\r') { break; }
            // 除了制表符, 其他所有控制字符(如NULL、换行符等)都是非法的
            if ((signed char)header_value[i] < ' ' && header_value[i] != '\t') { return -2; }

            i++;
        }

        if (*ptr == '\n') { ptr++; } else { return -2; } // '\r'后面必须是'\n', 否则就是语法错误

        if (ptr == end) { return 0; } //

        // 修剪本行行尾空白字符
        while (i > 0) {
            if (header_value[i - 1] == ' ' || header_value[i - 1] == '\t') {
                i--;
            } else { break; }
        }

        if (*ptr != ' ' && *ptr != '\t') { break; } // 不是续行, 结束循环

        ptr++;
        header_value[i++] = ' '; // 将续行转换为一个空格
    }

    header_value[i] = '\0';
    ret = http_parser_add_header(parser->name_buf, strlen(parser->name_buf), header_value, i, parser);
    if (ret < 0) return ret;

    parser->header_offset += ptr - begin; // 移动全局偏移量
    parser->header_state = HPS_HEADER_NAME; // 准备解析下一个头部名
    return 1;
}

// HTTP报文头部解析的核心调度器
static int parse_message_header(const void *message, size_t size, http_parser_t *parser) {
    const char *ptr;
    size_t len;
    int ret;

    do {
        ptr = (const char *)message + parser->header_offset; // 计算当前解析位置
        len = size - parser->header_offset; // 计算剩余数据长度
        // 根据状态调用子解析函数
        if (parser->header_state == HPS_START_LINE) {
            ret = parse_start_line(ptr, len, parser);
        } else if (parser->header_state == HPS_HEADER_VALUE) {
            ret = parse_header_value(ptr, len, parser);
        } else /* if (parser->header_state == HPS_HEADER_NAME) */
        {
            ret = parse_header_name(ptr, len, parser);
            if (parser->header_state == HPS_HEADER_COMPLETE) { return 1; } // if语句恒为false？？？
        }
    } while (ret > 0);

    return ret;
}

#define CHUNK_SIZE_MAX		(2 * 1024 * 1024 * 1024U - HTTP_CHUNK_LINE_MAX - 4)

// 分块传输解析
static int parse_chunk_data(const char *ptr, size_t len, http_parser_t *parser) {
    size_t min = MIN(HTTP_CHUNK_LINE_MAX, len);
    size_t chunk_size;
    char *end;
    size_t i;

    for (i = 0; i < min; i++) {
        if (ptr[i] == '\r') {
            if (i == len - 1) { return 0; } // 数据不完整，需要更多

            if (ptr[i + 1] != '\n') { return -2; } // 语法错误: '\r'后面必须是'\n'

            // 将ptr开头的数字部分转换为unsigned int
            chunk_size = strtoul(ptr, &end, 16); // 以16进制解析. HTTP chunked 编码规定块大小必须用十六进制数字表示
            if (end == ptr) { return -2; } // 解析失败，无有效数字

            // 块大小为 0: 这是一个特殊信号, 表示整个分块传输结束(EOF)
            if (chunk_size == 0) {
                chunk_size = i + 2; // 计算本行消耗的字节数（大小行 + \r\n）
                parser->chunk_state = CPS_TRAILER_PART; // 状态转移至尾部解析
            } else if (chunk_size < CHUNK_SIZE_MAX) {
                // 块大小正常: 计算包含块数据及其前后CRLF的完整块长度
                chunk_size += i + 4; // 块大小 + 大小行长度 + 数据后的\r\n ？？？
                if (len < chunk_size) { return 0; } // 如果数据不够，等待下次调用
            } else { return -2; } // 块大小过长

            parser->chunk_offset += chunk_size; // 移动全局偏移量
            return 1; // 成功解析一个块
        }
    }
    if (i == HTTP_CHUNK_LINE_MAX) { return -2; }
    return 0;
}

// 解析位于所有数据块之后的可选尾部头部(Trailer)部分
static int parse_trailer_part(const char *ptr, size_t len, http_parser_t *parser) {
    size_t min = MIN(HTTP_TRAILER_LINE_MAX, len);
    size_t i;

    for (i = 0; i < min; i++) {
        if (ptr[i] == '\r') {
            if (i == len - 1) { return 0; }

            if (ptr[i + 1] != '\n') { return -2; }

            parser->chunk_offset += i + 2; // 移动全局偏移量，跳过刚解析的这行
            if (i == 0) { parser->chunk_state = CPS_CHUNK_COMPLETE; } // 遇到空行，标记整个分块传输完成
            return 1;
        }
    }
    if (i == HTTP_TRAILER_LINE_MAX) { return -2; }
    return 0;
}

// HTTP分块传输解析核心调度器
static int parse_chunk(const void *message, size_t size, http_parser_t *parser) {
    const char *ptr;
    size_t len;
    int ret;

    do {
        ptr = (const char *)message + parser->chunk_offset; // 计算当前解析位置
        len = size - parser->chunk_offset; // 计算剩余数据长度
        // 根据状态调用子解析函数
        if (parser->chunk_state == CPS_CHUNK_DATA) {
            ret = parse_chunk_data(ptr, len, parser);
        } else /* if (parser->chunk_state == CPS_TRAILER_PART) */
        {
            ret = parse_trailer_part(ptr, len, parser);
            if (parser->chunk_state == CPS_CHUNK_COMPLETE) { return 1; }
        }
    } while (ret > 0);

    return ret;
}

void http_parser_init(int is_resp, http_parser_t *parser) {
    parser->header_state = HPS_START_LINE; // 初始解析状态为解析请求行/状态行
    parser->header_offset = 0;
    parser->transfer_length = (size_t)-1;
    parser->content_length = is_resp ? (size_t)-1 : 0;
    parser->version = NULL;
    parser->method = NULL;
    parser->uri = NULL;
    parser->code = NULL;
    parser->phrase = NULL;
    INIT_LIST_HEAD(&parser->header_list);
    parser->msg_buf = NULL;
    parser->msg_size = 0;
    parser->buf_size = 0;
    parser->has_connection = 0;
    parser->has_content_length = 0;
    parser->has_keep_alive = 0;
    parser->expect_continue = 0;
    parser->keep_alive = 1;
    parser->chunked = 0;
    parser->complete = 0;
    parser->is_resp = is_resp;
}

// 将接收到的数据块追加到解析器的缓冲区中, 并智能地判断整个 HTTP 消息(包括头部和主体)是否已经完整接收
int http_parser_append_message(const void *buf, size_t *n, http_parser_t *parser) {
    int ret;

    // 避免了对已完整解析的消息进行不必要的操作
    if (parser->complete) {
        *n = 0; // 告知调用者本次未消费任何数据
        return 1; // 返回成功，因为消息早已完成
    }

    // 检查当前缓冲区是否足以容纳新数据. 如果不足, 则动态扩展缓冲区
    if (parser->msg_size + *n + 1 > parser->buf_size) {
        // 新大小至少为 HTTP_MSGBUF_INIT_SIZE和当前缓冲区大小两倍中的较大者
        size_t new_size = MAX(HTTP_MSGBUF_INIT_SIZE, 2 * parser->buf_size);
        // ... 指数增长直到满足需求
        while (new_size < parser->msg_size + *n + 1) { new_size *= 2; }
        // 当需要扩容时, 新大小至少是当前大小的两倍. 这种策略摊还了多次扩容的成本, 避免了每次追加数据都可能触发realloc的性能陷阱, 是动态数组的经典优化手段
        void *new_base = realloc(parser->msg_buf, new_size);
        if (!new_base) { return -1; }

        parser->msg_buf = new_base;
        parser->buf_size = new_size;
    }
    // 新数据被追加到缓冲区末尾
    memcpy((char *)parser->msg_buf + parser->msg_size, buf, *n);
    // 并更新总消息大小
    parser->msg_size += *n;
    // 检查头部是否已解析完成. 如果没有, 则调用 parse_message_header
    if (parser->header_state != HPS_HEADER_COMPLETE) {
        ret = parse_message_header(parser->msg_buf, parser->msg_size, parser);
        if (ret <= 0) { return ret; } // 依赖头部解析结果

        if (parser->chunked) {
            // 初始化分块解析状态
            parser->chunk_offset = parser->header_offset; // 标记头部结束后的主体开始位置
            parser->chunk_state = CPS_CHUNK_DATA; // 状态设为 CPS_CHUNK_DATA, 准备解析数据块
        } else if (parser->transfer_length == (size_t)-1) {
            // 如果不分块，且传输长度尚未设置(初始值通常默认为(size_t)-1)
            // 则从已解析的 Content-Length头部获取内容长度。这用于处理具有明确长度的消息体
            parser->transfer_length = parser->content_length;
        }
    }

    if (parser->transfer_length != (size_t)-1) {
        size_t total = parser->header_offset + parser->transfer_length;
        // 数据量已达到承诺的长度
        if (parser->msg_size >= total) {
            *n -= parser->msg_size - total; // 计算本批次实际消费的数据量
            parser->msg_size = total; // 修剪缓冲区，去除多余数据
            parser->complete = 1; // 标记完成
            return 1;
        }
        return 0; // 数据不足, 需要继续接收
    }
    // 既不分块也无固定长度, 等待数据
    if (!parser->chunked) { return 0; }

    if (parser->chunk_state != CPS_CHUNK_COMPLETE) {
        // 如果启用分块编码且分块解析未完成, 则调用 parse_chunk函数.
        // 该函数会解析分块格式（每个块由长度、数据、\r\n组成），直到遇到长度为0的终止块
        ret = parse_chunk(parser->msg_buf, parser->msg_size, parser);
        if (ret <= 0) { return ret; }
    }
    // 分块解析完成后的处理
    *n -= parser->msg_size - parser->chunk_offset;
    parser->msg_size = parser->chunk_offset;
    parser->complete = 1;
    return 1;
}

int is_http_parser_header_complete(const http_parser_t *parser) {
    return parser->header_state == HPS_HEADER_COMPLETE;
}

// 从已解析的HTTP消息中安全提取消息体（Body）
int http_parser_get_body(const void **body, size_t *size, const http_parser_t *parser) {
    // 确保 消息体已完全接收并解析成功, 同时HTTP头部也已经成功解析
    if (parser->complete && parser->header_state == HPS_HEADER_COMPLETE) {
        *body = (char *)parser->msg_buf + parser->header_offset; // 获取消息体数据在缓冲区中的指针
        *size = parser->msg_size - parser->header_offset; // 获取纯消息体的长度
        // 在缓冲区有效数据(msg_size字节)的下一个字节处写入了一个空字符.
        // 方便调用者将消息体作为C风格字符串(即以 \0结尾的字符数组)来处理
        ((char *)parser->msg_buf)[parser->msg_size] = '\0';
        // 这要求缓冲区 msg_buf 的实际分配大小(buf_size)至少为 msg_size + 1, 以确保有空间写入 \0 且不会发生内存越界
        return 0;
    }
    return 1;
}

int http_parser_set_method(const char *method, http_parser_t *parser) {
    method = strdup(method);
    if (method) {
        free(parser->method);
        parser->method = (char *)method;
        return 0;
    }
    return -1;
}

int http_parser_set_uri(const char *uri, http_parser_t *parser) {
    uri = strdup(uri);
    if (uri) {
        free(parser->uri);
        parser->uri = (char *)uri;
        return 0;
    }
    return -1;
}

int http_parser_set_version(const char *version, http_parser_t *parser) {
    version = strdup(version);
    if (version) {
        free(parser->version);
        parser->version = (char *)version;
        return 0;
    }
    return -1;
}

int http_parser_set_code(const char *code, http_parser_t *parser) {
    code = strdup(code);
    if (code) {
        free(parser->code);
        parser->code = (char *)code;
        return 0;
    }
    return -1;
}

int http_parser_set_phrase(const char *phrase, http_parser_t *parser) {
    phrase = strdup(phrase);
    if (phrase) {
        free(parser->phrase);
        parser->phrase = (char *)phrase;
        return 0;
    }
    return -1;
}

// 追加一个新的头部字段, 允许同名字段共存
int http_parser_add_header(const void *name, size_t name_len, const void *value,
                           size_t value_len, http_parser_t *parser) {
    if (add_message_header((const char *)name, name_len, (const char *)value, value_len, parser) >= 0) {
        check_message_header((const char *)name, name_len, (const char *)value, value_len, parser);
        return 0;
    }
    return -1;
}


// 设置一个头部字段, 覆盖已存在的同名字段
int http_parser_set_header(const void *name, size_t name_len, const void *value,
                           size_t value_len, http_parser_t *parser) {
    if (set_message_header((const char *)name, name_len, (const char *)value, value_len, parser) >= 0) {
        check_message_header((const char *)name, name_len, (const char *)value, value_len, parser);
        return 0;
    }
    return -1;
}

void http_parser_deinit(http_parser_t *parser) {
    struct __header_line *line;
    struct list_head *pos, *tmp;

    list_for_each_safe(pos, tmp, &parser->header_list) {
        line = list_entry(pos, struct __header_line, list);
        list_del(pos);
        if (line->buf != (char *)(line + 1)) { free(line->buf); }

        free(line);
    }

    free(parser->version);
    free(parser->method);
    free(parser->uri);
    free(parser->code);
    free(parser->phrase);
    free(parser->msg_buf);
}

int http_header_cursor_next(const void **name, size_t *name_len, const void **value,
                            size_t *value_len, http_header_cursor_t *cursor) {
    struct __header_line *line;

    if (cursor->next->next != cursor->head) {
        cursor->next = cursor->next->next;
        line = list_entry(cursor->next, struct __header_line, list);
        *name = line->buf;
        *name_len = line->name_len;
        *value = line->buf + line->name_len + 2;
        *value_len = line->value_len;
        return 0;
    }

    return 1;
}

// 在HTTP头部链表中查找特定字段名并返回其对应值(通过传入的指针返回)
int http_header_cursor_find(const void *name, size_t name_len, const void **value,
                            size_t *value_len, http_header_cursor_t *cursor) {
    struct __header_line *line;

    // 检查是否已经遍历到链表的末尾(即下一个节点是否指向链表头)
    while (cursor->next->next != cursor->head) {
        cursor->next = cursor->next->next;
        line = list_entry(cursor->next, struct __header_line, list);
        if (line->name_len == name_len) {
            if (strncasecmp(line->buf, (const char *)name, name_len) == 0) {
                *value = line->buf + name_len + 2;
                *value_len = line->value_len;
                return 0;
            }
        }
    }

    return 1;
}

// 删除HTTP头部链表中指定节点
int http_header_cursor_erase(http_header_cursor_t *cursor) {
    struct __header_line *line;

    if (cursor->next != cursor->head) {
        line = list_entry(cursor->next, struct __header_line, list);
        cursor->next = cursor->next->prev;
        list_del(&line->list);
        // line + 1表示在 struct __header_line结构体之后的内存地址.
        // 如果line->buf等于这个地址, 说明字符串缓冲区是内嵌在结构体之后分配的(通常通过一次性的 malloc);
        // 如果不相等, 则说明buf指向一个独立分配的内存块
        if (line->buf != (char *)(line + 1)) {
            // 释放独立分配的缓冲区
            free(line->buf);
        }

        free(line);
        return 0;
    }

    return 1;
}