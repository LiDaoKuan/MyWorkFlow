//
// Created by ldk on 10/14/25.
//

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

// 高性能的HTTP请求头字段构造器:
static int __add_message_header(const char *name, size_t name_len, const char *value, size_t value_len, http_parser_t *parser) {
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
static int __set_message_header(const char *name, size_t name_len, const char *value, size_t value_len, http_parser_t *parser) {
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
    return __add_message_header(name, name_len, value, value_len, parser);
}

// 解析和设置HTTP请求行关键信息
static int __match_request_line(const char *method, size_t method_len, const char *uri, size_t uri_len,
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

// 解析HTTP响应状态行
static int __match_status_line(const char *version, size_t version_len, const char *code, size_t code_len,
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

static void __check_message_header(const char *name, size_t name_len, const char *value, size_t value_len, http_parser_t *parser) {
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
            if (value_len != 8 || strncasecmp(value, "identity", 8) != 0) {
                parser->chunked = 1;
            } else { parser->chunked = 0; }
        }
        break;
    }
}