//
// Created by ldk on 10/14/25.
//

#ifndef MYWORKFLOW_HTTP_PARSER_H
#define MYWORKFLOW_HTTP_PARSER_H

#include <stddef.h>
#include "list.h"

#define HTTP_HEADER_NAME_MAX	64

typedef struct __http_parser {
    int header_state; // 头部解析状态机, 记录解析头部字段名或值的当前阶段
    int chunk_state; // 分块传输编码解析状态机, 用于解析Transfer-Encoding: chunked的复杂格式
    size_t header_offset; // 已经解析的头部长度. 在当前头部字段(名或值)中已解析的字节偏移量
    size_t chunk_offset; // 在当前分块数据中已解析的字节偏移量
    size_t content_length; // 从 Content-Length头部获取的消息体确切长度(字节数)
    size_t transfer_length; // 消息体预期长度(or 实际传输的数据总长度???), 对于分块传输, 此值会动态计算并增长
    char *version; // 指向解析出的HTTP版本字段的指针. 如 "HTTP/1.1"
    char *method; // 指向解析出的HTTP方法字段的指针. 如 "GET", "POST"
    char *uri; // 指向解析出的请求 URI 的指针
    char *code; // 指向解析出的 HTTP 响应状态码字符串的指针. 如 "200"
    char *phrase; // 指向解析出的 HTTP 响应原因短语的指针. 如 "OK"
    struct list_head header_list; // 用于存储所有解析出的 HTTP 头部键值对的链表结构
    char name_buf[HTTP_HEADER_NAME_MAX]; // 固定大小的缓冲区, 用于暂存正在解析的头部字段名
    void *msg_buf; // 指向动态分配的消息体缓冲区
    size_t msg_size; // 消息体缓冲区中当前已存储的数据大小
    size_t buf_size; // 消息体缓冲区的总容量
    char has_connection; // 布尔标志. 表示消息中是否包含 Connection 头部
    char has_content_length; // 布尔标志. 表示消息中是否包含 Content-Length 头部
    char has_keep_alive; // 布尔标志. 表示消息中是否包含 Keep-Alive 头部或相关指示
    char expect_continue; // 布尔标志. 表示客户端期望收到 100 Continue 响应后再发送消息体
    char keep_alive; // 布尔标志. 表示当前连接是否应保持长连接
    char chunked; // 布尔标志，表示消息体是否采用分块传输编码
    char complete; // 布尔标志. 表示整个 HTTP 消息(头部+主体)是否已完全解析完毕
    char is_resp; // 布尔标志. 标识此解析器实例是用于解析 HTTP响应(1) 还是 HTTP请求(0)
} http_parser_t;

// 一个轻量级的迭代器, 用于安全、线性地遍历存储在 http_parser_t 的 header_list 中的所有HTTP头部
typedef struct __http_header_cursor {
    const struct list_head *head; // 指向链表头部, 标识遍历的终点(因为是循环链表)
    const struct list_head *next; // 初始指向链表头
} http_header_cursor_t;

#ifdef __cplusplus
extern "C" {

#endif

void http_parser_init(int is_resp, http_parser_t *parser);
int http_parser_append_message(const void *buf, size_t *n, http_parser_t *parser);
int http_parser_get_body(const void **body, size_t *size, const http_parser_t *parser);
int is_http_parser_header_complete(const http_parser_t *parser);
int http_parser_set_method(const char *method, http_parser_t *parser);
int http_parser_set_uri(const char *uri, http_parser_t *parser);
int http_parser_set_version(const char *version, http_parser_t *parser);
int http_parser_set_code(const char *code, http_parser_t *parser);
int http_parser_set_phrase(const char *phrase, http_parser_t *parser);
int http_parser_add_header(const void *name, size_t name_len, const void *value, size_t value_len, http_parser_t *parser);
int http_parser_set_header(const void *name, size_t name_len, const void *value, size_t value_len, http_parser_t *parser);
void http_parser_deinit(http_parser_t *parser);

int http_header_cursor_next(const void **name, size_t *name_len, const void **value, size_t *value_len, http_header_cursor_t *cursor);
int http_header_cursor_find(const void *name, size_t name_len, const void **value, size_t *value_len, http_header_cursor_t *cursor);
int http_header_cursor_erase(http_header_cursor_t *cursor);

#ifdef __cplusplus
}
#endif

static inline const char *http_parser_get_method(const http_parser_t *parser) {
    return parser->method;
}

static inline const char *http_parser_get_uri(const http_parser_t *parser) {
    return parser->uri;
}

static inline const char *http_parser_get_version(const http_parser_t *parser) {
    return parser->version;
}

static inline const char *http_parser_get_code(const http_parser_t *parser) {
    return parser->code;
}

static inline const char *http_parser_get_phrase(const http_parser_t *parser) {
    return parser->phrase;
}

static inline int http_parser_chunked(const http_parser_t *parser) {
    return parser->chunked;
}

static inline int http_parser_keep_alive(const http_parser_t *parser) {
    return parser->keep_alive;
}

static inline int http_parser_has_connection(const http_parser_t *parser) {
    return parser->has_connection;
}

static inline int http_parser_has_content_length(const http_parser_t *parser) {
    return parser->has_content_length;
}

static inline int http_parser_has_keep_alive(const http_parser_t *parser) {
    return parser->has_keep_alive;
}

static inline void http_parser_close_message(http_parser_t *parser) {
    parser->complete = 1;
}

// 初始化 http头部 遍历游标
static inline void http_header_cursor_init(http_header_cursor_t *cursor, const http_parser_t *parser) {
    cursor->head = &parser->header_list; // 记录链表起点
    cursor->next = cursor->head; // 当前指针指向链表头
}

// 将 HTTP 头部遍历游标重置到起始位置
static inline void http_header_cursor_rewind(http_header_cursor_t *cursor) {
    cursor->next = cursor->head;
}

// 空实现
// 即使当前不需要清理工作, 定义一个 deinit函数也为未来可能的需求变化预留了接口.
// 如果未来游标结构需要分配资源(如缓存), 只需修改此函数内部实现即可, 无需改变调用它的代码, 这符合软件设计的开闭原则
static inline void http_header_cursor_deinit(http_header_cursor_t *cursor) {}

#endif //MYWORKFLOW_HTTP_PARSER_H