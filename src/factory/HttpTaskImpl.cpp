//
// Created by ldk on 12/20/25.
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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
           Liu Kai (liukaidx@sogou-inc.com)
           Xie Han (xiehan@sogou-inc.com)
           Li Yingxin (liyingxin@sogou-inc.com)
*/

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "WFTaskError.h"
#include "WFTaskFactory.h"
#include "StringUtil.h"
#include "WFGlobal.h"
#include "HttpUtil.h"
#include "SSLWrapper.h"
#include "PackageWrapper.h"
#include "HttpTaskImpl.inl"

using namespace protocol;

#define HTTP_KEEPALIVE_DEFAULT	(60 * 1000)     // 默认Keep-Alive超时60秒（需要传入毫秒单位参数）
#define HTTP_KEEPALIVE_MAX		(300 * 1000)    // 最大允许Keep-Alive超时300秒

/**********Client**********/

/**
 * @brief 对HTTP Basic认证信息进行Base64编码
 * @param p 格式为"username:password"的原始字符串
 * @param auth 输出参数, 填充编码后的"Basic <base64>"字符串
 * @return 0 成功
 * @return -1 内存分配失败
 */
static int __encode_auth(const char *p, std::string &auth) {
    const size_t len = strlen(p);
    const size_t base64_len = (len + 2) / 3 * 4; // Base64编码后长度
    const auto base64 = static_cast<char *>(malloc(base64_len + 1));

    if (!base64) {
        return -1;
    }

    // 使用OpenSSL进行Base64编码
    EVP_EncodeBlock(reinterpret_cast<unsigned char *>(base64), reinterpret_cast<const unsigned char *>(p), len);
    auth.append("Basic ");
    auth.append(base64, base64_len); // 仅追加编码内容, 不含终止符

    free(base64);
    return 0;
}

/**
 * @brief 支持重定向/重试的HTTP客户端任务
 * 继承自WFComplexClientTask, 实现HTTP特有的连接管理、认证、重定向逻辑
 */
class ComplexHttpTask : public WFComplexClientTask<HttpRequest, HttpResponse> {
public:
    /**
     * @param redirect_max 允许的最大重定向次数
     * @param retry_max 允许的最大重试次数
     * @param callback 用户回调函数
     */
    ComplexHttpTask(int redirect_max, int retry_max, http_callback_t &&callback) :
        WFComplexClientTask(retry_max, std::move(callback)),
        redirect_max_(redirect_max),
        redirect_count_(0) {
        HttpRequest *client_req = this->get_req();
        // 设置默认请求方法和HTTP版本
        client_req->set_method(HttpMethodGet);
        client_req->set_http_version("HTTP/1.1");
    }

    // 重写基类关键虚函数
protected:
    CommMessageOut *message_out() override; // 请求发送前的预处理
    CommMessageIn *message_in() override;   // 响应接收后的处理
    int keep_alive_timeout() override;      // 动态计算Keep-Alive超时
    bool init_success() override;           // URI解析成功后的初始化
    void init_failed() override;            // URI解析失败的处理
    bool finish_once() override;            // 单次请求完成后的状态机

protected:
    /**
     * @brief 检查是否需要重定向
     * @param uri 当前请求的URI
     * @param new_uri 输出参数，存储重定向目标URI
     * @return true需要重定向，false不需要
     */
    bool need_redirect(const ParsedURI &uri, ParsedURI &new_uri);

    /**
     * @brief 解析Location头生成新URI
     * @param client_resp 服务器响应
     * @param uri 当前请求URI
     * @param new_uri 输出参数，存储解析后的新URI
     * @return true解析成功，false失败（如超过重定向限制）
     */
    bool redirect_url(HttpResponse *client_resp, const ParsedURI &uri, ParsedURI &new_uri);

    /**
     * @brief 设置空请求（用于初始化失败场景）
     * 移除Host/Authorization头，设置默认URI
     */
    void set_empty_request();

    /**
     * @brief 响应完整性检查
     * 处理服务器异常断开连接等边界情况
     */
    void check_response();

private:
    int redirect_max_;   // 全局最大重定向次数
    int redirect_count_; // 当前已重定向次数
};

/**
 * @brief 请求发送前的预处理（关键: 动态设置请求头）
 * 1. 补充Content-Length/Chunked头
 * 2. 处理Connection/Keep-Alive头
 * 3. 动态计算Keep-Alive超时时间
 */
CommMessageOut *ComplexHttpTask::message_out() {
    HttpRequest *req = this->get_req();
    struct HttpMessageHeader header;
    bool is_alive; // 标记是否启用Keep-Alive

    // 非分块传输且无Content-Length
    if (!req->is_chunked() && !req->has_content_length_header()) {
        size_t body_size = req->get_output_body_size();
        const char *method = req->get_method();

        if (body_size != 0 || strcmp(method, "POST") == 0 ||
            strcmp(method, "PUT") == 0) {
            char buf[32];
            header.name = "Content-Length";
            header.name_len = strlen("Content-Length");
            header.value = buf;
            header.value_len = sprintf(buf, "%zu", body_size);
            req->add_header(&header);
        }
    }
    // Connection头处理
    if (req->has_connection_header()) {
        is_alive = req->is_keep_alive(); // 保留用户设置
    } else {
        header.name = "Connection";
        header.name_len = strlen("Connection");
        is_alive = (this->keep_alive_timeo != 0); // 依据框架超时设置
        if (is_alive) {
            header.value = "Keep-Alive";
            header.value_len = strlen("Keep-Alive");
        } else {
            header.value = "close";
            header.value_len = strlen("close");
        }

        req->add_header(&header); // 补充缺失的Connection头
    }

    // 禁用Keep-Alive时重置超时
    if (!is_alive) {
        this->keep_alive_timeo = 0;
    }
    // 启用Keep-Alive且存在Keep-Alive头时解析超时参数
    else if (req->has_keep_alive_header()) {
        HttpHeaderCursor cursor(req);

        // req---Connection: Keep-Alive
        // req---Keep-Alive: timeout=0,max=100
        // 标准格式: Keep-Alive: timeout=5, max=100
        header.name = "Keep-Alive";
        header.name_len = strlen("Keep-Alive");
        header.value = NULL;
        header.value_len = 0;
        if (cursor.find(&header)) {
            std::string keep_alive(static_cast<const char *>(header.value), header.value_len);
            std::vector<std::string> params = StringUtil::split(keep_alive, ',');

            for (const auto &kv : params) {
                std::vector<std::string> arr = StringUtil::split(kv, '=');
                if (arr.size() < 2) {
                    arr.emplace_back("0"); // 处理无值参数
                }

                std::string key = StringUtil::strip(arr[0]);
                std::string val = StringUtil::strip(arr[1]);
                if (strcasecmp(key.c_str(), "timeout") == 0) {
                    // 转换为毫秒, 限制最大值
                    this->keep_alive_timeo = 1000 * atoi(val.c_str());
                    break; // 只取第一个timeout参数
                }
            }
        }

        // 限制超时范围: 0 ~ HTTP_KEEPALIVE_MAX
        if (static_cast<unsigned int>(this->keep_alive_timeo) > HTTP_KEEPALIVE_MAX) {
            this->keep_alive_timeo = HTTP_KEEPALIVE_MAX;
        }
    }

    // 交由基类完成最终消息构建
    return this->WFComplexClientTask::message_out();
}

/**
 * @brief 响应接收后的处理
 * 特殊处理HEAD请求: 无响应体, 直接结束解析
 */
CommMessageIn *ComplexHttpTask::message_in() {
    HttpResponse *resp = this->get_resp();

    // HEAD请求无响应体, 需显式结束解析
    if (strcmp(this->get_req()->get_method(), HttpMethodHead) == 0) {
        resp->parse_zero_body();
    }

    return this->WFComplexClientTask::message_in();
}

/**
 * @brief 动态计算Keep-Alive超时
 * @return 有效超时值(毫秒), 响应要求关闭连接时返回0
 */
int ComplexHttpTask::keep_alive_timeout() {
    return this->resp.is_keep_alive() ? this->keep_alive_timeo : 0;
}

/**
 * @brief 初始化失败时的空请求设置
 * 用于URI解析失败等场景, 避免后续处理异常
 */
void ComplexHttpTask::set_empty_request() {
    HttpRequest *client_req = this->get_req();
    HttpHeaderCursor cursor(client_req);
    struct HttpMessageHeader header = {
        .name = "Host",
        .name_len = strlen("Host"),
    };

    // 重置为最简请求
    client_req->set_request_uri("/");
    cursor.find_and_erase(&header); // 移除Host头

    header.name = "Authorization";
    header.name_len = strlen("Authorization");
    cursor.find_and_erase(&header); // 移除认证头
}

/**
 * @brief URI解析失败的处理
 * 调用空请求设置, 避免使用无效URI
 */
void ComplexHttpTask::init_failed() {
    this->set_empty_request();
}

/**
 * @brief URI解析成功后的初始化
 * 1. 验证scheme（http/https）
 * 2. 构建请求URI（path+query）
 * 3. 设置Host头（含端口逻辑）
 * 4. 处理Basic认证
 * @return true 初始化成功
 * @return false 失败（设置错误状态）
 */
bool ComplexHttpTask::init_success() {
    HttpRequest *client_req = this->get_req();
    std::string request_uri;
    std::string header_host;
    bool is_ssl;

    // 验证scheme
    if (uri_.scheme && strcasecmp(uri_.scheme, "http") == 0) {
        is_ssl = false;
    } else if (uri_.scheme && strcasecmp(uri_.scheme, "https") == 0) {
        is_ssl = true;
    } else {
        this->state = WFT_STATE_TASK_ERROR;
        this->error = WFT_ERR_URI_SCHEME_INVALID;
        return false;
    }

    //todo http+unix
    //https://stackoverflow.com/questions/26964595/whats-the-correct-way-to-use-a-unix-domain-socket-in-requests-framework
    //https://stackoverflow.com/questions/27037990/connecting-to-postgres-via-database-url-and-unix-socket-in-rails

    // 构建请求路径
    if (uri_.path && uri_.path[0]) {
        request_uri = uri_.path;
    } else {
        request_uri = "/"; // 默认根路径
    }

    // 拼接查询参数
    if (uri_.query && uri_.query[0]) {
        request_uri += "?";
        request_uri += uri_.query;
    }

    // 构建Host头（RFC标准：不含默认端口）
    if (uri_.host && uri_.host[0]) {
        header_host = uri_.host;
    }

    // 非默认端口需显式包含在Host头中
    if (uri_.port && uri_.port[0]) {
        int port = atoi(uri_.port);

        if (is_ssl) {
            // HTTPS默认端口443
            if (port != 443) {
                header_host += ":";
                header_host += uri_.port;
            }
        } else {
            // HTTP默认端口80
            if (port != 80) {
                header_host += ":";
                header_host += uri_.port;
            }
        }
    }

    // 设置传输层类型（SSL/TCP）
    this->WFComplexClientTask::set_transport_type(is_ssl ? TT_TCP_SSL : TT_TCP);
    client_req->set_request_uri(request_uri.c_str());
    client_req->set_header_pair("Host", header_host.c_str());

    // 处理Basic认证（userinfo格式：username:password）
    if (uri_.userinfo && uri_.userinfo[0]) {
        std::string userinfo(uri_.userinfo);
        std::string http_auth;

        StringUtil::url_decode(userinfo); // URL解码（如%40转@）

        if (__encode_auth(userinfo.c_str(), http_auth) < 0) {
            this->state = WFT_STATE_SYS_ERROR;
            this->error = errno; // 保存内存分配错误
            return false;
        }

        client_req->set_header_pair("Authorization", http_auth.c_str());
    }

    return true;
}

/**
 * @brief 解析Location头生成新URI
 * 处理相对路径/绝对路径等复杂情况
 * @return true 成功
 * @return false 失败（如超过重定向限制）
 */
bool ComplexHttpTask::redirect_url(HttpResponse *client_resp, const ParsedURI &uri, ParsedURI &new_uri) {
    // 检查重定向次数限制
    if (redirect_count_ < redirect_max_) {
        redirect_count_++;
        std::string url;
        HttpHeaderCursor cursor(client_resp);

        // 获取Location头
        if (!cursor.find("Location", url) || url.empty()) {
            this->state = WFT_STATE_TASK_ERROR;
            this->error = WFT_ERR_HTTP_BAD_REDIRECT_HEADER;
            return false;
        }

        // 相对路径处理（RFC 7231 Section 7.1.2）
        if (url[0] == '/') {
            // 非网络路径（如"/path"）
            if (url[1] != '/') {
                // 保留原始端口
                if (uri.port) {
                    url = ':' + (uri.port + url);
                }
                // 拼接原始host
                url = "//" + (uri.host + url);
            }
            // 拼接原始scheme
            url = uri.scheme + (':' + url);
        }
        // 解析新URI
        URIParser::parse(url, new_uri);
        return true;
    }
    // 超过重定向限制
    return false;
}

/**
 * @brief 检查是否需要重定向及方法转换
 * 遵循RFC 7231重定向规范：
 * - 301/302/303: 非GET/HEAD请求转为GET
 * - 307/308: 保持原请求方法
 * @return true 需要重定向
 * @return false 不需要
 */
bool ComplexHttpTask::need_redirect(const ParsedURI &uri, ParsedURI &new_uri) {
    HttpRequest *client_req = this->get_req();
    HttpResponse *client_resp = this->get_resp();
    const char *status_code_str = client_resp->get_status_code();
    const char *method = client_req->get_method();

    if (!status_code_str || !method) {
        return false;
    }

    int status_code = atoi(status_code_str);

    switch (status_code) {
    case 301: // Moved Permanently
    case 302: // Found
    case 303: // See Other
        if (redirect_url(client_resp, uri, new_uri)) {
            // 非GET/HEAD方法转为GET（RFC规定）
            if (strcasecmp(method, HttpMethodGet) != 0 &&
                strcasecmp(method, HttpMethodHead) != 0) {
                client_req->set_method(HttpMethodGet);
            }

            return true;
        } else {
            break;
        }
    case 307: // Temporary Redirect
    case 308: // Permanent Redirect
        if (redirect_url(client_resp, uri, new_uri)) {
            // 保持原请求方法
            return true;
        } else {
            break;
        }

    default: break;
    }

    return false;
}

/**
 * @brief 响应完整性边界检查
 * 处理服务器异常断开连接（ECONNRESET）但响应头完整的情况
 * 典型场景: 服务器发送完响应头后关闭连接（无Content-Length/分块）
 */
void ComplexHttpTask::check_response() {
    HttpResponse *resp = this->get_resp();
    resp->end_parsing(); // 确保解析完成

    // 处理服务器提前关闭连接
    if (this->state == WFT_STATE_SYS_ERROR && this->error == ECONNRESET) {
        /* Servers can end the message by closing the connection. */
        /* 服务器通过关闭连接结束消息的合法场景 */
        if (resp->is_header_complete() && !resp->is_chunked() &&
            !resp->has_content_length_header()) {
            this->state = WFT_STATE_SUCCESS; // 修正为成功状态
            this->error = 0;
        }
    }
}

/**
 * @brief 单次请求完成后的状态机
 * 1. 响应完整性检查
 * 2. 重定向处理（含认证信息继承）
 * 3. 重试控制
 * @return true 任务结束
 * @return false 需重试（此处始终返回true）
 */
bool ComplexHttpTask::finish_once() {
    // 非成功状态需进行完整性检查
    if (this->state != WFT_STATE_SUCCESS) {
        this->check_response();
    }

    if (this->state == WFT_STATE_SUCCESS) {
        ParsedURI new_uri;
        if (this->need_redirect(uri_, new_uri)) // 检查是否需要重定向
        {
            if (uri_.userinfo && strcasecmp(uri_.host, new_uri.host) == 0) // 重定向安全策略: 仅相同host继承认证信息
            {
                if (!new_uri.userinfo) // 新URI无认证信息
                {
                    new_uri.userinfo = uri_.userinfo; // 继承原始认证
                    uri_.userinfo = nullptr;          // 防止重复释放
                }
            }
            // 不同host时清除当前请求的认证头（安全考虑）
            else if (uri_.userinfo) {
                HttpRequest *client_req = this->get_req();
                HttpHeaderCursor cursor(client_req);
                struct HttpMessageHeader header = {
                    .name = "Authorization",
                    .name_len = strlen("Authorization")
                };
                cursor.find_and_erase(&header);
            }
            // 触发重定向（基类将重置任务状态）
            this->set_redirect(new_uri);
        }
        // 失败状态且无需重定向时禁用重试
        else if (this->state != WFT_STATE_SUCCESS) {
            this->disable_retry(); // 设置retry_times_ = retry_max_
        }
    }
    return true;
}

/*******Proxy Client*******/

static SSL *__create_ssl(SSL_CTX *ssl_ctx) {
    BIO *wbio; // 写BIO: SSL加密后的数据将写入此缓冲区
    BIO *rbio; // 读BIO: SSL从该缓冲区读取待解密的原始数据
    SSL *ssl;  // 要创建的SSL对象

    // 创建读BIO（内存缓冲区）
    rbio = BIO_new(BIO_s_mem());
    if (rbio) {
        // 创建写BIO（内存缓冲区）
        wbio = BIO_new(BIO_s_mem());
        if (wbio) {
            // 基于SSL上下文创建SSL对象
            ssl = SSL_new(ssl_ctx);
            if (ssl) {
                /**
                 * 4. 关键步骤: 将BIO绑定到SSL对象
                 *
                 * SSL_set_bio(ssl, rbio, wbio) 执行：
                 * - 将rbio设置为SSL的读数据源
                 * - 将wbio设置为SSL的写数据目标
                 * - SSL对象将接管两个BIO的生命周期（成功时调用者不再需要BIO_free）
                 *
                 * 内存BIO的工作流程:
                 * 1) 应用从网络接收数据 -> 写入rbio -> SSL_read()解密
                 * 2) 应用调用SSL_write()加密 -> 数据存入wbio -> 从wbio读取发送到网络
                 */
                SSL_set_bio(ssl, rbio, wbio);
                return ssl; // 成功返回SSL对象
            }
            // 错误处理: SSL创建失败
            BIO_free(wbio); // 释放写BIO（SSL未接管所有权）
        }
        // 错误处理: 写BIO创建失败
        BIO_free(rbio); // 释放读BIO
    }
    return nullptr;
}

/**
 * @class ComplexHttpProxyTask
 * @brief 处理复杂HTTP代理请求的任务类, 支持HTTP/HTTPS代理、身份验证和连接复用
 *
 * 该类扩展了基础的HTTP任务功能, 专门处理代理场景:
 * 1. 支持普通HTTP代理和HTTPS隧道代理(CONNECT方法)
 * 2. 处理代理认证(Proxy-Authorization头)
 * 3. 维护原始用户请求URI与代理目标URI的映射
 * 4. 管理SSL连接的特殊生命周期(握手、加密通信)
 *
 * 设计关键点：
 * - 代理连接与普通HTTP连接的抽象统一
 * - SSL连接通过组合而非继承方式集成
 * - 状态机驱动的连接初始化流程
 * - 零拷贝优化: 使用移动语义处理URI对象
 *
 * 典型工作流程:
 * 1. 用户设置目标URI(set_user_uri)
 * 2. 代理任务解析URI确定是否需要SSL隧道
 * 3. 与代理服务器建立连接(明文或SSL)
 * 4. 发送CONNECT请求(HTTPS情况)或直接转发请求(HTTP情况)
 * 5. 处理代理认证挑战(407响应)
 * 6. 完成端到端通信
 */
class ComplexHttpProxyTask : public ComplexHttpTask {
public:
    /**
     * @param redirect_max 允许的最大重定向次数
     * @param retry_max 允许的最大重试次数
     * @param callback 请求完成后的回调函数
     */
    ComplexHttpProxyTask(int redirect_max, int retry_max, http_callback_t &&callback) :
        ComplexHttpTask(redirect_max, retry_max, std::move(callback)), is_user_request_(true) {}

    /**
     * @brief 设置用户请求的目标URI(移动语义版本)
     * @param uri 已解析的URI对象, 通过移动语义转移所有权
     */
    void set_user_uri(ParsedURI &&uri) { user_uri_ = std::move(uri); }

    /**
     * @brief 设置用户请求的目标URI(拷贝语义版本)
     * @param uri 已解析的URI对象, 通过拷贝创建副本
     */
    void set_user_uri(const ParsedURI &uri) { user_uri_ = uri; }

    /**
     * @brief 获取当前处理的URI
     * @return 指向当前URI的常量指针
     *
     * 重写说明:
     * - 在代理场景中, "当前URI"始终是用户请求的原始URI
     * - 与基类不同, 不随重定向而改变(代理任务需要保持原始目标)
     */
    [[nodiscard]] const ParsedURI *get_current_uri() const override { return &user_uri_; }

    /* 以下为重写的基类虚函数，实现代理特有的行为 */
protected:
    CommMessageOut *message_out() override;
    CommMessageIn *message_in() override;
    int keep_alive_timeout() override;
    int first_timeout() override;
    bool init_success() override;
    bool finish_once() override;

protected:
    /**
     * @brief 获取当前连接对象
     * @return SSLConnection对象指针
     *
     * 重写说明:
     * - 普通连接: 直接返回基类连接
     * - SSL连接: 返回SSLConnection包装对象
     *   (代理场景中, 原始连接是到代理服务器的, SSL连接是到目标服务器的隧道)
     */
    [[nodiscard]] WFConnection *get_connection() const override {
        WFConnection *conn = this->ComplexHttpTask::get_connection();

        if (conn && is_ssl_) {
            return static_cast<SSLConnection *>(conn->get_context());
        }

        return conn;
    }

private:
    /**
     * @struct SSLConnection
     * @brief SSL连接的封装, 组合OpenSSL组件
     *
     * 设计说明：
     * - 继承WFConnection以融入框架连接管理
     * - 不直接使用OpenSSL API，而是通过组件组合：
     *   * SSL: OpenSSL核心对象
     *   * SSLHandshaker: 管理非阻塞握手状态机
     *   * SSLWrapper: 消息加密/解密适配器
     * - 符合"组合优于继承"原则, 降低耦合度
     */
    struct SSLConnection : public WFConnection {
        SSL *ssl;                 // OpenSSL核心对象
        SSLHandshaker handshaker; // 非阻塞SSL握手器
        SSLWrapper wrapper;

        explicit SSLConnection(SSL *ssl) :
            handshaker(ssl), wrapper(&wrapper, ssl) {
            /** 注意: wrapper(&wrapper, ssl)中的自引用是设计特性:
             * 允许wrapper在加密/解密回调中访问自身状态
             * 避免在异步I/O回调中悬挂指针问题
             */
            this->ssl = ssl;
        }
    };

    [[nodiscard]] SSLHandshaker *get_ssl_handshaker() const {
        // 为什么不用dynamic_cast??? 因为 this->get_connect() 确保返回 1SSLConnection
        return &static_cast<SSLConnection *>(this->get_connection())->handshaker;
    }

    SSLWrapper *get_ssl_wrapper(ProtocolMessage *msg) const {
        auto *conn = static_cast<SSLConnection *>(this->get_connection());
        conn->wrapper = SSLWrapper(msg, conn->ssl);
        return &conn->wrapper;
    }

    /**
     * @brief 初始化SSL连接
     * @return 0 成功
     * @return 负数错误码
     *
     * 关键步骤:
     * 1. 创建SSL对象
     * 2. 设置SNI(服务器名称指示)
     * 3. 启动非阻塞握手
     * 4. 配置连接上下文
     */
    int init_ssl_connection();

    // 代理任务特有状态成员
    std::string proxy_auth_; // 代理认证凭据(格式: "Basic base64encode(user:pass)")
    ParsedURI user_uri_;     // 用户请求的原始URI(代理目标)
    bool is_ssl_;            // 是否为HTTPS代理(需要CONNECT隧道)
    bool is_user_request_;   // 是否为用户直接发起的请求(非重试/重定向生成)
    short state_;            // 任务状态机状态(0:初始, 1:CONNECT发送, 2:隧道建立...)
    int error_;              // 最近发生的错误码(0表示无错误)
};

/**
 * @brief 初始化SSL连接，为HTTPS代理建立安全隧道
 *
 * 该函数在已建立的TCP连接（到代理服务器）之上创建SSL层,
 * 为后续的HTTPS通信建立加密隧道. 主要流程:
 * 1. 创建SSL对象
 * 2. 配置SNI（服务器名称指示）
 * 3. 设置客户端模式
 * 4. 创建SSL连接包装器
 * 5. 将SSL上下文绑定到基础连接
 * 6. 设置资源清理策略
 *
 * @return int
 * @retval 0 成功
 * @retval -1 失败
 *
 * @note 该函数假设:
 * - 已经成功建立到代理服务器的TCP连接
 * - CONNECT请求已成功完成（收到200 Connection Established）
 * - user_uri_包含有效的目标主机名
 *
 * @warning 此函数不执行SSL握手, 仅初始化SSL对象. SSL握手将在后续I/O过程中通过SSLHandshaker异步完成.
 */
int ComplexHttpProxyTask::init_ssl_connection() {
    // 获取SSL上下文
    static SSL_CTX *ssl_ctx = WFGlobal::get_ssl_client_ctx(); // static变量: 避免重复获取全局上下文的开销
    SSL *ssl = __create_ssl(ssl_ctx_ ? ssl_ctx_ : ssl_ctx);
    WFConnection *conn;

    // 检查SSL对象创建结果
    if (!ssl) {
        return -1;
    }

    // 配置SSL关键参数
    SSL_set_tlsext_host_name(ssl, user_uri_.host);
    SSL_set_connect_state(ssl);

    // 获取底层TCP连接（到代理服务器的连接）
    conn = this->ComplexHttpTask::get_connection();
    // 创建SSL连接包装器
    auto *ssl_conn = new SSLConnection(ssl);

    // 定义资源清理策略
    auto &&deleter = [](void *ctx) {
        auto *ssl_conn = static_cast<SSLConnection *>(ctx);
        SSL_free(ssl_conn->ssl); // 先释放SSL核心对象（会自动清理BIO等子资源）
        delete ssl_conn;         // 再释放包装对象
    };
    // 关联SSL连接与底层TCP连接. 当TCP连接关闭时, 自动触发删除器
    conn->set_context(ssl_conn, std::move(deleter));
    return 0;
}

/**
 * @brief 生成出站消息（代理任务多阶段处理）
 * 1. seqid=0: 生成CONNECT请求（HTTPS代理隧道建立）
 * 2. seqid=1: 生成SSL握手消息（仅HTTPS）
 * 3. 后续请求: 普通HTTP请求（可能需SSL包装）
 *
 * @note 代理任务具有多阶段特性:
 *       - 阶段0: 与代理建立隧道(CONNECT方法)
 *       - 阶段1: SSL握手(仅HTTPS)
 *       - 阶段2+: 实际业务请求
 */
CommMessageOut *ComplexHttpProxyTask::message_out() {
    long long seqid = this->get_seq(); // 获取当前请求阶段ID

    // 阶段0: CONNECT请求（建立代理隧道）
    if (seqid == 0) // CONNECT
    {
        auto *conn_req = new HttpRequest;        // 创建独立的CONNECT请求
        std::string request_uri(user_uri_.host); // 构建目标: 端口

        request_uri += ":";
        if (user_uri_.port) {
            // 使用URI中指定的端口
            request_uri += user_uri_.port;
        } else {
            // 无指定端口时使用协议默认端口
            request_uri += is_ssl_ ? "443" : "80";
        }

        // 设置CONNECT请求关键参数
        conn_req->set_method("CONNECT");
        conn_req->set_request_uri(request_uri); // 格式: host:port
        conn_req->set_http_version("HTTP/1.1");
        conn_req->add_header_pair("Host", request_uri.c_str()); // 代理要求Host头

        // 添加代理认证头（如配置）
        if (!proxy_auth_.empty()) {
            conn_req->add_header_pair("Proxy-Authorization", proxy_auth_);
        }

        is_user_request_ = false; // 标记为内部请求（非用户直接发起）
        return conn_req;          // 返回CONNECT请求对象
    }
    // 阶段1: SSL握手（仅HTTPS代理）
    else if (seqid == 1 && is_ssl_) {
        is_user_request_ = false;    // 标记为内部请求
        return get_ssl_handshaker(); // 返回SSL握手器（非标准HTTP消息）
    }

    // 阶段2+: 普通HTTP请求
    // 通过基类生成标准HTTP请求
    auto *msg = static_cast<ProtocolMessage *>(this->ComplexHttpTask::message_out());
    return is_ssl_ ? get_ssl_wrapper(msg) : msg; // SSL场景返回加密包装器
}

/**
 * @brief 创建入站消息解析器（多阶段响应处理）
 * 1. seqid=0: CONNECT响应解析器
 * 2. seqid=1: SSL握手响应处理器
 * 3. 后续响应: 普通HTTP响应（可能需SSL解密）
 *
 * @note 响应处理与请求阶段严格对应:
 *       - CONNECT响应不包含body（隧道建立成功/失败）
 *       - SSL握手无标准HTTP语义
 *       - 业务响应需解密（HTTPS）
 */
CommMessageIn *ComplexHttpProxyTask::message_in() {
    long long seqid = this->get_seq(); // 获取当前响应阶段ID

    // 阶段0: CONNECT响应
    if (seqid == 0) {
        auto *conn_resp = new HttpResponse;
        conn_resp->parse_zero_body(); // 明确指定无body（隧道建立响应）
        return conn_resp;
    }
    // 阶段1: SSL握手响应
    else if (seqid == 1 && is_ssl_) {
        return get_ssl_handshaker(); // 复用握手器处理握手响应
    }

    // 阶段2+: 普通HTTP响应
    // 1. 通过基类创建标准响应解析器
    // 2. HTTPS场景下添加SSL解密层
    auto *msg = static_cast<ProtocolMessage *>(this->ComplexHttpTask::message_in());
    return is_ssl_ ? get_ssl_wrapper(msg) : msg; // SSL场景返回解密包装器
}

/**
 * @brief 计算连接保活超时（代理隧道特殊处理）
 * 1. seqid=0: 处理CONNECT响应
 *    - 200成功: 初始化SSL连接（HTTPS）
 *    - 407认证: 禁用重试（需用户处理）
 *    - 其他错误: 标记任务失败
 * 2. seqid=1: SSL握手阶段（固定超时）
 * 3. 后续请求: 复用基类保活策略
 *
 * @return int 超时时间(毫秒), 0表示立即关闭连接
 */
int ComplexHttpProxyTask::keep_alive_timeout() {
    long long seqid = this->get_seq(); // 获取当前阶段ID

    // 重置内部状态（后续可能被覆盖）
    state_ = WFT_STATE_SUCCESS;
    error_ = 0;

    // CONNECT响应处理
    if (seqid == 0) {
        HttpResponse *resp = this->get_resp();
        const char *code_str;
        int status_code;

        // 将原始响应移动到任务响应对象
        *resp = std::move(*(HttpResponse *)this->get_message_in());
        code_str = resp->get_status_code();
        status_code = code_str ? atoi(code_str) : 0;

        // 处理CONNECT响应状态码
        switch (status_code) {
        case 200: break;                                // 隧道建立成功
        case 407: this->disable_retry();                // 代理认证失败（需用户提供凭证）
        default: state_ = WFT_STATE_TASK_ERROR;         // 标记任务失败
            error_ = WFT_ERR_HTTP_PROXY_CONNECT_FAILED; // 设置代理连接错误
            return 0;                                   // 立即关闭连接
        }

        this->clear_resp(); // 清理临时响应对象

        // HTTPS场景: 初始化SSL连接
        if (is_ssl_ && init_ssl_connection() < 0) {
            state_ = WFT_STATE_SYS_ERROR; // 系统级错误（如内存不足）
            error_ = errno;               // 保存系统错误码
            return 0;
        }
        // 返回默认保活时间（隧道建立后）
        return HTTP_KEEPALIVE_DEFAULT;
    } else if (seqid == 1 && is_ssl_) // SSL握手阶段
    {
        return HTTP_KEEPALIVE_DEFAULT; // 使用固定保活时间
    }
    // 业务请求阶段: 复用基类保活策略
    return this->ComplexHttpTask::keep_alive_timeout();
}

/**
 * @brief 获取首次响应超时时间
 * @return int 超时时间(毫秒)
 *
 * 逻辑说明:
 * - 用户直接请求: 使用配置的watch_timeo（较长，含DNS/连接/SSL握手）
 * - 内部请求(CONNECT/SSL握手): 使用0（立即失败，依赖阶段超时控制）
 */
int ComplexHttpProxyTask::first_timeout() {
    return is_user_request_ ? this->watch_timeo : 0;
}

/**
 * @brief 任务初始化检查（代理特有逻辑）
 * 1. 验证代理URI方案(http)
 * 2. 验证目标URI合法性
 * 3. 确定是否SSL连接
 * 4. 处理代理认证
 * 5. 构建连接描述信息
 * 6. 设置Host头和Authorization头
 *
 * @return bool true表示初始化成功
 */
bool ComplexHttpProxyTask::init_success() {
    // 1. 验证代理URI方案必须为http
    if (!uri_.scheme || strcasecmp(uri_.scheme, "http") != 0) {
        this->state = WFT_STATE_TASK_ERROR;
        this->error = WFT_ERR_URI_SCHEME_INVALID; // 仅支持http代理
        return false;
    }

    // 2. 检查目标URI解析状态
    if (user_uri_.state == URI_STATE_ERROR) {
        this->state = WFT_STATE_SYS_ERROR;
        this->error = uri_.error; // 保留原始解析错误
        return false;
    } else if (user_uri_.state != URI_STATE_SUCCESS) {
        this->state = WFT_STATE_TASK_ERROR;
        this->error = WFT_ERR_URI_PARSE_FAILED; // URI解析失败
        return false;
    }

    // 3. 确定协议类型（http/https）
    if (user_uri_.scheme && strcasecmp(user_uri_.scheme, "http") == 0) {
        is_ssl_ = false; // 明文HTTP
    } else if (user_uri_.scheme && strcasecmp(user_uri_.scheme, "https") == 0) {
        is_ssl_ = true; // 需要SSL隧道
    } else {
        this->state = WFT_STATE_TASK_ERROR;
        this->error = WFT_ERR_URI_SCHEME_INVALID; // 仅支持http/https目标
        return false;
    }

    // 4. 验证端口号
    int user_port;
    if (user_uri_.port) {
        user_port = atoi(user_uri_.port);
        if (user_port <= 0 || user_port > 65535) {
            this->state = WFT_STATE_TASK_ERROR;
            this->error = WFT_ERR_URI_PORT_INVALID; // 无效端口号
            return false;
        }
    } else {
        user_port = is_ssl_ ? 443 : 80;
    }

    // 5. 构建连接描述信息（用于日志/调试）
    std::string info("http-proxy|remote:");
    info += is_ssl_ ? "https://" : "http://";
    info += user_uri_.host;
    info += ":";
    if (user_uri_.port) {
        info += user_uri_.port;
    } else {
        info += is_ssl_ ? "443" : "80";
    }

    // 6. 处理代理认证
    if (uri_.userinfo && uri_.userinfo[0]) {
        std::string userinfo(uri_.userinfo);
        StringUtil::url_decode(userinfo); // URL解码（含特殊字符）

        proxy_auth_.clear();
        // 生成Proxy-Authorization头值（Basic/Digest）
        if (__encode_auth(userinfo.c_str(), proxy_auth_) < 0) {
            this->state = WFT_STATE_SYS_ERROR;
            this->error = errno; // 保留编码错误
            return false;
        }

        info += "|auth:";
        info += proxy_auth_; // 将认证信息加入描述
    }

    // 7. 设置连接描述（框架内部使用）
    this->WFComplexClientTask::set_info(info);

    // 8. 构建请求URI和Host头
    std::string request_uri;
    std::string header_host;

    // 8.1 构建请求路径（含query）
    if (user_uri_.path && user_uri_.path[0]) {
        request_uri = user_uri_.path;
    } else {
        request_uri = "/"; // 无路径时使用根路径
    }

    if (user_uri_.query && user_uri_.query[0]) {
        request_uri += "?";
        request_uri += user_uri_.query; // 拼接查询参数
    }

    // 8.2 构建Host头（含端口，非默认端口时）
    if (user_uri_.host && user_uri_.host[0]) {
        header_host = user_uri_.host;
    }

    if ((is_ssl_ && user_port != 443) || (!is_ssl_ && user_port != 80)) {
        header_host += ":";
        header_host += uri_.port; // 添加非标准端口
    }

    // 9. 配置客户端请求
    HttpRequest *client_req = this->get_req();
    client_req->set_request_uri(request_uri.c_str());         // 设置请求路径
    client_req->set_header_pair("Host", header_host.c_str()); // 设置Host头
    this->WFComplexClientTask::set_transport_type(TT_TCP);    // 强制使用TCP

    // 10. 处理目标服务器认证（非代理认证）
    if (user_uri_.userinfo && user_uri_.userinfo[0]) {
        std::string userinfo(user_uri_.userinfo);
        StringUtil::url_decode(userinfo); // URL解码

        std::string http_auth;
        // 生成Authorization头（Basic/Digest）
        if (__encode_auth(userinfo.c_str(), http_auth) < 0) {
            this->state = WFT_STATE_SYS_ERROR;
            this->error = errno;
            return false;
        }

        client_req->set_header_pair("Authorization", http_auth.c_str());
    }
    return true; // 初始化成功
}

/**
 * @brief 完成单次请求处理（代理特有逻辑）
 * 1. 内部请求(CONNECT/SSL)清理
 * 2. 用户请求错误处理
 * 3. 重定向处理（保留认证信息）
 * 4. 重试策略控制
 *
 * @return bool true表示任务完全结束
 */
bool ComplexHttpProxyTask::finish_once() {
    // 1. 内部请求(CONNECT/SSL)后处理
    if (!is_user_request_) {
        // 1.1 合并内部错误到任务状态
        if (this->state == WFT_STATE_SUCCESS && state_ != WFT_STATE_SUCCESS) {
            this->state = state_;
            this->error = error_;
        }

        // 1.2 清理内部请求/响应对象
        if (this->get_seq() == 0) {
            // CONNECT阶段
            delete this->get_message_in();  // 释放响应对象
            delete this->get_message_out(); // 释放请求对象
        }

        is_user_request_ = true; // 恢复用户请求标记
        return false;            // 未完成（需继续后续阶段）
    }

    // 用户请求错误检查
    if (this->state != WFT_STATE_SUCCESS) {
        this->check_response(); // 基类错误处理
    }

    // 3. 重定向处理
    if (this->state == WFT_STATE_SUCCESS) {
        ParsedURI new_uri;
        // 3.1 检查是否需要重定向
        if (this->need_redirect(user_uri_, new_uri)) {
            // 3.2 保留认证信息策略
            if (user_uri_.userinfo &&
                strcasecmp(user_uri_.host, new_uri.host) == 0) // 同域
            {
                if (!new_uri.userinfo) // 新URI无认证信息
                {
                    new_uri.userinfo = user_uri_.userinfo; // 保留原始认证
                    user_uri_.userinfo = nullptr;          // 转移所有权
                }
            } else if (user_uri_.userinfo) // 跨域且有认证
            {
                HttpRequest *client_req = this->get_req();
                HttpHeaderCursor cursor(client_req);
                struct HttpMessageHeader header = {
                    .name = "Authorization",
                    .name_len = strlen("Authorization")
                };

                cursor.find_and_erase(&header); // 清除敏感头
            }

            // 3.3 更新目标URI并触发重定向
            user_uri_ = std::move(new_uri); // 重置代理URI（复用相同代理）
            this->set_redirect(uri_);
        } else if (this->state != WFT_STATE_SUCCESS) // 无重定向但有错误
        {
            this->disable_retry(); // 禁用重试（永久错误）
        }
    }

    return true;
}

/*******Chunked Client******/

/**
 * @brief 支持分块传输编码的HTTP任务
 *
 * 该类扩展了ComplexHttpTask, 专门处理Transfer-Encoding: chunked的响应.
 * 核心特性:
 * 1. 逐块处理响应体，避免等待完整响应
 * 2. 通过回调实时处理每个数据块
 * 3. 保持连接管理（Keep-Alive）的正确性
 * 4. 兼容非分块响应和特殊状态码
 *
 * 工作流程:
 * 1. 首次接收: 解析响应头
 * 2. 检测分块标志: 设置分块处理器
 * 3. 逐块接收: 每次接收到完整块触发用户回调
 * 4. 块结束: 检测到大小为0的块时终止
 */
class ComplexHttpChunkedTask : public ComplexHttpTask {
protected:
    CommMessageIn *message_in() override;

    /**
     * @brief 计算保活超时时间
     *
     * 根据响应头中的Connection字段决定是否保持连接
     * @return int 保活时间(毫秒), 0表示关闭连接
     */
    int keep_alive_timeout() override {
        return resp_is_keep_alive_ ? this->keep_alive_timeo : 0;
    }

    /**
     * @brief 单次请求完成后的状态机
     *
     * 分块传输模式下:
     * - 每个分块视为独立完成单元
     * - 非分块模式复用基类逻辑
     * @return bool true表示当前阶段完成
     */
    bool finish_once() override {
        return chunking_ ? true : ComplexHttpTask::finish_once();
    }

protected:
    /**
     * @brief 分块传输包装器
     *
     * 负责管理分块解析状态机:
     * 1. 首次调用: 处理响应头
     * 2. 后续调用: 处理每个数据块
     * 3. 块结束: 检测终止块
     */
    class ChunkWrapper : public PackageWrapper {
    protected:
        ProtocolMessage *next_in(ProtocolMessage *msg) override;

    protected:
        ComplexHttpChunkedTask *task_; // 外部任务指针（打破封装边界）

    public:
        ChunkWrapper(ComplexHttpChunkedTask *task) :
            PackageWrapper(nullptr) {
            task_ = task;
        }

        friend class ComplexHttpChunkedTask;
    };

protected:
    bool chunking_;                                                  // 标记是否处于分块传输模式
    bool resp_is_keep_alive_;                                        // 响应头指示的Keep-Alive状态
    HttpMessageChunk chunk_;                                         // 当前分块解析器
    ChunkWrapper wrapper_;                                           // 分块传输包装器
    std::function<void (HttpMessageChunk *, WFHttpTask *)> extract_; // 用户分块处理回调

public:
    /**
     * @param redirect_max 最大重定向次数
     * @param extract 分块处理回调（移动语义）
     * @param callback 任务完成回调（移动语义）
     *
     * 初始化逻辑：
     * 1. 基类初始化（禁用自动重试, 由分块逻辑控制）
     * 2. 绑定任务与包装器
     * 3. 初始化分块状态
     */
    ComplexHttpChunkedTask(int redirect_max,
                           std::function<void (HttpMessageChunk *, WFHttpTask *)> &&extract,
                           http_callback_t &&callback) :
        ComplexHttpTask(redirect_max, 0, std::move(callback)),
        wrapper_(this),
        extract_(std::move(extract)) {
        chunking_ = false; // 默认不分块？？？
    }
};

/**
 * @brief 创建入站消息解析器（分块传输入口）
 *
 * 逻辑分支：
 * 1. HEAD请求: 无响应体, 使用标准解析器
 * 2. 其他请求:
 *    - 预设零体解析（防止基类自动处理body）
 *    - 启用分块包装器
 *
 * @note 该方法在连接建立后、接收响应前调用
 */
CommMessageIn *ComplexHttpChunkedTask::message_in() {
    HttpResponse *resp = this->get_resp();

    // HEAD请求无响应体, 使用标准解析流程
    if (strcmp(this->get_req()->get_method(), HttpMethodHead) == 0) {
        return ComplexHttpTask::message_in();
    }

    // 预设零体解析 - 禁用基类body处理
    resp->parse_zero_body();
    // 设置分块包装器
    wrapper_.set_message(resp);
    return &wrapper_; // 返回分块感知的解析器
}

/**
 * @brief 分块状态机：获取下一个解析对象
 *
 * 状态转换：
 * ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
 * │ 响应头解析  │───▶│ 首块处理    │───▶│ 后续块处理  │
 * └─────────────┘    └─────────────┘    └─────────────┘
 *       │                  │                  │
 *       ▼                  ▼                  ▼
 *  状态码检查        用户回调(nullptr)    用户回调(chunk)
 *       │                  │                  │
 *       ▼                  ▼                  ▼
 *  分块模式判断      设置首块限制        重置分块对象
 *
 * @param msg 上一个解析完成的消息
 * @return ProtocolMessage* 下一个待解析对象
 */
ProtocolMessage *ComplexHttpChunkedTask::ChunkWrapper::next_in(ProtocolMessage *msg) {
    HttpResponse *resp = task_->get_resp();
    const void *chunk_data;
    size_t size;
    // 阶段1: 响应头解析完成
    if (msg == resp) {
        int status_code = atoi(resp->get_status_code());
        // 记录Keep-Alive状态（用于连接复用）
        task_->resp_is_keep_alive_ = resp->is_keep_alive();
        // 处理无body响应（RFC 7230 3.3.3）
        if (status_code / 100 == 1 || status_code == 204 || status_code == 304) {
            return nullptr; // 无body, 终止解析
        }
        // 阶段1.1: 处理2xx成功响应
        if (status_code / 100 == 2) {
            // 通知用户: 开始接收body（首块前回调）
            task_->extract_(nullptr, task_);
            // 检测分块传输编码
            if (resp->is_chunked()) {
                size = resp->get_size_limit();      // 继承大小限制
                task_->chunk_.set_size_limit(size); // 应用到首块
                task_->chunking_ = true;            // 激活分块模式
                return &task_->chunk_;              // 返回首块解析器
            }
        }
        // 阶段1.2: 处理非2xx但有body的响应
        http_parser_t *parser = (http_parser_t *)resp->get_parser();
        // 情况1: 已知传输长度（非分块）
        if (parser->transfer_length != 0) {
            return nullptr; // 交由标准流程处理
        }
        // 情况2: 分块传输（非2xx状态码）
        if (resp->is_chunked()) {
            parser->transfer_length = (size_t)-1; // 标记分块模式
        }
        // 情况3: 非分块但有Content-Length
        else if (parser->content_length != 0) {
            parser->transfer_length = parser->content_length;
        }
        // 情况4: 无长度信息 - 无法处理
        else {
            return nullptr;
        }

        // 重置解析器状态, 准备接收body
        parser->complete = 0;
        return resp;
    }

    // 阶段2: 数据块解析完成
    task_->chunk_.get_chunk_data(&chunk_data, &size);
    // 检测是否是终止块（大小为0的块）
    if (size == 0) {
        return nullptr; // 分块传输结束
    }

    // 计算剩余大小限制（用于下一块）
    size = task_->chunk_.get_size_limit() - size;
    // 通知用户: 新分块到达
    task_->extract_(&task_->chunk_, task_);

    // 重置分块对象（原地构造）
    task_->chunk_.~HttpMessageChunk();    // 手动调用析构
    new(&task_->chunk_) HttpMessageChunk; // 在task_->chunk位置创建新对象
    task_->chunk_.set_size_limit(size);   // 应用剩余限制
    return &task_->chunk_;                // 返回自身处理下一块
}

/* *********Client Factory********* */

/**
 * @brief 创建普通HTTP任务（通过URL字符串）
 *
 * 工作流程:
 * 1. 创建ComplexHttpTask实例（支持重定向/重试）
 * 2. 解析URL为结构化URI
 * 3. 初始化任务参数
 * 4. 设置默认保活时间
 *
 * @param url 目标URL（如 "http://example.com/path"）
 * @param redirect_max 最大重定向次数（0表示禁止重定向）
 * @param retry_max 最大重试次数（0表示禁止重试）
 * @param callback 任务完成回调
 * @return WFHttpTask* 创建的任务对象
 */
WFHttpTask *WFTaskFactory::create_http_task(const std::string &url,
                                            int redirect_max,
                                            int retry_max,
                                            http_callback_t callback) {
    // 创建核心任务对象（支持重定向/重试）
    auto *task = new ComplexHttpTask(redirect_max,
                                     retry_max,
                                     std::move(callback));
    // 解析URL（线程安全，内部使用RFC3986标准解析）
    ParsedURI uri;
    URIParser::parse(url, uri);
    // 初始化任务（设置目标地址、协议版本等）
    task->init(std::move(uri));
    // 启用Keep-Alive（默认60秒）
    task->set_keep_alive(HTTP_KEEPALIVE_DEFAULT);
    return task;
}


/**
 * @brief 创建普通HTTP任务（通过预解析URI）
 *
 * 优化点：
 * - 避免重复解析URI
 * - 适用于多次请求同一域名的场景
 *
 * @param uri 预解析的URI对象（由URIParser生成）
 * @param redirect_max 最大重定向次数
 * @param retry_max 最大重试次数
 * @param callback 任务完成回调
 * @return WFHttpTask* 创建的任务对象
 */
WFHttpTask *WFTaskFactory::create_http_task(const ParsedURI &uri,
                                            int redirect_max,
                                            int retry_max,
                                            http_callback_t callback) {
    auto *task = new ComplexHttpTask(redirect_max,
                                     retry_max,
                                     std::move(callback));

    task->init(uri);                              // 初始化任务(设置目标地址、协议版本等)
    task->set_keep_alive(HTTP_KEEPALIVE_DEFAULT); // 设置保活时间
    return task;
}

/**
 * @brief 创建代理HTTP任务（通过URL字符串）
 *
 * 代理工作流程：
 * 1. 创建专用代理任务对象（ComplexHttpProxyTask）
 * 2. 分离解析用户URL和代理URL
 * 3. 设置真实目标（user_uri）和代理目标（uri）
 *
 * @note 代理请求使用HTTP CONNECT方法建立隧道
 *
 * @param url 用户目标URL（如 "https://example.com"）
 * @param proxy_url 代理服务器URL（如 "http://proxy:8080"）
 * @param redirect_max 最大重定向次数（在真实目标上生效）
 * @param retry_max 最大重试次数
 * @param callback 任务完成回调
 * @return WFHttpTask* 代理任务对象
 */
WFHttpTask *WFTaskFactory::create_http_task(const std::string &url, const std::string &proxy_url,
                                            int redirect_max, int retry_max,
                                            http_callback_t callback) {
    // 创建专用代理任务（处理CONNECT隧道）
    auto *task = new ComplexHttpProxyTask(redirect_max, retry_max, std::move(callback));

    ParsedURI uri, user_uri;
    // 分离解析
    URIParser::parse(url, user_uri);  // 真实目标
    URIParser::parse(proxy_url, uri); // 代理服务器

    // 设置双URI（关键步骤）
    task->set_user_uri(std::move(user_uri)); // 保存真实目标
    task->set_keep_alive(HTTP_KEEPALIVE_DEFAULT);
    task->init(std::move(uri)); // 代理作为实际连接目标
    return task;
}

/**
 * @brief 创建代理HTTP任务（通过预解析URI）
 *
 * 高级用法：
 * - 适用于需要精细控制URI的场景
 * - 避免字符串解析开销
 *
 * @param uri 代理服务器URI
 * @param proxy_uri 代理服务器URI
 * @param redirect_max 最大重定向次数
 * @param retry_max 最大重试次数
 * @param callback 任务完成回调
 * @return WFHttpTask* 代理任务对象
 */
WFHttpTask *WFTaskFactory::create_http_task(const ParsedURI &uri, const ParsedURI &proxy_uri,
                                            int redirect_max, int retry_max,
                                            http_callback_t callback) {
    auto *task = new ComplexHttpProxyTask(redirect_max, retry_max, std::move(callback));

    task->set_user_uri(uri); // 保存真实目标
    task->set_keep_alive(HTTP_KEEPALIVE_DEFAULT);
    task->init(proxy_uri); // 代理作为实际连接目标
    return task;
}

/**
 * @brief 创建分块传输任务（内部接口）
 *
 * @warning 内部工厂方法, 不建议直接调用
 *
 * 特性:
 * - 专为Transfer-Encoding: chunked设计
 * - 通过extract回调逐块处理数据
 * - 与普通HTTP任务分离（职责单一原则）
 *
 * @param url 目标URL
 * @param redirect_max 最大重定向次数
 * @param extract 分块数据提取回调
 * @param callback 任务完成回调
 * @return WFHttpTask* 分块传输任务
 */
WFHttpTask *__WFHttpTaskFactory::create_chunked_task(const std::string &url,
                                                     int redirect_max,
                                                     extract_t extract,
                                                     http_callback_t callback) {
    // 创建专用分块任务
    auto *task = new ComplexHttpChunkedTask(redirect_max, std::move(extract), std::move(callback));
    // 解析URI
    ParsedURI uri;
    URIParser::parse(url, uri);
    // 初始化任务
    task->init(std::move(uri));
    task->set_keep_alive(HTTP_KEEPALIVE_DEFAULT); // 设置保活时间
    return task;
}

/**
 * @brief 创建分块传输任务（预解析URI版本）
 *
 * 优化场景:
 * - 与普通任务分离（避免分块逻辑污染主流程）
 * - 保持接口一致性
 *
 * @param uri 预解析的目标URI
 * @param redirect_max 最大重定向次数
 * @param extract 分块数据提取回调
 * @param callback 任务完成回调
 * @return WFHttpTask* 分块传输任务
 */
WFHttpTask *__WFHttpTaskFactory::create_chunked_task(const ParsedURI &uri,
                                                     int redirect_max,
                                                     extract_t extract,
                                                     http_callback_t callback) {
    auto *task = new ComplexHttpChunkedTask(redirect_max, std::move(extract), std::move(callback));

    task->init(uri);
    task->set_keep_alive(HTTP_KEEPALIVE_DEFAULT);
    return task;
}

/* *********Server********* */

/**
 * @brief HTTP服务器任务类
 *
 * 该类实现HTTP服务器的核心逻辑, 主要职责:
 * 1. 处理Keep-Alive连接管理
 * 2. 自动补全响应头（Content-Length/Connection）
 * 3. 解析客户端Keep-Alive参数
 * 4. 状态码标准化处理
 *
 * 设计特点:
 * - 与客户端任务分离（关注点分离）
 * - 自动处理协议细节（开发者只需关注业务逻辑）
 * - 支持HTTP/1.1协议规范（RFC 7230）
 *
 * @note 继承自WFServerTask模板, 绑定HttpRequest/HttpResponse协议
 */
class WFHttpServerTask : public WFServerTask<protocol::HttpRequest, protocol::HttpResponse> {
private:
    using TASK = WFNetworkTask<protocol::HttpRequest, protocol::HttpResponse>;

public:
    /**
     * @param service 通信服务对象（管理连接/线程）
     * @param proc 业务处理回调（核心逻辑入口）
     *
     * 初始化流程:
     * 1. 调用基类构造函数
     * 2. 绑定全局调度器（WFGlobal::get_scheduler()）
     */
    WFHttpServerTask(CommService *service, std::function<void (TASK *)> &proc) :
        WFServerTask(service, WFGlobal::get_scheduler(), proc) {}

protected:
    void handle(int state, int error) override;
    CommMessageOut *message_out() override;

protected:
    bool req_is_keep_alive_;         // 请求是否要求Keep-Alive
    bool req_has_keep_alive_header_; // 请求是否包含Keep-Alive头
    std::string req_keep_alive_;     // Keep-Alive头原始值（如"timeout=5,max=100"）
};

/**
 * @brief 任务状态处理（Keep-Alive信息提取）
 *
 * 核心逻辑:
 * - 仅在WFT_STATE_TOREPLY状态处理（准备回复阶段）
 * - 提取客户端请求中的Keep-Alive参数
 *
 * Keep-Alive头格式示例:
 *   Keep-Alive: timeout=5, max=100
 *
 * @note 该方法在业务回调执行后、发送响应前调用
 */
void WFHttpServerTask::handle(int state, int error) {
    if (state == WFT_STATE_TOREPLY) {
        // 检测基础Keep-Alive状态（Connection头）
        req_is_keep_alive_ = this->req.is_keep_alive();
        // 仅当请求要求Keep-Alive且存在Keep-Alive头时处理
        if (req_is_keep_alive_ && this->req.has_keep_alive_header()) {
            HttpHeaderCursor cursor(&this->req);
            struct HttpMessageHeader header = {
                .name = "Keep-Alive", // 头字段名
                .name_len = strlen("Keep-Alive"),
            };
            // 查找Keep-Alive头
            req_has_keep_alive_header_ = cursor.find(&header);
            if (req_has_keep_alive_header_) {
                // 保存原始值（用于后续解析）
                req_keep_alive_.assign(static_cast<const char *>(header.value), header.value_len);
            }
        } else {
            req_has_keep_alive_header_ = false;
        }
    }
    // 调用基类处理（状态机流转）
    this->WFServerTask::handle(state, error);
}

CommMessageOut *WFHttpServerTask::message_out() {
    HttpResponse *resp = this->get_resp();
    struct HttpMessageHeader header;

    // 若未设置, 默认使用HTTP/1.1（现代标准）
    if (!resp->get_http_version()) {
        resp->set_http_version("HTTP/1.1");
    }

    const char *status_code_str = resp->get_status_code();
    // 检查状态码和原因短语
    if (!status_code_str || !resp->get_reason_phrase()) {
        int status_code;

        if (status_code_str) {
            status_code = atoi(status_code_str); // 尝试转换现有状态码
        } else {
            status_code = HttpStatusOK; // 若缺失则自动补全（默认200 OK）
        }
        // 标准化状态行（设置标准原因短语）
        HttpUtil::set_response_status(resp, status_code);
    }

    // 处理Content-Length. 分块传输由协议栈自动处理, 此处仅处理普通响应
    // 非分块传输（!is_chunked）并且 未手动设置Content-Length
    if (!resp->is_chunked() && !resp->has_content_length_header()) {
        char buf[32];
        header.name = "Content-Length";
        header.name_len = strlen("Content-Length");
        // 计算响应体大小并格式化
        header.value = buf;
        header.value_len = sprintf(buf, "%zu", resp->get_output_body_size());
        resp->add_header(&header); // 添加头字段
    }

    // 确定连接是否保持
    bool is_alive;
    if (resp->has_connection_header()) {
        is_alive = resp->is_keep_alive(); // 使用响应设置
    } else {
        is_alive = this->req_is_keep_alive_; // 回退到请求设置
    }

    // 处理Keep-Alive超时
    if (!is_alive) {
        this->keep_alive_timeo = 0; // 立即关闭连接
    } else {
        // req---Connection: Keep-Alive
        // req---Keep-Alive: timeout=5,max=100
        // 解析客户端Keep-Alive参数（如"timeout=5,max=100"）
        if (this->req_has_keep_alive_header_) {
            int flag = 0; // 标志位: bit0=timeout已处理, bit1=max已处理
            // 拆分参数（逗号分隔）
            std::vector<std::string> params = StringUtil::split(this->req_keep_alive_, ',');
            for (const auto &kv : params) {
                // 拆分键值对（等号分隔）
                std::vector<std::string> arr = StringUtil::split(kv, '=');
                if (arr.size() < 2) {
                    arr.emplace_back("0"); // 无值时默认0
                }
                // 去除空格（健壮性处理）
                std::string key = StringUtil::strip(arr[0]);
                std::string val = StringUtil::strip(arr[1]);
                // 处理timeout参数（单位: 秒→毫秒）
                if (!(flag & 1) && strcasecmp(key.c_str(), "timeout") == 0) {
                    flag |= 1;
                    // keep_alive_timeo = 5000ms when Keep-Alive: timeout=5
                    this->keep_alive_timeo = 1000 * atoi(val.c_str());
                    if (flag == 3) {
                        break; // 所有参数已处理
                    }
                }
                // 处理max参数（最大请求数）
                else if (!(flag & 2) && strcasecmp(key.c_str(), "max") == 0) {
                    flag |= 2;
                    // 检查当前请求序号是否超过限制
                    if (this->get_seq() >= atoi(val.c_str())) {
                        this->keep_alive_timeo = 0; // 超过限制, 关闭连接
                        break;
                    }
                    if (flag == 3) {
                        break;
                    }
                }
            }
        }

        // 超时边界检查（防止DoS攻击）
        if (static_cast<unsigned int>(this->keep_alive_timeo) > HTTP_KEEPALIVE_MAX) {
            this->keep_alive_timeo = HTTP_KEEPALIVE_MAX; // 上限限制（默认300秒）
        }
        //if (this->keep_alive_timeo < 0 || this->keep_alive_timeo > HTTP_KEEPALIVE_MAX)
    }

    // 添加Connection头（若缺失）
    if (!resp->has_connection_header()) {
        header.name = "Connection";
        header.name_len = 10; // "Connection"长度
        if (this->keep_alive_timeo == 0) {
            header.value = "close";
            header.value_len = 5;
        } else {
            header.value = "Keep-Alive";
            header.value_len = 10;
        }

        resp->add_header(&header);
    }
    // 调用基类方法（实际序列化响应）
    return this->WFServerTask::message_out();
}

/* *********Server Factory********* */

/**
 * @brief 创建http任务
 * @param service 通信服务对象（管理连接/线程）
 * @param process 业务处理回调（核心逻辑入口）
 * @return WFHttpServerTask*
 */
WFHttpTask *WFServerTaskFactory::create_http_task(CommService *service, std::function<void (WFHttpTask *)> &process) {
    return new WFHttpServerTask(service, process);
}