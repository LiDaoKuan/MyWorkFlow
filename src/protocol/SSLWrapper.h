//
// Created by ldk on 12/20/25.
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

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef MYWORKFLOW_SSLWRAPPER_H
#define MYWORKFLOW_SSLWRAPPER_H

#include <openssl/ssl.h>
#include "ProtocolMessage.h"

namespace protocol {
    /**
     * @brief   SSL/TLS握手协议处理器
     * @details 专门处理SSL/TLS连接建立阶段的协议交互
     *          作为独立的ProtocolMessage, 管理完整的握手流程
     * @note    生命周期通常很短, 仅存在于连接建立阶段
     * @warning 非线程安全, 应由单个连接线程独占使用
     */
    class SSLHandshaker : public ProtocolMessage {
    public:
        int encode(struct iovec vectors[], int max) override;
        int append(const void *buf, size_t *size) override;

    protected:
        SSL *ssl; // OpenSSL库的SSL上下文指针, 管理握手状态机

    public:
        explicit SSLHandshaker(SSL *ssl) {
            this->ssl = ssl; // 传入的必须是已初始化的SSL上下文
        }

    public:
        SSLHandshaker(SSLHandshaker &&handshaker) = default;
        SSLHandshaker &operator =(SSLHandshaker &&handshaker) = default;
    };

    class SSLWrapper : public ProtocolWrapper {
    protected:
        int encode(struct iovec vectors[], int max) override;
        int append(const void *buf, size_t *size) override;

    protected:
        int feedback(const void *buf, size_t size) override;

    protected:
        int append_message();

    protected:
        SSL *ssl;

    public:
        SSLWrapper(ProtocolMessage *message, SSL *ssl) :
            ProtocolWrapper(message) // 建立双向连接: wrapper持有message, message的wrapper指针指向本对象
        {
            this->ssl = ssl;
        }

    public:
        SSLWrapper(SSLWrapper &&wrapper) = default;
        SSLWrapper &operator =(SSLWrapper &&wrapper) = default;
    };

    /**
     * @brief   服务器端SSL专用包装器
     * @details 专门处理服务器端SSL连接的特殊需求
     *          如客户端证书验证、SNI(服务器名称指示)处理等
     * @note    与客户端SSLWrapper的主要差异在握手和认证阶段
     *          数据传输阶段行为基本相同
     */
    class ServerSSLWrapper : public SSLWrapper {
    protected:
        int append(const void *buf, size_t *size) override;

    public:
        ServerSSLWrapper(ProtocolMessage *message, SSL *ssl) :
            SSLWrapper(message, ssl) {}

    public:
        ServerSSLWrapper(ServerSSLWrapper &&wrapper) = default;
        ServerSSLWrapper &operator =(ServerSSLWrapper &&wrapper) = default;
    };
}
#endif //MYWORKFLOW_SSLWRAPPER_H