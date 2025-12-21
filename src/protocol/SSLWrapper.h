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
    class SSLHandshaker : public ProtocolMessage {
    public:
        int encode(struct iovec vectors[], int max) override;
        int append(const void *buf, size_t *size) override;

    protected:
        SSL *ssl;

    public:
        explicit SSLHandshaker(SSL *ssl) {
            this->ssl = ssl;
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
            ProtocolWrapper(message) {
            this->ssl = ssl;
        }

    public:
        SSLWrapper(SSLWrapper &&wrapper) = default;
        SSLWrapper &operator =(SSLWrapper &&wrapper) = default;
    };

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