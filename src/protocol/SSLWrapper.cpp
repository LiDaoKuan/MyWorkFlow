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

#include <cerrno>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "SSLWrapper.h"

namespace protocol {
    /**
     * @brief OpenSSL 1.0.2及以下版本的兼容性处理
     * @details 在OpenSSL 1.1.0之前，SSL_get_wbio()返回的BIO可能不是最终写入目标
     *          需要遍历BIO链找到最底层的可写BIO（通常是socket BIO）
     * @note    1.1.0+版本已修复此问题, 无需此处理
     */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    static inline BIO *__get_wbio(SSL *ssl) {
        BIO *wbio = SSL_get_wbio(ssl); // 获取当前写BIO
        BIO *next = BIO_next(wbio);    // 检查是否有下一级BIO
        return next ? next : wbio;     // 返回链中最底层的BIO（用于实际网络写入）
    }

# define SSL_get_wbio(ssl)	__get_wbio(ssl)
#endif

    /**
     * @brief   将握手数据编码为网络字节流
     * @param   vectors 输出缓冲区数组
     * @param   max     最大缓冲区数量
     * @return  实际使用的缓冲区数量
     * @details 生成ClientHello/ServerHello等握手消息
     *          与OpenSSL库交互获取加密数据
     * @warning 必须在非阻塞模式下使用
     */
    int SSLHandshaker::encode(struct iovec vectors[], int max) {
        BIO *wbio = SSL_get_wbio(this->ssl); // 获取写BIO（内存BIO）
        char *ptr;
        long len;
        int ret;

        // 驱动SSL握手状态机
        ret = SSL_do_handshake(this->ssl);
        if (ret <= 0) {
            // 处理握手错误
            ret = SSL_get_error(this->ssl, ret);
            // 仅SSL_ERROR_WANT_READ情况下可继续（需要更多数据）
            if (ret != SSL_ERROR_WANT_READ) {
                // 系统错误直接返回, 否则设置标准错误码
                if (ret != SSL_ERROR_SYSCALL) {
                    // 非系统错误, 将ret转换为标准errno
                    errno = -ret;
                }
                return -1;
            }
        }

        // 从内存BIO获取生成的握手数据
        len = BIO_get_mem_data(wbio, &ptr);
        if (len > 0) {
            // 将数据放入第一个iovec
            vectors[0].iov_base = ptr;
            vectors[0].iov_len = len;
            return 1; // 返回使用的缓冲区数量
        } else if (len == 0) {
            return 0; // 无数据需要发送
        } else {
            errno = EIO; // BIO内部错误
            return -1;
        }
    }

    /**
     * @brief   SSL握手处理核心逻辑
     * @param[in]   buf  接收到的握手数据
     * @param[in,out] size 数据大小（输入可用大小, 输出消耗大小）
     * @param[in]   ssl  SSL上下文
     * @param[out]  ptr  生成的响应数据指针
     * @param[out]  len  生成的响应数据长度
     * @return  处理状态
     * @retval  0   需要更多数据
     * @retval  -1  错误
     * @details 1. 将接收到的数据写入读BIO
     *          2. 驱动SSL状态机
     *          3. 从写BIO获取需要发送的响应
     * @note    内部函数, 不重置BIO状态
     */
    static int __ssl_handshake(const void *buf, size_t *size, SSL *ssl,
                               char **ptr, long *len) {
        BIO *wbio = SSL_get_wbio(ssl); // 写BIO（生成响应）
        BIO *rbio = SSL_get_rbio(ssl); // 读BIO（接收数据）

        // 将接收到的数据写入SSL缓冲区
        int ret = BIO_write(rbio, buf, *size);
        if (ret <= 0) {
            return -1;
        }
        // 更新实际消耗的数据量
        *size = ret;
        // 驱动SSL状态机
        ret = SSL_do_handshake(ssl);
        if (ret <= 0) {
            ret = SSL_get_error(ssl, ret);
            // 非SSL_ERROR_WANT_READ视为错误
            if (ret != SSL_ERROR_WANT_READ) {
                if (ret != SSL_ERROR_SYSCALL) {
                    errno = -ret;
                }
                return -1;
            }
            // 需要更多数据, 但可能已有响应需要发送
            ret = 0;
        }

        // 从写BIO获取生成的响应数据
        *len = BIO_get_mem_data(wbio, ptr);
        if (*len < 0) {
            return -1;
        }

        return ret;
    }

    /**
     * @brief   处理接收到的SSL握手数据
     * @param[in]   buf  接收到的数据
     * @param[in,out] size 数据大小（输入可用大小，输出消耗大小）
     * @return  处理状态
     * @details 1. 重置写BIO确保无残留数据
     *          2. 处理握手数据
     *          3. 通过feedback机制立即发送响应
     * @note    完成握手后，会自动转换为数据传输模式
     */
    int SSLHandshaker::append(const void *buf, size_t *size) {
        BIO *wbio = SSL_get_wbio(this->ssl);
        char *ptr;
        long len;
        long n;
        int ret;

        // 重置写BIO, 清除之前的数据
        BIO_reset(wbio);
        // 处理握手数据
        ret = __ssl_handshake(buf, size, this->ssl, &ptr, &len);
        if (ret != 0) {
            return ret;
        }

        // 有响应数据需要立即发送
        if (len > 0) {
            // 通过feedback机制发送（不阻塞当前处理流程）
            n = this->feedback(ptr, len);
            // 发送后重置BIO
            BIO_reset(wbio);
        } else {
            // 无响应数据
            n = 0;
        }

        // 检查响应数据是否全部发送
        if (n == len) {
            return ret; // 成功
        }

        // 部分发送或错误
        if (n >= 0) {
            errno = ENOBUFS; // 缓冲区不足
        }

        return -1;
    }

    /**
     * @brief   加密上层协议消息
     * @param   vectors 输出缓冲区
     * @param   max     最大缓冲区数
     * @return  实际使用的缓冲区数
     * @details 将被包装消息(message)的数据进行SSL加密
     *          生成符合SSL记录协议的加密数据
     */
    int SSLWrapper::encode(struct iovec vectors[], int max) {
        BIO *wbio = SSL_get_wbio(this->ssl); // 写BIO（获取加密数据）
        struct iovec *iov;
        char *ptr;
        long len;
        int ret;

        // 先获取上层协议要发送的原始数据（明文）
        ret = this->ProtocolWrapper::encode(vectors, max);
        // 处理错误和特殊返回值（如需要更多缓冲区）
        if ((unsigned int)ret > (unsigned int)max) {
            return ret;
        }

        // 限制实际处理的缓冲区数量
        max = ret;
        // 遍历所有iovec, 加密每个数据块
        for (iov = vectors; iov < vectors + max; iov++) {
            if (iov->iov_len > 0) {
                // 通过SSL_write加密数据（数据会进入wbio）
                ret = SSL_write(this->ssl, iov->iov_base, iov->iov_len);
                if (ret <= 0) {
                    // 处理加密错误
                    ret = SSL_get_error(this->ssl, ret);
                    if (ret != SSL_ERROR_SYSCALL) {
                        errno = -ret;
                    }
                    return -1;
                }
            }
        }

        // 从wbio获取加密后的数据
        len = BIO_get_mem_data(wbio, &ptr);
        if (len > 0) {
            // 将加密数据放入第一个iovec
            vectors[0].iov_base = ptr;
            vectors[0].iov_len = len;
            return 1;
        } else if (len == 0) {
            return 0; // 无数据
        } else {
            errno = EIO;
            return -1;
        }
    }

#define BUFSIZE		8192    // SSL读缓冲区大小

    /**
     * @brief   处理SSL解密后的应用数据
     * @return  处理状态
     * @details 1. 循环读取SSL解密数据
     *          2. 将数据分块传递给上层协议
     *          3. 处理SSL错误
     * @note    此函数不直接处理网络数据, 仅处理已解密数据
     */
    int SSLWrapper::append_message() {
        char buf[BUFSIZE]; // 解密数据缓冲区
        int ret;

        // 循环读取直到无更多数据
        while ((ret = SSL_read(this->ssl, buf, BUFSIZE)) > 0) {
            size_t nleft = ret; // 剩余未处理数据量
            char *p = buf;      // 当前处理位置
            size_t n;           // 本次处理的数据量

            // 可能一次无法处理全部数据（如应用层协议边界）
            do {
                n = nleft;
                // 传递给上层协议解析
                ret = this->ProtocolWrapper::append(p, &n);
                if (ret == 0) {
                    // 成功处理n字节
                    nleft -= n;
                    p += n;
                } else {
                    // 上层协议解析出错
                    return ret;
                }
            } while (nleft > 0);
        }

        // 处理SSL_read错误
        ret = SSL_get_error(this->ssl, ret);
        // SSL_ERROR_WANT_READ表示需要更多数据, 不视为错误
        if (ret != SSL_ERROR_WANT_READ) {
            if (ret != SSL_ERROR_SYSCALL) {
                // 非系统错误, 转换为标准errno
                errno = -ret;
            }
            // 系统错误, 返回
            return -1;
        }

        return 0; // 需要更多数据
    }

    /**
     * @brief   处理接收到的加密数据
     * @param[in]   buf  加密数据
     * @param[in,out] size 数据大小
     * @return  处理状态
     * @details 1. 重置写BIO
     *          2. 将数据写入读BIO
     *          3. 调用append_message处理解密数据
     */
    int SSLWrapper::append(const void *buf, size_t *size) {
        BIO *wbio = SSL_get_wbio(this->ssl); // 写BIO
        BIO *rbio = SSL_get_rbio(this->ssl); // 读BIO
        int ret;

        // 重置写BIO, 准备接收新生成的数据（如重协商）
        BIO_reset(wbio);
        // 将接收到的加密数据写入SSL读缓冲区
        ret = BIO_write(rbio, buf, *size);
        if (ret <= 0) {
            return -1;
        }

        // 更新实际消耗的数据量
        *size = ret;
        // 处理解密数据
        return this->append_message();
    }

    /**
     * @brief   SSL层即时反馈机制
     * @param[in] buf  要反馈的明文数据
     * @param[in] size 数据大小
     * @return  反馈的字节数
     * @details 1. 加密反馈数据
     *          2. 通过底层连接立即发送
     *          3. 用于SSL重协商等场景
     * @note    不影响当前接收流程
     */
    int SSLWrapper::feedback(const void *buf, size_t size) {
        BIO *wbio = SSL_get_wbio(this->ssl); // 写BIO
        char *ptr;
        long len;
        long n;
        int ret;

        // 空数据直接返回
        if (size == 0) {
            return 0;
        }

        // 加密反馈数据
        ret = SSL_write(this->ssl, buf, size);
        if (ret <= 0) {
            ret = SSL_get_error(this->ssl, ret);
            if (ret != SSL_ERROR_SYSCALL) {
                errno = -ret;
            }

            return -1;
        }

        // 从wbio获取加密后的数据
        len = BIO_get_mem_data(wbio, &ptr);
        if (len >= 0) {
            // 通过基类feedback机制发送（不经过SSL加密！）
            n = this->ProtocolWrapper::feedback(ptr, len);
            // 发送后重置BIO
            BIO_reset(wbio);
            // 检查是否全部发送
            if (n == len) {
                return size; // 返回原始明文大小
            }
            // 部分发送
            if (ret > 0) {
                errno = ENOBUFS;
            }
        }

        return -1;
    }

    /**
     * @brief   服务器端SSL数据处理
     * @param[in]   buf  接收到的数据
     * @param[in,out] size 数据大小
     * @return  处理状态
     * @details 1. 优先完成SSL握手
     * @details 2. 处理可能的握手响应
     * @details 3. 交由通用逻辑处理应用数据
     * @note    服务器端可能在接收第一条消息时才开始握手
     */
    int ServerSSLWrapper::append(const void *buf, size_t *size) {
        BIO *wbio = SSL_get_wbio(this->ssl); // 写BIO
        char *ptr;
        long len;
        long n;

        // 重置写BIO
        BIO_reset(wbio);
        // 尝试完成握手
        if (__ssl_handshake(buf, size, this->ssl, &ptr, &len) < 0) {
            return -1;
        }

        // 有握手响应需要发送
        if (len > 0) {
            // 直接调用ProtocolMessage::feedback（不经过SSLWrapper层）
            // 避免在握手阶段触发二次加密
            n = this->ProtocolMessage::feedback(ptr, len);
            // 重置写BIO
            BIO_reset(wbio);
        } else {
            n = 0;
        }

        // 检查握手响应是否全部发送
        if (n == len) {
            // 握手完成，处理应用数据
            return this->append_message();
        }

        // 部分发送或错误
        if (n >= 0) {
            errno = ENOBUFS;
        }

        return -1;
    }
}