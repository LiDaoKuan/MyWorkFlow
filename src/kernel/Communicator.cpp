//
// Created by ldk on 10/7/25.
//

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <cerrno>
#include <climits>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "list.h"
#include "msgqueue.h"
#include "thrdpool.h"
#include "poller.h"
#include "mpoller.h"
#include "Communicator.h"

#include <ranges>

struct CommConnEntry {
    list_head list; // 用于将多个CommConnEntry链接成一个链表, 方便统一管理(如空闲连接池, 活跃连接链表等)
    CommConnection *conn;
    long long seq; // 序列号, 用于标识连接的顺序或作为唯一ID, 常用于日志或异步操作匹配
    int sockfd;
#define CONN_STATE_CONNECTING	0
#define CONN_STATE_CONNECTED	1
#define CONN_STATE_RECEIVING	2   // 接收数据
#define CONN_STATE_SUCCESS		3
#define CONN_STATE_IDLE			4   // 空闲
#define CONN_STATE_KEEPALIVE	5   // 保活
#define CONN_STATE_CLOSING		6
#define CONN_STATE_ERROR		7   // 出错
    int state; // 记录连接处于生命周期中的哪个阶段
    int error;
    int ref; // 引用计数, 用户跟踪当前有多少个模块正在使用该条目
    iovec *write_iov; // 写入数据缓冲区
    SSL *ssl; // SSL/TSL上下文, 如果连接启用了加密, 该指针指向OpenSSL的SSL对象, 负责所有的加密解密操作
    CommSession *session; // 会话上下文, 指向与此次连接关联的会话对象, 通常包含协议处理逻辑和用户数据
    CommTarget *target; // 连接目标, 指向描述连接目标(如远程服务器地址)的对象
    CommService *service; // 所属服务, 指向创建并管理此连接的服务实例. 如果是客户端连接, 则service==nullptr
    mpoller_t *mpoller; // 多路复用器, 指向管理I/O事件的多路复用对象
    /* Connection entry's mutex is for client session only. */
    pthread_mutex_t mutex; // 用于保护CommConnEntry结构体自身的数据的线程安全访问
};

// 设置文件描述符为非阻塞状态
static inline int set_fd_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags >= 0) {
        flags = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    return flags;
}

// 如果套接字没有绑定地址, 则绑定该套接字
static int bind_sockaddr(const int sockfd, const sockaddr *addr, const socklen_t addrlen) {
    sockaddr_storage ss{};
    socklen_t len;

    len = sizeof(sockaddr_storage);
    // 通过getsockname获取套接字当前绑定的地址信息, 如果获取失败则返回值<0
    if (getsockname(sockfd, reinterpret_cast<sockaddr *>(&ss), &len) < 0) {
        return -1;
    }
    ss.ss_family = 0; // 将地址族清零
    while (len != 0) {
        // 从sockaddr_storage结构体的末尾开始, 向前逐个字节检查. 只要发现任何一个字节不为0，就立即跳出循环
        if (reinterpret_cast<char *>(&ss)[--len] != 0) {
            // 遇到非零字节，跳出循环
            break;
        }
    }
    // 从尾到头都没有遇到非零字节, 说明原来未绑定
    if (len == 0) {
        if (bind(sockfd, addr, addrlen) < 0) {
            // 绑定失败, 返回-1
            return -1;
        }
    }
    return 0;
}

// 在已有 TCP 连接上建立 SSL/TLS 加密层, 但是并不执行SSL握手
static int create_ssl(SSL_CTX *ssl_ctx, CommConnEntry *entry) {
    // 创建一个与现有socket文件描述符关联的BIO.
    // BIO_NOCLOSE: 当这个BIO被释放时, 不要自动关闭与之关联的socket, 这样socket的生命周期就可以由外部的连接管理逻辑(如CommConnEntry)独立控制, 避免双重关闭
    BIO *bio = BIO_new_socket(entry->sockfd, BIO_NOCLOSE);
    if (bio) {
        entry->ssl = SSL_new(ssl_ctx);
        if (entry->ssl) {
            // 将前面创建好的BIO对象绑定到SSL结构体上
            // 传入同一个bio对象两次, 意味着这个 socket BIO 同时负责从网络中读取加密数据交给SSL解密, 以及将SSL加密后的数据写入网络
            SSL_set_bio(entry->ssl, bio, bio);
            return 0;
        }
        // ssl_new失败, 释放之前创建的BIO
        BIO_free(bio);
    }
    //
    return -1;
}

#define SSL_WRITEV_BUFSIZE	2048

/**自定义的向量写（vectored write）优化实现,
 * 核心思路是在特定条件下, 将多个小数据块合并到一个连续缓冲区中, 从而将多次潜在的 SSL 记录封装减少为一次, 以提升传输效率 */
static int ssl_writev(SSL *ssl, struct iovec vectors[], const int cnt) {
    // 只在第一个数据块(vectors[0])本身小于某个预设的缓冲区大小(SSL_WRITEV_BUFSIZE), 并且总共有多个数据块(cnt > 1)时, 才执行合并操作.
    // 避免对本来就很大的单个数据块进行不必要的拷贝(因为大块数据可能已经能够有效利用网络报文), 同时也避免在只有一个数据块时进行无意义的合并操作
    if (vectors[0].iov_len < SSL_WRITEV_BUFSIZE && cnt > 1) {
        // SSL_get_app_data: 获取之前设置的自定义的数据指针
        char *p = static_cast<char *>(SSL_get_app_data(ssl));
        size_t nleft = SSL_WRITEV_BUFSIZE;
        if (!p) {
            // p==nullptr, 说明之前没有设置过, 分配空间, 通过SSL_set_app_data设置
            p = static_cast<char *>(malloc(SSL_WRITEV_BUFSIZE));
            if (!p) { return -1; } // 空间分配失败, 直接 return -1
            if (SSL_set_app_data(ssl, p) <= 0) {
                // set失败, 释放先前分配的指针
                free(p);
                return -1;
            }
        }
        // 至此, 确保p指向的内存是可用的
        size_t n = vectors[0].iov_len;
        memcpy(p, vectors[0].iov_base, n); // 拷贝第一个块
        vectors[0].iov_base = p; // 重定向基址

        p += n; // p指针后移
        nleft -= n; // 剩余空间-n
        for (int i = 1; i < cnt; ++i) {
            // 计算当前块要拷贝的长度
            if (vectors[i].iov_len < nleft) {
                n = vectors[i].iov_len;
            } else {
                n = nleft;
            }
            // 拷贝当前块
            memcpy(p, vectors[i].iov_base, n);
            vectors[i].iov_base = static_cast<char *>(vectors[i].iov_base) + n; // 调整原向量的基址
            vectors[i].iov_len -= n; // 调整原向量的长度
            // 更新指针和剩余空间
            p += n;
            nleft -= n;
            if (nleft == 0) {
                // n一定 <= nleft, 所以nleft最多为0, 不会是负数!
                break;
            }
        }
        // 更新第一个向量的长度为总拷贝长
        vectors[0].iov_len = SSL_WRITEV_BUFSIZE - nleft;
    }
    // 发送合并后的数据(或者未合并的第一块数据)
    return SSL_write(ssl, vectors[0].iov_base, vectors[0].iov_len);
}

/* 释放连接资源 */
static void release_conn(struct CommConnEntry *entry) {
    delete entry->conn;
    if (!entry->service) {
        // 如果entry->service==nullptr, 则这是一个客户端连接, 连接对象是独立创建的, 其内部的mutex也需要由它自己负责销毁
        // 如果entry->service!=nullptr, 连接对象很可能由某个服务(如CommService)统一管理.
        // 这个服务可能会维护一个连接池或采用其他复用机制, 因此连接入口的mutex生命周期应由服务来统一管理, 而非在单个连接释放时销毁, 以避免破坏复用机制
        pthread_mutex_destroy(&entry->mutex);
    }
    if (entry->ssl) {
        free(SSL_get_app_data(entry->ssl)); // 首先释放附加在SSL对象上的应用程序数据缓冲区
        SSL_free(entry->ssl); // 再释放SSL上下文对象
    }
    close(entry->sockfd); // 关闭sock
    free(entry); // 释放CommConnEntry本身
}

int CommTarget::init(const sockaddr *_addr, const socklen_t _addrlen, int _connect_timeout, int _response_timeout) {
    int ret = 0;
    this->addr = static_cast<sockaddr *>(malloc(_addrlen));
    if (this->addr) {
        ret = pthread_mutex_init(&this->mutex, nullptr);
        if (ret == 0) {
            memcpy(this->addr, _addr, _addrlen); // 此处使用内存拷贝, 却不直接用指针指向对应内存, why???
            this->addrlen = _addrlen;
            this->connect_timeout = _connect_timeout;
            this->response_timeout = _response_timeout;
            INIT_LIST_HEAD(&this->idle_list); // 初始化空闲连接列表
            // SSL功能是可选的, 需要后续主动配置才能启用
            this->ssl_ctx = nullptr;
            this->ssl_connect_timeout = 0;
            return 0;
        }
        // mutex 初始化失败, 释放之前分配的addr内存
        errno = ret;
        free(this->addr);
    }
    return -1;
}

void CommTarget::deinit() {
    pthread_mutex_destroy(&this->mutex); // 销毁互斥锁
    free(this->addr); // 释放内存
}

int CommMessageIn::feedback(const void *buf, const size_t size) {
    const CommConnEntry *comm_conn_entry = this->entry;
    const sockaddr *addr;
    socklen_t addrlen;
    if (!comm_conn_entry->ssl) {
        // 没有启用SSL
        if (comm_conn_entry->service) {
            // 存在service对象: 表明当前可能是服务端在主动向客户端发送反馈. 需要先获取目标的地址
            comm_conn_entry->target->get_addr(&addr, &addrlen);
            // sendto通常用于无连接的套接字(如 UDP), 为什么此处会使用sendto呢？
            return sendto(comm_conn_entry->sockfd, buf, size, 0, addr, addrlen);
        }
        // 没有service对象, 说明当前是客户端环境, 直接使用write发送数据
        return write(comm_conn_entry->sockfd, buf, size);
    }
    // 启用了SSL
    // 数据大小为0, 直接返回0, 表示写入了0字节
    if (size == 0) {
        return 0;
    }
    int ret = SSL_write(comm_conn_entry->ssl, buf, size); // SSL数据写入
    if (ret <= 0) {
        // 出错, 获取出错原因
        ret = SSL_get_error(comm_conn_entry->ssl, ret);
        if (ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE) {
            // 可重试错误: SSL 层在当前状态下暂时无法完成写入操作.
            errno = EAGAIN;
        } else if (ret != SSL_ERROR_SYSCALL) {
            // 非系统调用错误: 将errno设置为SSL错误码的负值
            errno = -ret;
        }
        // 系统调用错误: 不覆盖errno, 但是将ret置为-1
        ret = -1;
    }
    return ret; // 返回SSL错误码
}

// 刷新会话的超时时间
void CommMessageIn::renew() {
    CommSession *session = this->entry->session;
    session->timeout = -1;
    session->begin_time.tv_sec = -1;
    session->begin_time.tv_nsec = -1;
}

int CommService::init(const sockaddr *_bind_addr, const socklen_t _addrlen, int _listen_timeout, int _response_timeout) {
    int ret = 0;
    this->bind_addr = static_cast<sockaddr *>(malloc(_addrlen));
    if (this->bind_addr) {
        ret = pthread_mutex_init(&this->mutex, nullptr);
        if (ret == 0) {
            memcpy(this->bind_addr, _bind_addr, _addrlen);
            this->addrlen = _addrlen;
            this->listen_timeout = _listen_timeout;
            this->response_timeout = _response_timeout;
            INIT_LIST_HEAD(&this->keep_alive_list);

            this->ssl_ctx = nullptr;
            this->ssl_accept_timeout = 0;
            return 0;
        }
        errno = ret;
        free(this->bind_addr);
    }
    return -1;
}

void CommService::deinit() {
    pthread_mutex_destroy(&this->mutex);
    free(this->bind_addr);
}

/* 从CommService维护的 “保活连接链表”（keep_alive_list）中清理（关闭）最多 max 个连接; 如果max==-1, 则清理所有连接*/
int CommService::drain(const int max) {
    CommConnEntry *entry = nullptr;
    list_head *pos = nullptr;
    int cnt = 0;

    const int errno_bak = errno; // 备份errno
    pthread_mutex_lock(&this->mutex);
    while (cnt != max && !list_is_empty(&this->keep_alive_list)) {
        pos = this->keep_alive_list.prev;
        // 获取pos所在的CommConnEntry地址
        entry = list_entry(pos, struct CommConnEntry, list);
        // 将pos从list中删除
        list_del(pos);
        // 已删除节点数量++
        cnt++;
        // 取消对应sockfd的监听
        mpoller_del(entry->sockfd, entry->mpoller);
        // 设置连接状态为关闭
        entry->state = CONN_STATE_CLOSING;
    }
    pthread_mutex_unlock(&entry->mutex);
    errno = errno_bak; // 恢复errno
    return cnt; // 返回关闭的连接数量
}

inline void CommService::incref() {
    __sync_add_and_fetch(&this->ref, 1);
}

inline void CommService::decref() {
    if (__sync_sub_and_fetch(&this->ref, 1) == 0) {
        this->handle_unbound();
    }
}

// 管理服务端到特定客户端的连接
class CommServiceTarget : public CommTarget {
public:
    // 增加引用计数. 表示该连接被新的任务或操作引用
    void incref() { __sync_and_and_fetch(&this->ref, 1); }

    // 减少引用计数. 当计数归零时，触发连接销毁链：通知服务、释放资源、删除自身对象
    void decref() {
        if (__sync_sub_and_fetch(&this->ref, 1) == 0) {
            // 调用所属服务的decref(),
            // 在workflow中, 服务端(CommService)会持有其所有活跃连接的引用.
            // 每个连接销毁时都通知服务,使得服务可以知道当前活跃连接数
            this->service->decref();
            this->deinit(); // 释放资源
            delete this; // 调用析构函数
        }
    }

    // 关闭连接
    int shutdown();

private:
    int sockfd;
    int ref; // 引用计数

    CommService *service; // 指向所属服务, 用于在连接关闭时通知服务端更新状态

    // 私有析构, 对象的销毁必须通过decref()
    virtual ~CommServiceTarget() = default;
    friend class Communicator;
};

/* 从空闲链表中移除并且关闭一个连接 */
int CommServiceTarget::shutdown() {
    CommConnEntry *entry;
    int errno_back;
    int ret = 0;
    pthread_mutex_lock(&this->mutex);
    if (!list_is_empty(&this->idle_list)) {
        // 获取空闲链表中第一个连接所在的CommConnEntry
        entry = list_entry(this->idle_list.next, struct CommConnEntry, list);
        // 从空闲链表中删除该节点
        list_del(&entry->list);
        if (this->service->reliable) {
            // 可靠模式: 移除监听, 设置状态迁移, 允许连接完成最后的收尾工作，避免数据丢失.
            errno_back = errno;
            mpoller_del(entry->sockfd, entry->mpoller);
            entry->state = CONN_STATE_CLOSING;
            errno = errno_back;
        } else {
            // 非可靠模式: 立即释放资源
            release_conn(entry);
            __sync_sub_and_fetch(&this->ref, 1);
        }
        ret = 1;
    }
    pthread_mutex_unlock(&this->mutex);
    return ret;
}

CommSession::~CommSession() {
    // 被动接受的会话(通常可以理解为 服务端接受的连接 )在销毁时需要执行一系列特定的清理工作,
    // 因为这类连接可能由连接池管理, 生命周期更为复杂.
    // 而主动发起的连接(如客户端连接)可能采用更简单的生命周期管理, 因此直接返回
    if (!this->passive) { return; }

    auto _target = dynamic_cast<CommServiceTarget *>(this->target);
    if (!this->out && _target->has_idle_conn()) {
        // !this->out: 表示它没有向外发送消息的需求, 进一步验证它是由服务端管理的入站连接
        // _target->has_idle_conn(): 检查这个CommServiceTarget所管理的连接池中是否还存在空闲的连接

        // 并非直接销毁对象, 而是触发一个优雅的关闭流程, 通知连接池开始关闭其管理的空闲连接
        _target->shutdown();
    }
    // 减少引用计数
    _target->decref();
}

// 获取首次超时的超时时间(间隔, 毫秒)
inline int Communicator::first_timeout(CommSession *session) {
    int timeout = session->target->response_timeout; // 获取target中预设的响应超时时间
    // 下面的if语句的目的是: 从两个超时设置中选出更紧急（时间更短）的那个来使用
    // timeout<0 可能 表示无限等待或者使用系统默认值？？？
    // 比较session->timeout和timeout, 如果session的timeout更小, 则采用session的timeout
    // 但是考虑到session->timeout 可能<0, 所以将两者都转换为unsigned int进行比较
    if (timeout < 0 || static_cast<unsigned int>(session->timeout) <= static_cast<unsigned int>(timeout)) {
        timeout = session->timeout; // 采用会话的超时
        session->timeout = 0; // 会话的超时阀值只在第一次有效？？？
    } else {
        // 说明target的timeout更紧急
        clock_gettime(CLOCK_MONOTONIC, &session->begin_time);
    }

    return timeout;
}

// 获取下一次超时的超时时间(间隔, 毫秒)
int Communicator::next_timeout(CommSession *session) {
    int timeout = session->target->response_timeout;
    timespec cur_time{};
    int time_used, time_left;

    // 如果当前会话(session)设置了独立的超时时间(session->timeout > 0),函数会进入精细化的时间计算流程
    if (session->timeout > 0) {
        clock_gettime(CLOCK_MONOTONIC, &cur_time); // 获取当前时间
        // time_used表示从会话开始(session->begin_time)到当前时刻已经消耗的时间(毫秒)
        time_used = 1000 * (cur_time.tv_sec - session->begin_time.tv_sec) + (cur_time.tv_nsec - session->begin_time.tv_nsec) / 1000000;
        // 计算剩余时间
        time_left = session->timeout - time_used;
        /* here timeout >= 0 */
        if (time_left <= timeout) {
            // 如果剩余时间小于0, 则设置超时时间为0, 否则设置超时时间为timeleft
            timeout = time_left < 0 ? 0 : time_left;
            session->timeout = 0;
        }
    }

    return timeout;
}

// 获得发送操作的超时
int Communicator::first_timeout_send(CommSession *session) {
    session->timeout = session->send_timeout(); // 可能是考虑多态？？？
    return first_timeout(session);
}

// 获得接收操作的超时
int Communicator::first_timeout_recv(CommSession *session) {
    session->timeout = session->receive_timeout(); // 可能是考虑多态？？？
    return first_timeout(session);
}

//
void Communicator::shutdown_service(CommService *service) {
    close(service->listen_fd);
    service->listen_fd = -1;
    service->drain(-1); // 清理所有连接
    service->decref();
}

#ifndef IOV_MAX
#define IOV_MAX     16
#endif

// 同步式发送消息. 返回剩余未处理的向量数量
int Communicator::send_message_sync(iovec io_vec[], int cnt, CommConnEntry *entry) const {
    CommSession *session = entry->session;
    int timeout;
    ssize_t wrote_size;
    int i;
    while (cnt > 0) {
        if (!entry->ssl) {
            // 没有开启SSL, 使用分散写, 直接写入
            wrote_size = writev(entry->sockfd, io_vec, cnt <= IOV_MAX ? cnt : IOV_MAX);
            // n表示已经写入的字节数(不出错情况下)
            if (wrote_size < 0) {
                // 错误码为EAGAIN, 表示套接字缓冲区已满, 函数返回剩余未发送的向量数cnt
                // 否则返回-1, 表示出现了未知错误
                return errno == EAGAIN ? cnt : -1;
            }
        } else if (io_vec->iov_len > 0) {
            wrote_size = ssl_writev(entry->ssl, io_vec, cnt);
            if (wrote_size <= 0) {
                return cnt;
            }
        } else { wrote_size = 0; }
        // 下面的for循环: 根据已经写入的字节数, 计算和更新io_vec[i].base和io_vec[i].iov_len, 方便后续对未写入的部分进行处理
        for (i = 0; i < cnt; ++i) {
            if (static_cast<size_t>(wrote_size) >= io_vec[i].iov_len) {
                // 如果当前向量数据已全部发送完, 则从总发送字节数n中减去该向量的长度, 继续处理下一个向量
                wrote_size -= io_vec[i].iov_len;
            } else if (wrote_size > 0) {
                // 如果当前向量只发送了一部分, 调整该向量的起始指针和剩余长度
                io_vec[i].iov_base = static_cast<char *>(io_vec[i].iov_base) + wrote_size;
                io_vec[i].iov_len -= wrote_size;
                return cnt - i; // 返回剩余未处理的向量数量
            } else {
                // n==0, 刚好写完了i个iovec, 跳出循环做后续处理
                break;
            }
        }
        io_vec += i;
        cnt -= 1;
    }
    CommService *service = entry->service;
    if (service) {
        // 服务端连接(service!=nullptr)
        __sync_add_and_fetch(&entry->ref, 1); // 增加引用计数，防止被意外释放
        timeout = session->keep_alive_timeout(); // 获取保活超时时间
        switch (timeout) {
        default: // timeout!=0，才会执行default段的代码
            mpoller_set_timeout(entry->sockfd, timeout, this->mpoller); // 设置超时
            pthread_mutex_lock(&service->mutex);
            if (service->listen_fd >= 0) {
                entry->state = CONN_STATE_KEEPALIVE; // 设置为保活状态
                list_add(&entry->list, &service->keep_alive_list); // 加入保活列表
                entry = nullptr; // 标记entry已被管理，防止后续重复操作
            }
            pthread_mutex_unlock(&service->mutex);
            // 如果service->listen_fd < 0 (服务器执行了关闭逻辑, 如调用了shutdown或者stop类似函数),
            // 那么entry就不为空, if语句就会执行, 接着发生switch-case的穿透, 执行case 0
            if (entry) {
                // timeout==0, 会直接跳转到case 0处, 不会执行前面的代码
            case 0: // 执行立即关闭逻辑
                mpoller_del(entry->sockfd, this->mpoller); // 立即将fd从多路复用器中移除
                entry->state = CONN_STATE_CLOSING; // 设置为关闭中状态
            }
        }
    }
    // 客户端连接(service==nullptr)
    else {
        // 如果是空闲连接, 则进行超时时间计算. 否则不执行.
        // 如果一个连接是空闲状态, 说明它完成了之前的任务, 现在的任务对这个连接来说是新任务, 需要重新设置超时时间
        if (entry->state == CONN_STATE_IDLE) {
            timeout = session->first_timeout(); // ？？？
            if (timeout == 0) {
                timeout = first_timeout_recv(session); // 获取接收超时
            } else {
                // 重置超时状态. 防止该会话上一次任务的超时值影响这次任务？？
                session->timeout = -1;
                session->begin_time.tv_sec = -1;
                session->begin_time.tv_nsec = 0;
            }
            // 设置接收超时
            mpoller_set_timeout(entry->sockfd, timeout, this->mpoller);
        }
        // 设置为接收状态
        entry->state = CONN_STATE_RECEIVING;
    }
    return 0;
}

// 异步消息发送. 函数不会等待数据发送完成, 而是将数据拷贝一份交给系统底层处理, 然后直接返回
int Communicator::send_message_async(iovec vectors[], const int cnt, CommConnEntry *entry) const {
    poller_data data{};
    int timeout;
    int ret;
    int i;

    entry->write_iov = static_cast<iovec *>(malloc(cnt * sizeof(iovec))); // 准备数据写入缓冲区
    if (entry->write_iov) {
        // 异步发送过程中, 原始数据向量可能在函数返回后就被释放或修改, 所以需要深拷贝一份以确保异步操作过程中数据的完整性和安全性
        for (i = 0; i < cnt; i++) {
            entry->write_iov[i] = vectors[i];
        }
    } else { return -1; } // 缓冲区准备失败, 返回-1

    data.operation = PD_OP_WRITE;
    data.fd = entry->sockfd;
    data.ssl = entry->ssl;
    data.partial_written = partial_written; // 部分写入的回调函数
    data.context = entry; // 连接条目作为上下文
    data.write_iov = entry->write_iov;
    data.iovcnt = cnt;
    timeout = first_timeout_send(entry->session); // 获取发送操作的超时时间
    if (entry->state == CONN_STATE_IDLE) {
        // 如果是空闲连接, 说明这是复用了先前的连接, 使用mpoller_mod修改已有的监听事件比添加新事件更高效
        ret = mpoller_mod(&data, timeout, this->mpoller);
        if (ret < 0 && errno == ENOENT) {
            // 如果mpoller_mod返回错误且错误码为ENOENT, 表示该文件描述符尚未被多路复用器监听.
            // 此时将连接状态改为CONN_STATE_RECEIVING, 这可能触发后续的添加操作或特殊处理逻辑
            entry->state = CONN_STATE_RECEIVING;
        }
    } else {
        // 对于非空闲连接, 使用mpoller_add添加新的写监听事件.
        // 如果添加成功后发现通信器正在停止(stop_flag为真)则立即取消刚添加的监听, 这是优雅关闭的一部分
        ret = mpoller_add(&data, timeout, this->mpoller);
        if (ret >= 0) {
            if (this->stop_flag) {
                // 如果添加成功后发现通信器正在停止, 则立即取消刚刚添加的监听. 这是优雅关闭的一部分
                mpoller_del(data.fd, this->mpoller);
            }
        }
    }

    if (ret < 0) {
        free(entry->write_iov);
        if (entry->state != CONN_STATE_RECEIVING) {
            // 只有当连接状态不是CONN_STATE_RECEIVING时，才返回-1表示完全失败,
            return -1;
        }
        // 如果状态已经是 RECEIVING，即使前面的操作失败，仍返回 1，这可能表示连接处于某种可恢复状态
    }

    return 1;
}

#define ENCODE_IOV_MAX      2048

// 智能混合发送: 它先尝试同步发送, 如果未能一次性发送完所有数据, 则对剩余部分启用异步发送
int Communicator::send_message(CommConnEntry *entry) const {
    iovec io_vec[ENCODE_IOV_MAX];
    iovec *end;
    int cnt = entry->session->out->encode(io_vec, ENCODE_IOV_MAX);
    if (static_cast<unsigned int>(cnt) > ENCODE_IOV_MAX) {
        // 缓冲区溢出
        if (cnt > ENCODE_IOV_MAX) {
            errno = EOVERFLOW;
        }
        return -1;
    }
    // cnt个iovec发送成功的情况下, 同步发送的结束位置
    end = io_vec + cnt;
    cnt = this->send_message_sync(io_vec, cnt, entry);
    // cnt>0: 此时cnt表示剩余未写入的io_vec数, 可能因为缓冲区已满, 导致部分iovec没有被写入
    if (cnt <= 0) {
        // 出错, 返回错误码
        return cnt;
    }
    // 异步写入剩余未写入的数据
    return this->send_message_async(end - cnt, cnt, entry);
}

/**服务端处理请求.
 * 核心逻辑: 根据poller返回的事件状态来驱动连接状态机的转换, 并执行相应的回调处理 */
void Communicator::handle_incoming_request(poller_result *res) {
    auto entry = static_cast<CommConnEntry *>(res->data.context);
    CommTarget *target = entry->target;
    CommSession *session = nullptr;
    int state = -1;

    switch (res->state) {
    case PR_ST_SUCCESS: {
        // IO操作成功, 将连接置为空闲状态以供复用
        session = entry->session;
        state = CS_STATE_TOREPLY;
        pthread_mutex_lock(&target->mutex);
        if (entry->state == CONN_STATE_SUCCESS) {
            // 如果当前连接状态为SUCCESS, 则增加其引用计数, 然后将状态改为IDLE(空闲), 添加到空闲链表中
            __sync_add_and_fetch(&entry->ref, 1);
            entry->state = CONN_STATE_IDLE;
            list_add(&entry->list, &target->idle_list);
        }
        pthread_mutex_unlock(&target->mutex);
        break;
    }
    /**开发者希望 PR_ST_FINISHED 和 PR_ST_ERROR 这两种状态共享绝大部分处理逻辑(比如它们后面的锁操作和内部switch).
     * 通过 if (true) case PR_ST_ERROR: 这种写法, 使得当poller结果是PR_ST_FINISHED时,
     * 程序在执行完res->error = ECONNRESET;后, 能直接跳转到PR_ST_ERROR的代码位置继续执行.
     * 这避免了将同样的代码写两遍*/
    case PR_ST_FINISHED: // 连接正常关闭？？？
        res->error = ECONNRESET; // 为FINISHED状态设置特定错误码
        if (true) // 这个条件永远为真，目的是为了语法正确，从而实现case穿透
        case PR_ST_ERROR: state = CONN_STATE_ERROR;
        else // 由于if(true)，else分支永远不会执行，此处仅为了语法
        case PR_ST_DELETED: // PR_ST_DELETED和PR_ST_STOPPED: 这两个状态的处理逻辑完全一致, 所以直接用标准的case贯穿写法合并在一起
    case PR_ST_STOPPED: // 当连接需要关闭(PR_ST_STOPPED)或者删除(PR_ST_DELETED)时, 判断当前状态执行相应清理操作
        state = CS_STATE_STOPPED;
        pthread_mutex_lock(&target->mutex);
        switch (entry->state) {
        case CONN_STATE_KEEPALIVE: // 保活
            pthread_mutex_lock(&entry->service->mutex);
            if (entry->state == CONN_STATE_KEEPALIVE) {
                list_del(&entry->list); // 从保活链表中移除
            }
            pthread_mutex_unlock(&entry->service->mutex);
            break;
        case CONN_STATE_IDLE: list_del(&entry->list); // 从空闲链表中移除
            break;
        case CONN_STATE_ERROR: res->error = entry->error; // 传递错误码
            state = CS_STATE_ERROR;
        // 此处不写break; 继续执行 CONN_STATE_RECEIVING 分支的代码以获取session;
        // 因为无论连接是在接收中出错还是早已出错，都需要获取会话上下文来向上层通知这个错误
        case CONN_STATE_RECEIVING: session = entry->session;
            break;
        case CONN_STATE_SUCCESS: entry->state = CONN_STATE_CLOSING; // 标记连接考试关闭
            entry = nullptr; // 用nullptr标记此条目已经处理, 防止后续重复处理
            break;
        }
        pthread_mutex_unlock(&target->mutex);
        break;
    }
    if (entry) {
        // 如果entry不为空, 说明出现了错误,
        if (session) {
            // 如果获取到了有效的session. 执行回调, 通知上层
            session->handle(state, res->error);
        }
        // 引用计数-1
        if (__sync_sub_and_fetch(&entry->ref, 1) == 0) {
            // 当计数减至0时, 表示没有其他部分再需要这个连接,
            // 随即调用__release_conn(entry)释放连接占用的核心资源（如套接字、SSL上下文等）
            release_conn(entry); // 释放连接相关资源
            dynamic_cast<CommServiceTarget *>(target)->decref(); // 减少目标引用计数
        }
    }
}

/* 客户端处理来自服务端的恢复. */
void Communicator::handle_incoming_reply(struct poller_result *res) {
    auto entry = static_cast<struct CommConnEntry *>(res->data.context);
    CommTarget *target = entry->target; // 获取对端信息(服务端)
    CommSession *session = nullptr;
    pthread_mutex_t *mutex;
    int state = -1;

    switch (res->state) {
    case PR_ST_SUCCESS: // IO操作成功完成
        session = entry->session;
        state = CS_STATE_SUCCESS;
        pthread_mutex_lock(&target->mutex);
        if (entry->state == CONN_STATE_SUCCESS) {
            __sync_add_and_fetch(&entry->ref, 1);
            if (session->timeout != 0) /* 如果session->timeout!=0，意味着设置了保活机制 */
            {
                entry->state = CONN_STATE_IDLE; // 转为空闲状态
                list_add(&entry->list, &target->idle_list); // 加入空闲链表
            } else { entry->state = CONN_STATE_CLOSING; } // 没有设置保活, 连接关闭
        }
        pthread_mutex_unlock(&target->mutex);
        break;
    case PR_ST_FINISHED: res->error = ECONNRESET;
        if (true) case PR_ST_ERROR: state = CS_STATE_ERROR;
        else case PR_ST_DELETED:
    case PR_ST_STOPPED: state = CS_STATE_STOPPED;
        mutex = &entry->mutex; // PR_ST_FINISHED, PR_ST_ERROR, PR_ST_STOPPED共同处理逻辑
        pthread_mutex_lock(&target->mutex);
        pthread_mutex_lock(mutex); // 对entry->mutex上锁, 因为客户端的CommSession可能被多个线程操作(例如，用户主动取消请求),需要更细粒度的锁来保证状态修改的原子性, 防止竞态条件
        switch (entry->state) {
        case CONN_STATE_IDLE: list_del(&entry->list);
            break;
        case CONN_STATE_ERROR: res->error = entry->error;
            state = CS_STATE_ERROR;
        case CONN_STATE_RECEIVING: session = entry->session;
            break;
        case CONN_STATE_SUCCESS:
            /* This may happen only if handler_threads > 1. */
            entry->state = CONN_STATE_CLOSING;
            entry = nullptr;
            break;
        }
        pthread_mutex_unlock(&target->mutex);
        pthread_mutex_unlock(mutex);
        break;
    }

    if (entry) {
        // entry不为nullptr，说明出错了
        if (session) {
            target->release(); // 释放target的资源
            session->handle(state, res->error); // 回调处理错误
        }
        // 减少引用计数
        if (__sync_sub_and_fetch(&entry->ref, 1) == 0) { release_conn(entry); }
    }
}

/* 处理异步读取操作结果. 根据连接的类型(服务端或客户端)将事件结果分发给不同的处理逻辑 */
void Communicator::handle_read_result(struct poller_result *res) {
    auto entry = static_cast<struct CommConnEntry *>(res->data.context);
    // PR_ST_MODIFIED是一个特殊状态, 通常表示该连接的相关参数(如监听事件)已被修改, 但并非有新的数据到达, 因此不需要立即处理读事件
    // if语句确保只有当读取操作是源于真实的数据到达或连接事件时，才进行后续处理
    if (res->state != PR_ST_MODIFIED) {
        if (entry->service) {
            // 服务端连接
            this->handle_incoming_request(res);
        } else {
            // 客户端连接
            this->handle_incoming_reply(res);
        }
    }
}

/**处理服务端异步发送回复的结果
 * 在服务端向客户端发送数据后, 根据发送结果决定是保持连接以备复用, 还是清理连接资源 */
void Communicator::handle_reply_result(struct poller_result *res) {
    auto entry = static_cast<struct CommConnEntry *>(res->data.context);
    CommService *service = entry->service;
    CommSession *session = entry->session;
    CommTarget *target = entry->target;
    int timeout;
    int state;

    switch (res->state) {
    case PR_ST_FINISHED: timeout = session->keep_alive_timeout(); // 连接正常结束, 首选检查是否需要连接保活.
        if (timeout != 0) {
            // 保活时间存在, 进行连接保活
            // 决定保活后，立即通过 __sync_add_and_fetch(&entry->ref, 1)增加连接的引用计数. 因为后续一定会执行引用计数的减少, 所以两者平衡
            __sync_add_and_fetch(&entry->ref, 1);
            /* 将操作类型改为 PD_OP_READ，并设置创建消息的回调函数为 Communicator::create_request.
             * 这标志着该连接的角色从一个“发送回复”的连接转变回一个“等待接收请求”的连接 */
            res->data.operation = PD_OP_READ;
            res->data.create_message = create_request;
            res->data.message = nullptr;
            pthread_mutex_lock(&target->mutex);
            if (mpoller_add(&res->data, timeout, this->mpoller) >= 0) {
                pthread_mutex_lock(&service->mutex);
                // 检查服务是否在运行
                if (!this->stop_flag && service->listen_fd >= 0) {
                    // 如果服务正常运行, 则将连接状态置为CONN_STATE_KEEPALIVE并加入服务的保活列表
                    entry->state = CONN_STATE_KEEPALIVE;
                    list_add(&entry->list, &service->keep_alive_list);
                } else {
                    // 如果服务已停止, 则立即取消监听, 并将连接状态置为CONN_STATE_CLOSING准备关闭
                    mpoller_del(res->data.fd, this->mpoller);
                    entry->state = CONN_STATE_CLOSING;
                }
                pthread_mutex_unlock(&service->mutex);
            } else { __sync_sub_and_fetch(&entry->ref, 1); }
            pthread_mutex_unlock(&target->mutex);
        }

        if (true) state = CS_STATE_SUCCESS;
        else if (true) case PR_ST_ERROR: state = CS_STATE_ERROR;
        else case PR_ST_DELETED: /* DELETED seems not possible. */
    case PR_ST_STOPPED: state = CS_STATE_STOPPED;
        // 无论是否保活, 都会执行回调并清理资源
        session->handle(state, res->error);
        if (__sync_sub_and_fetch(&entry->ref, 1) == 0) {
            release_conn(entry);
            dynamic_cast<CommServiceTarget *>(target)->decref();
        }

        break;
    }
}

/* 处理服务端异步读取客户端请求结果 */
void Communicator::handle_request_result(struct poller_result *res) {
    auto entry = static_cast<struct CommConnEntry *>(res->data.context);
    CommSession *session = entry->session;
    int timeout;
    int state;

    switch (res->state) {
    case PR_ST_FINISHED: // 当 I/O 操作成功读取数据后，函数准备处理下一个请求或维持连接
        /**这步将连接状态设置为CONN_STATE_RECEIVING, 表示连接正处于接收数据的状态.
         * 同时, 它重新配置res->data结构体, 为下一次的读取操作做好准备, 其中create_reply是创建回复消息的回调函数 */
        entry->state = CONN_STATE_RECEIVING;
        res->data.operation = PD_OP_READ;
        res->data.create_message = create_reply;
        res->data.message = nullptr;
        timeout = session->first_timeout(); // 优先使用session->first_timeout()的值
        if (timeout == 0) {
            // 如果该值为0, 则调用first_timeout_recv(session)获取一个接收超时
            timeout = first_timeout_recv(session);
        } else {
            // 如果不为0, 则会重置会话的超时状态(将timeout设为-1, begin_time设为无效值), 这通常表示一个一次性的短超时, 用于接收请求后的后续操作
            session->timeout = -1;
            session->begin_time.tv_sec = -1;
            session->begin_time.tv_nsec = 0;
        }
        /* 尝试将连接重新加入多路复用器(mpoller). 如果成功, 会检查服务是否正在停止(stop_flag), 如果是则立即将连接从多路复用器中移除. */
        if (mpoller_add(&res->data, timeout, this->mpoller) >= 0) {
            if (this->stop_flag) { mpoller_del(res->data.fd, this->mpoller); }
            break;
        }
        /* 如果 mpoller_add 失败, 则记录错误码, 并利用 switch 的 fall-through 特性进入错误处理分支 */
        res->error = errno;
        if (true) case PR_ST_ERROR: state = CS_STATE_ERROR;
        else case PR_ST_DELETED:
    case PR_ST_STOPPED: state = CS_STATE_STOPPED;
        // 释放target目标资源
        entry->target->release();
        session->handle(state, res->error); // 回调函数处理错误
        pthread_mutex_lock(&entry->mutex);
        /* do nothing */
        pthread_mutex_unlock(&entry->mutex);
        // 将连接条目 (entry) 的引用计数减1
        if (__sync_sub_and_fetch(&entry->ref, 1) == 0) { release_conn(entry); }

        break;
    }
}

// 处理异步写操作完成后的结果
void Communicator::handle_write_result(struct poller_result *res) {
    auto entry = static_cast<struct CommConnEntry *>(res->data.context);

    free(entry->write_iov); // 释放写缓冲区
    entry->write_iov = nullptr;
    if (entry->service) {
        // 通常意味着服务端已经向客户端发送了一个响应(Reply), 需要处理此回复发送后的后续事宜，例如可能将连接置为 Keep-Alive 状态以复用
        this->handle_reply_result(res);
    } else {
        // 通常表示客户端已经向服务器发送了一个请求(Request),需要处理请求发送后的后续事宜，例如开始准备接收服务器的响应
        this->handle_request_result(res);
    }
}

/* 接收新的客户端连接 */
CommConnEntry *Communicator::accept_conn(CommServiceTarget *target, CommService *service) {
    CommConnEntry *entry = nullptr;
    size_t size;
    // 设置非阻塞
    if (set_fd_nonblock(target->sockfd) >= 0) {
        /* 分配的内存只包含mutex字段之前的所有字段, 而mutex及其之后的字段(如果存在)并未被分配.
         * 这通常是因为互斥锁mutex需要特殊的初始化(如pthread_mutex_init), 不能简单地通过 malloc来初始化，因此推迟到后续步骤处理 */
        size = offsetof(CommConnEntry, mutex);
        entry = static_cast<CommConnEntry *>(malloc(size));
        if (entry) {
            // 调用回调函数, 将新套接字传递进去, 由上层业务逻辑来创建并返回一个具体的连接对象(例如CommConnection)
            entry->conn = service->new_connection(target->sockfd);
            if (entry->conn) {
                entry->seq = 0; // 序列号置零, 标志一个新的请求-响应周期的开始
                entry->mpoller = nullptr; // 多路复用器指针初始为空，后续由框架赋值
                entry->service = service; // 记录该连接所属的服务
                entry->target = target; // 记录该连接所属的目标
                entry->ssl = nullptr; // SSL上下文初始为空, 表示当前是普通TCP连接
                entry->sockfd = target->sockfd;
                entry->state = CONN_STATE_CONNECTED; // 设置连接状态为“已连接”, 这是连接状态机的起点
                entry->ref = 1; // 初始化引用计数为1
                return entry;
            }
            free(entry);
        }
    }

    return nullptr;
}

// 处理客户端的连接建立结果
void Communicator::handle_connect_result(poller_result *res) {
    auto entry = static_cast<CommConnEntry *>(res->data.context);
    CommSession *session = entry->session;
    CommTarget *target = entry->target;
    int timeout;
    int state;
    int ret;

    switch (res->state) {
    case PR_ST_FINISHED: // TCP 连接成功建立
        // 如果目标配置了 SSL 上下文（target->ssl_ctx）且当前连接尚未初始化 SSL（!entry->ssl），则进入 SSL 初始化流程
        if (target->ssl_ctx && !entry->ssl) {
            // 创建SSL对象, 并且初始化SSL
            if (create_ssl(target->ssl_ctx, entry) >= 0 && target->init_ssl(entry->ssl) >= 0) {
                ret = 0;
                res->data.operation = PD_OP_SSL_CONNECT; // 初始化成功, 配置下一次异步操作为SSL握手(PD_OP_SSL_CONNECT)
                res->data.ssl = entry->ssl;
                timeout = target->ssl_connect_timeout; // 设置SSL握手超时时间
            } else { ret = -1; }
        }
        // 通过 message_out() 获取应用层需要发送的消息(如http请求)
        else if ((session->out = session->message_out()) != nullptr) {
            ret = this->send_message(entry); // 尝试发送消息
            if (ret == 0) {
                // ret==0: 表示数据需要异步发送或已进入发送队列
                res->data.operation = PD_OP_READ; // 准备开始接收服务器的回复
                res->data.create_message = create_reply;
                res->data.message = nullptr;
                timeout = session->first_timeout(); // 计算接收的首次超时时间
                if (timeout == 0) {
                    timeout = first_timeout_recv(session); // ？？？？
                } else {
                    // 重置超时计时
                    session->timeout = -1;
                    session->begin_time.tv_sec = -1;
                    session->begin_time.tv_nsec = 0;
                }
            } else if (ret > 0) { break; } // 数据已经全部同步发送完毕, 直接跳出switch
        } else { ret = -1; } // 无法获取待发送消息，标记失败

        if (ret >= 0) {
            // 无论走哪条路径，如果需要进行下一步异步操作(SSL握手或等待读取回复)函数会尝试将其注册到多路复用器
            if (mpoller_add(&res->data, timeout, this->mpoller) >= 0) {
                if (this->stop_flag) { mpoller_del(res->data.fd, this->mpoller); }
                break; // 注册成功，跳出switch
            }
        }
        // 如果mpoller_add失败或ret<0，则记录错误并进入错误处理.
        res->error = errno;
        if (1) case PR_ST_ERROR: state = CS_STATE_ERROR;
        else case PR_ST_DELETED:
    case PR_ST_STOPPED: state = CS_STATE_STOPPED;
        // 释放与通信目标相关的资源
        target->release();
        session->handle(state, res->error); // 回调上层, 通知最终结果
        release_conn(entry); // 释放连接条目本身占用的所有资源(如套接字、SSL上下文、内存等)
        break;
    }
}

//
void Communicator::handle_listen_result(poller_result *res) {
    auto service = static_cast<CommService *>(res->data.context);
    CommConnEntry *entry;
    CommServiceTarget *target;
    int timeout;

    switch (res->state) {
    case PR_ST_SUCCESS: // I/O操作成功
        target = static_cast<CommServiceTarget *>(res->data.result); // 获取对端信息
        entry = accept_conn(target, service); // 接收新连接
        if (entry) {
            entry->mpoller = this->mpoller;
            // 如果该service已经有ssl上下文
            if (service->ssl_ctx) {
                // 创建SSL对象, 并且初始化SSL
                if (create_ssl(service->ssl_ctx, entry) >= 0 && service->init_ssl(entry->ssl) >= 0) {
                    res->data.operation = PD_OP_SSL_ACCEPT; // 初始化成功, 配置下一次异步操作为SSL握手(PD_OP_SSL_ACCEPT)
                    timeout = service->ssl_accept_timeout; // 设置SSL握手超时时间
                }
            } else {
                // 该service没有设置SSL上下文, 直接配置读事件
                res->data.operation = PD_OP_READ;
                res->data.create_message = create_request;
                res->data.message = nullptr;
                timeout = target->response_timeout;
            }

            if (res->data.operation != PD_OP_LISTEN) {
                res->data.fd = entry->sockfd;
                res->data.ssl = entry->ssl;
                res->data.context = entry;
                if (mpoller_add(&res->data, timeout, this->mpoller) >= 0) {
                    if (this->stop_flag) { mpoller_del(res->data.fd, this->mpoller); }
                    break;
                }
            }

            release_conn(entry);
        } else { close(target->sockfd); }

        target->decref();
        break;

    case PR_ST_DELETED: this->shutdown_service(service);
        break;

    case PR_ST_ERROR:
    case PR_ST_STOPPED: service->handle_stop(res->error);
        break;
    }
}

// 处理 UDP 数据报接收结果
void Communicator::handle_recvfrom_result(poller_result *res) {
    auto service = static_cast<CommService *>(res->data.context);
    CommConnEntry *entry;
    CommSession *session;
    CommTarget *target;
    int state, error;

    switch (res->state) {
    case PR_ST_SUCCESS: // 成功接收到一个 UDP 数据报
        entry = static_cast<CommConnEntry *>(res->data.result);
        session = entry->session;
        target = entry->target;
        if (entry->state == CONN_STATE_SUCCESS) {
            // 状态正常, 将会话状态设置为CS_STATE_TOREPLY, 表示服务器需要准备回复
            state = CS_STATE_TOREPLY;
            error = 0;
            entry->state = CONN_STATE_IDLE; // 连接状态置为空闲
            list_add(&entry->list, &target->idle_list); // 加入空闲链表
        } else {
            // entry本身已处于错误状态或其他异常状态
            // 会话状态被设置为 CS_STATE_ERROR，并记录相应的错误码
            state = CS_STATE_ERROR;
            if (entry->state == CONN_STATE_ERROR) {
                error = entry->error;
            } else { error = EBADMSG; }
        }

        session->handle(state, error);
        if (state == CS_STATE_ERROR) {
            release_conn(entry);
            dynamic_cast<CommServiceTarget *>(target)->decref();
        }

        break;

    case PR_ST_DELETED: this->shutdown_service(service);
        break;

    case PR_ST_ERROR:
    case PR_ST_STOPPED: service->handle_stop(res->error);
        break;
    }
}

void Communicator::handle_ssl_accept_result(poller_result *res) const {
    auto entry = static_cast<struct CommConnEntry *>(res->data.context);
    CommTarget *target = entry->target;
    int timeout;

    switch (res->state) {
    case PR_ST_FINISHED: res->data.operation = PD_OP_READ;
        res->data.create_message = Communicator::create_request;
        res->data.message = nullptr;
        timeout = target->response_timeout;
        if (mpoller_add(&res->data, timeout, this->mpoller) >= 0) {
            if (this->stop_flag) mpoller_del(res->data.fd, this->mpoller);
            break;
        }

    case PR_ST_DELETED:
    case PR_ST_ERROR:
    case PR_ST_STOPPED: release_conn(entry);
        dynamic_cast<CommServiceTarget *>(target)->decref();
        break;
    }
}

void Communicator::handle_sleep_result(poller_result *res) {
    auto session = static_cast<SleepSession *>(res->data.context);
    int state = -1;

    switch (res->state) {
    case PR_ST_FINISHED: state = SS_STATE_COMPLETE;
        break;
    case PR_ST_DELETED: res->error = ECANCELED;
    case PR_ST_ERROR: state = SS_STATE_ERROR;
        break;
    case PR_ST_STOPPED: state = SS_STATE_DISRUPTED;
        break;
    }

    session->handle(state, res->error);
}

void Communicator::handle_aio_result(struct poller_result *res) {
    auto service = static_cast<IOService *>(res->data.context);
    IOSession *session;
    int state, error;

    switch (res->state) {
    case PR_ST_SUCCESS: session = static_cast<IOSession *>(res->data.result);
        pthread_mutex_lock(&service->mutex);
        list_del(&session->list);
        pthread_mutex_unlock(&service->mutex);
        if (session->res >= 0) {
            state = IOS_STATE_SUCCESS;
            error = 0;
        } else {
            state = IOS_STATE_ERROR;
            error = -session->res;
        }

        session->handle(state, error);
        service->decref();
        break;

    case PR_ST_DELETED: this->shutdown_io_service(service);
        break;

    case PR_ST_ERROR:
    case PR_ST_STOPPED: service->handle_stop(res->error);
        break;
    }
}

void Communicator::handle_poller_result(poller_result *res) {
    switch (res->data.operation) {
    case PD_OP_TIMER: this->handle_sleep_result(res);
        break;
    case PD_OP_READ: this->handle_read_result(res);
        break;
    case PD_OP_WRITE: this->handle_write_result(res);
        break;
    case PD_OP_CONNECT:
    case PD_OP_SSL_CONNECT: this->handle_connect_result(res);
        break;
    case PD_OP_LISTEN: this->handle_listen_result(res);
        break;
    case PD_OP_RECVFROM: this->handle_recvfrom_result(res);
        break;
    case PD_OP_SSL_ACCEPT: this->handle_ssl_accept_result(res);
        break;
    case PD_OP_EVENT:
    case PD_OP_NOTIFY: this->handle_aio_result(res);
        break;
    default: free(res);
        thrdpool_exit(this->thrdpool);
        return;
    }

    free(res);
}

void Communicator::handler_thread_routine(void *context) {
    auto comm = static_cast<Communicator *>(context);
    void *msg;

    while ((msg = msgqueue_get(comm->msgqueue)) != nullptr) comm->handle_poller_result(static_cast<poller_result *>(msg));
}

int Communicator::append_message(const void *buf, size_t *size, poller_message_t *msg) {
    auto in = (CommMessageIn *)msg;
    CommConnEntry *entry = in->entry;
    CommSession *session = entry->session;
    int timeout;
    int ret;

    ret = in->append(buf, size);
    if (ret > 0) {
        entry->state = CONN_STATE_SUCCESS;
        if (!entry->service) {
            timeout = session->keep_alive_timeout();
            session->timeout = timeout; /* Reuse session's timeout field. */
            if (timeout == 0) {
                mpoller_del(entry->sockfd, entry->mpoller);
                return ret;
            }
        } else timeout = -1;
    } else if (ret == 0 && session->timeout != 0) {
        if (session->begin_time.tv_sec < 0) {
            if (session->begin_time.tv_nsec < 0) timeout = session->first_timeout();
            else timeout = 0;

            if (timeout == 0) timeout = Communicator::first_timeout_recv(session);
            else session->begin_time.tv_nsec = 0;
        } else timeout = Communicator::next_timeout(session);
    } else return ret;

    /* This set_timeout() never fails, which is very important. */
    mpoller_set_timeout(entry->sockfd, timeout, entry->mpoller);
    return ret;
}

poller_message_t *Communicator::create_request(void *context) {
    auto entry = static_cast<struct CommConnEntry *>(context);
    CommService *service = entry->service;
    CommTarget *target = entry->target;
    CommSession *session;
    CommMessageIn *in;
    int timeout;

    if (entry->state == CONN_STATE_IDLE) {
        pthread_mutex_lock(&target->mutex);
        /* do nothing */
        pthread_mutex_unlock(&target->mutex);
    }

    pthread_mutex_lock(&service->mutex);
    if (entry->state == CONN_STATE_KEEPALIVE) list_del(&entry->list);
    else if (entry->state != CONN_STATE_CONNECTED) { entry = nullptr; }

    pthread_mutex_unlock(&service->mutex);
    if (!entry) {
        errno = EBADMSG;
        return nullptr;
    }

    session = service->new_session(entry->seq, entry->conn);
    if (!session) { return nullptr; }

    session->passive = 1;
    entry->session = session;
    session->target = target;
    session->conn = entry->conn;
    session->seq = entry->seq++;
    session->out = nullptr;
    session->in = nullptr;

    timeout = Communicator::first_timeout_recv(session);
    mpoller_set_timeout(entry->sockfd, timeout, entry->mpoller);
    entry->state = CONN_STATE_RECEIVING;

    dynamic_cast<CommServiceTarget *>(target)->incref();

    in = session->message_in();
    if (in) {
        in->poller_message_t::append = Communicator::append_message;
        in->entry = entry;
        session->in = in;
    }

    return in;
}

poller_message_t *Communicator::create_reply(void *context) {
    auto entry = static_cast<struct CommConnEntry *>(context);
    CommSession *session;
    CommMessageIn *in;

    if (entry->state == CONN_STATE_IDLE) {
        pthread_mutex_lock(&entry->mutex);
        /* do nothing */
        pthread_mutex_unlock(&entry->mutex);
    }

    if (entry->state != CONN_STATE_RECEIVING) {
        errno = EBADMSG;
        return nullptr;
    }

    session = entry->session;
    in = session->message_in();
    if (in) {
        in->poller_message_t::append = Communicator::append_message;
        in->entry = entry;
        session->in = in;
    }

    return in;
}

int Communicator::recv_request(const void *buf, size_t size, CommConnEntry *entry) {
    CommService *service = entry->service;
    CommTarget *target = entry->target;
    CommSession *session;
    CommMessageIn *in;
    size_t n;
    int ret;

    session = service->new_session(entry->seq, entry->conn);
    if (!session) return -1;

    session->passive = 1;
    entry->session = session;
    session->target = target;
    session->conn = entry->conn;
    session->seq = entry->seq++;
    session->out = nullptr;
    session->in = nullptr;

    entry->state = CONN_STATE_RECEIVING;

    dynamic_cast<CommServiceTarget *>(target)->incref();

    in = session->message_in();
    if (in) {
        in->entry = entry;
        session->in = in;
        do {
            n = size;
            ret = in->append(buf, &n);
            if (ret == 0) {
                size -= n;
                buf = (const char *)buf + n;
            } else if (ret < 0) {
                entry->error = errno;
                entry->state = CONN_STATE_ERROR;
            } else entry->state = CONN_STATE_SUCCESS;
        } while (ret == 0 && size > 0);
    }

    return 0;
}

int Communicator::partial_written(size_t n, void *context) {
    auto entry = static_cast<struct CommConnEntry *>(context);
    CommSession *session = entry->session;
    int timeout;

    timeout = Communicator::next_timeout(session);
    mpoller_set_timeout(entry->sockfd, timeout, entry->mpoller);
    return 0;
}

void *Communicator::accept(const struct sockaddr *addr, socklen_t addrlen,
                           int sockfd, void *context) {
    auto service = static_cast<CommService *>(context);
    auto target = new CommServiceTarget;

    if (target) {
        if (target->init(addr, addrlen, 0, service->response_timeout) >= 0) {
            service->incref();
            target->service = service;
            target->sockfd = sockfd;
            target->ref = 1;
            return target;
        }

        delete target;
    }

    close(sockfd);
    return nullptr;
}

void *Communicator::recvfrom(const sockaddr *addr, const socklen_t addrlen, const void *buf, size_t size, void *context) {
    auto service = static_cast<CommService *>(context);
    CommConnEntry *entry;
    CommServiceTarget *target;
    void *result;
    int sockfd;

    sockfd = dup(service->listen_fd);
    if (sockfd >= 0) {
        result = Communicator::accept(addr, addrlen, sockfd, context);
        if (result) {
            target = static_cast<CommServiceTarget *>(result);
            entry = Communicator::accept_conn(target, service);
            if (entry) {
                if (Communicator::recv_request(buf, size, entry) >= 0) return entry;

                release_conn(entry);
            } else close(sockfd);

            target->decref();
        }
    }

    return nullptr;
}

void Communicator::callback(struct poller_result *res, void *context) {
    auto comm = static_cast<Communicator *>(context);
    msgqueue_put(res, comm->msgqueue);
}

int Communicator::create_handler_threads(size_t handler_threads) {
    thrdpool_task task = {
        .routine = Communicator::handler_thread_routine,
        .context = this
    };
    size_t i;

    this->thrdpool = thrdpool_create(handler_threads, 0);
    if (this->thrdpool) {
        for (i = 0; i < handler_threads; i++) {
            if (thrdpool_schedule(&task, this->thrdpool) < 0) break;
        }

        if (i == handler_threads) return 0;

        msgqueue_set_nonblock(this->msgqueue);
        thrdpool_destroy(nullptr, this->thrdpool);
    }

    return -1;
}

int Communicator::create_poller(size_t poller_threads) {
    poller_params params = {
        .max_open_file = static_cast<size_t>(sysconf(_SC_OPEN_MAX)),
        .call_back = Communicator::callback,
        .context = this
    };

    if ((ssize_t)params.max_open_file < 0) return -1;

    this->msgqueue = msgqueue_create(16 * 1024, sizeof(struct poller_result));
    if (this->msgqueue) {
        this->mpoller = mpoller_create(&params, poller_threads);
        if (this->mpoller) {
            if (mpoller_start(this->mpoller) >= 0) return 0;

            mpoller_destroy(this->mpoller);
        }

        msgqueue_destroy(this->msgqueue);
    }

    return -1;
}

int Communicator::init(size_t poller_threads, size_t handler_threads) {
    if (poller_threads == 0) {
        errno = EINVAL;
        return -1;
    }

    if (this->create_poller(poller_threads) >= 0) {
        if (this->create_handler_threads(handler_threads) >= 0) {
            this->event_handler = nullptr;
            this->stop_flag = 0;
            return 0;
        }

        mpoller_stop(this->mpoller);
        mpoller_destroy(this->mpoller);
        msgqueue_destroy(this->msgqueue);
    }

    return -1;
}

void Communicator::deinit() {
    this->stop_flag = 1;
    mpoller_stop(this->mpoller);
    if (this->event_handler) this->event_handler->wait();

    msgqueue_set_nonblock(this->msgqueue);
    thrdpool_destroy(nullptr, this->thrdpool);
    mpoller_destroy(this->mpoller);
    msgqueue_destroy(this->msgqueue);
}

int Communicator::nonblock_connect(CommTarget *target) {
    int sockfd = target->create_connect_fd();

    if (sockfd >= 0) {
        if (set_fd_nonblock(sockfd) >= 0) {
            if (connect(sockfd, target->addr, target->addrlen) >= 0 ||
                errno == EINPROGRESS) {
                return sockfd;
            }
        }

        close(sockfd);
    }

    return -1;
}

struct CommConnEntry *Communicator::launch_conn(CommSession *session,
                                                CommTarget *target) {
    struct CommConnEntry *entry;
    int sockfd;
    int ret;

    sockfd = Communicator::nonblock_connect(target);
    if (sockfd >= 0) {
        entry = static_cast<struct CommConnEntry *>(malloc(sizeof(CommConnEntry)));
        if (entry) {
            ret = pthread_mutex_init(&entry->mutex, nullptr);
            if (ret == 0) {
                entry->conn = target->new_connection(sockfd);
                if (entry->conn) {
                    entry->seq = 0;
                    entry->mpoller = nullptr;
                    entry->service = nullptr;
                    entry->target = target;
                    entry->session = session;
                    entry->ssl = nullptr;
                    entry->sockfd = sockfd;
                    entry->state = CONN_STATE_CONNECTING;
                    entry->ref = 1;
                    return entry;
                }

                pthread_mutex_destroy(&entry->mutex);
            } else
                errno = ret;

            free(entry);
        }

        close(sockfd);
    }

    return nullptr;
}

int Communicator::request_idle_conn(CommSession *session, CommTarget *target) {
    CommConnEntry *entry;
    list_head *pos;
    int ret = -1;

    while (true) {
        pthread_mutex_lock(&target->mutex);
        if (!list_is_empty(&target->idle_list)) {
            pos = target->idle_list.next;
            entry = list_entry(pos, struct CommConnEntry, list);
            list_del(pos);
            pthread_mutex_lock(&entry->mutex);
        } else entry = nullptr;

        pthread_mutex_unlock(&target->mutex);
        if (!entry) {
            errno = ENOENT;
            return -1;
        }

        if (mpoller_set_timeout(entry->sockfd, -1, this->mpoller) >= 0) break;

        entry->state = CONN_STATE_CLOSING;
        pthread_mutex_unlock(&entry->mutex);
    }

    entry->session = session;
    session->conn = entry->conn;
    session->seq = entry->seq++;
    session->out = session->message_out();
    if (session->out) ret = this->send_message(entry);

    if (ret < 0) {
        entry->error = errno;
        mpoller_del(entry->sockfd, this->mpoller);
        entry->state = CONN_STATE_ERROR;
        ret = 1;
    }

    pthread_mutex_unlock(&entry->mutex);
    return ret;
}

int Communicator::request_new_conn(CommSession *session, CommTarget *target) {
    CommConnEntry *entry;
    poller_data data{};
    int timeout;

    entry = Communicator::launch_conn(session, target);
    if (entry) {
        entry->mpoller = this->mpoller;
        session->conn = entry->conn;
        session->seq = entry->seq++;
        data.operation = PD_OP_CONNECT;
        data.fd = entry->sockfd;
        data.ssl = nullptr;
        data.context = entry;
        timeout = session->target->connect_timeout;
        if (mpoller_add(&data, timeout, this->mpoller) >= 0) return 0;

        release_conn(entry);
    }

    return -1;
}

int Communicator::request(CommSession *session, CommTarget *target) {
    int errno_bak;

    if (session->passive) {
        errno = EINVAL;
        return -1;
    }

    errno_bak = errno;
    session->target = target;
    session->out = nullptr;
    session->in = nullptr;
    if (this->request_idle_conn(session, target) < 0) {
        if (this->request_new_conn(session, target) < 0) {
            session->conn = nullptr;
            session->seq = 0;
            return -1;
        }
    }

    errno = errno_bak;
    return 0;
}

int Communicator::nonblock_listen(CommService *service) {
    int sockfd = service->create_listen_fd();
    int ret;

    if (sockfd >= 0) {
        if (set_fd_nonblock(sockfd) >= 0) {
            if (bind_sockaddr(sockfd, service->bind_addr,
                              service->addrlen) >= 0) {
                ret = listen(sockfd, SOMAXCONN);
                if (ret >= 0 || errno == EOPNOTSUPP) {
                    service->reliable = (ret >= 0);
                    return sockfd;
                }
            }
        }

        close(sockfd);
    }

    return -1;
}

int Communicator::bind(CommService *service) {
    poller_data data{};
    int errno_bak = errno;
    int sockfd;

    sockfd = Communicator::nonblock_listen(service);
    if (sockfd >= 0) {
        service->listen_fd = sockfd;
        service->ref = 1;
        data.fd = sockfd;
        data.context = service;
        data.result = nullptr;
        if (service->reliable) {
            data.operation = PD_OP_LISTEN;
            data.accept = Communicator::accept;
        } else {
            data.operation = PD_OP_RECVFROM;
            data.recvfrom = Communicator::recvfrom;
        }

        if (mpoller_add(&data, service->listen_timeout, this->mpoller) >= 0) {
            errno = errno_bak;
            return 0;
        }

        close(sockfd);
    }

    return -1;
}

void Communicator::unbind(CommService *service) {
    int errno_bak = errno;

    if (mpoller_del(service->listen_fd, this->mpoller) < 0) {
        /* Error occurred on listen_fd or Communicator::deinit() called. */
        this->shutdown_service(service);
        errno = errno_bak;
    }
}

int Communicator::reply_reliable(CommSession *session, CommTarget *target) {
    CommConnEntry *entry;
    list_head *pos;
    int ret = -1;

    pthread_mutex_lock(&target->mutex);
    if (!list_is_empty(&target->idle_list)) {
        pos = target->idle_list.next;
        entry = list_entry(pos, struct CommConnEntry, list);
        list_del(pos);

        session->out = session->message_out();
        if (session->out) ret = this->send_message(entry);

        if (ret < 0) {
            entry->error = errno;
            mpoller_del(entry->sockfd, this->mpoller);
            entry->state = CONN_STATE_ERROR;
            ret = 1;
        }
    } else
        errno = ENOENT;

    pthread_mutex_unlock(&target->mutex);
    return ret;
}

int Communicator::reply_message_unreliable(struct CommConnEntry *entry) {
    struct iovec vectors[ENCODE_IOV_MAX];
    int cnt;

    cnt = entry->session->out->encode(vectors, ENCODE_IOV_MAX);
    if ((unsigned int)cnt > ENCODE_IOV_MAX) {
        if (cnt > ENCODE_IOV_MAX)
            errno = EOVERFLOW;
        return -1;
    }

    if (cnt > 0) {
        struct msghdr message = {
            .msg_name = entry->target->addr,
            .msg_namelen = entry->target->addrlen,
            .msg_iov = vectors,
#ifdef __linux__
            .msg_iovlen = (size_t)cnt,
#else
            .msg_iovlen = cnt,
#endif
        };
        if (sendmsg(entry->sockfd, &message, 0) < 0) return -1;
    }

    return 0;
}

int Communicator::reply_unreliable(CommSession *session, CommTarget *target) {
    CommConnEntry *entry;
    list_head *pos;

    if (!list_is_empty(&target->idle_list)) {
        pos = target->idle_list.next;
        entry = list_entry(pos, struct CommConnEntry, list);
        list_del(pos);

        session->out = session->message_out();
        if (session->out) {
            if (this->reply_message_unreliable(entry) >= 0) return 0;
        }

        release_conn(entry);
        dynamic_cast<CommServiceTarget *>(target)->decref();
    } else
        errno = ENOENT;

    return -1;
}

int Communicator::reply(CommSession *session) {
    CommConnEntry *entry;
    CommServiceTarget *target;
    int errno_bak;
    int ret;

    if (!session->passive) {
        errno = EINVAL;
        return -1;
    }

    if (session->out) {
        errno = ENOENT;
        return -1;
    }

    errno_bak = errno;
    target = dynamic_cast<CommServiceTarget *>(session->target);
    if (target->service->reliable) ret = this->reply_reliable(session, target);
    else ret = this->reply_unreliable(session, target);

    if (ret == 0) {
        entry = session->in->entry;
        session->handle(CS_STATE_SUCCESS, 0);
        if (__sync_sub_and_fetch(&entry->ref, 1) == 0) {
            release_conn(entry);
            target->decref();
        }
    } else if (ret < 0) return -1;

    errno = errno_bak;
    return 0;
}

int Communicator::push(const void *buf, size_t size, CommSession *session) {
    CommMessageIn *in = session->in;
    pthread_mutex_t *mutex;
    int ret;

    if (!in) {
        errno = ENOENT;
        return -1;
    }

    if (session->passive) mutex = &session->target->mutex;
    else mutex = &in->entry->mutex;

    pthread_mutex_lock(mutex);
    if ((!session->passive || session->target->has_idle_conn()) &&
        in->entry->session == session) {
        ret = in->inner()->feedback(buf, size);
    } else {
        errno = ENOENT;
        ret = -1;
    }

    pthread_mutex_unlock(mutex);
    return ret;
}

int Communicator::shutdown(CommSession *session) {
    CommServiceTarget *target;

    if (!session->passive) {
        errno = EINVAL;
        return -1;
    }

    target = dynamic_cast<CommServiceTarget *>(session->target);
    if (session->out || !target->shutdown()) {
        errno = ENOENT;
        return -1;
    }

    return 0;
}

int Communicator::sleep(SleepSession *session) {
    timespec value;

    if (session->duration(&value) >= 0) {
        if (mpoller_add_timer(&value, session, &session->timer, &session->index,
                              this->mpoller) >= 0) {
            return 0;
        }
    }

    return -1;
}

int Communicator::unsleep(SleepSession *session) {
    return mpoller_del_timer(session->timer, session->index, this->mpoller);
}

#ifdef __linux__

void Communicator::shutdown_io_service(IOService *service) {
    pthread_mutex_lock(&service->mutex);
    close(service->event_fd);
    service->event_fd = -1;
    pthread_mutex_unlock(&service->mutex);
    service->decref();
}

int Communicator::io_bind(IOService *service) {
    poller_data data;
    int event_fd;

    event_fd = service->create_event_fd();
    if (event_fd >= 0) {
        if (set_fd_nonblock(event_fd) >= 0) {
            service->ref = 1;
            data.operation = PD_OP_EVENT;
            data.fd = event_fd;
            data.event = IOService::aio_finish;
            data.context = service;
            data.result = nullptr;
            if (mpoller_add(&data, -1, this->mpoller) >= 0) {
                service->event_fd = event_fd;
                return 0;
            }
        }

        close(event_fd);
    }

    return -1;
}

void Communicator::io_unbind(IOService *service) {
    int errno_bak = errno;

    if (mpoller_del(service->event_fd, this->mpoller) < 0) {
        /* Error occurred on event_fd or Communicator::deinit() called. */
        this->shutdown_io_service(service);
        errno = errno_bak;
    }
}

#else

void Communicator::shutdown_io_service(IOService *service) {
    pthread_mutex_lock(&service->mutex);
    close(service->pipe_fd[0]);
    close(service->pipe_fd[1]);
    service->pipe_fd[0] = -1;
    service->pipe_fd[1] = -1;
    pthread_mutex_unlock(&service->mutex);
    service->decref();
}

int Communicator::io_bind(IOService *service) {
    struct poller_data data;
    int pipe_fd[2];

    if (service->create_pipe_fd(pipe_fd) >= 0) {
        if (set_fd_nonblock(pipe_fd[0]) >= 0) {
            service->ref = 1;
            data.operation = PD_OP_NOTIFY;
            data.fd = pipe_fd[0];
            data.notify = IOService::aio_finish;
            data.context = service;
            data.result = NULL;
            if (mpoller_add(&data, -1, this->mpoller) >= 0) {
                service->pipe_fd[0] = pipe_fd[0];
                service->pipe_fd[1] = pipe_fd[1];
                return 0;
            }
        }

        close(pipe_fd[0]);
        close(pipe_fd[1]);
    }

    return -1;
}

void Communicator::io_unbind(IOService *service) {
    int errno_bak = errno;

    if (mpoller_del(service->pipe_fd[0], this->mpoller) < 0) {
        /* Error occurred on pipe_fd or Communicator::deinit() called. */
        this->shutdown_io_service(service);
        errno = errno_bak;
    }
}

#endif

int Communicator::is_handler_thread() const {
    return thrdpool_in_pool(this->thrdpool);
}

extern "C" void __thrdpool_schedule(const struct thrdpool_task *, void *,
                                    thrdpool_t *);

int Communicator::increase_handler_thread() {
    void *buf = malloc(4 * sizeof(void *));

    if (buf) {
        if (thrdpool_increase(this->thrdpool) >= 0) {
            struct thrdpool_task task = {
                .routine = Communicator::handler_thread_routine,
                .context = this
            };
            __thrdpool_schedule(&task, buf, this->thrdpool);
            return 0;
        }

        free(buf);
    }

    return -1;
}

int Communicator::decrease_handler_thread() {
    struct poller_result *res;
    size_t size;

    size = sizeof(struct poller_result) + sizeof(void *);
    res = static_cast<poller_result *>(malloc(size));
    if (res) {
        res->data.operation = -1;
        msgqueue_put_head(res, this->msgqueue);
        return 0;
    }

    return -1;
}

void Communicator::event_handler_routine(void *context) {
    auto res = static_cast<struct poller_result *>(context);
    Communicator *comm = *reinterpret_cast<Communicator **>(res + 1);
    comm->handle_poller_result(res);
}

void Communicator::callback_custom(struct poller_result *res, void *context) {
    auto comm = static_cast<Communicator *>(context);
    CommEventHandler *handler = comm->event_handler;

    if (handler) {
        *reinterpret_cast<Communicator **>(res + 1) = comm;
        handler->schedule(Communicator::event_handler_routine, res);
    } else Communicator::callback(res, context);
}

void Communicator::customize_event_handler(CommEventHandler *handler) {
    this->event_handler = handler;
    if (handler) mpoller_set_callback(Communicator::callback_custom, this->mpoller);
    else mpoller_set_callback(Communicator::callback, this->mpoller);
}