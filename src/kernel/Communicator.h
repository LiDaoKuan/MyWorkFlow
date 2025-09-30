//
// Created by ldk on 9/28/25.
//

#ifndef MYWORKFLOW_COMMUNICATOR_H
#define MYWORKFLOW_COMMUNICATOR_H

#include <unistd.h>
#include <bits/pthreadtypes.h>
#include <openssl/ssl.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "list.h"

// final: 禁止类被继承或者虚函数被重写
class CommConnection final {
public:
    virtual ~CommConnection() = default;
};

class CommTarget {
public:
    int init(const sockaddr *addr, socklen_t len, int connect_timeout, int response_timeout);

    /**@brief 执行清理操作*/
    void deinit();

public:
    void get_addr(const sockaddr **addr, socklen_t **addrlen) const {
        *addr = this->addr;
        *addrlen = this->addrlen;
    }

    [[nodiscard]] bool has_idle_conn() const { return !list_is_empty(&this->idle_list); }

protected:
    void set_ssl(SSL_CTX *_ssl_ctx, int _ssl_connect_timeout) {
        this->ssl_ctx = _ssl_ctx;
        this->ssl_connect_timeout = _ssl_connect_timeout;
    }

    [[nodiscard]] SSL_CTX *get_ssl_ctx() const { return ssl_ctx; }

    /* 下面的虚函数是设计核心：
     * 类定义了操作骨架，而将具体步骤的实现在子类中。使得扩展不同协议（HTTP/Redis/MySQL）变得非常容易 */
private:
    /* 创建原始Socket. 默认使用 socket()系统调用. 派生类可重写以定制Socket选项（如非阻塞模式） */
    virtual int creat_connect_fd() {
        return socket(this->addr->sa_family, SOCK_STREAM, 0);
    }

    /**工厂方法. 根据已连接的Socket文件描述符，创建特定的连接对象（如 HttpConnection, RedisConnection）.
     * 默认返回基础的 CommConnection，派生类应重写此方法来实例化自己的特定连接对象 */
    virtual CommConnection *new_connection(int connect_fd) { return new CommConnection; }

    // SSL初始化钩子. 用于在SSL握手前后执行自定义操作（如验证证书）.
    virtual int init_ssl(SSL *ssl) { return 0; }

public:
    virtual void release() {};

private:
    sockaddr *addr;
    socklen_t *addrlen;
    int connect_timeout; // 连接超时时间
    int response_timeout; // 等待响应超时时间
    int ssl_connect_timeout; //SSL上下文，用于加密连接。包含SSL握手超时
    SSL_CTX *ssl_ctx; // SSL上下文，用于加密连接

private:
    struct list_head idle_list; // 空闲连接链表。用于实现连接池，管理空闲的持久连接以提升性能。
    pthread_mutex_t mutex; // 互斥锁
    friend class CommServiceTarget;
    friend class Communicator;
    /* Communicator很可能是全局通信器，负责所有IO的调度。CommServiceTarget可能是某种服务端目标。
     * 友元声明允许它们直接访问 CommTarget的私有成员（如直接操作 idle_list），从而实现高效协作，但避免了暴露这些细节给普通用户。*/
};

class CommMessageOut {
private:
    virtual void encode(struct iovec vectors[], int max) = 0;

public:
    virtual ~CommMessageOut() = default;
    friend class Communicator;
};

/* private继承：体现了 "实现继承而非接口继承" 的设计思想。
 框架内部的核心调度器（如 Communicator）需要操作 poller_message_t接口，但又不希望用户直接接触到这个底层接口。
 私有继承恰好实现了这个目的：它允许 CommMessageIn复用 poller_message_t的实现，同时又对外隐藏了基类的所有公共成员 */
class CommMessageIn : private poller_message_t {
    //
};


#endif //MYWORKFLOW_COMMUNICATOR_H