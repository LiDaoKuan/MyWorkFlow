//
// Created by ldk on 9/28/25.
//

#ifndef MYWORKFLOW_COMMUNICATOR_H
#define MYWORKFLOW_COMMUNICATOR_H

#include <unistd.h>
#include <openssl/ssl.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cstddef>
#include <pthread.h>
#include <ctime>
#include "list.h"
#include "poller.h"
#include "mpoller.h"
#include "msgqueue.h"
#include "thrdpool.h"

// final: 禁止类被继承或者虚函数被重写
class CommConnection final {
public:
    virtual ~CommConnection() = default;
};

// 存储对端的连接信息
class CommTarget {
public:
    int init(const sockaddr *addr, socklen_t addrlen, int connect_timeout, int response_timeout);

    /* 执行清理操作 */
    void deinit();

    void get_addr(const sockaddr **addr, socklen_t *addrlen) const {
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
    /* 创建流式Socket. 默认使用socket()系统调用. 派生类可重写以定制Socket选项(如非阻塞模式) */
    virtual int create_connect_fd() {
        return socket(this->addr->sa_family, SOCK_STREAM, 0);
    }

    /**工厂方法. 根据已连接的Socket文件描述符，创建特定的连接对象（如 HttpConnection, RedisConnection）.
     * 默认返回基础的 CommConnection，派生类应重写此方法来实例化自己的特定连接对象 */
    virtual CommConnection *new_connection(int connect_fd) { return new CommConnection; }

    // SSL初始化钩子. 用于在SSL握手前后执行自定义操作（如验证证书）.
    virtual int init_ssl(SSL *ssl) { return 0; }

public:
    virtual void release() {}

private:
    sockaddr *addr;
    socklen_t addrlen;
    int connect_timeout; // 连接超时时间
    int response_timeout; // 等待响应超时时间
    int ssl_connect_timeout; //SSL上下文，用于加密连接。包含SSL握手超时
    SSL_CTX *ssl_ctx; // SSL上下文，用于加密连接

    list_head idle_list; // 空闲连接链表. 用于实现连接池, 管理空闲的持久连接以提升性能.
    pthread_mutex_t mutex; // 互斥锁
    friend class CommServiceTarget;
    friend class Communicator;
    /* Communicator很可能是全局通信器，负责所有IO的调度. CommServiceTarget可能是某种服务端目标.
     * 友元声明允许它们直接访问 CommTarget的私有成员（如直接操作 idle_list），从而实现高效协作，但避免了暴露这些细节给普通用户. */
};

class CommMessageOut {
private:
    // 对数据进行编码, 编码后的数据放入参数数组vectors[]中, 返回编码成功后的数组长度
    virtual int encode(struct iovec vectors[], int max) = 0;

public:
    virtual ~CommMessageOut() = default;
    friend class Communicator;
};

// private继承：体现了 "实现继承而非接口继承" 的设计思想.
// 框架内部的核心调度器（如 Communicator）需要操作 poller_message_t 接口，但又不希望用户直接接触到这个底层接口。
// 私有继承恰好实现了这个目的: 它允许 CommMessageIn 复用 poller_message_t 的实现, 同时又对外隐藏了基类的所有公共成员

/**这个类体现了 模板方法模式 和 策略模式 的思想.
 * CommMessageIn固定了消息处理的“骨架”(如何时调用append), 而将具体协议解析的“策略”留给子类实现.
 * 它在WorkFlow这类异步网络框架中，很可能扮演着应用层协议解包器的角色 */
class CommMessageIn : private poller_message_t {
private:
    /* 消息组装核心, 处理接收到的数据流. 继承自__poller_message. 必须由子类实现. 会更改传入的参数size为剩余未处理的数据大小 */
    virtual int append(const void *buf, size_t *size) = 0;

protected:
    // Send small packet while receiving. Calling only in append.
    virtual int feedback(const void *buf, size_t size); /* 可在接收过程中发送小数据包. 即时反馈, 用于协议交互(如ACK).  */

    // In append(), reset the begin time of receiving to current time.
    virtual void renew(); /* 重置接收超时计时. 当收到部分数据时调用renew(), 可以防止因网络延迟或传输大消息时间过长而导致连接被误关闭 */

    // Return the deepest wrapped message.
    virtual CommMessageIn *inner() { return this; } // 返回最内层消息对象. 支持消息嵌套, 用于解包多层协议.
    /*此方法支持消息嵌套或包装. 例如，一个SSL解密消息内部可能包装着一个HTTP消息.
     *通过重写此方法，可以返回最内层的消息对象，使得上层逻辑可以直接处理核心业务数据，而无需关心外层的加密或封装协议。
     *这是一种典型的 装饰器模式 或 链式处理思想 的体现。*/

private:
    /*指向连接上下文的指针, 很可能包含了该连接的所有状态信息, 如文件描述符、对端地址、应用层上下文等.
     *它是连接与消息处理之间的桥梁*/
    struct CommConnEntry *entry;

public:
    virtual ~CommMessageIn();
    friend class Communicator;
};

#define CS_STATE_SUCCESS    0
#define CS_STATE_ERROR      1
#define CS_STATE_STOPPED     2
#define CS_STATE_TOREPLY    3  /* for service session only */

/* 管理单个网络会话生命周期 */
class CommSession {
private:
    /* message_out/message_in 这两个纯虚函数是 “工厂方法模式” 的典型应用.
     * 它强制要求每个具体的协议会话(如HTTPSession、MySQLSession)必须提供自己专用的消息解析器(CommMessageIn)和消息构造器(CommMessageOut).
     * 这使得 CommSession 本身完全不关心数据包的具体格式（无论是 HTTP 头部、MySQL 协议包还是自定义二进制协议），实现了真正的 协议无关性.
     * 框架底层(如Communicator)在需要读取或发送数据时，只需调用这两个接口获得相应的消息处理器进行操作即可 */

    // message_out/message_in: 提供消息处理器, 用于构造请求和解析响应
    virtual CommMessageOut *message_out() = 0;
    virtual CommMessageIn *message_in() = 0;

    /* 下面四个函数使用了策略模式:
     * 可以根据不同协议的特性(如HTTP请求需要响应超时, 而TCP长连接可能需要心跳保活)来定制最合适的超时策略
     * 这些函数返回 -1 表示禁用超时，返回 0 表示使用默认值，返回正数表示自定义超时毫秒数 */

    // 控制超时策略, 管理连接生命周期
    virtual int send_timeout() { return -1; } /* 控制发送数据过程的超时, 防止因网络延迟或对端无响应导致的连接长期挂起, 默认返回-1, 即: 永不超时 */
    virtual int receive_timeout() { return -1; } /* 控制接收数据过程的超时, 防止因网络延迟或对端无响应导致的连接长期挂起 */
    virtual int keep_alive_timeout() { return 0; } /* 管理连接空闲时间，是实现 HTTP Keep-Alive 或数据库连接池等长连接功能的关键 */
    virtual int first_timeout() { return 0; } /* 控制连接建立或首包发送的超时, 对于快速发现不可达的服务端至关重要 */

    /* handle方法是整个异步框架的 回调入口, 是 “模板方法模式” 的体现.
     * 当底层的 I/O 操作完成(如连接建立成功、数据接收完毕、超时发生或出错)时, WorkFlow 的 Communicator 会调用此函数
     * 子类在此方法中实现核心业务逻辑. 如：
     *  - 当state为成功时，处理接收到的完整请求(CommMessageIn), 并生成回复数据(CommMessageOut)
     *  - 当发生错误或超时时，进行资源的清理和错误日志记录 */

    // 异步事件处理, 处理IO操作结果或状态变更
    virtual void handle(int state, int error) = 0;

protected:
    // 获取会话上下文, 如连接对象、消息对象和序列号
    [[nodiscard]] CommTarget *get_target() const { return this->target; }
    [[nodiscard]] CommConnection *get_connect() const { return this->conn; }
    [[nodiscard]] CommMessageIn *get_message_in() const { return this->msg_in; }
    [[nodiscard]] CommMessageOut *get_message_out() const { return msg_out; }
    [[nodiscard]] long long get_seq() const { return this->seq; }

private:
    CommTarget *target;
    CommConnection *conn; // 代表底层的网络连接
    CommMessageOut *msg_out; // 指向当前会话使用的消息处理器
    CommMessageIn *msg_in; // 指向当前会话使用的消息处理器
    long long seq; // 序列号, 用于匹配请求和响应, 尤其在多路复用的连接中非常重要

    struct timespec begin_time; // 操作的开始时间
    int timeout; // 操作的超时阀值(毫秒？)
    int passive; // 当设置为 1 时, 表示该会话是由服务端被动接受的连接, 这将影响框架内部对其生命周期管理的策略

public:
    CommSession() { this->passive = 0; }
    virtual ~CommSession() = 0;
    friend class CommMessageIn;
    friend class Communicator;
};

/* 管理服务端通信生命周期 */
class CommService {
public:
    // 服务端地址绑定、参数配置、资源初始化
    int init(const sockaddr *_bind_addr, socklen_t _addrlen, int _listen_timeout, int response_timeout);
    void deinit(); // 释放资源
    int drain(int max); // 优雅关闭，排空现有连接

    void get_addr(const sockaddr **addr_, socklen_t *addrlen_) const {
        *addr_ = this->bind_addr;
        *addrlen_ = this->addrlen;
    }

protected:
    void set_ssl(SSL_CTX *ssl_ctx_, int ssl_accept_timeout_) {
        this->ssl_ctx = ssl_ctx_;
        this->ssl_accept_timeout = ssl_accept_timeout_;
    }

    [[nodiscard]] SSL_CTX *get_ssl_ctx() const { return this->ssl_ctx; }

private:
    // 工厂方法. 子类必须实现，为每个新连接创建特定的协议会话对象
    /**依赖倒置原则: 高层模块(Communicator)依赖于抽象的CommSession接口，而非具体的实现细节
     *
     * 框架层(如Communicator)在接受新连接后，会调用此方法
     *
     * 子类(如WFServer)必须重写此方法, 并返回一个特定于协议(如HTTP、MySQL)的CommSession子类对象(如HttpSession) */
    virtual CommSession *new_session(long long seq, CommConnection *conn) = 0;
    // 服务停止的通知回调
    virtual void handle_stop(int error) {}
    // 服务解绑的通知回调
    virtual void handle_unbound() = 0;

    // 可重写的底层辅助函数，如创建监听套接字、连接对象和 SSL 初始化
    virtual int create_listen_fd() { return socket(this->bind_addr->sa_family, SOCK_STREAM, 0); }
    virtual CommConnection *new_connection(int accept_fd) { return new CommConnection; }
    virtual int init_ssl(SSL *ssl) { return 0; }

    // 内部生命周期管理
    void incref();
    void decref();

private:
    sockaddr *bind_addr;
    socklen_t addrlen;
    int listen_timeout; // 控制监听套接字接受新连接的等待时间，影响服务启动的容忍度
    int response_timeout; // 定义服务端发出响应后等待客户端确认或后续操作的最大时间，影响请求完整周期
    int ssl_accept_timeout; // 限制SSL/TLS握手阶段的持续时间，保护服务端资源
    SSL_CTX *ssl_ctx; // 存储SSL库的配置上下文（如证书、私钥、协议版本），是所有SSL连接的基础

    int reliable; // 标志位，用于启用TCP保活机制，以检测和清理失效连接??? or 用于控制可靠关闭和非可靠关闭
    int listen_fd;
    int ref; // 引用计数器，用于跟踪活跃连接数，是实现优雅停机的关键

    list_head keep_alive_list; // 管理处于Keep-Alive状态的连接链表，支持连接复用
    pthread_mutex_t mutex;

public:
    virtual ~CommService() = 0;
    friend class CommServiceTarget;
    friend class Communicator;
};

#define SS_STATE_COMPLETE   0
#define SS_STATE_ERROR      1
#define SS_STATE_DISRUPTED  2

/*虽然类名是 SleepSession，但其 handle 方法处理的 state 参数暗示了它可能管理着一个小的状态机*/
class SleepSession {
private:
    // 计算休眠时长, 为任务调度提供时间依据(策略模式)
    virtual int duration(timespec *value) = 0;
    // 处理状态变更, 响应超时、唤醒等异步事件
    virtual void handle(int state, int error) = 0;

private:
    void *timer; // 指向关联的定时器对象. 生命周期绑定, 确保休眠会话与定时器同生共死
    int index; // 在管理器中的索引/标识???

public:
    virtual ~SleepSession();
    friend class Communicator;
};

#ifdef __linux__
# include "IOService_linux.h"
#else
# include "IOService_thread.h"
#endif

class CommEventHandler {
private:
    /**投递异步任务, 将函数指针和上下文关联
     * 该方法将“要执行的任务”(routine)和“任务执行时所需的数据”(context)解耦.
     * 框架的核心组件(如Communicator)只需要调用 schedule来投递任务，而完全无需关心底层是使用线程池、事件循环还是其他机制来执行这些任务.
     * 这为实现多种不同的调度策略(如单线程队列、多线程工作窃取、优先级队列等)提供了极大的灵活性 */
    virtual void schedule(void (*routine)(void *), void *context) = 0;
    // 等待事件就绪. 等待的具体语义完全由子类决定
    virtual void wait() = 0;

public:
    virtual ~CommEventHandler();
    friend class Communicator;
};

class Communicator {
public:
    int init(size_t poller_pthreads, size_t handler_threads);
    void deinit();

    int request(CommSession *session, CommTarget *target);
    int reply(CommSession *session);

    int push(const void *buf, size_t size, CommSession *session);

    int shutdown(CommSession *session);
    int bind(CommService *service);
    void unbind(CommService *service);

    int sleep(SleepSession *session) ;
    int unsleep(SleepSession *session);

    int io_bind(IOService *io_service);
    void io_unbind(IOService *io_service);

public:
    [[nodiscard]] int is_handler_thread() const;

    int increase_handler_thread();
    int decrease_handler_thread();

    void customize_event_handler(CommEventHandler *handler);

private:
    __mpoller *mpoller{nullptr};
    __msgqueue *msgqueue{nullptr};
    __thrdpool *thrdpool{nullptr};
    int stop_flag = 0;

    CommEventHandler *event_handler{nullptr}; // 用于用户自定义事件处理器

private:
    int create_poller(size_t poller_threads);
    int create_handler_threads(size_t handler_threads);
    void shutdown_service(CommService *service);
    void shutdown_io_service(IOService *io_service);
    int send_message_sync(iovec io_vec[], int cnt, CommConnEntry *entry) const;
    int send_message_async(iovec vectors[], int cnt, CommConnEntry *entry) const;

    int send_message(CommConnEntry *entry) const;

    int request_new_conn(CommSession *session, CommTarget *target);
    int request_idle_conn(CommSession *session, CommTarget *target);

    int reply_message_unreliable(CommConnEntry *entry);

    int reply_reliable(CommSession *session, CommTarget *target);
    int reply_unreliable(CommSession *session, CommTarget *target);

    void handle_poller_result(poller_result *res);

    void handle_incoming_request(poller_result *res);
    void handle_incoming_reply(poller_result *res);

    void handle_request_result(poller_result *res);
    void handle_reply_result(poller_result *res);

    void handle_write_result(poller_result *res);
    void handle_read_result(poller_result *res);

    void handle_connect_result(poller_result *res);
    void handle_listen_result(poller_result *res);

    void handle_recvfrom_result(poller_result *res);

    void handle_ssl_accept_result(poller_result *res) const;

    void handle_sleep_result(poller_result *res);

    void handle_aio_result(poller_result *res);

    static void handler_thread_routine(void *context);

    static int nonblock_connect(CommTarget *target);
    static int nonblock_listen(CommService *service);

    static CommConnEntry *launch_conn(CommSession *session, CommTarget *target);
    static CommConnEntry *accept_conn(class CommServiceTarget *target, CommService *service);

    static int first_timeout(CommSession *session);
    static int next_timeout(CommSession *session);

    static int first_timeout_send(CommSession *session);
    static int first_timeout_recv(CommSession *session);

    static int append_message(const void *buf, size_t *size, poller_message_t *msg);

    static poller_message_t *create_request(void *context);
    static poller_message_t *create_reply(void *context);

    static int recv_request(const void *buf, size_t size, CommConnEntry *entry);

    static int partial_written(size_t n, void *context);

    static void *create_target(const sockaddr *addr, socklen_t addrlen, int sockfd, void *context);
    static void *recvfrom(const sockaddr *addr, socklen_t addrlen, const void *buf, size_t size, void *context);

    static void callback(poller_result *res, void *context);

private:
    static void event_handler_routine(void *context);
    static void callback_custom(poller_result *res, void *context);

public:
    virtual ~Communicator() = default;
};

#endif //MYWORKFLOW_COMMUNICATOR_H