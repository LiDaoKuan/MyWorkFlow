//
// Created by ldk on 9/29/25.
//

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/timerfd.h>
#else
#include <sys/event.h>
#undef LIST_HEAD
#undef SLIST_HEAD
#endif
#include <error.h>
#include <unistd.h>

#include "poller.h"
#include "list.h"
#include "rbtree.h"

#define POLLER_BUFSIZE      (256 * 1024)
#define POLLER_EVENTS_MAX   256

/**一个 __poller_node节点的典型生命周期是:
 * 在 poller_add 操作中通过 malloc创建
 * 在 I/O 操作完成或发生错误后，由工作线程将其地址写入管道.
 * __poller_handle_pipe 函数读取到该地址，执行资源释放回调.
 * 上层 Communicator 在 handler_thread_routine 中收到回调后，最终调用 free 释放节点本身 */

/**代表一个异步任务.
 * 一个__poller_node 节点既能挂在链表上，也能挂在红黑树上，
 * 使得框架可以根据需要（例如，是否设置超时）用最高效的数据结构来管理它。 */
struct __poller_node {
    int state;
    int error;
    struct poller_data data; // 存储与本次I/O操作直接相关的任务数据，通常包含文件描述符、操作类型（读/写）和回调函数等
#pragma pack(1)
    // 精巧的内存复用设计。通过联合体（union），使得该节点可以同时作为链表节点或红黑树节点，从而灵活地插入到不同的数据结构中管理，节省了内存
    union {
        struct list_head list; // 指向__poller_node在循环链表中的节点
        struct rb_node rb; // 指向__poller_node在红黑树中的节点
    };
#pragma pack()
    char in_rbtree; // 标记该节点当前是否在红黑树中
    char removed; // 标记该节点是否已被移除，用于防止重复操作
    int event; // 关注的事件掩码。指定感兴趣的事件类型，例如 POLLIN（可读）或 POLLOUT（可写）
    struct timespec timeout; // 精确的超时时间点. 使用 timespec结构可以支持高精度的定时控制
    struct __poller_node *res; // 结果指针。可能用于指向操作完成后的结果节点，或在链表中链接下一个节点。
};

/* 维护着所有被监控的描述符，并驱动事件循环 */
struct __poller {
    size_t max_open_files; // 设定可监控的最大文件描述符数量，防止资源耗尽
    void (*callback)(struct poller_result *, void *); // 当监控的fd有事件发生时，会调用callback函数，并将context作为参数传递，用于处理具体的I/O业务逻辑
    void *context; // 事件处理的上下文？？？

    pthread_t tid; // tid记录了运行事件循环的线程ID
    int pfd; // pfd通常是 epoll 的内核事件表
    int timerfd; // 定时器的文件描述符，用于精确管理时间
    // 用于线程间通信，常见于唤醒阻塞在I/O多路复用调用（如epoll_wait）中的工作线程
    int pipe_rd; // 读端
    int pipe_wr; // 写端
    int stopped; // stopped是一个标志，用于安全地停止事件循环
    /* 下面是多层次的数据结构，用于高效管理大量连接 */
    struct rb_root timeo_tree; // 红黑数根节点。根据超时时间对节点进行排序，便于快速查找和处理最早超时的节点
    struct rb_node *tree_first; // 指向红黑数的最小节点。用于快速获取最近要超时的节点
    struct rb_node *tree_last; // 指向红黑数的最大节点。
    struct list_head timeo_list; // 循环链表头节点。设置了超时时间的链表
    struct list_head no_timeo_list; // 没有设置超时时间的链表
    struct __poller_node **nodes; // 节点指针数组. 提供了一种通过文件描述符（fd）作为索引来快速查找对应 __poller_node的方法
    pthread_mutex_t mutex; // 保证在多线程环境下对核心数据结构的访问是线程安全的
    char buf[POLLER_BUFSIZE]; // 内部共享缓冲区。用于临时存储I/O数据或控制信息，减少内存分配开销
};

#ifdef __linux__

static inline int __poller_create_pfd() {
    return epoll_create(1);
}

static inline int __poller_close_pfd(int fd) {
    return close(fd);
}

/**将文件描述符加入内核事件表. 进行监听
 * @param fd: 要监控的文件描述符;
 * @param event: 关注的事件(如可读、可写);
 * @param data: 用户数据指针，用于事件触发时回调识别. 应该传入 __poller_node* 类型 */
static inline int __poller_add_fd(int fd, int event, void *data, poller_t *poller) {
    struct epoll_event ev = {
        .events = event,
        .data = {
            .ptr = data
        }
    };
    return epoll_ctl(poller->pfd, EPOLL_CTL_ADD, fd, &ev);
}

static inline int __poller_del_fd(int fd, int event, poller_t *poller) {
    return epoll_ctl(poller->pfd, EPOLL_CTL_DEL, fd, NULL);
}

static inline int __poller_mod_fd(int fd, int old_event, int new_event, void *data, poller_t *poller) {
    struct epoll_event ev = {
        .events = new_event,
        .data = {
            .ptr = data
        }
    };
    return epoll_ctl(poller->pfd, EPOLL_CTL_MOD, fd, &ev);
}

/* 创建timerfd, 使用阻塞模式 */
static inline int __poller_create_timerfd() {
    /* CLOCK_MONOTONIC是一种“单调”时钟，意味着它从某个固定点（通常是系统启动时间）开始计时，只增不减
     * 第二个参数flags可选:
     *  - TFD_NONBLOCK: 设置文件描述符为非阻塞模式。设置后，对该定时器描述符的 read操作在无超时事件时会立即返回并设置 EAGAIN 错误
     *  - TFD_CLOEXEC: 设置文件描述符为“执行时关闭”。当程序调用 exec()系列函数执行新程序时，此描述符会被自动关闭，防止它被意外继承到新程序中
     *  - 0 表示使用默认行为。即阻塞I/O模式，且文件描述符在 exec()后保持打开状态
     *  其中TFD_NONBLOCK和TFD_CLOEXEC可以同时使用: TFD_NONBLOCK | TFD_CLOEXEC
     */
    return timerfd_create(CLOCK_MONOTONIC, 0);
}

static inline int __poller_close_timerfd(int fd) {
    return close(fd);
}

/* 添加对timerfd上的超时事件(读事件)的监听 */
static inline int __poller_add_timerfd(int timerfd, poller_t *poller) {
    static struct poller_result node = {
        .data = {
            .operation = PD_OP_TIMER
        }
    };
    // EPOLLET: epoll 只在 fd 状态从“不可读”变为“可读”时通知一次。
    // 这要求工作者在事件触发后必须一次性读取完 timerfd 中的数据（即超时次数），否则可能错过后续通知
    return __poller_add_fd(timerfd, EPOLLIN | EPOLLET, &node, poller);
}

/* 设置timerfd的超时时间 */
static inline int __poller_set_timerfd(int timerfd, const struct timespec *abstime, poller_t *poller) {
    struct itimerspec timer = {
        .it_interval = {}, // it_interval.tv_sec: 循环间隔的秒数. it_value.tv_nsec: 循环间隔的纳秒数. 不设置表示
        .it_value = *abstime // it_value.tv_sec 首次超时的秒数. it_value.tv_nsec: 首次超时的毫秒数
    };
    return timerfd_settime(timerfd, TFD_TIMER_ABSTIME, &timer, NULL);

    /* 当定时器超时，fd变为可读。你必须调用 read 从 fd 中读取一个 uint64_t 类型的值，该值表示自上次读取后累计的超时次数。
     * 这是一个关键操作，如果不读取，下次将不会收到通知 */
}

typedef struct epoll_event __poller_event_t;

/* 阻塞式epoll */
static inline int __poller_wait(__poller_event_t *events, int maxevents, poller_t *poller) {
    /* timeout参数：
     *  - -1: 阻塞模式
     *  - 0: 非阻塞模式，立即返回
     *  - >0: 表示定时阻塞的时间，单位毫秒 */
    return epoll_wait(poller->pfd, events, maxevents, -1);
}

/* 根据传入的epoll_event*获得其内部的data.ptr，该字段曾在__poller_add_fd时写入 */
static inline void *__poller_event_data(const __poller_event_t *event) {
    return event->data.ptr;
}

#else /* BSD, macOS */

static inline int __poller_create_pfd() {
    return kqueue();
}

static inline int __poller_close_pfd(int fd) {
    return close(fd);
}

static inline int __poller_add_fd(int fd, int event, void *data,
                                  poller_t *poller) {
    struct kevent ev;
    EV_SET(&ev, fd, event, EV_ADD, 0, 0, data);
    return kevent(poller->pfd, &ev, 1, NULL, 0, NULL);
}

static inline int __poller_del_fd(int fd, int event, poller_t *poller) {
    struct kevent ev;
    EV_SET(&ev, fd, event, EV_DELETE, 0, 0, NULL);
    return kevent(poller->pfd, &ev, 1, NULL, 0, NULL);
}

static inline int __poller_mod_fd(int fd, int old_event,
                                  int new_event, void *data,
                                  poller_t *poller) {
    struct kevent ev[2];
    EV_SET(&ev[0], fd, old_event, EV_DELETE, 0, 0, NULL);
    EV_SET(&ev[1], fd, new_event, EV_ADD, 0, 0, data);
    return kevent(poller->pfd, ev, 2, NULL, 0, NULL);
}

static inline int __poller_create_timerfd() {
    return 0;
}

static inline int __poller_close_timerfd(int fd) {
    return 0;
}

static inline int __poller_add_timerfd(int fd, poller_t *poller) {
    return 0;
}

static int __poller_set_timerfd(int fd, const struct timespec *abstime,
                                poller_t *poller) {
    static struct poller_result node = {
        .data = {
            .operation = PD_OP_TIMER
        }
    };
    struct timespec curtime;
    long long nseconds;
    struct kevent ev;
    int flags;

    if (abstime->tv_sec || abstime->tv_nsec) {
        flags = EV_ADD | EV_ONESHOT;
        clock_gettime(CLOCK_MONOTONIC, &curtime);
        nseconds = 1000000000LL * (abstime->tv_sec - curtime.tv_sec);
        nseconds += abstime->tv_nsec - curtime.tv_nsec;
        if (nseconds < 0) nseconds = 0;
    } else {
        flags = EV_DELETE;
        nseconds = 0;
    }

    EV_SET(&ev, fd, EVFILT_TIMER, flags, NOTE_NSECONDS, nseconds, &node);
    return kevent(poller->pfd, &ev, 1, NULL, 0, NULL);
}

typedef struct kevent __poller_event_t;

static inline int __poller_wait(__poller_event_t *events, int maxevents,
                                poller_t *poller) {
    return kevent(poller->pfd, NULL, 0, events, maxevents, NULL);
}

static inline void *__poller_event_data(const __poller_event_t *event) {
    return event->udata;
}

#define EPOLLIN		EVFILT_READ
#define EPOLLOUT	EVFILT_WRITE
#define EPOLLET		0

#endif


static inline long __timeout_cmp(const struct __poller_node *node1, const struct __poller_node *node2) {
    long ret = node1->timeout.tv_sec - node2->timeout.tv_sec;
    if (ret == 0) {
        ret = node1->timeout.tv_nsec - node2->timeout.tv_nsec;
    }
    return ret;
}

/* 将节点node插入poller的红黑数中 */
static void __poller_tree_insert(struct __poller_node *node, poller_t *poller) {
    // 注意此处是 **p 是指向指针的指针
    struct rb_node **p = &poller->timeo_tree.rb_node; // 获取指向当前poller红黑树的根节点的指针的指针
    struct rb_node *parent = NULL;
    struct __poller_node *entry;
    // 通过 rb_entry宏将 poller->tree_last（红黑树最右节点）转换为 __poller_node类型，用于快速比较
    entry = rb_entry(poller->tree_last, struct __poller_node, rb);
    if (!*p) {
        // 当前红黑数为null.
        // 新节点直接成为根节点，同时 tree_first和 tree_last均指向该节点
        poller->tree_first = &node->rb;
        poller->tree_last = &node->rb;
    } else if (__timeout_cmp(node, entry) >= 0) {
        // 新节点超时时间 ≥ 当前最大超时节点
        // 将新节点插入到当前最大超时节点tree_last的右子树上
        parent = poller->tree_last;
        p = &parent->rb_right; // 令 p(二重指针) 指向 "指向目标插入位置的指针(一重指针)"
        poller->tree_last = &node->rb; // 更新 tree_last 为新插入的节点
    } else {
        // 新节点超时时间 < 当前最大超时节点
        do {
            // 记录parent
            parent = *p;
            // 通过 rb_entry 宏将 *p（红黑树当前节点）转换为 __poller_node 类型，用于快速比较
            entry = rb_entry(*p, struct __poller_node, rb);
            // 比较当前节点entry和要插入的节点node的超时时间大小。来进行左子树或者右子树的递归比较
            if (__timeout_cmp(node, entry) < 0) {
                p = &(*p)->rb_left; // 递归到左子树
            } else {
                p = &(*p)->rb_right; // 递归到右子树
            }
        } while (*p); // 当*p为 NULL 时, 已经找到了要插入的位置
        // 如果要插入的位置时最小超时节点的左子树，那么需要更新poller内的最小超时节点指针
        if (p == &poller->tree_first->rb_left) {
            poller->tree_first = &node->rb;
        }
    }
    node->in_rbtree = 1; // 标记node插入红黑数中
    rb_link_node(&node->rb, parent, p); // 将node插入红黑数中
    rb_insert_color(&node->rb, &poller->timeo_tree); // 平衡红黑数
}

static inline void __poller_tree_erase(struct __poller_node *node, poller_t *poller) {
    if (&node->rb == poller->tree_first) {
        // 如果node->rb是poller的红黑数的最小超时节点，需要更改poller的最小超时节点为node->rb的后继结点
        poller->tree_first = rb_next(&node->rb);
    }
    if (&node->rb == poller->tree_last) {
        // 如果node->rb是poller的红黑数的最大超时节点，需要更改poller的最大超时节点为node->rb的前序结点
        poller->tree_last = rb_prev(&node->rb);
    }
    rb_erase(&node->rb, &poller->timeo_tree); // 从红黑数中删除node
    node->in_rbtree = 0; // 标记 node 已经从红黑数中移除
}

/* 将node从poller的红黑数或者循环链表中移除 */
static int __poller_remove_node(struct __poller_node *node, poller_t *poller) {
    pthread_mutex_lock(&poller->mutex);
    int removed = node->removed;
    // 如果节点已经被移除，则不需要重复操作
    if (!removed) {
        poller->nodes[node->data.fd] = NULL;
        if (node->in_rbtree) {
            __poller_tree_erase(node, poller);
        } else {
            // 不再红黑树中，就在循环链表中
            list_del(&node->list);
        }
        // 从poller->pfd对应的内核事件表中删除node->data.fd
        __poller_del_fd(node->data.fd, node->event, poller);
    }
    pthread_mutex_unlock(&poller->mutex);
    return removed;
}

/**将网络读取到的数据块（buf）逐步拼装成一条完整的应用层消息，并在消息完整时通知上层处理器.
 * 仅由 __poller_handle_read 函数调用
 * @param buf 指向新读取的数据块
 * @param n 数据块大小
 * @param node 代表一个网络连接上下文，其中data.message字段可能指向一个正在组装的消息
 * @param poller
 * @return 消息组装状态
 *         - >0 成功组装出一条完整消息
 *         - 0 消息尚不完整，需要更多数据
 *         - <0 发生错误
 */
static int __poller_append_message(const void *buf, size_t *n, struct __poller_node *node, poller_t *poller) {
    poller_message_t *msg = node->data.message;
    struct __poller_node *res;
    int ret = 0;
    if (!msg) {
        // msg为空，说明刚开始组装消息，创建新的消息和结果对象
        // 创建空间用于存储组装结果。这块内存的释放由WorkFlow的通信器（Communicator）模块在后续流程中负责
        res = (struct __poller_node *)malloc(sizeof(struct __poller_node));
        if (!res) {
            return -1;
        }
        // 通过 create_message回调（例如，创建HTTP请求解析器）创建一个新的消息对象 msg，并同时分配一个用于承载最终结果的 res 对象
        msg = node->data.creat_message(node->data.context);
        if (!msg) {
            // msg空间分配失败，释放res内存后返回-1
            free(res);
            return -1;
        }
        // 更改data.message和res的指向，方便后续接收数据
        node->data.message = msg;
        node->res = res;
    } else {
        // msg已存在，则说明之前的数据还未拼凑出一条完整消息，当前数据是续传，直接复用已有的 msg 和 res 即可
        res = node->res;
    }
    // 开始接收数据
    // append函数的具体实现由应用层协议（如HTTP、Redis）决定。该方法会尝试从 buf 中解析数据，并更新 *n 为本次实际消费的数据量
    ret = msg->append(buf, n, msg);
    if (ret > 0) {
        // 当 append返回大于0，意味着一条完整的消息已经准备就绪
        // 1. 设置结果对象res的状态
        res->data = node->data;
        res->error = 0;
        res->state = PR_ST_SUCCESS;
        // 2. 触发回调，通知上层有消息可处理。注意此处传参有类型强转
        poller->callback((struct poller_result *)res, poller->context);
        // 3. 清空node中的消息状态，准备接收下一条消息
        node->data.message = NULL;
        node->res = NULL;
    }

    return ret;
}

/* 处理 SSL 非阻塞 I/O 操作错误 */
static int __poller_handle_ssl_error(struct __poller_node *node, int ret, poller_t *poller) {
    // 通过 SSL_get_error获取具体的错误原因
    // 关键点: 在非阻塞模式下，SSL 操作可能因底层 I/O 未就绪而无法立即完成，
    // 此时会返回 SSL_ERROR_WANT_READ或 SSL_ERROR_WANT_WRITE，这不是真正的错误，而是需要等待特定事件的通知
    const int error = SSL_get_error(node->data.ssl, ret);
    int event;
    switch (error) {
    // SSL_ERROR_WANT_READ: 表示 SSL 层需要读取更多数据才能继续（如握手数据或解密数据），此时应监听可读事件（EPOLLIN）
    case SSL_ERROR_WANT_READ: {
        event = EPOLLIN | EPOLLET; // 需要等待可读事件
        break;
    }
    // SSL_ERROR_WANT_WRITE: 表示 SSL 层需要写入数据才能继续（如握手响应或加密数据），此时应监听可写事件（EPOLLOUT）
    case SSL_ERROR_WANT_WRITE: {
        event = EPOLLOUT | EPOLLET; // 需要等待可写事件
        break;
    }
    default: {
        errno = -error;
    }
    case SSL_ERROR_SYSCALL: {
        return -1; // 真实错误，直接失败
    }
    }

    if (event == node->event) {
        return 0; // 事件未变化，无需修改 epoll
    }
    pthread_mutex_lock(&poller->mutex);
    if (!node->removed) {
        // 将fd要监听的事件改为event(该函数操作的是内核事件表，所以仍需要手动更新node->event字段)
        ret = __poller_mod_fd(node->data.fd, node->event, event, node, poller);
        if (ret >= 0) {
            node->event = event; // 更新节点的事件状态
        }
    } else {
        ret = 0;
    }
    pthread_mutex_unlock(&poller->mutex);
    return ret;
}

/* 从文件描述符（包括普通 socket 和 SSL 连接）读取数据，并组装成完整的应用层消息 */
static void __poller_handle_read(struct __poller_node *node, poller_t *poller) {
    ssize_t nleft; // 存储已接收的字节数
    size_t n;
    char *p;
    while (1) {
        p = poller->buf; // 指向共享缓冲区
        if (!node->data.ssl) {
            // 普通socket读取
            nleft = read(node->data.fd, p, POLLER_BUFSIZE);
            // 如果无数据可读，立即返回
            if (nleft < 0 && errno == EAGAIN) { return; }
        } else {
            // SSL读取
            nleft = SSL_read(node->data.ssl, p, POLLER_BUFSIZE);
            if (nleft <= 0) {
                // 处理SSL错误
                if (__poller_handle_ssl_error(node, nleft, poller) >= 0) { return; }
                if (errno == -SSL_ERROR_ZERO_RETURN) {
                    nleft = 0;
                } else { nleft = -1; }
            }
        }
        if (nleft <= 0) {
            break;
        }
        // 该循环将TCP粘包问题交给了上层去处理。
        // __poller_append_message()会调用上层回调函数，对接收到的数据交给上层进行处理
        // 上层就避免不了对数据进行拆包
        do {
            n = nleft;
            // __poller_append_message()会修改 n 为实际接收的字节数
            if (__poller_append_message(p, &n, node, poller) >= 0) {
                nleft -= n; // 消费已处理的数据
                p += n; // 移动缓冲区指针
            } else {
                nleft = -1; // 消息组装出现错误（如协议错误）
            }
        } while (nleft > 0); // 只要还有未处理的数据就继续

        if (nleft < 0) {
            // 当__poller_append_message返回-1（如消息解析失败），会设置nleft = -1。
            // 此判断会检测到该错误，并break跳出外层的while(1)读数据循环，进入错误处理流程（如关闭连接）
            break;
        }

        if (node->removed) {
            // 这是一个重要的异步安全措施。
            // 在非阻塞多线程环境中，可能在处理数据的期间，另一个线程（比如因为超时或主动关闭）已经移除了这个连接（node）。
            // 如果发现node->removed被标记，函数立即return，避免对一个已失效的连接进行任何后续操作
            return;
        }
    }
    if (__poller_remove_node(node, poller)) {
        // 确保节点已经被正式从poller的监控中移除，从而避免任何后续可能的无效操作
        return;
    }
    if (nleft == 0) {
        // nleft==0 表示对端连接已经关闭
        node->error = 0;
        node->state = PR_ST_FINISHED; // 连接正常关闭
    } else {
        node->error = errno;
        node->state = PR_ST_ERROR; // 读取错误
    }

    free(node->res);
    poller->callback((struct poller_result *)node, poller->context);
}

#ifndef IOV_MAX
#define IOV_MAX     16
#endif


/* 将数据写入 socket（包括普通 TCP 和 SSL 连接），并管理写缓冲区的状态 */
static void __poller_handle_write(struct __poller_node *node, poller_t *poller) {
    struct iovec *iov = node->data.write_iov; // iov可能是一个iovec数组
    size_t count = 0; // 本次调用累计已经写入的字节数
    ssize_t nleft; // 单次系统调用已经写入的字节数
    int iovcnt; // 当前批次处理的iovec数量
    int ret = 0; // 错误状态标识

    // 只要还有数据待写入就持续尝试
    while (node->data.iovcnt > 0) {
        if (!node->data.ssl) {
            // 普通TCP写入
            iovcnt = node->data.iovcnt;
            if (iovcnt > IOV_MAX) {
                // 限制单次写入的iovec的数量
                iovcnt = IOV_MAX;
            }
            /* writev: 将iov数组中的iovcnt个块一并写入文件描述符中. 即: 集中写 */
            nleft = writev(node->data.fd, iov, iovcnt);
            if (nleft < 0) {
                ret = errno == EAGAIN ? 0 : 1; // EAGAIN表示缓冲区写满，非错误
                break;
            }
        } else if (iov->iov_len > 0) {
            // SSL写入，单次只处理一个iovec块（SSL协议限制）
            nleft = SSL_write(node->data.ssl, iov->iov_base, iov->iov_len);
            if (nleft <= 0) {
                ret = __poller_handle_ssl_error(node, nleft, poller); // 处理SSL重协商等
                break;
            }
        } else {
            // iov->iov_len==0，跳过。
            nleft = 0;
        }
        count += nleft;
        do {
            if (nleft >= iov->iov_len) {
                // 当前iovec已全部写入: 移动到下一个iovec
                nleft -= iov->iov_len;
                iov->iov_base = (char *)iov->iov_base + iov->iov_len;
                iov->iov_len = 0; // 移动到下一个iovec之前先将当前iov_len置为0
                iov++;
                node->data.iovcnt--;
            } else {
                // 当前iovec部分写入，调整基址和长度
                iov->iov_base = (char *)iov->iov_base + nleft;
                iov->iov_len -= nleft; // 更新当前iovec块的长度
                break;
            }
        } while (node->data.iovcnt > 0);
    }

    node->data.write_iov = iov; // 保存当前iovec位置(可能有数据没写完(缓冲区已满))
    // 还有数据待写入且无错误
    if (node->data.iovcnt > 0 && ret >= 0) {
        // count==0: 本次未写入任何数据，直接返回等待下次事件
        if (count == 0) { return; }
        // 通过回调通知上层"部分写入"，可能会更新超时时间
        // 当partial_writen返回false时，说明上层的业务处理出现了问题，此时不return
        // 而是进入后续流程，清理未发送的数据。因为业务已经出错，此时没写入的数据也已经失效
        if (node->data.partial_written(count, node->data.context) >= 0) { return; }
    }
    // 清理节点并回调。
    // 如果是出错的情况，则直接丢弃未写入的数据。
    if (__poller_remove_node(node, poller)) { return; }
    // 设置最终状态
    if (node->data.iovcnt == 0) {
        node->error = 0;
        node->state = PR_ST_FINISHED; // 写入完成
    } else {
        node->error = errno;
        node->state = PR_ST_ERROR; // 写入出错
    }

    // 异步通知上层
    poller->callback((struct poller_result *)node, poller->context);
}

/* 非阻塞accept新连接 */
static void __poller_handle_listen(struct __poller_node *node, poller_t *poller) {
    struct __poller_node *res = node->res; // 存储连接建立的结果
    struct sockaddr_storage ss;
    struct sockaddr *addr = (struct sockaddr *)&ss;
    socklen_t addrlen;

    while (1) {
        addrlen = sizeof(struct sockaddr_storage); //
        const int sockfd = accept(node->data.fd, addr, &addrlen);
        if (sockfd < 0) {
            if (errno == EAGAIN || errno == EMFILE || errno == ENFILE) return; // 临时性错误，返回等待下一次事件
            else if (errno == ECONNABORTED) continue; // 连接中止。忽略并继续接收下一个
            else break; // 其他严重错误，跳出循环
        }
        void *result = node->data.accept(addr, addrlen, sockfd, node->data.context);
        if (!result) { break; } // accept返回NULL，表示创建上下文失败，跳出循环
        res->data = node->data;
        res->data.result = result; // 存储新创建的连接上下文
        res->error = 0;
        res->state = PR_ST_SUCCESS;
        // 将node复制一份，利用副本通过回调机制通知上层
        poller->callback((struct poller_result *)res, poller->context);

        // 通知完成后，它立即为下一次可能的连接接受分配新的资源。res的内存应该会在callback()中被释放掉，因此此处需要重新申请
        // 这种 预先分配 的策略旨在提升性能，避免在连续到达大量新连接时频繁进行内存分配
        res = (struct __poller_node *)malloc((sizeof(struct __poller_node)));
        node->res = res; // 更新node的res指针，为下一次accept做准备
        if (!res) { break; } // 如果分配失败，则退出循环
        if (node->removed) { return; }
    }

    /**循环一般情况下不会终止。循环终止的情况如下:
     * 严重错误：如 accept调用返回不可恢复的错误。
     * 资源分配失败：如无法为下一次 accept分配 res内存。
     * 回调失败：node->data.accept返回 NULL。
     */
    // 循环终止，将监听节点node从poller中移除
    if (__poller_remove_node(node, poller)) { return; }
    node->error = errno;
    node->state = PR_ST_ERROR; // 设置错误状态
    free(node->res); // 释放循环中预分配的资源
    poller->callback((struct poller_result *)res, poller->context); // 通知上层监听失败
}

/* 当框架发起一个非阻塞的 TCP 连接后，这个函数负责检查连接是否成功建立，并向上层报告最终结果 */
static void __poller_handle_connect(struct __poller_node *node, poller_t *poller) {
    socklen_t len = sizeof(int);
    int error;
    /* 使用 getsockopt 函数并指定 SO_ERROR选项，来获取这个 socket 上异步连接操作的真实结果 */
    if (getsockopt(node->data.fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) { error = errno; }
    /**为什么这么设计？
     * 发起非阻塞连接后，即使 connect系统调用返回了 EINPROGRESS（表示连接正在进行中），连接也可能在后台成功或失败。
     * 当 epoll 检测到该 socket 可写时，并不意味着连接成功，只意味着连接过程有了结果（可能成功也可能失败）。
     * 此时必须使用 getsockopt(fd, SOL_SOCKET, SO_ERROR, ...)来获取确切的错误码。
     * 如果连接成功，error将被设置为 0；如果失败，则会被设置为具体的错误码（如 ECONNREFUSED）。这是 Linux 下处理非阻塞连接的标准方法
     */
    /**清理
     * 无论连接成功与否，都调用 __poller_remove_node将对应的 __poller_node节点从 poller 的监控（如 epoll 实例、超时定时器）中移除。
     * 这是因为连接建立阶段已经完成，不再需要监听该 socket 的可写事件来确认连接状态
     * 如果移除操作本身失败（例如节点已被移除），函数直接返回，避免后续操作
     */
    if (__poller_remove_node(node, poller)) { return; }
    if (error) {
        node->error = 0;
        node->state = PR_ST_FINISHED; // 连接已就绪，可以进行后续的数据收发了
    } else {
        node->error = error;
        node->state = PR_ST_ERROR; // 状态设为 PR_ST_ERROR，并将具体的错误码保存在 node->error中，便于上层诊断（如连接被拒绝、超时等）
    }

    /**通过 poller->callback将结果（即 poller_result）投递到消息队列中.
     * 在 WorkFlow 中，这个回调通常是 Communicator::callback，它会将结果交给独立的 Handler 线程进行处理，从而不阻塞 poller 线程的事件循环
     */
    poller->callback((struct poller_result *)node, poller->context);
}

/* 处理无连接协议（如UDP）数据接收的核心异步I/O处理函数 */
static void __poller_handle_recvfrom(struct __poller_node *node, poller_t *poller) {
    struct __poller_node *res = node->res; // 存储数据接收的结果。但并不直接存储接收的数据
    struct sockaddr_storage ss;
    struct sockaddr *addr = (struct sockaddr *)&ss;
    socklen_t addrlen;

    while (1) {
        addrlen = sizeof(struct sockaddr_storage);
        /**addr和 addrlen用于获取发送方的地址信息，这对于UDP协议是必需的，因为每个数据报可能来自不同的客户端
         * 同时addr是直接传递指针，addrlen是引用传递 */
        ssize_t n = recvfrom(node->data.fd, poller->buf, POLLER_BUFSIZE, 0, addr, &addrlen);
        if (n < 0) {
            // n<0 说明出现错误
            if (errno == EAGAIN) {
                // 如果recvfrom返回EAGAIN，表示内核缓冲区暂无数据可读，直接return. 等待下次可读事件
                return;
            } else {
                break; // 其他错误，跳出while，然后调用callback通知上层
            }
        }

        // 调用回调函数, 传递上下文context, 交由上层处理接收到的数据
        void *result = node->data.recvfrom(addr, addrlen, poller->buf, n, node->data.context);
        if (!result) break; // 如果该回调返回 NULL，通常表示协议解析错误或内存分配失败，当前循环会终止。

        res->data = node->data;
        res->data.result = result; // 存储协议回调返回的结果
        res->error = 0;
        res->state = PR_ST_SUCCESS;
        /* 通过callback将结果投递到消息队列，由后台Handler线程池消费，从而不阻塞I/O线 */
        poller->callback((struct poller_result *)res, poller->context);

        // 为下一个可能到达的数据报预分配资源
        res = (struct __poller_node *)malloc(sizeof(struct __poller_node));
        node->res = res;
        if (!res) { break; } // 内存分配失败则退出循环

        if (node->removed) { return; } // 检查节点是否已被移除
    }

    /* 跳出while循环说明出错，将当前事件从监听poller中删除，同时设置错误信息，通过callback上报给上层 */
    if (__poller_remove_node(node, poller)) { return; }

    node->error = errno;
    node->state = PR_ST_ERROR;
    free(node->res);
    poller->callback((struct poller_result *)node, poller->context);
}

/* 服务器接受客户端的SSL握手请求 */
static void __poller_handle_ssl_accept(struct __poller_node *node, poller_t *poller) {
    const int ret = SSL_accept(node->data.ssl); // 执行或继续整个 TLS/SSL 握手过程，包括协商加密算法、验证证书（如果启用）、交换密钥等

    if (ret <= 0) {
        // ret<=0表示握手没有完成，但不一定是致命错误。
        // __poller_handle_ssl_error会检查具体的错误原因
        // 如果是可恢复错误，如SSL_ERROR_WANT_READ或 SSL_ERROR_WANT_WRITE，表示 SSL 层需要等待 socket 变为可读或可写才能继续握手。
        //      __poller_handle_ssl_error会更新 epoll 监听的事件并返回 >=0。
        // 如果是致命错误，如证书验证失败、协议错误，__poller_handle_ssl_error返回 <0，程序流程将继续向下执行，进行错误处理
        if (__poller_handle_ssl_error(node, ret, poller) >= 0) {
            // 如果是可恢复错误，则直接return，等待下次握手。不进行后续错误处理
            return;
        }
    }
    // 如果握手成功或者发生致命错误，将当前node从监听poller中移除
    if (__poller_remove_node(node, poller)) return;

    if (ret > 0) {
        // 握手成功。向上层传递成功信息
        node->error = 0;
        node->state = PR_ST_FINISHED;
    } else {
        // 握手失败，设置错误码。方便上层分析
        node->error = errno;
        node->state = PR_ST_ERROR;
    }
    // 无论是否握手成功，都将握手状态交给上层处理
    poller->callback((struct poller_result *)node, poller->context);
}

/* 客户端向服务端发起SSL握手 */
static void __poller_handle_ssl_connect(struct __poller_node *node, poller_t *poller) {
    int ret = SSL_connect(node->data.ssl);

    if (ret <= 0) {
        if (__poller_handle_ssl_error(node, ret, poller) >= 0) return;
    }

    if (__poller_remove_node(node, poller)) return;

    if (ret > 0) {
        node->error = 0;
        node->state = PR_ST_FINISHED;
    } else {
        node->error = errno;
        node->state = PR_ST_ERROR;
    }

    poller->callback((struct poller_result *)node, poller->context);
}

/* 通知对端关闭连接 */
static void __poller_handle_ssl_shutdown(struct __poller_node *node, poller_t *poller) {
    int ret = SSL_shutdown(node->data.ssl);

    if (ret <= 0) {
        if (__poller_handle_ssl_error(node, ret, poller) >= 0) return;
    }

    if (__poller_remove_node(node, poller)) return;

    if (ret > 0) {
        node->error = 0;
        node->state = PR_ST_FINISHED;
    } else {
        node->error = errno;
        node->state = PR_ST_ERROR;
    }

    poller->callback((struct poller_result *)node, poller->context);
}

/* 处理事件通知文件描述符(如eventfd) */
static void __poller_handle_event(struct __poller_node *node, poller_t *poller) {
    struct __poller_node *res = node->res;
    unsigned long long cnt = 0;
    unsigned long long value = 0;

    while (1) {
        ssize_t n = read(node->data.fd, &value, sizeof(unsigned long long));
        if (n == sizeof(unsigned long long)) {
            cnt += value; // 成功读取，累计事件计数
        } else {
            // n要么小于0, 要么等于sizeof(unsigned long long)。
            // n>=0并且n!=sizeof(unsigned long long)视为错误
            if (n >= 0) {
                errno = EINVAL; // 读取字节数不对，视为错误
            }
            break;
        }
    }
    if (errno == EAGAIN) {
        // 如果错误是 EAGAIN（或 EWOULDBLOCK），表示当前无数据可读，但文件描述符是非阻塞的，这是正常情况。
        // 函数继续处理已读取到的事件（cnt > 0时）。其他错误则直接进入错误处理
        while (1) {
            if (cnt == 0) {
                return; // 所有事件处理完毕，直接返回
            }
            cnt--;
            void *result = node->data.event(node->data.context);
            if (!result) { break; } // 回调返回NULL，表示处理失败或无需进一步处理。如果处理失败，后续事件将会被丢弃
            res->data = node->data;
            res->data.result = result;
            res->error = 0;
            res->state = PR_ST_SUCCESS;
            poller->callback((struct poller_result *)res, poller->context);

            res = (struct __poller_node *)malloc(sizeof(struct __poller_node));
            node->res = res;
            if (!res) { break; }
            if (!node->removed) { return; }
        }
        node->error = errno;
        node->state = PR_ST_ERROR;
        free(node->res);
        // 向上层报告错误
        poller->callback((struct poller_result *)node, poller->context);
    }
}

/* 处理内部线程间通知 */
static void __poller_handle_notify(struct __poller_node *node, poller_t *poller) {
    struct __poller_node *res = node->res;
    void *result;
    ssize_t n;

    while (1) {
        n = read(node->data.fd, &result, sizeof(void *));
        if (n == sizeof(void *)) {
            // 该函数期望每次读取恰好是一个 void* 指针大小的数据。这通常是一个指向某个消息或任务描述符的指针，由通知的发送方写入
            // 成功读取到一个指针数据，进行处理
            result = node->data.notify(result, node->data.context);
            if (!result) break;

            res->data = node->data;
            res->data.result = result;
            res->error = 0;
            res->state = PR_ST_SUCCESS;
            poller->callback((struct poller_result *)res, poller->context);

            res = (struct __poller_node *)malloc(sizeof(struct __poller_node));
            node->res = res;
            if (!res) break;

            if (node->removed) return;
        } else if (n < 0 && errno == EAGAIN) {
            // 无数据可读，直接返回
            return;
        } else {
            // 处理错误
            if (n > 0) { errno = EINVAL; }
            break;
        }
    }

    if (__poller_remove_node(node, poller)) return;

    if (n == 0) {
        node->error = 0;
        node->state = PR_ST_FINISHED;
    } else {
        node->error = errno;
        node->state = PR_ST_ERROR;
    }

    free(node->res);
    poller->callback((struct poller_result *)node, poller->context);
}

/* 处理通过管道发送过来的通知. 安全地回收已完成或出错的 I/O 操作所占用的资源 */
static int __poller_handle_pipe(poller_t *poller) {
    /**从 poller->pipe_rd（管道的读端）读取数据
     * 在 WorkFlow 的设计中，其他线程（如处理网络 I/O 的线程）会将需要清理的 __poller_node节点的
     * 内存地址（即 void*指针）写入到管道的写端 poller->pipe_wr */
    struct __poller_node **node = (struct __poller_node **)poller->buf;
    int stop = 0;
    /**一次读取最多 POLLER_BUFSIZE 字节的数据，然后除以 sizeof(void *) 计算出本次读取了多少个节点指针。
     * 这种批量处理的方式减少了系统调用的次数，提升了效率 */
    const int n = read(poller->pipe_rd, node, POLLER_BUFSIZE) / sizeof(void *);
    for (int i = 0; i < n; i++) {
        if (node[i]) {
            free(node[i]->res);
            poller->callback((struct poller_result *)node[i], poller->context);
        } else {
            // 如果读取到一个 NULL指针，设置 stop = 1，但并不会立即退出，
            // 而是继续处理完本轮读取到的所有指针，最后将停止标志返回给调用者，由调用者决定是否终止事件循环
            stop = 1;
        }
    }

    return stop;
}

/**集中处理超时事件
 * @param time_node 系统启动后的时间 */
static void __poller_handle_timeout(const struct __poller_node *time_node, poller_t *poller) {
    struct __poller_node *node;
    struct list_head *pos, *tmp;
    LIST_HEAD(timeo_list); // 临时链表，存储超时节点

    pthread_mutex_lock(&poller->mutex); // 加锁
    // 遍历定时事件链表
    list_for_each_safe(pos, tmp, &poller->timeo_list) {
        // 由某个定时事件得到它所在的__poller_node事件节点node的地址
        node = list_entry(pos, struct __poller_node, list);
        if (__timeout_cmp(node, time_node) > 0) {
            // 如果当前节点未超时。那么在这之后的所有节点也一定未超时
            break;
        }
        if (node->data.fd >= 0) {
            poller->nodes[node->data.fd] = NULL;
            // 将超时节点从poller监听中移除
            __poller_del_fd(node->data.fd, node->event, poller);
        } else {
            node->removed = 1;
        }
        // 将超时节点 移动 到临时链表中
        list_move_tail(pos, &timeo_list);
    }
    while (poller->tree_first) {
        // 由poller->tree_first得到它所在的__poller_node节点的地址
        node = rb_entry(poller->tree_first, struct __poller_node, rb);
        if (__timeout_cmp(node, time_node) > 0) { break; }
        if (node->data.fd > 0) {
            poller->nodes[node->data.fd] = NULL;
            __poller_del_fd(node->data.fd, node->event, poller);
        } else {
            node->removed = 1;
        }
        // 更新最小超时节点。同时也移动到下一个节点方便循环继续判断
        poller->tree_first = rb_next(poller->tree_first);
        // 将超时节点从红黑树中删除
        rb_erase(&node->rb, &poller->timeo_tree);
        // 将超时节点加入到临时链表中
        list_add_tail(&node->list, &timeo_list);
        if (!poller->tree_first) {
            poller->tree_last = NULL;
        }
    }
    pthread_mutex_unlock(&poller->mutex); // 解锁

    // 批量处理超时节点
    list_for_each_safe(pos, tmp, &timeo_list) {
        // 获得pos所在的__poller_node地址
        node = list_entry(pos, struct __poller_node, list);
        if (node->data.fd >= 0) {
            node->error = ETIMEDOUT;
            node->state = PR_ST_ERROR;
        } else {
            node->error = 0;
            node->state = PR_ST_FINISHED;
        }
        free(node->res);
        // 通知上层处理超时事件
        poller->callback((struct poller_result *)node, poller->context);
    }
}

/* 设置定时器下一次超时唤醒的时间 */
static void __poller_set_timer(poller_t *poller) {
    struct __poller_node *node = NULL;
    struct timespec abstime;

    pthread_mutex_lock(&poller->mutex);
    if (!list_is_empty(&poller->timeo_list)) {
        // node指向 poller->timeo_list 的最小超时事件所在的 __poller_node
        node = list_entry(poller->timeo_list.next, struct __poller_node, list);
    }

    if (poller->tree_first) {
        // first 指向 红黑数的最小超时节点所在的 __poller_node
        struct __poller_node *first = rb_entry(poller->tree_first, struct __poller_node, rb);
        if (!node || __timeout_cmp(first, node) < 0) {
            // node 指向 红黑数和链表的最小超时事件
            node = first;
        }
    }

    if (node) {
        abstime = node->timeout; // 使用节点的绝对超时时间
    } else {
        abstime.tv_sec = 0;
        abstime.tv_nsec = 0; // 没有定时任务，则清除定时器
    }

    __poller_set_timerfd(poller->timerfd, &abstime, poller);
    pthread_mutex_unlock(&poller->mutex);
}

/* 核心事件循环函数. 处理事件分发 */
static void *__poller_thread_routine(void *arg) {
    poller_t *poller = (poller_t *)arg; // 传入参数
    __poller_event_t events[POLLER_EVENTS_MAX]; // 存储epoll监听到的事件
    struct __poller_node time_node;
    struct __poller_node *node;
    int has_pipe_event = 0;
    int nevents = 0;
    int i = 0;

    while (1) {
        __poller_set_timer(poller); // 设置定时器
        nevents = __poller_wait(events, POLLER_EVENTS_MAX, poller); // 阻塞等待
        clock_gettime(CLOCK_MONOTONIC, &time_node.timeout); // 记录当前时间
        has_pipe_event = 0;
        // 循环遍历所有已经发生的事件
        for (i = 0; i < nevents; i++) {
            // 取出设置监听时传入的信息
            node = (struct __poller_node *)__poller_event_data(&events[i]);
            switch (node->data.operation) {
            // 根据当初设置的值判断触发了什么操作
            case PD_OP_READ: __poller_handle_read(node, poller);
                break;
            case PD_OP_WRITE: __poller_handle_write(node, poller);
                break;
            case PD_OP_LISTEN: __poller_handle_listen(node, poller);
                break;
            case PD_OP_CONNECT: __poller_handle_connect(node, poller);
                break;
            case PD_OP_RECVFROM: __poller_handle_recvfrom(node, poller);
                break;
            case PD_OP_SSL_ACCEPT: __poller_handle_ssl_accept(node, poller);
                break;
            case PD_OP_SSL_CONNECT: __poller_handle_ssl_connect(node, poller);
                break;
            case PD_OP_SSL_SHUTDOWN: __poller_handle_ssl_shutdown(node, poller);
                break;
            case PD_OP_EVENT: __poller_handle_event(node, poller);
                break;
            case PD_OP_NOTIFY: __poller_handle_notify(node, poller);
                break;
            case -1: has_pipe_event = 1; // 特殊管道事件
                break;
            default: ;
            }
        }

        if (has_pipe_event) {
            if (__poller_handle_pipe(poller)) {
                // 处理管道消息，若返回非0则说明出现问题，退出循环
                break;
            }
        }
        // 处理所有超时事件
        __poller_handle_timeout(&time_node, poller);
    }

    return NULL;
}

static int __poller_open_pipe(poller_t *poller) {
    static struct poller_result node = {
        .data = {
            .operation = -1
        }
    };
    int pipefd[2];
    // 创建管道. pipefd[1]写入， pipefd[0]读出
    if (pipe(pipefd) >= 0) {
        // 监听管道读端
        if (__poller_add_fd(pipefd[0], EPOLLIN, &node, poller) >= 0) {
            poller->pipe_rd = pipefd[0];
            poller->pipe_wr = pipefd[1];
            return 0;
        }

        close(pipefd[0]);
        close(pipefd[1]);
    }
    return -1;
}

/* 给poller创建并添加定时器文件描述符timerfd */
static int __poller_create_timer(poller_t *poller) {
    int timerfd = __poller_create_timerfd();

    if (timerfd >= 0) {
        // 添加监听
        if (__poller_add_timerfd(timerfd, poller) >= 0) {
            poller->timerfd = timerfd; // 保存timerfd
            return 0;
        }
        // 创建失败，关闭timerfd
        __poller_close_timerfd(timerfd);
    }
    // 失败返回-1
    return -1;
}

/**创建并初始化一个poller_t结构体实例，用于管理I/O事件循环。
 * 该函数负责分配内存、创建内部文件描述符（如定时器fd）、初始化互斥锁及各类链表和树结构，并设置用户回调函数。
 * 若任何一步失败，将立即清理已分配资源并返回NULL
 * @param nodes_buf 指向指针数组的指针，应该已经在调用该函数前分配空间
 * @param params 指向配置参数结构体的指针，包含最大文件数、回调函数指针及用户上下文信息
 * @return 创建成功返回指向目标实例的指针，失败返回NULL
 */
poller_t *__poller_create(void **nodes_buf, const struct poller_params *params) {
    poller_t *poller = (poller_t *)malloc(sizeof(poller_t));
    int ret;
    if (!poller) {
        return NULL;
    }
    poller->pfd = __poller_create_pfd();
    if (poller->pfd >= 0) {
        if (__poller_create_timer(poller) >= 0) {
            // 创建并初始化互斥锁
            ret = pthread_mutex_init(&poller->mutex, NULL);
            if (ret == 0) {
                poller->nodes = (struct __poller_node **)nodes_buf;
                poller->max_open_files = params->max_open_file;
                poller->callback = params->call_back;
                poller->context = params->context;

                /* 设置红黑数，定时链表，非定时链表 */
                poller->timeo_tree.rb_node = NULL;
                poller->tree_first = NULL;
                poller->tree_last = NULL;
                INIT_LIST_HEAD(&poller->timeo_list);
                INIT_LIST_HEAD(&poller->no_timeo_list);

                poller->stopped = 1;
                return poller;
            }
            // 没进入if语句，说明出错了. 关闭刚刚打开的文件描述符
            errno = ret;
            __poller_close_timerfd(poller->timerfd);
        }

        __poller_close_pfd(poller->pfd);
    }

    free(poller);
    return NULL;
}

/* 创建poller */
poller_t *poller_create(const struct poller_params *params) {
    void **nodes_buf = (void **)calloc(params->max_open_file, sizeof(void *));
    if (nodes_buf) {
        poller_t *poller = __poller_create(nodes_buf, params);
        if (poller) {
            return poller;
        }
        free(nodes_buf);
    }

    return NULL;
}

/* 销毁poller_t实例 */
void __poller_destroy(poller_t *poller) {
    pthread_mutex_destroy(&poller->mutex); // 销毁互斥锁
    __poller_close_timerfd(poller->timerfd); // 关闭定时器文件描述符timerfd
    __poller_close_pfd(poller->pfd); // 关闭内核事件表对应的文件描述符
    free(poller); // 释放空间
}

/* 销毁poller_t实例 */
void poller_destroy(poller_t *poller) {
    free(poller->nodes);
    __poller_destroy(poller);
}

/* 开启poller线程 */
int poller_start(poller_t *poller) {
    pthread_t tid;
    int ret = 0;

    pthread_mutex_lock(&poller->mutex);
    if (__poller_open_pipe(poller) >= 0) {
        // 如果管道创建成功。则开启poller线程
        ret = pthread_create(&tid, NULL, __poller_thread_routine, poller);
        if (ret == 0) {
            // 线程创建成功
            poller->tid = tid;
            poller->stopped = 0;
        } else {
            // 线程创建失败
            errno = ret;
            close(poller->pipe_wr);
            close(poller->pipe_rd);
        }
    }

    pthread_mutex_unlock(&poller->mutex);
    return -poller->stopped; // 返回poller线程开启状态
}

/* 向poller中添加node节点 */
static void __poller_insert_node(struct __poller_node *node, poller_t *poller) {
    struct __poller_node *end = list_entry(poller->timeo_list.prev, struct __poller_node, list);
    if (list_is_empty(&poller->timeo_list)) {
        list_add(&node->list, &poller->timeo_list);
        end = rb_entry(poller->tree_first, struct __poller_node, rb);
    } else if (__timeout_cmp(node, end) >= 0) {
        list_add_tail(&node->list, &poller->timeo_list);
        return;
    } else {
        __poller_tree_insert(node, poller);
        if (&node->rb != poller->tree_first) {
            return;
        }
        end = list_entry(poller->timeo_list.next, struct __poller_node, list);
    }
    if (!poller->tree_first || __timeout_cmp(node, end) < 0) {
        __poller_set_timerfd(poller->timerfd, &node->timeout, poller);
    }
}

/*  */
static void __poller_node_set_timeout(int timeout, struct __poller_node *node) {
    //
}

static int __poller_data_get_event(int *event, const struct poller_data *data) {
    //
}

static struct __poller_node *__poller_new_node(const struct poller_data *data, int timeout, poller_t *poller) {
    //
}

int poller_add(const struct poller_data *data, int timeout, poller_t *poller) {
    //
}

int poller_del(int fd, poller_t *poller) {
    //
}

int poller_mod(const struct poller_data *data, int timeout, poller_t *poller) {
    //
}

int poller_set_timeout(int fd, int timeout, poller_t *poller) {
    //
}

int poller_add_timer(const struct timespec *value, void *context, void **timer, poller_t *poller) {
    //
}

int poller_del_timer(void *timer, poller_t *poller) {
    //
}

void poller_set_callback(void (*callback)(struct poller_result *, void *), poller_t *poller) {
    //
}

void poller_stop(poller_t *poller) {
    //
}