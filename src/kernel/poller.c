//
// Created by ldk on 9/29/25.
//

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

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

/* 一个节点既能挂在链表上，也能挂在红黑树上，使得框架可以根据需要（例如，是否设置超时）用最高效的数据结构来管理它。 */
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
    struct timespec timeout; // 精确的超时时间点。使用 timespec结构可以支持高精度的定时控制
    struct __poller_node *res; // 结果指针。可能用于指向操作完成后的结果节点，或在链表中链接下一个节点。
};

/* 维护着所有被监控的描述符，并驱动事件循环 */
struct __poller {
    size_t max_open_files; // 设定可监控的最大文件描述符数量，防止资源耗尽
    void (*callback)(struct poller_result *, void *); //当监控的fd有事件发生时，会调用callback函数，并将context作为参数传递，用于处理具体的I/O业务逻辑
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
    struct __poller_node **nodes; // 节点指针数组。提供了一种通过文件描述符（fd）作为索引来快速查找对应 __poller_node的方法
    pthread_mutex_t mutex; // 保证在多线程环境下对核心数据结构的访问是线程安全的
    char buf[POLLER_BUFSIZE]; // 内部缓冲区。用于临时存储I/O数据或控制信息，减少内存分配开销
};

#ifdef __linux__

static inline int __poller_create_pfd() {
    return epoll_create(1);
}

static inline int __poller_close_pfd(int fd) {
    return close(fd);
}

/**fd: 要监控的文件描述符;
 * event: 关注的事件(如可读、可写);
 * data: 用户数据指针，用于事件触发时回调识别 */
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

static inline int __poller_add_timerfd(int fd, const struct timespec *abstime, poller_t *poller) {
    struct itimerspec timer = {
        .it_interval = {}, // it_interval.tv_sec: 循环间隔的秒数. it_value.tv_nsec: 循环间隔的纳秒数. 不设置表示
        .it_value = *abstime // it_value.tv_sec 首次超时的秒数. it_value.tv_nsec: 首次超时的毫秒数
    };
    return timerfd_settime(fd, TFD_TIMER_ABSTIME, &timer, NULL);

    /* 当定时器超时，fd变为可读。你必须调用 read从 fd中读取一个 uint64_t类型的值，该值表示自上次读取后累计的超时次数。
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

/**将网络读取到的数据块（buf）逐步拼装成一条完整的应用层消息，并在消息完整时通知上层处理器
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
        // 创建空间用于存储组装结果
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

static int __poller_handle_ssl_error(struct __poller_node *node, int ret, poller_t *poller) {
    int error = SSL_get_error(node->data.ssl, ret);
    int event;
    switch (error) {
    case SSL_ERROR_WANT_READ: {
        event = EPOLLIN | EPOLLET;
        break;
    }
    case SSL_ERROR_WANT_WRITE: {
        event = EPOLLOUT | EPOLLET;
        break;
    }
    default: {
        errno = -error;
    }
    case SSL_ERROR_SYSCALL: {
        return -1;
    }
    }

    if (event == node->event) {
        return 0;
    }
    pthread_mutex_lock(&poller->mutex);
    if (!node->removed) {
        ret = __poller_mod_fd(node->data.fd, node->event, event, node, poller);
        if (ret >= 0) {
            node->event = event;
        }
    } else {
        ret = 0;
    }
    pthread_mutex_unlock(&poller->mutex);
    return ret;
}

static int __poller_handle_read(struct __poller_node *node, poller_t *poller) {
    ssize_t nleft;
    size_t n;
    char *p;
    while (1) {
        //
    }
}