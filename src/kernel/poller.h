//
// Created by ldk on 9/29/25.
//

#ifndef MYWORKFLOW_POLLER_H
#define MYWORKFLOW_POLLER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>


typedef struct __poller poller_t;
typedef struct __poller_message poller_message_t;

/* 核心职责: 协议消息的组装与解析(从网络字节流中切分出完整的应用层消息) */
struct __poller_message {
    /**实现消息分帧的关键函数. 每当有数据从网络到达，框架就会调用当前连接对应的 poller_message_t 对象的 append 方法.
     * 该方法需要实现以下逻辑:
     * 1. 解析数据: 根据具体协议（HTTP头部、Redis协议等）解析传入的缓冲区.
     * 2. 判断完整性: 检查当前数据是否构成一个完整、可处理的应用层消息.
     * 3. 返回值驱动:
     *       - 返回 1：表示消息已收完，框架将通知上层该消息就绪。
     *       - 返回 0：表示消息尚未完整，需要更多数据，框架会继续等待读取。
     *       - 返回 -1：表示协议错误，框架会关闭连接。
     * 4. size_t参数: 这是一个双向参数. append方法通过它告诉框架本次调用消费了多少数据，即使消息未完整收完，也可以分批处理 */
    int (*append)(const void *, size_t *, poller_message_t *);
    /**C语言中的一种常用技巧，也称为“柔性数组”. 可以写成: int a[]; 或者 int a[0];
     * 允许在分配 poller_message_t内存时，额外分配一片连续的空间来存储协议相关的数据（如HTTP头部、请求体等）.
     * 这样做的好处是内存连续，一次分配即可容纳结构体和数据，效率高，并且能更好地利用缓存. */
    char data[0];
};

/* 单次IO操作的上下文容器 */
struct poller_data {
    // -1 表示管道读事件
#define PD_OP_TIMER			0
#define PD_OP_READ			1
#define PD_OP_WRITE			2
#define PD_OP_LISTEN		3
#define PD_OP_CONNECT		4
#define PD_OP_RECVFROM		5
#define PD_OP_SSL_READ		PD_OP_READ
#define PD_OP_SSL_WRITE		PD_OP_WRITE
#define PD_OP_SSL_ACCEPT	6
#define PD_OP_SSL_CONNECT	7
#define PD_OP_SSL_SHUTDOWN	8
#define PD_OP_EVENT			9
#define PD_OP_NOTIFY		10
    short operation; // 操作类型标识符. 指定当前要执行何种I/O操作（如读、写、监听、连接等），是事件分发的唯一依据.
    unsigned short iovcnt; // 分散/聚集 I/O 向量计数. 用于写操作，指定下文中 struct iovec 数组的元素个数，支持高性能的数据批量发送.
    int fd;
    SSL *ssl;

    // 根据 operation的不同，会调用与之对应的特定回调函数
    union {
        /* 当fd可读时，调用此函数创建一个 poller_message_t派生对象，用于开始或继续消息的组装 */
        poller_message_t * (*creat_message)(void *);
        /* 在异步发送数据时，每当有部分数据被成功写入内核缓冲区后调用，可用于更新超时时间 */
        int (*partial_written)(size_t, void *);
        /* 当监听socket有新连接到达时调用，用于接受连接并创建新的通信fd */
        void * (*accept)(const struct sockaddr *, socklen_t, int, void *);
        /* 该回调函数负责解析接收到的数据报(用const void* 接收)，并结合发送方地址(sockaddr*)进行业务逻辑处理 */
        void *(*recvfrom)(const struct sockaddr *, socklen_t, const void *, size_t, void *);
        /* 处理非网络文件描述符 (fd) 的异步 I/O 事件，如磁盘文件、管道或信号事件 */
        void *(*event)(void *);
        /* 实现内部线程间通知或用户自定义的轻量级事件处理。用于安全地唤醒阻塞在 I/O 多路复用调用（如 epoll_wait）上的线程，并传递内部消息 */
        void *(*notify)(void *, void *);
    };

    /**这是一个 void*指针，用于传递业务相关的上下文信息.
     * 例如，在 create_message被调用时，这个 context会作为参数传入，从而使得创建的消息对象能够关联到具体的连接或服务 */
    void *context;

    // 在IO操作的不同阶段，用于指向相关的数据缓冲区.
    union {
        poller_message_t *message; // 用于读操作，指向正在组装的 poller_message_t 对象.
        struct iovec *write_iov; // 用于写操作，指向需要发送的数据块.可能是个数组，这样可以一次性发送多个iovec块(集中写)。
        void *result; // 指向连接上下文
    };
};

/* I/O事件就绪通知的载体，是连接底层I/O多路复用层（如epoll）与上层任务处理器的桥梁. */
struct poller_result {
    // I/O操作成功完成. 例如，一个读操作成功读取了数据，或一个连接请求成功建立.
#define PR_ST_SUCCESS   0
    // 任务正常结束，通常用于连接关闭等正常流程.
#define PR_ST_FINISHED  1
    // 操作过程中发生错误.此时需要检查error字段获取具体的系统错误码.
#define PR_ST_ERROR     2
    // 该I/O任务已被主动取消或删除. 例如，定时器在到期前被用户取消.
#define PR_ST_DELETED   3
    // 事件被修改，比如在epoll中使用了 EPOLLONESHOT 标志后，需要重新注册事件.
#define PR_ST_MODIFIED  4
    // 通常与进程或服务退出相关，表示由于系统关闭等原因而停止.
#define PR_ST_STOPPED   5
    int state; // 记录本次I/O操作的具体结果状态，其值对应上方的常量宏。
    int error; // 当state为错误状态（如PR_ST_ERROR）时，存储具体的错误码（如errno）
    struct poller_data data; // poller_data结构体承载了执行I/O操作所需的全部上下文信息，可以看作是附在结果上的“任务说明书”
};

struct poller_params {
    size_t max_open_file;
    void (*call_back)(struct poller_result *, void *);
    void *context;
};


/**extern "C"的作用: 就是用来抑制 C++ 编译器的名称修饰.
 * 当 C++ 编译器看到 extern "C"时，它会被告知：“请用 C 语言的规则来处理下面这些函数的名字. ”
 * 这样，函数 poller_create在 C++ 代码中产生的符号名就会是 _poller_create，与 C 语言编译的库文件中的符号名完全一致，链接就能成功了
 */
#ifdef __cplusplus
extern "C" {



#endif

poller_t *poller_creat(const struct poller_params *params);
int poller_start(poller_t *poller);
int poller_add(const struct poller_data *data, int timeout, poller_t *poller);
int poller_del(int fd, poller_t *poller);
int poller_mod(const struct poller_data *data, int timeout, poller_t *poller);
int poller_set_timeout(int fd, int timeout, poller_t *poller);
int poller_add_timer(const struct timespec *value, void *context, void **timer, poller_t *poller);
int poller_del_timer(void *timer, poller_t *poller);
void poller_set_callback(void (*callback)(struct poller_result *, void *), poller_t *poller);
void poller_stop(poller_t *poller);
void poller_destroy(poller_t *poller);

#ifdef __cplusplus
}
#endif

#endif //MYWORKFLOW_POLLER_H