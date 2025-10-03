//
// Created by ldk on 10/3/25.
//

#include <sys/uio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include "list.h"
#include "IOService_linux.h"

#include <cstring>
#include <asm/unistd_64.h>

/* Linux async I/O interface from libaio.h */

typedef struct io_context *io_context_t;

typedef enum io_iocb_cmd {
    IO_CMD_PREAD = 0,
    IO_CMD_PWRITE = 1,

    IO_CMD_FSYNC = 2,
    IO_CMD_FDSYNC = 3,

    IO_CMD_POLL = 5,
    IO_CMD_NOOP = 6,
    IO_CMD_PREADV = 7,
    IO_CMD_PWRITEV = 8,
} io_iocb_cmd_t;

/* 小端序, 32bit */
#if defined(__i386__) || (defined(__arm__) && !defined(__ARMEB__)) || \
    defined(__sh__) || defined(__bfin__) || defined(__MIPSEL__) || \
    defined(__cris__) || (defined(__riscv) && __riscv_xlen == 32) || \
    (defined(__GNUC__) && defined(__BYTE_ORDER__) && \
__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && __SIZEOF_LONG__ == 4)

#define PADDED(x, y)        x; unsigned y
#define PADDEDptr(x, y)     x; unsigned y
#define PADDEDul(x, y)      unsigned long x; unsigned y

/* 小端序, 64bit */
#elif defined(__ia64__) || defined(__x86_64__) || defined(__alpha__) || \
    (defined(__aarch64__) && defined(__AARCH64EL__)) || \
    (defined(__risv__) && __riscv_xlen == 64 ) || \
    (defined(__GNUC__) && defined(__BYTE_ORDER__) && \
__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ && __SIZEOF_LONG__ == 8)

/* 通过调整成员声明顺序来应对字节序差异
 * PADDED(x, y): 主要目的是确保在结构体中，当需要特定内存对齐或避免编译器插入填充字节时，能正确排列成员
 * PADDEDptr(x, y) 和 PADDEDul(x, y): 是指针和长整型的特化版本，其定义在不同平台下的变化反映了指针长度和长整型大小(long在32位和64位系统上可能不同) */

// PADDED: 根据目标平台的字节序和字长, 智能地排列结构体成员.
// 它的目的是确保像指针和长整型这样的成员在结构体中位于其自然对齐的地址上, 从而保证在不同架构(如32位/64位、小端序/大端序)下都能正确访问
#define PADDED(x, y)	    x, y
#define PADDEDptr(x, y)	    x
#define PADDEDul(x, y)	    unsigned long x

/* 大段序, 64 bits */
#elif defined(__powerpc64__) || defined(__s390x__) || \
(defined(__sparc__) && defined(__arch64__)) || \
(defined(__aarch64__) && defined(__AARCH64EB__)) || \
(defined(__GNUC__) && defined(__BYTE_ORDER__) && \
__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ && __SIZEOF_LONG__ == 8)
#define PADDED(x, y)	    unsigned y; x
#define PADDEDptr(x,y)	    x
#define PADDEDul(x, y)	    unsigned long x

/* 大端序, 32 bits */
#elif defined(__PPC__) || defined(__s390__) || \
(defined(__arm__) && defined(__ARMEB__)) || \
defined(__sparc__) || defined(__MIPSEB__) || defined(__m68k__) || \
defined(__hppa__) || defined(__frv__) || defined(__avr32__) || \
(defined(__GNUC__) && defined(__BYTE_ORDER__) && \
__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ && __SIZEOF_LONG__ == 4)
#define PADDED(x, y)	    unsigned y; x
#define PADDEDptr(x, y)	    unsigned y; x
#define PADDEDul(x, y)	    unsigned y; unsigned long x

#else
#error	endian?
#endif

// 用于 IO 轮询操作的核心数据结构
struct io_iocb_poll {
    // events: 	指定要监控的事件，例如可读(EPOLLIN)、可写(EPOLLOUT)
    PADDED(int events, __pad1);
    // __pad1是一个填充字段. 编译器不会用它存储有意义的数据, 它的存在纯粹是为了“占位”,
    // 以确保 events字段前后有合适的空间, 从而满足整个 iocb结构体内部联合体的对齐要求. 这能有效避免因平台差异导致的内存访问错误或性能下降
};

struct io_iocb_sockaddr {
    struct sockaddr *addr;
    int len;
};

/* Linux AIO 系统中用于描述一个具体I/O操作请求（如读、写）的核心数据结构 */
struct io_iocb_common {
    // buf: 数据缓冲区指针. 对于读操作, 这是存放读取结果的内存地址; 对于写操作，这是待写入数据的内存地址.
    PADDEDptr(void* buf, __pad1);
    // nbytes: 要传输的数据字节数. 指定本次读或写操作的数据量.
    PADDEDul(nbytes, __pad2);
    // 文件偏移量. 指定从文件的哪个位置开始读或写.
    long long offset;
    // 填充字段. 用于内存对齐，暂无实际用途
    long long __pad3;
    // 控制标志位. 用于设置I/O操作的额外选项, 如是否使用eventfd进行事件通知
    unsigned flags;
    // 事件通知文件描述符. 当flags设置了IOCB_FLAG_RESFD时, I/O完成事件会通知到这个eventfd.
    unsigned resfd;
};

struct io_iocb_vector {
    const struct iovec *vec;
    int nr;
    long long offset;
};

struct iocb {
    PADDEDptr(void* data, __pad1);
    PADDED(unsigned key, aio_rw_flags);

    short aio_lio_opcode; // 命令码. 指示要求的I/O操作类型
    short aio_reqprio;
    int aio_fildes; // 目标文件的描述符。该文件需要以 O_DIRECT 标志打开，以使用直接I/O，绕过内核缓存

    union {
        struct io_iocb_common c; // 用于普通读写操作
        struct io_iocb_vector v; // 用于向量I/O (Vectored I/O) 操作，类似readv和writev系统调用. 它允许一次系统调用传输多个分散的内存缓冲区，适用于处理报文等场景
        struct io_iocb_poll poll; // 当操作码为 IO_CMD_POLL时使用, 用于异步监测文件描述符上的事件(例如是否可读或可写)
        struct io_iocb_sockaddr saddr; // 用于异步处理套接字地址相关的操作, 例如异步接受连接或异步连接
    } u;
};

struct io_event {
    // data: 用户自定义上下文. 通常是在提交请求的iocb中设置的指针, 用于在回调中识别具体请求或关联业务数据
    PADDEDptr(void* data, __pad1);
    // 指向已完成的I/O控制块. 也指向最初提交的 struct iocb的指针, 方便访问原始的请求参数
    PADDEDptr(struct iocb* obj, __pad2);
    // 操作结果值. 对于成功的读写操作, 表示实际传输的字节数; 若失败, 则为负的错误码
    PADDEDul(res, __pad3);
    // 辅助结果或保留字段. 通常为0; 暂未使用？
    PADDEDul(res2, __pad4);
};

#undef PADDED
#undef PADDEDptr
#undef PADDEDul

/* 创建并初始化一个异步I/O上下文 */
static inline int io_setup(int maxevents, io_context_t *ctxp) {
    return syscall(__NR_io_setup, maxevents, ctxp);
}

/* 销毁异步I/O上下文，释放所有内核资源 */
static inline int io_destroy(io_context_t ctx) {
    return syscall(__NR_io_destroy, ctx);
}

/* 向指定上下文提交一个或多个异步I/O请求 */
static inline int io_submit(io_context_t ctx, long nr, struct iocb *ios[]) {
    return syscall(__NR_io_submit, ctx, nr, ios);
}

/* 尝试取消一个已提交但未完成的I/O请求 */
static inline int io_cancel(io_context_t ctx, struct iocb *iocb, struct io_event *evt) {
    return syscall(__NR_io_cancel, ctx, iocb, evt);
}

/* 获取已完成的I/O事件, 调用它会阻塞当前线程, 直到有至少min_nr个事件完成或超过timeout指定的时间.
 * 事件执行的结果存储在 struct io_event 中 */
static inline int io_getevents(io_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout) {
    return syscall(__NR_io_getevents, ctx_id, min_nr, nr, events, timeout);
}

/**将I/O请求iocb与eventfd关联, 实现事件驱动通知.
 * 当这个请求完成时, 内核会自动向该 eventfd 发送信号
 * 应用程序可以将这个 eventfd 注册到像 epoll 这样的I/O多路复用机制中.
 * 这样，程序的主循环可以在同一个地方同时等待网络事件和I/O完成事件，实现真正的非阻塞和高并发*/
static inline void io_set_eventfd(struct iocb *iocb, int eventfd) {
    // 通过位或操作将第0位（最低位）强制设为1.
    // 这种操作是“只设位，不清位”. 如果 flags之前已经设置了其他功能的标志位(比如第1位是是否使用偏移量等), 这个操作不会覆盖它们，确保了各功能标志之间互不干扰
    iocb->u.c.flags |= (1 << 0) /* IOCB_FLAG_RESFD */;
    /* 绑定描述符: 将一个具体的eventfd文件描述符赋值给预留字段. 告诉内核:"当I/O完成时，请向这个特定的eventfd写入通知。" */
    iocb->u.c.resfd = eventfd;
}

void IOSession::prep_pread(int fd, void *buf, size_t count, long long offset) {
    iocb *iocb = (struct iocb *)this->iocb_buf;
    memset(iocb, 0, sizeof(*iocb));
    iocb->aio_fildes = fd;
    iocb->aio_lio_opcode = IO_CMD_PREAD;
    iocb->u.c.buf = buf;
    iocb->u.c.nbytes = count;
    iocb->u.c.offset = offset;
}

void IOSession::prep_pwrite(int fd, void *buf, size_t count, long long offset) {
    iocb *iocb = (struct iocb *)this->iocb_buf;
    memset(iocb, 0, sizeof(*iocb));
    iocb->aio_fildes = fd;
    iocb->aio_lio_opcode = IO_CMD_PWRITE;
    iocb->u.c.buf = buf;
    iocb->u.c.nbytes = count;
    iocb->u.c.offset = offset;
}

void IOSession::prep_preadv(int fd, const struct iovec *iov, int iovcnt, long long offset) {
    iocb *iocb = (struct iocb *)this->iocb_buf;

    memset(iocb, 0, sizeof(*iocb));
    iocb->aio_fildes = fd;
    iocb->aio_lio_opcode = IO_CMD_PREADV;
    iocb->u.c.buf = (void *)iov;
    iocb->u.c.nbytes = iovcnt;
    iocb->u.c.offset = offset;
}

void IOSession::prep_pwritev(int fd, const struct iovec *iov, int iovcnt, long long offset) {
    iocb *iocb = (struct iocb *)this->iocb_buf;

    memset(iocb, 0, sizeof(*iocb));
    iocb->aio_fildes = fd;
    iocb->aio_lio_opcode = IO_CMD_PWRITEV;
    iocb->u.c.buf = (void *)iov;
    iocb->u.c.nbytes = iovcnt;
    iocb->u.c.offset = offset;
}

void IOSession::prep_fsync(int fd) {
    iocb *iocb = (struct iocb *)this->iocb_buf;

    memset(iocb, 0, sizeof(*iocb));
    iocb->aio_fildes = fd;
    iocb->aio_lio_opcode = IO_CMD_FSYNC;
}

void IOSession::prep_fdsync(int fd) {
    //
}

int IOService::init(int maxevents) {
    return 0;
}

void IOService::deinit() {
    //
}

void IOService::incref() {
    //
}

void IOService::decref() {
    //
}

int IOService::request(IOSession *session) {
    //
}

void *IOService::aio_finish(void *context) {
    //
}