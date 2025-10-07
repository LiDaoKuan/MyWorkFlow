//
// Created by ldk on 10/2/25.
//

#ifndef MYWORKFLOW_IOSERVICE_LINUX_H
#define MYWORKFLOW_IOSERVICE_LINUX_H

#include <sys/uio.h>
#include <sys/eventfd.h>
#include <cstddef>
#include <pthread.h>
#include "list.h"

#define IOS_STATE_SUCCESS   0
#define IOS_STATE_ERROR     1

class IOSession {
private:
    virtual int prepare() = 0;
    // 当内核完成I/O操作后, 框架会调用此方法. 子类在此实现业务逻辑, 如处理读取到的数据或处理写入错误
    virtual void handle(int state, int error) = 0;

protected:
    // 设置异步IO操作的参数
    void prep_pread(int fd, void *buf, size_t count, long long offset);
    void prep_pwrite(int fd, void *buf, size_t count, long long offset);
    void prep_preadv(int fd, const iovec *iov, int iovcnt, long long offset);
    void prep_pwritev(int fd, const iovec *iov, int iovcnt, long long offset);
    void prep_fsync(int fd);
    void prep_fdsync(int fd);

    [[nodiscard]] long get_res() const { return this->res; }

private:
    char iocb_buf[64]{}; // 固定大小的缓冲区. 很可能用于存储一个 struct iocb (I/O控制块)
    long res{}; // 存储IO操作的结果. 通常表示实际读写的字节数. 如果操作出错则为负的错误码

    list_head list{}; // 将多个IOSession对象链接成一个链表, 实现批量提交和批量完成检查

public:
    virtual ~IOSession() = default;
    friend class IOService;
    friend class Communicator;
};

class IOService {
public:
    /* 初始化 AIO 上下文和内部资源 */
    int init(int maxevents);
    /* 清理资源 */
    void deinit();

    /* 提交异步 I/O 请求, 将I/O会话任务提交给内核AIO机制 */
    int request(IOSession *session);

private:
    /* 服务停止时通知(默认空实现) */
    virtual void handle_stop(int error) {}
    /* 所有会话处理完成后的回调通知 */
    virtual void handle_unbound() = 0;

    // 创建内部事件通知 fd 默认使用(eventfd)
    virtual int create_event_fd() {
        // eventfd()返回一个特殊的文件描述符, 该文件描述符包含一个由内核维护的64bit的计数器
        // 这个计数器可以用于用户空间应用程序之间的“等待/通知”机制, 或者用于内核通知用户空间应用程序事件消息
        return eventfd(0, 0);
    }

    /* 引用计数操作, 跟踪活跃会话数, 用于生命周期管理 */
    void incref();
    void decref();

    /**内核 AIO 完成时的统一回调入口
     * @param context 传入的指针一定要能够转换为IOService类型指针, 确保能够正确被解读
     * @return 如果有已完成事件, 返回指向IOSession对象的指针, 由调用着检查事件的完成结果. 如果没有已完成事件, 返回nullptr */
    static void *aio_finish(void *context);

private:
    struct io_context *io_ctx{nullptr}; // 指向 Linux AIO 上下文, 关联内核AIO实例.
    int event_fd{-1}; // 事件通知文件描述符. 信号量或通信管道, 用于线程间事件通知
    int ref{0}; // 引用计数器. 统计活跃会话, 实现优雅停机
    list_head session_list{}; // 管理所有关联的IOSession对象, 每个IOSession对象都代表一个已经提交但未处理完成的绘会话
    pthread_mutex_t mutex{};

public:
    virtual ~IOService() = default;
    friend class Communicator;
};

void test();

#endif //MYWORKFLOW_IOSERVICE_LINUX_H