//
// Created by ldk on 10/12/25.
//

#ifndef MYWORKFLOW_COMMSCHEDULER_H
#define MYWORKFLOW_COMMSCHEDULER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include "Communicator.h"

// 通信调度对象基类
class CommSchedObject {
public:
    // 获取最大负载
    [[nodiscard]] size_t get_max_load() const { return this->max_load; }
    // 获取当前负载
    [[nodiscard]] size_t get_cur_load() const { return this->cur_load; }

private:
    // 核心调度算法接口. 由子类实现
    virtual CommTarget *acquire(int wait_timeout) = 0;

protected:
    size_t max_load;
    size_t cur_load;

public:
    virtual ~CommSchedObject() = default;
    friend class CommScheduler;
};

class CommSchedGroup;

class CommSchedTarget : public CommSchedObject, public CommTarget {
public:
    // 连接初始化
    int init(const sockaddr *addr, socklen_t len, int connect_timeout, int response_timeout, size_t max_connections);
    // 资源清理
    void deinit();

public:
    // 包含SSL的连接初始化.
    int init(const sockaddr *addr, socklen_t addrlen, SSL_CTX *ssl_ctx, int connect_timeout,
             int ssl_connect_timeout, int response_timeout, size_t max_connections) {
        int ret = this->init(addr, addrlen, connect_timeout, response_timeout, max_connections);

        if (ret >= 0) { this->set_ssl(ssl_ctx, ssl_connect_timeout); }

        return ret;
    }

private:
    // 从连接池中获取一个可用连接
    CommTarget *acquire(int wait_timeout) final;
    // 将连接归还给连接池
    void release() final;

private:
    CommSchedGroup *group; // 连接池组管理
    int index; // 在组中的索引
    int wait_cnt; // 当前等待连接的线程数
    pthread_mutex_t mutex;
    pthread_cond_t cond; // 条件变量, 用于线程间同步
    friend class CommSchedGroup;
};

// 连接调度器组
class CommSchedGroup : public CommSchedObject {
public:
    // 初始化调度器组
    int init();
    // 销毁调度器组
    void deinit();
    // 添加target
    int add(CommSchedTarget *target);
    // 移除target
    int remove(CommSchedTarget *target);

private:
    CommTarget *acquire(int wait_timeout) final;

private:
    CommSchedTarget **tg_heap; // 优先级队列(小顶堆), 堆顶是当前"最空闲"(负载最低)的目标
    int heap_size; // 堆当前大小
    int heap_buf_size; // 数组容量
    int wait_cnt; // 当前等待连接的线程数
    pthread_mutex_t mutex;
    pthread_cond_t cond;

private:
    // 比较两个target对象的优先级
    static int target_cmp(const CommSchedTarget *target1, const CommSchedTarget *target2);
    // 从指定节点top向下调整
    void heapify(int top) const;
    // 当某个目标的优先级发生变化时, 向上或者向下调整其在堆中的位置
    void heap_adjust(int index, bool swap_on_equal);
    // 向堆中插入新目标
    int heap_insert(CommSchedTarget *target);
    // 从堆中移除新目标
    void heap_remove(int index);

    friend class CommSchedTarget;
};

// 通信调度枢纽. 采用外观模式
class CommScheduler {
public:
    int init(size_t poller_threads, size_t handler_threads) { return this->comm.init(poller_threads, handler_threads); }

    void deinit() { this->comm.deinit(); }

    // 客户端发起请求(建立连接)
    int request(CommSession *session, CommSchedObject *object, const int wait_timeout, CommTarget **target) {
        int ret = -1;
        *target = object->acquire(wait_timeout); // 1. 获取连接
        if (*target) {
            ret = this->comm.request(session, *target); // 2. 发起异步请求
            if (ret < 0) { (*target)->release(); } // 3. 失败则立即释放连接
        }
        return ret;
    }

    int reply(CommSession *session) { return this->comm.reply(session); }

    int shutdown(CommSession *session) { return this->comm.shutdown(session); }

    int push(const void *buf, size_t size, CommSession *session) { return this->comm.push(buf, size, session); }

    int bind(CommService *service) { return this->comm.bind(service); }

    void unbind(CommService *service) { this->comm.unbind(service); }

    int sleep(SleepSession *session) { return this->comm.sleep(session); }

    /* Call 'unsleep' only before 'handle()' returns. */
    int unsleep(SleepSession *session) { return this->comm.unsleep(session); }

    /* for file aio services. */
    int io_bind(IOService *service) { return this->comm.io_bind(service); }

    void io_unbind(IOService *service) { this->comm.io_unbind(service); }

    [[nodiscard]] int is_handler_thread() const { return this->comm.is_handler_thread(); }

    int increase_handler_thread() { return this->comm.increase_handler_thread(); }

    int decrease_handler_thread() { return this->comm.decrease_handler_thread(); }

    void customize_event_handler(CommEventHandler *handler) { this->comm.customize_event_handler(handler); }

private:
    Communicator comm;

public:
    virtual ~CommScheduler() = default;
};


#endif //MYWORKFLOW_COMMSCHEDULER_H