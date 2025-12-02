//
// Created by ldk on 10/25/25.
//

#ifndef MYWORKFLOW_WFTASKFACTORY_H
#define MYWORKFLOW_WFTASKFACTORY_H

#include <sys/types.h>
#include <sys/uio.h>
#include <ctime>
#include <utility>
#include <functional>
#include <openssl/ssl.h>
#include "URIParser.h"
// #include "RedisMessage.h"
#include "HttpMessage.h"
// #include "MySQLMessage.h"
#include "DnsMessage.h"
#include "Workflow.h"
#include "WFTask.h"
#include "WFGraphTask.h"
#include "EndpointParams.h"

// Network Client/Server tasks

using WFHttpTask = WFNetworkTask<protocol::HttpRequest, protocol::HttpResponse>;
using http_callback_t = std::function<void (WFHttpTask *)>;

// using WFRedisTask = WFNetworkTask<protocol::RedisRequest, protocol::RedisResponse>;
// using redis_callback_t = std::function<void (WFRedisTask *)>;

// using WFMySQLTask = WFNetworkTask<protocol::MySQLRequest, protocol::MySQLResponse>;
// using mysql_callback_t = std::function<void (WFMySQLTask *)>;

using WFDnsTask = WFNetworkTask<protocol::DnsRequest, protocol::DnsResponse>;
using dns_callback_t = std::function<void (WFDnsTask *)>;

// File IO tasks

// 标准文件I/O参数. 支持随机访问I/O
struct FileIOArgs {
    int fd;
    void *buf; // 数据缓冲区指针
    size_t count; // 要读写的数据长度（字节）
    off_t offset; // 文件偏移量
};

// 向量化文件I/O参数. 用于 分散/聚集 I/O.
struct FileVIOArgs {
    int fd;
    const struct iovec *iov; // 缓冲区数组指针
    int iovcnt; // 数组大小
    off_t offset; // 文件偏移量
};

// 文件同步参数. 对应 fsync() 或 fdatasync() 系统调用, 用于确保数据持久化到存储设备
struct FileSyncArgs {
    int fd;
};

using WFFileIOTask = WFFileTask<struct FileIOArgs>;
using fio_callback_t = std::function<void (WFFileIOTask *)>;

using WFFileVIOTask = WFFileTask<struct FileVIOArgs>;
using fvio_callback_t = std::function<void (WFFileVIOTask *)>;

using WFFileSyncTask = WFFileTask<struct FileSyncArgs>;
using fsync_callback_t = std::function<void (WFFileSyncTask *)>;

// Timer and counter
using timer_callback_t = std::function<void (WFTimerTask *)>;
using counter_callback_t = std::function<void (WFCounterTask *)>;

using mailbox_callback_t = std::function<void (WFMailboxTask *)>;

using selector_callback_t = std::function<void (WFSelectorTask *)>;

// Graph (DAG) task.
using graph_callback_t = std::function<void (WFGraphTask *)>;

using WFEmptyTask = WFGenericTask;

using WFDynamicTask = WFGenericTask;
using dynamic_create_t = std::function<SubTask *(WFDynamicTask *)>;

using repeated_create_t = std::function<SubTask *(WFRepeaterTask *)>;
using repeater_callback_t = std::function<void (WFRepeaterTask *)>;

using module_callback_t = std::function<void (const WFModuleTask *)>;

class WFTaskFactory {
public:
    // 创建http任务
    static WFHttpTask *create_http_task(const std::string &url, int redirect_max, int retry_max, http_callback_t callback);
    // 创建http任务
    static WFHttpTask *create_http_task(const ParsedURI &uri, int redirect_max, int retry_max, http_callback_t callback);
    // 创建http任务
    static WFHttpTask *create_http_task(const std::string &url, const std::string &proxy_url, int redirect_max,
                                        int retry_max, http_callback_t callback);
    // 创建http任务
    static WFHttpTask *create_http_task(const ParsedURI &uri, const ParsedURI &proxy_uri, int redirect_max,
                                        int retry_max, http_callback_t callback);

    // static WFRedisTask *create_redis_task(const std::string &url, int retry_max, redis_callback_t callback);

    // static WFRedisTask *create_redis_task(const ParsedURI &uri, int retry_max, redis_callback_t callback);

    // static WFMySQLTask *create_mysql_task(const std::string &url, int retry_max, mysql_callback_t callback);

    // static WFMySQLTask *create_mysql_task(const ParsedURI &uri, int retry_max, mysql_callback_t callback);

    // 创建DNS解析任务. 通过原始的URL字符串（如 "https://example.com:8080/path"）
    static WFDnsTask *create_dns_task(const std::string &url, int retry_max, dns_callback_t callback);
    // 创建DNS解析任务. 通过已解析的结构化URI
    static WFDnsTask *create_dns_task(const ParsedURI &uri, int retry_max, dns_callback_t callback);

public:
    // 异步随机读任务. 从文件指定位置（offset）读取指定长度（count）的数据到缓冲区（buf）
    static WFFileIOTask *create_pread_task(int fd, void *buf, size_t count,
                                           off_t offset, fio_callback_t callback);

    // 异步随即写. 将缓冲区（buf）中的数据写入文件指定位置（offset）
    static WFFileIOTask *create_pwrite_task(int fd, const void *buf, size_t count,
                                            off_t offset, fio_callback_t callback);

    // 异步分散读. 将文件数据一次性读入多个不连续的缓冲区（iov）
    static WFFileVIOTask *create_preadv_task(int fd, const struct iovec *iov, int iovcnt,
                                             off_t offset, fvio_callback_t callback);

    // 异步聚集写. 将多个缓冲区的数据一次性写入文件
    static WFFileVIOTask *create_pwritev_task(int fd, const struct iovec *iov, int iovcnt,
                                              off_t offset, fvio_callback_t callback);

    // 异步强制同步. 确保文件数据及元数据写入物理存储设备
    static WFFileSyncTask *create_fsync_task(int fd, fsync_callback_t callback);

    /* On systems that do not support fdatasync(), like macOS,
     * fdsync task is equal to fsync task. */
    static WFFileSyncTask *create_fdsync_task(int fd, fsync_callback_t callback);

    /* File tasks with path name. 根据文件路径的文件IO任务 */
public:
    static WFFileIOTask *create_pread_task(const std::string &path, void *buf, size_t count,
                                           off_t offset, fio_callback_t callback);

    static WFFileIOTask *create_pwrite_task(const std::string &path, const void *buf,
                                            size_t count, off_t offset, fio_callback_t callback);

    static WFFileVIOTask *create_preadv_task(const std::string &path, const struct iovec *iov, int iovcnt,
                                             off_t offset, fvio_callback_t callback);

    static WFFileVIOTask *create_pwritev_task(const std::string &path, const struct iovec *iov, int iovcnt,
                                              off_t offset, fvio_callback_t callback);

public:
    // 创建基础（匿名）定时器. 指定秒和纳秒后触发回调
    static WFTimerTask *create_timer_task(time_t seconds, long nanoseconds, timer_callback_t callback);

    /* Create a named timer. 创建可命名的定时器. 为定时器指定一个唯一名称 */
    static WFTimerTask *create_timer_task(const std::string &timer_name, time_t seconds, long nanoseconds,
                                          timer_callback_t callback);

    /* Cancel all timers under the name. 取消所有指定名称的定时器 */
    static int cancel_by_name(const std::string &timer_name) {
        return WFTaskFactory::cancel_by_name(timer_name, (size_t)-1);
    }

    /* Cancel at most 'max' timers under the name. 取消指定名称的至多 max 个定时器 */
    static int cancel_by_name(const std::string &timer_name, size_t max);

    /* Timer to be canceled immediately after started. 创建“立即取消”的定时器 */
    static WFTimerTask *create_timer_task(timer_callback_t callback);

    /* Timer in microseconds. (deprecated) （已弃用）使用微秒单位创建定时器 */
    static WFTimerTask *create_timer_task(unsigned int microseconds, timer_callback_t callback);

public:
    /**创建匿名计数器
     * Create an unnamed counter. Call counter->count() directly.
     * NOTE: never call count() exceeding target_value. 、
     * 计数操作需通过返回的 WFCounterTask 对象指针直接调用 count().
     * 严禁调用 count() 的次数超过 target_value, 否则可能导致程序未定义行为 */
    static WFCounterTask *create_counter_task(unsigned int target_value, counter_callback_t callback) {
        return new WFCounterTask(target_value, std::move(callback));
    }

    /* Create a named counter. 创建命名计数器 */
    static WFCounterTask *create_counter_task(const std::string &counter_name, unsigned int target_value, counter_callback_t callback);

    /**对指定名称的计数器进行单次计数. 当多个计数器共享同一名称时，此操作仅对最先创建的那个计数器生效
     * Count by a counter's name. When count_by_name(), it's safe to count
     * exceeding target_value. When multiple counters share a same name,
     * this operation will be performed on the first created. */
    static int count_by_name(const std::string &counter_name) {
        return WFTaskFactory::count_by_name(counter_name, 1);
    }

    /**对指定名称的计数器进行 n 次计数. 操作会按照计数器的创建顺序依次作用于多个同名计数器, 可能导致多个计数器同时达到目标值
     * Count by name with a value n. When multiple counters share this name,
     * the operation is performed on the counters in the sequence of its
     * creation, and more than one counter may reach target value. */
    static int count_by_name(const std::string &counter_name, unsigned int n);

public:
    // 创建绑定到特定消息指针的邮箱任务. 消息会存入指定内存地址.
    static WFMailboxTask *create_mailbox_task(void **mailbox, mailbox_callback_t callback) {
        return new WFMailboxTask(mailbox, std::move(callback));
    }

    /* Use 'user_data' as mailbox. 创建邮箱任务，消息直接存入任务内部的 user_data 字段，无需外部指针 */
    static WFMailboxTask *create_mailbox_task(mailbox_callback_t callback) {
        return new WFMailboxTask(std::move(callback));
    }

    // 创建命名邮箱任务并绑定到特定消息指针. 支持通过名称进行消息广播
    static WFMailboxTask *create_mailbox_task(const std::string &mailbox_name, void **mailbox, mailbox_callback_t callback);

    // 创建命名邮箱任务, 消息存入内部 user_data. 支持通过名称进行消息广播
    static WFMailboxTask *create_mailbox_task(const std::string &mailbox_name, mailbox_callback_t callback);

    /**向所有使用该名称的邮箱任务广播一条消息
     * The 'msg' will be sent to the all mailbox tasks under the name, and
     * would be lost if no task matched. */
    static int send_by_name(const std::string &mailbox_name, void *msg) {
        return WFTaskFactory::send_by_name(mailbox_name, msg, (size_t)-1);
    }

    // 向使用该名称的邮箱任务广播消息, 但最多只通知 max 个任务
    static int send_by_name(const std::string &mailbox_name, void *msg, size_t max);

    // 类型安全的批量消息发送, 可发送一个消息数组
    template <typename T>
    static int send_by_name(const std::string &mailbox_name, T *const msg[], size_t max);

public:
    // 创建多候选选择的异步任务
    static WFSelectorTask *create_selector_task(size_t candidates, selector_callback_t callback) {
        return new WFSelectorTask(candidates, std::move(callback));
    }

public:
    // 创建条件任务（匿名）. 指定条件触发时传递消息的缓冲区指针
    static WFConditional *create_conditional(SubTask *task, void **msgbuf) {
        return new WFConditional(task, msgbuf);
    }

    // 创建条件任务（匿名）. 条件触发时消息直接存入类内的user_data
    static WFConditional *create_conditional(SubTask *task) {
        return new WFConditional(task);
    }

    // 创建条件任务（指定名称）. 消息缓冲区由外部指定
    static WFConditional *create_conditional(const std::string &cond_name, SubTask *task, void **msgbuf);

    // 创建条件任务（指定名称）. 消息缓冲区使用类内的user_data
    static WFConditional *create_conditional(const std::string &cond_name, SubTask *task);

    // 向所有名为 cond_name 的条件任务发送同一条消息 msg
    static int signal_by_name(const std::string &cond_name, void *msg) {
        return WFTaskFactory::signal_by_name(cond_name, msg, static_cast<size_t>(-1));
    }

    // 最多只向 max 个名为 cond_name 的条件任务发送消息
    static int signal_by_name(const std::string &cond_name, void *msg, size_t max);

    /**上方函数的应用场景:
     * 1. 限流器: 假设你有一个连接池, 最多支持10个并发. 当有15个任务在等待连接时, 每次释放一个连接回池中,
     *      你可以调用 signal_by_name("connection_available", freed_conn, 1), 确保每次只唤醒一个等待任务来获取这个新释放的连接, 从而精确控制并发数.
     * 2. 批量任务分发: 如果你有一批数据需要处理, 但不想一次性唤醒所有消费者导致系统过载, 可以分批唤醒.
     *      例如，每次唤醒5个任务：signal_by_name("data_ready", data_batch, 5)
     */

    // 向最多 max 个任务发送一个消息数组中的不同消息
    template <typename T>
    static int signal_by_name(const std::string &cond_name, T *const msg[], size_t max);

public:
    // 创建守卫任务: 将一个需要受保护的资源才能执行的实际任务（SubTask *task）包装起来，并与一个全局唯一的资源名（resource_name）绑定
    static WFConditional *create_guard(const std::string &resource_name, SubTask *task);

    static WFConditional *create_guard(const std::string &resource_name, SubTask *task, void **msgbuf);

    // create_guard 和 release_guard 必须成对使用

    /* 释放资源锁并通知等待者: 在当前任务完成并释放资源后, 此函数会向下一个等待该资源的“守卫”任务发送信号(msg), 使其获得资源并开始执行
     * The 'guard' is acquired after started, so call 'release_guard' after
     * and only after the task is finished, typically in its callback.
     * The function returns 1 if another is signaled, otherwise returns 0. */
    static int release_guard(const std::string &resource_name, void *msg);

    // 释放资源锁的安全版本. 功能与 release_guard 相同, 但提供了更强的异常安全保证, 确保即使在信号发送过程中出现错误, 资源也能被正确标记为已释放
    static int release_guard_safe(const std::string &resource_name, void *msg);

public:
    // 创建一个GoTask, 并将其分配给指定名称（queue_name）的计算队列
    template <class FUNC, class... ARGS>
    static WFGoTask *create_go_task(const std::string &queue_name, FUNC &&func, ARGS &&... args);

    /**创建带超时限制的GoTask
     * 任务运行时间超过指定的秒+纳秒时间后, 会被中断,
     * 其回调中任务状态（get_state()）为WFT_STATE_SYS_ERROR, 错误码（get_error()）为ETIMEDOUT
     * Create 'Go' task with running time limit in seconds plus nanoseconds.
     * If time exceeded, state WFT_STATE_SYS_ERROR and error ETIMEDOUT
     * will be got in callback. */
    template <class FUNC, class... ARGS>
    static WFGoTask *create_timedgo_task(time_t seconds, long nanoseconds, const std::string &queue_name, FUNC &&func, ARGS &&... args);

    /* Create 'Go' task on user's executor and execution queue. 允许用户自定义任务所使用的执行队列（ExecQueue *）和执行器（Executor *） */
    template <class FUNC, class... ARGS>
    static WFGoTask *create_go_task(ExecQueue *queue, Executor *executor, FUNC &&func, ARGS &&... args);

    // 创建自定义执行队列和执行器且带超时限制的GoTask
    template <class FUNC, class... ARGS>
    static WFGoTask *create_timedgo_task(time_t seconds, long nanoseconds, ExecQueue *queue, Executor *executor, FUNC &&func, ARGS &&... args);

    /* For capturing 'task' itself in go task's running function. 重置GoTask. 用于复用已有的GoTask对象, 为其绑定一个新的执行函数和参数 */
    template <class FUNC, class... ARGS>
    static void reset_go_task(WFGoTask *task, FUNC &&func, ARGS &&... args);

public:
    static WFGraphTask *create_graph_task(graph_callback_t callback) {
        return new WFGraphTask(std::move(callback));
    }

public:
    static WFEmptyTask *create_empty_task() {
        return new WFEmptyTask;
    }

    static WFDynamicTask *create_dynamic_task(dynamic_create_t create);

    static WFRepeaterTask *create_repeater_task(repeated_create_t create, repeater_callback_t callback) {
        return new WFRepeaterTask(std::move(create), std::move(callback));
    }

public:
    static WFModuleTask *create_module_task(SubTask *first, module_callback_t callback) {
        return new WFModuleTask(first, std::move(callback));
    }

    static WFModuleTask *create_module_task(SubTask *first, SubTask *last, module_callback_t callback) {
        auto *task = new WFModuleTask(first, std::move(callback));
        task->sub_series()->set_last_task(last);
        return task;
    }
};

template <class REQ, class RESP>
class WFNetworkTaskFactory {
private:
    using T = WFNetworkTask<REQ, RESP>;

public:
    static T *create_client_task(enum TransportType type, const std::string &host, unsigned short port,
                                 int retry_max, std::function<void (T *)> callback);

    static T *create_client_task(enum TransportType type, const std::string &url,
                                 int retry_max, std::function<void (T *)> callback);

    static T *create_client_task(enum TransportType type, const ParsedURI &uri,
                                 int retry_max, std::function<void (T *)> callback);

    static T *create_client_task(enum TransportType type, const struct sockaddr *addr, socklen_t addrlen,
                                 int retry_max, std::function<void (T *)> callback);

    static T *create_client_task(enum TransportType type, const struct sockaddr *addr, socklen_t addrlen,
                                 SSL_CTX *ssl_ctx, int retry_max, std::function<void (T *)> callback);

public:
    static T *create_server_task(CommService *service, std::function<void (T *)> &process);
};

template <class INPUT, class OUTPUT>
class WFThreadTaskFactory {
private:
    using T = WFThreadTask<INPUT, OUTPUT>;

public:
    static T *create_thread_task(const std::string &queue_name, std::function<void (INPUT *, OUTPUT *)> routine,
                                 std::function<void (T *)> callback);

    /* Create thread task with running time limit. */
    static T *create_thread_task(time_t seconds, long nanoseconds,
                                 const std::string &queue_name, std::function<void (INPUT *, OUTPUT *)> routine,
                                 std::function<void (T *)> callback);

public:
    /* Create thread task on user's executor and execution queue. */
    static T *create_thread_task(ExecQueue *queue, Executor *executor,
                                 std::function<void (INPUT *, OUTPUT *)> routine,
                                 std::function<void (T *)> callback);

    /* With running time limit. */
    static T *create_thread_task(time_t seconds, long nanoseconds,
                                 ExecQueue *queue, Executor *executor,
                                 std::function<void (INPUT *, OUTPUT *)> routine,
                                 std::function<void (T *)> callback);
};

#include "WFTaskFactory.inl"
#endif //MYWORKFLOW_WFTASKFACTORY_H