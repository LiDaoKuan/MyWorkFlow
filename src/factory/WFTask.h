//
// Created by ldk on 10/18/25.
//

/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#ifndef MYWORKFLOW_WFTASK_H
#define MYWORKFLOW_WFTASK_H

#include <cerrno>
#include <cstring>
#include <cassert>
#include <atomic>
#include <utility>
#include <functional>
#include "Executor.h"
#include "ExecRequest.h"
#include "Communicator.h"
#include "CommScheduler.h"
#include "CommRequest.h"
#include "SleepRequest.h"
#include "IORequest.h"
#include "Workflow.h"
#include "WFConnection.h"

enum {
    WFT_STATE_UNDEFINED = -1, /* 未定义状态 */
    WFT_STATE_SUCCESS = CS_STATE_SUCCESS, /* 任务成功完成 */
    WFT_STATE_TOREPLY = CS_STATE_TOREPLY, /* 需要回复. 仅用于服务器任务, 表示已接收请求并处理, 需要向客户端发送回复. for server task only */
    WFT_STATE_NOREPLY = CS_STATE_TOREPLY + 1, /* 无需回复. 仅用于服务器任务, 表示处理完请求后, 不需要向客户端发送回复. for server task only */
    WFT_STATE_SYS_ERROR = CS_STATE_ERROR, /* 系统内部错误. 指框架底层或操作系统级别的错误, 如内存分配失败、系统调用异常等 */
    WFT_STATE_SSL_ERROR = 65, /* SSL/TLS 握手或通信错误. 在建立安全加密连接时发生问题, 如证书验证失败、协议版本不匹配等 */
    WFT_STATE_DNS_ERROR = 66, /* DNS 解析失败. 仅用于客户端任务, 表示无法将域名解析为有效的IP地址. for client task only */
    WFT_STATE_TASK_ERROR = 67, /* 任务逻辑错误. 在任务自定义的回调函数或执行逻辑中抛出了异常或返回了错误 */
    WFT_STATE_ABORTED = CS_STATE_STOPPED /* 任务被主动中止. 任务可能被用户或其他外部逻辑主动取消或终止 */
};

template <class INPUT, class OUTPUT>
class WFThreadTask : public ExecRequest {
public:
    WFThreadTask(ExecQueue *queue, Executor *executor, std::function<void (WFThreadTask<INPUT, OUTPUT> *)> &&cb) :
        ExecRequest(queue, executor), callback(std::move(cb)) {
        this->user_data = nullptr;
        this->state = WFT_STATE_UNDEFINED; // 初始化为未定义状态
        this->error = 0;
    }

    // 启动任务(将其放入一个串行任务流中开始执行)
    void start() {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }

    // 立即取消并销毁尚未启动的任务
    void dismiss() {
        assert(!series_of(this));
        delete this;
    }

    void set_callback(std::function<void(WFThreadTask<INPUT, OUTPUT> *)> cb) { this->callback = std::move(cb); }

    INPUT *get_input() { return &this->input; }
    OUTPUT *get_output() { return &this->output; }

    const INPUT *get_input() const { return &this->input; }
    const OUTPUT *get_output() const { return &this->output; }

    [[nodiscard]] int get_state() const { return this->state; }
    [[nodiscard]] int get_error() const { return this->error; }

protected:
    // 任务完成后调用此函数
    SubTask *done() override {
        SeriesWork *series = series_of(this); // 获取任务所属的串行流

        if (this->callback) { this->callback(this); } // 如果有任务完成回调, 先执行回调

        delete this; // 销毁自身
        return series->pop(); // 返回任务流中的下一个任务
    }

public:
    void *user_data; // 用户自定义的上下文数据指针

protected:
    INPUT input; // 存储任务的输入数据
    OUTPUT output; // 存储任务的输出结果
    std::function<void(WFThreadTask<INPUT, OUTPUT> *)> callback; // 任务执行完成后的回调函数

protected:
    ~WFThreadTask() override = default;
};

template <class REQ, class RESP>
class WFNetworkTask : public CommRequest {
public:
    void start() {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }

    void dismiss() {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }

public:
    REQ *get_req() { return &this->req; }
    RESP *get_resp() { return &this->resp; }

    const REQ *get_req() const { return &this->req; }
    const RESP *get_resp() const { return &this->resp; }

public:
    void *user_data;

public:
    [[nodiscard]] int get_state() const { return this->state; }
    [[nodiscard]] int get_error() const { return this->error; }

    /**Call when error is ETIMEDOUT, return values:
     * TOR_NOT_TIMEOUT, TOR_WAIT_TIMEOUT, TOR_CONNECT_TIMEOUT,
     * TOR_TRANSMIT_TIMEOUT (send or receive).
     * SSL connect timeout also returns TOR_CONNECT_TIMEOUT. */
    // 获取超时的具体原因(如连接超时、传输超时)
    [[nodiscard]] int get_timeout_reason() const { return this->timeout_reason; }

    /* Call only in callback or server's process. */
    [[nodiscard]] long long get_task_seq() const {
        if (!this->target) {
            errno = ENOTCONN;
            return -1;
        }

        return this->get_seq();
    }

    // 获取对端地址(客户端或服务器地址)
    int get_peer_addr(sockaddr *addr, socklen_t *addrlen) const;

    // (纯虚函数)获取底层的连接对象, 由具体协议实现
    [[nodiscard]] virtual WFConnection *get_connection() const = 0;


    /* All in milliseconds. timeout == -1 for unlimited. */
public:
    // 设置发送超时(毫秒), -1 表示无限制
    void set_send_timeout(int timeout) { this->send_timeo = timeout; }
    // 设置接收超时(毫秒), -1 表示无限制
    void set_receive_timeout(int timeout) { this->receive_timeo = timeout; }
    // 设置连接保持时间, 用于长连接复用
    void set_keep_alive(int timeout) { this->keep_alive_timeo = timeout; }
    //
    void set_watch_timeout(int timeout) { this->watch_timeo = timeout; }

public:
    /* Do not reply this request. */
    // (服务器任务)标记无需回复客户端
    void noreply() {
        if (this->state == WFT_STATE_TOREPLY) { this->state = WFT_STATE_NOREPLY; }
    }

    /* Push reply data synchronously. */
    // (服务器任务)同步推送回复数据给客户端
    virtual int push(const void *buf, size_t size) {
        if (this->state != WFT_STATE_TOREPLY && this->state != WFT_STATE_NOREPLY) {
            errno = ENOENT;
            return -1;
        }

        return this->scheduler->push(buf, size, this);
    }

    /* To check if the connection was closed before replying.
       Always returns 'true' in callback. */
    [[nodiscard]] bool closed() const {
        switch (this->state) {
        case WFT_STATE_UNDEFINED: return false;
        case WFT_STATE_TOREPLY:
        case WFT_STATE_NOREPLY: return !this->target->has_idle_conn();
        default: return true;
        }
    }

public:
    void set_prepare(std::function<void (WFNetworkTask<REQ, RESP> *)> prep) {
        this->prepare = std::move(prep);
    }

public:
    void set_callback(std::function<void (WFNetworkTask<REQ, RESP> *)> cb) {
        this->callback = std::move(cb);
    }

protected:
    int send_timeout() override { return this->send_timeo; }
    int receive_timeout() override { return this->receive_timeo; }
    int keep_alive_timeout() override { return this->keep_alive_timeo; }
    int first_timeout() override { return this->watch_timeo; }

protected:
    int send_timeo;
    int receive_timeo;
    int keep_alive_timeo;
    int watch_timeo; // 任务整体看门狗超时. 任务从开始到结束的总时间限制. 是发送和接收超时的最后一道安全屏, 确保任务不会无限期挂起
    REQ req; // 模板化的请求对象由具体协议(如 HttpRequest)特化
    RESP resp; // 模板化的响应对象由具体协议(如 HttpResponse)特化
    std::function<void(WFNetworkTask<REQ, RESP> *)> prepare; // 在连接建立后、请求序列化并发送前调用. 可以基于连接实际状态（如加密套件、服务器信息）动态调整请求
    std::function<void(WFNetworkTask<REQ, RESP> *)> callback;

protected:
    /**@param object 与任务关联的通信调度目标(如一个服务器地址或连接对象)
     * @param scheduler 指定通信调度器, 负责管理底层的IO事件和线程
     * @param cb 任务完成时的回调函数 */
    WFNetworkTask(CommSchedObject *object, CommScheduler *scheduler, std::function<void(WFNetworkTask<REQ, RESP> *)> &&cb) :
        CommRequest(object, scheduler), callback(std::move(cb)) {
        this->send_timeo = -1; // 初始化为无限等待
        this->receive_timeo = -1; // 初始化为无限等待
        this->keep_alive_timeo = 0; // 0表示任务完成后不保持连接
        this->watch_timeo = 0; // 任务整体看门狗超时. 0表示没有设置全局超时, 或使用默认短超时以防任务挂起
        this->target = nullptr; // 指向具体通信目标的指针. 初始为 nullptr
        this->timeout_reason = TOR_NOT_TIMEOUT; // 超时原因. 初始化为“未超时”
        this->user_data = nullptr;
        this->state = WFT_STATE_UNDEFINED; // 任务状态. 初始为“未定义”, 任务执行过程中会被框架更新为成功、错误等状态
        this->error = 0;
    }

    ~WFNetworkTask() override = default;
};

class WFTimerTask : public SleepRequest {
public:
    void start() {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }

    void dismiss() {
        assert(!series_of(this));
        delete this;
    }

    [[nodiscard]] int get_state() const { return this->state; }
    [[nodiscard]] int get_error() const { return this->error; }

    void set_callback(std::function<void(WFTimerTask *)> cb) { this->callback = std::move(cb); }

public:
    void *user_data; // 用户自定义数据指针, 用于在回调函数中传递上下文信息

protected:
    // 任务完成后调用此函数
    SubTask *done() override {
        SeriesWork *series_work = series_of(this);
        if (this->callback) {
            this->callback(this);
        }
        delete this;
        return series_work->pop();
    }

protected:
    std::function<void (WFTimerTask *)> callback; // 任务完成后的回调函数

public:
    WFTimerTask(CommScheduler *scheduler, std::function<void (WFTimerTask *)> cb) :
        SleepRequest(scheduler), callback(std::move(cb)) {
        this->user_data = nullptr;
        this->state = WFT_STATE_UNDEFINED; // 初始化状态为未定义
        this->error = 0;
    }

protected:
    ~WFTimerTask() override = default;
};

template <class ARGS>
class WFFileTask : public IORequest {
public:
    void start() {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }

    void dismiss() {
        assert(!series_of(this));
        delete this;
    }

    [[nodiscard]] ARGS *get_args() { return &this->args; }

    [[nodiscard]] const ARGS *get_args() const { return &this->args; }

    // 获取IO操作结果(如实际读取/写入的字节数). 仅在任务成功(WFT_STATE_SUCCESS)时有意义
    [[nodiscard]] long get_retval() const {
        if (this->state == WFT_STATE_SUCCESS) {
            return this->get_res();
        } else { return -1; }
    }

    [[nodiscard]] int get_state() const { return this->state; }
    [[nodiscard]] int get_error() const { return this->error; }

    void set_callback(std::function<void (WFFileTask<ARGS> *)> cb) { this->callback = std::move(cb); }

public:
    void *user_data; // 用户自定义数据指针

protected:
    SubTask *done() override {
        SeriesWork *series = series_of(this);

        if (this->callback) { this->callback(this); }

        delete this;
        return series->pop();
    }

protected:
    ARGS args; // 模板化的操作参数. 例如，对于读文件操作，可能是包含文件名、偏移量、读取长度的结构体
    std::function<void (WFFileTask<ARGS> *)> callback; // 任务完成的回调

public:
    WFFileTask(IOService *service, std::function<void (WFFileTask<ARGS> *)> &&cb) :
        IORequest(service), callback(std::move(cb)) {
        this->user_data = nullptr;
        this->state = WFT_STATE_UNDEFINED;
        this->error = 0;
    }

protected:
    ~WFFileTask() override = default;
};

// 通用的任务类
class WFGenericTask : public SubTask {
public:
    void start() {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }

    void dismiss() {
        assert(!series_of(this));
        delete this;
    }

    [[nodiscard]] int get_state() const { return this->state; }
    [[nodiscard]] int get_error() const { return this->error; }

public:
    void *user_data;

protected:
    // 任务调度入口. 被框架调用后立即触发subtask_done(), 表示任务完成
    void dispatch() override {
        this->subtask_done(); // 被调度时立即标记为完成
    }

    /* 一旦开始调度这个任务, 这个任务会瞬间完成. 并立即进入done()回调阶段(在subtask_done中), 这种设计非常适用于以下场景:
    * 1.逻辑控制节点: 在复杂的任务流中作为一个信号或开关. 例如, 在某个条件满足后, 通过一个 WFGenericTask 来触发后续一系列任务的执行.
    * 2.空操作(No-op)任务: 用于占位或保持任务流的结构完整性.
    * 3.测试与调试: 在原型开发或测试中, 用于模拟一个立即成功或失败的任务. */

    SubTask *done() override {
        SeriesWork *series = series_of(this);
        delete this;
        return series->pop();
    }

protected:
    int state;
    int error;

public:
    WFGenericTask() {
        this->user_data = nullptr;
        this->state = WFT_STATE_UNDEFINED;
        this->error = 0;
    }

protected:
    ~WFGenericTask() override = default;
};

// 用于实现协同等待机制的计数器任务
class WFCounterTask : public WFGenericTask {
public:
    // 减少任务计数
    virtual void count() {
        // 注意此处是先减1, 再与0比较
        if (--this->value == 0) {
            this->state = WFT_STATE_SUCCESS;
            this->subtask_done();
        }
    }

public:
    void set_callback(std::function<void (WFCounterTask *)> cb) { this->callback = std::move(cb); }

protected:
    // 任务调度入口
    void dispatch() override {
        this->WFCounterTask::count();
    }

    SubTask *done() override {
        SeriesWork *series = series_of(this);

        if (this->callback) this->callback(this);

        delete this;
        return series->pop();
    }

protected:
    std::atomic<unsigned int> value; // 原子变量计数器
    std::function<void (WFCounterTask *)> callback; // 计数完成的回调

public:
    WFCounterTask(unsigned int target_value, std::function<void (WFCounterTask *)> &&cb) :
        value(target_value + 1), // 注意此处target_value加了1
        callback(std::move(cb)) {}

protected:
    ~WFCounterTask() override = default;
};

// 异步消息邮箱任务. 实现了多生产者-多消费者模式下的线程安全消息交换. 核心价值在于提供了无需锁的线程安全通信机制, 允许不同任务或线程通过共享的“邮箱”安全地传递数据指针
class WFMailboxTask : public WFGenericTask {
public:
    virtual void send(void *msg) {
        *this->mailbox = msg;
        // exchange: 将标志位无条件设为true, 并返回设置前的旧值
        // 如果返回的是false, 说明当前操作是“第一个到达的”(无论是send还是dispatch先执行), 此时只需设置标志位, 然后等待另一个操作到来
        if (this->flag.exchange(true)) {
            this->state = WFT_STATE_SUCCESS;
            this->subtask_done();
        }
    }

    // 接收方获取消息地址
    [[nodiscard]] void **get_mailbox() const { return this->mailbox; }

    void set_callback(std::function<void (WFMailboxTask *)> cb) { this->callback = std::move(cb); }

protected:
    // 任务调度入口
    void dispatch() override {
        if (this->flag.exchange(true)) {
            this->state = WFT_STATE_SUCCESS;
            this->subtask_done();
        }
    }

    SubTask *done() override {
        SeriesWork *series = series_of(this);

        if (this->callback) { this->callback(this); }

        delete this;
        return series->pop();
    }

protected:
    void **mailbox; // 消息中转站
    std::atomic<bool> flag;
    std::function<void (WFMailboxTask *)> callback;

public:
    // 使用外部指定的邮箱. 用于多个任务共享同一个邮箱的场景, 实现广播或共享消息
    WFMailboxTask(void **mailbox, std::function<void (WFMailboxTask *)> &&cb) :
        flag(false),
        callback(std::move(cb)) {
        this->mailbox = mailbox;
    }

    // 使用内部邮箱(user_data). 用于点对点单次消息传递, 消息存储在任务自身的user_data中
    explicit WFMailboxTask(std::function<void (WFMailboxTask *)> &&cb) : flag(false), callback(std::move(cb)) {
        this->mailbox = &this->user_data;
    }

protected:
    ~WFMailboxTask() override = default;
};

// 多候选选择的异步任务类
class WFSelectorTask : public WFGenericTask {
public:
    virtual int submit(void *msg) {
        void *tmp = nullptr;
        int ret = 0;

        // 只有当 message 的当前值是tmp(初始为 nullptr)时, 才会将其设置为新的msg
        // 第一个执行到此的候选会遇到message为nullptr, 从而设置成功. 后续候选再执行时, message已非nullptr, 因此提交失败, 返回0
        if (this->message.compare_exchange_strong(tmp, msg) && msg) {
            ret = 1;
            // flag标志位用于防止任务被多次标记为完成
            // 将flag设为true, 并返回其之前的值
            if (this->flag.exchange(true)) {
                this->state = WFT_STATE_SUCCESS;
                this->subtask_done();
            }
        }

        if (--this->nleft == 0) {
            if (!this->message) {
                // 如果此时message仍为nullptr, 说明没有任何候选成功提交消息, 任务被标记为系统错误
                this->state = WFT_STATE_SYS_ERROR;
                this->error = ENOMSG;
                this->subtask_done();
            }
            delete this;
        }
        return ret; // 无论成功与否, 最终都会调用 delete this销毁任务, 确保资源释放
    }

    [[nodiscard]] void *get_message() const { return this->message; }

public:
    void set_callback(std::function<void (WFSelectorTask *)> cb) {
        this->callback = std::move(cb);
    }

protected:
    void dispatch() override {
        if (this->flag.exchange(true)) {
            this->state = WFT_STATE_SUCCESS;
            this->subtask_done();
        }

        if (--this->nleft == 0) {
            if (!this->message) {
                // 如果此时message仍为nullptr, 说明没有任何候选成功提交消息, 任务被标记为系统错误
                this->state = WFT_STATE_SYS_ERROR;
                this->error = ENOMSG;
                this->subtask_done();
            }
            delete this;
        }
    }

    SubTask *done() override {
        SeriesWork *series = series_of(this);

        if (this->callback) { this->callback(this); }

        return series->pop();
    }

protected:
    std::atomic<void *> message; // 存储被选中的消息. 通过原子操作确保只有一个提交者能成功设置消息.
    std::atomic<bool> flag; // 任务完成同步标志. 用于协调submit()和dispatch()的完成信号, 确保只触发一次 subtask_done().
    std::atomic<size_t> nleft; // 剩余候选计数器.无论是通过 submit提交消息, 还是通过 dispatch进行调度, 每次操作都会递减 nleft. 当 nleft减至 0 时, 意味着所有候选操作都已执行完毕
    std::function<void (WFSelectorTask *)> callback; // 任务完成后的回调函数

public:
    WFSelectorTask(size_t candidates, std::function<void (WFSelectorTask *)> &&cb) :
        message(nullptr), flag(false),
        nleft(candidates + 1), // 注意此处是candidates+1
        callback(std::move(cb)) {}

protected:
    ~WFSelectorTask() override = default;
};

// 条件任务. 需要特定条件才能执行
class WFConditional : public WFGenericTask {
public:
    virtual void signal(void *msg) {
        *this->msgbuf = msg; // 保存消息
        // 检查并设置标志
        if (this->flag.exchange(true)) {
            this->subtask_done(); // 若标志已为true, 立即完成. 因为signal是虚函数, 所以子类可以重写这部分逻辑
        }
    }

protected:
    // 任务调度入口
    void dispatch() override {
        series_of(this)->push_front(this->task); // 将包装的任务加入系列
        this->task = nullptr; // 移交任务所有权
        // 检查并设置标志
        if (this->flag.exchange(true)) {
            this->subtask_done(); // 若标志已为true，立即完成. 子类可以重写这部分逻辑
        }
    }

protected:
    std::atomic<bool> flag; // 条件满足标志. 通过原子操作实现线程安全的条件状态同步
    SubTask *task; // 被包装的实际任务. 当条件满足时, 此任务将被执行
    void **msgbuf; // 消息缓冲区指针. 用于接收条件触发时传递过来的数据(如资源指针)

public:
    WFConditional(SubTask *task, void **msgbuf) :
        flag(false) {
        this->task = task;
        this->msgbuf = msgbuf;
    }

    explicit WFConditional(SubTask *task) :
        flag(false) {
        this->task = task;
        this->msgbuf = &this->user_data;
    }

protected:
    ~WFConditional() override { delete this->task; }
};

// 封装异步计算任务的基类
class WFGoTask : public ExecRequest {
public:
    void start() {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }

    void dismiss() {
        assert(!series_of(this));
        delete this;
    }

    [[nodiscard]] int get_state() const { return this->state; }
    [[nodiscard]] int get_error() const { return this->error; }

    void set_callback(std::function<void (WFGoTask *)> cb) { this->callback = std::move(cb); }

public:
    void *user_data;

protected:
    SubTask *done() override {
        SeriesWork *series = series_of(this);

        if (this->callback) { this->callback(this); }

        delete this;
        return series->pop();
    }

protected:
    std::function<void (WFGoTask *)> callback;

public:
    WFGoTask(ExecQueue *queue, Executor *executor) :
        ExecRequest(queue, executor) {
        this->user_data = nullptr;
        this->state = WFT_STATE_UNDEFINED;
        this->error = 0;
    }

protected:
    ~WFGoTask() override = default;
};

// 循环任务生成器
class WFRepeaterTask : public WFGenericTask {
public:
    void set_create(std::function<SubTask *(WFRepeaterTask *)> _create) {
        this->create = std::move(_create);
    }

    void set_callback(std::function<void (WFRepeaterTask *)> cb) { this->callback = std::move(cb); }

protected:
    // 任务调度入口
    void dispatch() override {
        // 调用用户提供的create函数, 动态创建一个新的子任务. 这个子任务可以是任何SubTask类型, 如HTTP请求、文件操作等
        SubTask *task = this->create(this);

        if (task) {
            series_of(this)->push_front(this); // 自己重新入队
            series_of(this)->push_front(task); // 子任务入队
        } else {
            this->state = WFT_STATE_SUCCESS; // 无任务则结束循环
        }

        this->subtask_done();
    }

    SubTask *done() override {
        SeriesWork *series = series_of(this);
        // 检查循环是否已终止, 如果 this->state != WFT_STATE_UNDEFINED, 说明循环已经终止
        if (this->state != WFT_STATE_UNDEFINED) {
            if (this->callback) { this->callback(this); }
            delete this;
        }

        return series->pop();
    }

protected:
    std::function<SubTask *(WFRepeaterTask *)> create;
    std::function<void (WFRepeaterTask *)> callback;

public:
    WFRepeaterTask(std::function<SubTask *(WFRepeaterTask *)> &&create, std::function<void (WFRepeaterTask *)> &&cb) :
        create(std::move(create)), callback(std::move(cb)) {}

protected:
    ~WFRepeaterTask() override = default;
};

// 复合任务类.
// 能够将一个完整的串行任务流(SeriesWork)包装成一个独立的、可以并行执行的单元(ParallelTask),
// 非常适合将复杂任务流模块化, 并作为独立单元嵌入到更大的并行工作流中
class WFModuleTask : public ParallelTask, protected SeriesWork {
public:
    void start() {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }

    void dismiss() {
        assert(!series_of(this));
        delete this;
    }

    SeriesWork *sub_series() { return this; }

    [[nodiscard]] const SeriesWork *sub_series() const { return this; }

    void set_callback(std::function<void (const WFModuleTask *)> cb) {
        this->callback = std::move(cb);
    }

public:
    void *user_data;

protected:
    SubTask *done() override {
        SeriesWork *series = series_of(this);

        if (this->callback) { this->callback(this); }

        delete this;
        return series->pop();
    }

protected:
    SubTask *first;
    std::function<void (const WFModuleTask *)> callback;

public:
    WFModuleTask(SubTask *first, std::function<void (const WFModuleTask *)> &&cb) :
        ParallelTask(&this->first, 1), // 初始化ParallelTask，子任务列表指向first
        SeriesWork(first, nullptr), // 初始化SeriesWork，以first为起始任务
        callback(std::move(cb)) {
        this->first = first;
        this->set_in_parallel(this); // 关键: 将自身设置为并行上下文
        this->user_data = nullptr;
    }

protected:
    ~WFModuleTask() override {
        if (!this->is_finished()) { this->dismiss_recursive(); }
    }
};

#include "WFTask.inl"

#endif //MYWORKFLOW_WFTASK_H