//
// Created by ldk on 9/28/25.
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

#ifndef MYWORKFLOW_WORKFLOW_INL
#define MYWORKFLOW_WORKFLOW_INL

#include "WFTask.h"

template <class REQ, class RESP>
int WFNetworkTask<REQ, RESP>::get_peer_addr(sockaddr *addr, socklen_t *addrlen) const {
    if (this->target) {
        const sockaddr *p = nullptr;
        socklen_t len = 0;
        // 获取地址
        this->target->get_addr(&p, &len);
        // 比较调用者提供的缓冲区大小 (*addrlen) 和实际需要的地址长度 (len)
        if (*addrlen >= len) {
            memcpy(addr, p, len); // 复制地址数据
            *addrlen = len; // 回传实际地址长度
            return 0;
        }
        errno = ENOBUFS;
    } else { errno = ENOTCONN; } // 未建立连接

    return -1;
}

// 用于客户端网络通信的模板类
template <class REQ, class RESP>
class WFClientTask : public WFNetworkTask<REQ, RESP> {
protected:
    // 提供要发送的消息. 可选地执行prepare回调后, 返回请求对象 req 的地址
    CommMessageOut *message_out() override {
        /* By using prepare function, users can modify the request after
         * the connection is established. */
        // 如果设置了prepare回调函数, 则执行
        if (this->prepare) { this->prepare(this); }

        return &this->req;
    }

    // 提供接收消息的缓冲区. 返回响应对象resp的地址, 框架会将收到的数据反序列化到此.
    CommMessageIn *message_in() override { return &this->resp; }

protected:
    // 获取底层连接对象. 用于在需要时直接操作网络连接
    [[nodiscard]] WFConnection *get_connection() const override {
        if (this->target) {
            WFConnection *conn = this->CommSession::get_connect();
            if (conn) { return conn; }
        }
        errno = ENOTCONN;
        return nullptr;
    }

protected:
    SubTask *done() override {
        SeriesWork *series = series_of(this);

        // 底层在遇到SSL相关错误时, 会先将其标记为系统错误并赋予一个负的错误码, 在 done()阶段进行统一转换
        if (this->state == WFT_STATE_SYS_ERROR && this->error < 0) {
            this->state = WFT_STATE_SSL_ERROR;
            this->error = -this->error;
        }

        if (this->callback) { this->callback(this); }

        delete this;
        return series->pop();
    }

public:
    WFClientTask(CommSchedObject *object, CommScheduler *scheduler, std::function<void (WFNetworkTask<REQ, RESP> *)> &&cb) :
        WFNetworkTask<REQ, RESP>(object, scheduler, std::move(cb)) {}

protected:
    ~WFClientTask() override = default;
};

// 用于服务端网络通信的模板类
template <class REQ, class RESP>
class WFServerTask : public WFNetworkTask<REQ, RESP> {
protected:
    // 提供要发送的响应消息
    CommMessageOut *message_out() override {
        /* By using prepare function, users can modify the response before
         * replying to the client. */
        if (this->prepare) {
            this->prepare(this);
        }
        return &this->resp;
    }

    // 提供接收请求的缓冲区指针
    CommMessageIn *message_in() override { return &this->req; }
    // 任务完成回调
    void handle(int state, int error) override;

protected:
    /* CommSession::get_connection() is supposed to be called only in the
     * implementations of it's virtual functions. As a server task, to call
     * this function after process() and before callback() is very dangerous
     * and should be blocked. */
    // 受控的连接获取. 确保仅在安全的上下文中才能获取底层连接对象
    [[nodiscard]] WFConnection *get_connection() const override {
        if (this->processor.task) {
            // 仅在Processor持有task时允许获取
            return static_cast<WFConnection *>(this->CommSession::get_connect());
        }
        errno = EPERM;
        return nullptr;
    }

protected:
    void dispatch() override {
        if (this->state == WFT_STATE_TOREPLY) {
            // 需要回复客户端的状态
            // 启用get_connection()
            this->processor.task = this;
            // 尝试回复
            if (this->scheduler->reply(this) >= 0) {
                return; // 回复操作已异步进行, 等待后续事件
            }
            this->state = WFT_STATE_SYS_ERROR; // 如果回复失败，则标记为系统错误
            this->error = errno;
            this->processor.task = nullptr;
        } else {
            // 非TOREPLY状态，可能直接关闭连接
            this->scheduler->shutdown(this);
        }
        // 标记当前任务完成
        this->subtask_done();
    }

    SubTask *done() override {
        SeriesWork *series = series_of(this);

        if (this->state == WFT_STATE_SYS_ERROR && this->error < 0) {
            this->state = WFT_STATE_SSL_ERROR;
            this->error = -this->error;
        }
        if (this->callback) { this->callback(this); }

        /* Defer deleting the task. */
        return series->pop();
    }

protected:
    // 业务逻辑处理类
    class Processor : public SubTask {
    public:
        Processor(WFServerTask<REQ, RESP> *task, std::function<void (WFNetworkTask<REQ, RESP> *)> &proc) :
            process(proc) {
            this->task = task;
        }

        // Processor类的核心作用是在一个安全的上下文中执行用户处理函数 process，并在执行后立即禁用对底层连接的访问（this->task = nullptr）
        void dispatch() override {
            this->process(this->task); // 执行用户处理函数
            this->task = nullptr; /* As a flag. get_conneciton() disabled. */
            this->subtask_done();
        }

        SubTask *done() override {
            return series_of(this)->pop();
        }

        std::function<void (WFNetworkTask<REQ, RESP> *)> &process; // 用户处理函数
        WFServerTask<REQ, RESP> *task;
    } processor;

    // 系列工作流(管理 WFServerTask 和其 Processor 的生命周期，在其析构时负责销毁 WFServerTask对象)
    class Series : public SeriesWork {
    public:
        explicit Series(WFServerTask<REQ, RESP> *task) :
            SeriesWork(&task->processor, nullptr) {
            this->set_last_task(task);
            this->task = task;
        }

        ~Series() override {
            delete this->task;
        }

        WFServerTask<REQ, RESP> *task;
    };

public:
    WFServerTask(CommService *service, CommScheduler *scheduler, std::function<void (WFNetworkTask<REQ, RESP> *)> &proc) :
        WFNetworkTask<REQ, RESP>(nullptr, scheduler, nullptr),
        processor(this, proc) {}

    /**WFServerTask将业务逻辑(process)和任务完成通知(callback)分离.
     * 用户将业务处理函数传入, 框架将其包装在Processor中执行. 而callback则用于在任务整个生命周期结束时进行通知.
     * 在资源管理上, 框架采用了延迟删除策略, 任务对象的销毁不再在done()中直接进行, 而是委托给 Series对象的析构函数,
     * 这优化了性能并简化了生命周期管理的逻辑 */

protected:
    ~WFServerTask() override {
        if (this->target) {
            static_cast<Series *>(series_of(&this->processor))->task = nullptr;
        }
    }
};

template <class REQ, class RESP>
void WFServerTask<REQ, RESP>::handle(int state, int error) {
    if (state == WFT_STATE_TOREPLY) {
        // 需要服务器回复的请求
        this->state = WFT_STATE_TOREPLY;
        this->target = this->get_target(); // 获取与此任务相关的通信目标
        // 创建一个 Series对象(一个特殊的系列工作流), 并将当前任务作为其最后一个任务.
        // 这个Series对象会管理任务的生命周期, 确保在系列中的所有处理步骤完成后, 才进行最终的回复和资源清理
        new Series(this); // 此处不算内存泄漏, 因为该对象的构造函数会将该对象放进任务流中. 在执行完成后框架会调用该对象的析构函数.
        this->processor.dispatch(); // 执行用户的业务逻辑
    } else if (this->state == WFT_STATE_TOREPLY) {
        // 当传入的state不是TOREPLY, 但任务当前状态是TOREPLY时, 通常意味着在处理过程中发生了错误(如超时或连接中断)
        this->state = state;
        this->error = error;
        if (error == ETIMEDOUT) {
            // 如果是超时错误(ETIMEDOUT), 则详细记录超时原因是传输超时(TOR_TRANSMIT_TIMEOUT)
            this->timeout_reason = TOR_TRANSMIT_TIMEOUT;
        }
        this->subtask_done();
    } else {
        delete this;
    }
}

#endif