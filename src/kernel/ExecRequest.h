//
// Created by ldk on 10/13/25.
//

#ifndef MYWORKFLOW_EXECREQUEST_H
#define MYWORKFLOW_EXECREQUEST_H

#include <cerrno>
#include "SubTask.h"
#include "Executor.h"

class ExecRequest : public SubTask, public ExecSession {
public:
    ExecRequest(ExecQueue *queue, Executor *executor) {
        this->executor = executor;
        this->queue = queue;
    }

    [[nodiscard]] ExecQueue *get_request_queue() const { return this->queue; }
    void set_request_queue(ExecQueue *_queue) { this->queue = _queue; }

    // 任务调度入口
    void dispatch() override {
        // 调用 executor->request(this, this->queue)将自身(ExecRequest对象)提交给执行器
        if (this->executor->request(this, this->queue) < 0) {
            this->handle(ES_STATE_ERROR, errno); // 任务提交出错, 处理错误
        }
    }

protected:
    int state{-1};
    int error{-1};

    ExecQueue *queue;
    Executor *executor;

protected:
    // 任务完成回调
    void handle(int _state, int _error) override {
        this->state = _state;
        this->error = _error;
        this->subtask_done();
    }
};

#endif //MYWORKFLOW_EXECREQUEST_H