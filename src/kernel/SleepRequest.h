//
// Created by ldk on 10/13/25.
//

#ifndef MYWORKFLOW_SLEEPREQUEST_H
#define MYWORKFLOW_SLEEPREQUEST_H

#include <cerrno>
#include "SubTask.h"
#include "Communicator.h"
#include "CommScheduler.h"

// 管理延迟执行或者定时任务
class SleepRequest : public SubTask, public SleepSession {
public:
    explicit SleepRequest(CommScheduler *scheduler) {
        this->scheduler = scheduler;
    }

    // 任务调度入口
    void dispatch() override {
        // 将睡眠操作委托给: scheduler执行
        if (this->scheduler->sleep(this) < 0) {
            // 提交给scheduler时出错
            this->handle(SS_STATE_ERROR, errno);
        }
    }

protected:
    // 主动取消正在进行的睡眠会话
    int cancel() {
        return this->scheduler->unsleep(this);
    }

protected:
    int state{-1};
    int error{-1};

    CommScheduler *scheduler; // 通信调度器指针. SleepRequest将具体的睡眠操作委托给它执行，从而利用框架高效的异步事件驱动机制

protected:
    void handle(int _state, int _error) override {
        this->state = _state;
        this->error = _error;
        this->subtask_done(); // 通知父任务该子任务已经完成
    }
};

#endif //MYWORKFLOW_SLEEPREQUEST_H