//
// Created by ldk on 10/13/25.
//

#ifndef MYWORKFLOW_SLEEPREQUEST_H
#define MYWORKFLOW_SLEEPREQUEST_H

#include <cerrno>
#include "SubTask.h"
#include "Communicator.h"
#include "CommScheduler.h"

class SleepRequest : public SubTask, public SleepSession {
public:
    explicit SleepRequest(CommScheduler *scheduler) {
        this->scheduler = scheduler;
    }

    void dispatch() override {
        if (this->scheduler->sleep(this) < 0) {
            this->handle(SS_STATE_ERROR, errno);
        }
    }

protected:
    int cancel() {
        return this->scheduler->unsleep(this);
    }

protected:
    int state{-1};
    int error{-1};

    CommScheduler *scheduler;

protected:
    void handle(int _state, int _error) override {
        this->state = _state;
        this->error = _error;
        this->subtask_done();
    }
};

#endif //MYWORKFLOW_SLEEPREQUEST_H