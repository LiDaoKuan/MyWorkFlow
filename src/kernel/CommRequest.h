//
// Created by ldk on 10/12/25.
//

#ifndef MYWORKFLOW_COMMREQUEST_H
#define MYWORKFLOW_COMMREQUEST_H

#include <errno.h>
#include <stddef.h>
#include "SubTask.h"
#include "Communicator.h"
#include "CommScheduler.h"

class CommRequest : public SubTask, public CommSession {
public:
    CommRequest(CommSchedObject *_object, CommScheduler *_scheduler) {
        this->scheduler = _scheduler;
        this->object = _object;
        this->wait_timeout = 0;
    }

    [[nodiscard]] CommSchedObject *get_request_object() const { return this->object; }
    void set_request_object(CommSchedObject *_object) { this->object = _object; }
    [[nodiscard]] int get_wait_timeout() const { return this->wait_timeout; }
    void set_wait_timeout(int timeout) { this->wait_timeout = timeout; }

    void dispatch() override {
        if (this->scheduler->request(this, this->object, this->wait_timeout, &this->target) < 0) {
            this->handle(CS_STATE_ERROR, errno);
        }
    }

protected:
    int state = 0;
    int error = 0;

    CommTarget *target{nullptr};
#define TOR_NOT_TIMEOUT         0
#define TOR_WAIT_TIMEOUT        1
#define TOR_CONNECT_TIMEOUT     2
#define TOR_TRANSMIT_TIMEOUT    3
    int timeout_reason{-1};

protected:
    int wait_timeout;
    CommSchedObject *object;
    CommScheduler *scheduler;

protected:
    void handle(int _state, int _error) override;
};


#endif //MYWORKFLOW_COMMREQUEST_H