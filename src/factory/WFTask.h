//
// Created by ldk on 10/18/25.
//

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
    WFT_STATE_UNDEFINED = -1,
    WFT_STATE_SUCCESS = CS_STATE_SUCCESS,
    WFT_STATE_TOREPLY = CS_STATE_TOREPLY, /* for server task only */
    WFT_STATE_NOREPLY = CS_STATE_TOREPLY + 1, /* for server task only */
    WFT_STATE_SYS_ERROR = CS_STATE_ERROR,
    WFT_STATE_SSL_ERROR = 65,
    WFT_STATE_DNS_ERROR = 66, /* for client task only */
    WFT_STATE_TASK_ERROR = 67,
    WFT_STATE_ABORTED = CS_STATE_STOPPED
};

template <class INPUT, class OUTPUT>
class WFThreadTask : public ExecRequest {
public:
    WFThreadTask(ExecQueue *queue, Executor *executor,
                 std::function<void (WFThreadTask<INPUT, OUTPUT> *)> &&cb) :
        ExecRequest(queue, executor),
        callback(std::move(cb)) {
        this->user_data = nullptr;
        this->state = WFT_STATE_UNDEFINED;
        this->error = 0;
    }

protected:
    ~WFThreadTask() override = default;
};

#include "WFTask.inl"

#endif //MYWORKFLOW_WFTASK_H