//
// Created by ldk on 10/12/25.
//

#include "CommRequest.h"

#include <errno.h>
#include "CommScheduler.h"
#include "CommRequest.h"

void CommRequest::handle(int _state, int _error) {
    this->state = _state;
    this->error = _error;
    if (_error != ETIMEDOUT) {
        this->timeout_reason = TOR_NOT_TIMEOUT;
    } else if (!this->target) {
        this->timeout_reason = TOR_WAIT_TIMEOUT;
    } else if (!this->get_message_out()) {
        this->timeout_reason = TOR_CONNECT_TIMEOUT;
    } else { this->timeout_reason = TOR_TRANSMIT_TIMEOUT; }

    this->subtask_done();
}