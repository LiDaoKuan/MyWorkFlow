//
// Created by ldk on 10/12/25.
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

#include "CommRequest.h"
#include "CommScheduler.h"

void CommRequest::handle(int _state, int _error) {
    this->state = _state;
    this->error = _error;
    if (_error != ETIMEDOUT) {
        this->timeout_reason = TOR_NOT_TIMEOUT;
    } else if (!this->target) {
        // 如果this->target为nullptr, 说明在CommRequest::dispatch()阶段, 调用scheduler->request(...)时,
        // 无法从连接池(如CommSchedGroup)中获取到一个可用的连接, 并在等待了wait_timeout时间后超时
        this->timeout_reason = TOR_WAIT_TIMEOUT;
    } else if (!this->get_message_out()) {
        // get_message_out()是一个由具体协议(如HTTP、Redis)实现的虚函数, 它返回一个指向待发送数据报文(CommMessageOut)的指针.
        // 如果这个指针为空, 说明连接尚未完全建立, 没有数据需要发送. 因此, 此时的超时判定为连接建立超时
        this->timeout_reason = TOR_CONNECT_TIMEOUT;
    } else {
        // 能进入else语句, 说明 连接已成功获取（target非空）且请求报文已准备好（message_out非空）
        // 此时的超时必然发生在 数据发送或接收响应 的过程中, 因此归类为传输超时
        this->timeout_reason = TOR_TRANSMIT_TIMEOUT;
    }
    this->subtask_done(); // 通知父任务本任务已完成
}