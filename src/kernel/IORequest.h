//
// Created by ldk on 10/13/25.
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

#ifndef MYWORKFLOW_IOREQUEST_H
#define MYWORKFLOW_IOREQUEST_H

#include <cerrno>
#include "SubTask.h"
#include "Communicator.h"

// 异步IO任务封装类
class IORequest : public SubTask, public IOSession {
public:
    explicit IORequest(IOService *service) {
        this->service = service;
    }

    // 任务调度入口
    void dispatch() override {
        // 将实际的IO请求委托给service
        if (this->service->request(this) < 0) {
            // 出错处理错误
            this->handle(IOS_STATE_ERROR, errno);
        }
    }

protected:
    int state{-1};
    int error{-1};

    IOService *service;

protected:
    // IO完成的回调
    void handle(int _state, int _error) override {
        this->state = _state; // 记录完成状态
        this->error = _error; // 记录错误码
        this->subtask_done(); // 通知父任务当前子任务已经完成
    }
};

#endif //MYWORKFLOW_IOREQUEST_H