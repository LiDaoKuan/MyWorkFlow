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

#ifndef MYWORKFLOW_COMMREQUEST_H
#define MYWORKFLOW_COMMREQUEST_H

#include <cerrno>
#include <cstddef>
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
    void set_wait_timeout(const int timeout) { this->wait_timeout = timeout; }

    // 实现任务启动接口
    void dispatch() override {
        // 将实际的网络请求发起工作委托给了CommScheduler.
        // scheduler->request是一个异步操作, 它会将请求提交给底层的Communicator(通信器), 然后立即返回, 不会阻塞当前线程
        if (this->scheduler->request(this, this->object, this->wait_timeout, &this->target) < 0) {
            // 返回值<0表示出现了错误
            this->handle(CS_STATE_ERROR, errno); // 立即失败
        }
    }

protected:
    int state = 0;
    int error = 0;

    CommTarget *target{nullptr}; // 最终使用的连接目标

#define TOR_NOT_TIMEOUT         0       // 非超时错误. 可能是连接被拒绝、DNS解析失败、SSL握手错误等
#define TOR_WAIT_TIMEOUT        1       // 等待资源超时. 在连接池中等待可用连接的时间超过设定值, 表示后端服务可能过载或连接池大小不足
#define TOR_CONNECT_TIMEOUT     2       // 连接建立超时. TCP三次握手或SSL握手未在指定时间内完成, 通常指向网络不通、防火墙拦截或服务未启动
#define TOR_TRANSMIT_TIMEOUT    3       // 数据传输超时. 连接已建立, 但请求的发送或响应接收未在规定时间内完成, 可能由于网络延迟、数据包丢失或服务端处理缓慢
    int timeout_reason{-1};

protected:
    int wait_timeout; // 获取连接的超时时间
    CommSchedObject *object; // 调度目标（如特定服务器连接池）
    CommScheduler *scheduler; // 通信调度器

protected:
    // 任务完成的回调
    void handle(int _state, int _error) override;
};

#endif //MYWORKFLOW_COMMREQUEST_H