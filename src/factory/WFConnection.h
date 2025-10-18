//
// Created by ldk on 10/18/25.
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

#ifndef MYWORKFLOW_WFCONNECTION_H
#define MYWORKFLOW_WFCONNECTION_H

#include <utility>
#include <atomic>
#include <functional>
#include "Communicator.h"

// 安全管理连接上下文
class WFConnection : public CommConnection {
public:
    [[nodiscard]] void *get_context() const {
        return this->context;
    }

    // 同时设置指针和清理函数, 将上下文生命周期与连接对象绑定, 确保资源安全释放
    void set_context(void *_context, std::function<void (void *)> _deleter) {
        this->context = _context;
        this->deleter = std::move(_deleter);
    }

    // 仅设置指针, 不绑定清理操作. 适用于上下文由外部管理的场景
    void set_context(void *_context) {
        this->context = _context;
    }

    // 原子性地比较并交换上下文指针
    void *test_set_context(void *test_context, void *new_context, std::function<void (void *)> _deleter) {
        // 原子操作compare_exchange_strong: 只有在当前 context 的值等于 test_context 时, 才会将其设置为 new_context
        if (this->context.compare_exchange_strong(test_context, new_context)) {
            this->deleter = std::move(_deleter);
            return new_context;
        }
        return test_context;
    }

    void *test_set_context(void *test_context, void *new_context) {
        if (this->context.compare_exchange_strong(test_context, new_context)) {
            return new_context;
        }
        return test_context;
    }

private:
    std::atomic<void *> context; // 线程安全的上下文指针, 存储用户自定义数据
    std::function<void (void *)> deleter; // 可定制的清理函数, 用于安全释放上下文资源

public:
    WFConnection() : context(nullptr) {}

protected:
    ~WFConnection() override {
        if (this->deleter) { this->deleter(this->context); }
    }
};

#endif //MYWORKFLOW_WFCONNECTION_H