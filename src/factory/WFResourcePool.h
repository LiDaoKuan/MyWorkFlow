//
// Created by ldk on 11/26/25.
//

/*
  Copyright (c) 2021 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Li Yingxin (liyingxin@sogou-inc.com)
           Xie Han (xiehan@sogou-inc.com)
*/

#ifndef MYWORKFLOW_WFRESOURCEPOOL_H
#define MYWORKFLOW_WFRESOURCEPOOL_H

#include <mutex>
#include "list.h"
#include "WFTask.h"

class WFResourcePool {
public:
    WFConditional *get(SubTask *task, void **resbuf);
    WFConditional *get(SubTask *task);
    void post(void *res);

public:
    struct Data {
        void *pop() { return this->pool->pop(); }
        void push(void *res) { this->pool->push(res); }

        void **res; // 存储资源对象的指针, 由构造函数拷贝外部传入的资源对象指针指向的内存获得
        long value; // 表示当前池中可用资源的数量, 是进行资源分配和回收判断的核心状态
        size_t index; // 指向res数组中下一个可用资源的位置, 实现了类似栈的LIFO（后进先出）访问模式
        list_head wait_list; // 等待队列: 当资源不足时, 请求资源的任务会挂载到这个等待队列上, 直到有资源被归还
        std::mutex mutex;
        WFResourcePool *pool; // 所属的资源池？？？
    };

protected:
    // 下面两个虚函数: 应用了策略模式
    // 定义资源的具体分配和回收策略(默认为LIFO), 可被子类重写以实现自定义策略(如FIFO)

    virtual void *pop() {
        return this->data_.res[this->data_.index++];
    }

    virtual void push(void *res) {
        this->data_.res[--this->data_.index] = res;
    }

protected:
    Data data_;

private:
    void create(size_t n);

public:
    WFResourcePool(void *const *res, size_t n);
    explicit WFResourcePool(size_t n);
    virtual ~WFResourcePool() { delete []this->data_.res; }
};

#endif //MYWORKFLOW_WFRESOURCEPOOL_H