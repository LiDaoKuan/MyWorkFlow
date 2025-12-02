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

#include <cstring>
#include "list.h"
#include "WFTask.h"
#include "WFResourcePool.h"

// 实现资源等待和异步唤醒机制
class RPConditional : public WFConditional {
public:
    list_head list{nullptr, nullptr};
    WFResourcePool::Data *data_;

public:
    void dispatch() override;
    // 预留的信号接口. 在此实现为空, 意味着当前逻辑可能不需要额外的信号机制, 或由dispatch统一处理
    void signal(void *res) override {}

public:
    // 接收待执行的任务(SubTask*)、可选的资源存储指针(resbuf)以及资源池数据(data_), 完成条件对象的初始化
    RPConditional(SubTask *task, void **resbuf, WFResourcePool::Data *data) :
        WFConditional(task, resbuf) {
        this->data_ = data;
    }

    RPConditional(SubTask *task, WFResourcePool::Data *data) :
        WFConditional(task) {
        this->data_ = data;
    }
};

// 当资源可用时, 由资源池调用此函数来唤醒并分派之前被挂起的任务
void RPConditional::dispatch() {
    WFResourcePool::Data *data = this->data_;

    data->mutex.lock();
    // 预减后判断: 在检查前就"假定"需要消耗一个资源配额.
    // 如果value从1减为0, 表示当前任务取走了最后一个资源
    // 如果value从0减为-1, 表示资源不足, 且当前任务成为第一个等待者
    // 后续的负数值直接反映了等待队列的长度
    if (--data->value >= 0) {
        // 资源可用: 立即分配
        this->WFConditional::signal(data->pop()); // 调用父类的方法
    } else {
        // 资源不足: 加入等待队列
        list_add_tail(&this->list, &data->wait_list);
    }

    data->mutex.unlock();
    this->WFConditional::dispatch(); // 调用基类方法, 提交任务使其继续执行
}

// 资源获取. 暂时没有任何调用方？？？？
WFConditional *WFResourcePool::get(SubTask *task, void **resbuf) {
    return new RPConditional(task, resbuf, &this->data_); // 返回条件任务, 由外部启动？？？
}

// 资源获取. 暂时没有任何调用方？？？？
WFConditional *WFResourcePool::get(SubTask *task) {
    return new RPConditional(task, &this->data_); // 返回条件任务, 由外部启动？？？
}

void WFResourcePool::create(size_t n) {
    this->data_.res = new void *[n];
    this->data_.value = n;
    this->data_.index = 0;
    INIT_LIST_HEAD(&this->data_.wait_list);
    this->data_.pool = this;
}

WFResourcePool::WFResourcePool(void *const *res, size_t n) {
    this->create(n);
    memcpy(this->data_.res, res, n * sizeof(void *));
}

WFResourcePool::WFResourcePool(size_t n) {
    this->create(n);
    memset(this->data_.res, 0, n * sizeof(void *));
}

// 资源归还
void WFResourcePool::post(void *res) {
    WFResourcePool::Data *data = &this->data_;
    WFConditional *cond;

    data->mutex.lock();
    // 首先增加计数器, 然后检查新值. 如果新值 <= 0, 说明递增前有任务在等待(因为递增后仍非正), 需要立即唤醒一个任务
    if (++data->value <= 0) {
        cond = list_entry(data->wait_list.next, RPConditional, list); // 取出队列首任务
        list_del(data->wait_list.next); // 从队列中移除队首
    } else {
        cond = nullptr;
        this->push(res); // 将资源放回池中
    }

    data->mutex.unlock();
    if (cond) {
        cond->WFConditional::signal(res); // 唤醒等待任务
    }
}