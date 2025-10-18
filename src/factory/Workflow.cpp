//
// Created by ldk on 10/17/25.
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

#include <cassert>
#include <cstddef>
#include <cstring>
#include <utility>
#include <functional>
#include <mutex>
#include "Workflow.h"

SeriesWork::SeriesWork(SubTask *first, series_callback_t &&cb) :
    callback(std::move(cb)) {
    this->queue = this->buf;
    this->queue_size = std::size(this->buf);
    this->front = 0;
    this->back = 0;
    this->canceled = false;
    this->finished = false;
    assert(!series_of(first));
    first->set_pointer(this);
    this->first = first;
    this->last = nullptr;
    this->context = nullptr;
    this->in_parallel = nullptr;
}

SeriesWork::~SeriesWork() {
    if (this->queue != this->buf) { delete []this->queue; }
}

// 立即终止并清理整个串行任务流
void SeriesWork::dismiss_recursive() {
    SubTask *task = this->first; //

    this->callback = nullptr; // 确保在系列被强制销毁后, 不会意外执行任何用户预设的回调函数
    do {
        delete task;
        task = this->pop_task(); // 获取队列中的下一个任务
    } while (task);
}

// 动态扩容任务队列(非线程安全)
void SeriesWork::expand_queue() {
    const int size = 2 * this->queue_size;
    auto **new_queue = new SubTask *[size];
    int index = 0;
    int j = this->front;
    do {
        new_queue[index++] = this->queue[j++];
        // 当j递增到等于queue_size(即到达原线性数组末尾)时, 将其重置为0. 这确保了能正确访问环形队列中位于数组开头的元素
        if (j == this->queue_size) { j = 0; }
    } while (j != this->back);

    if (this->queue != this->buf) { delete []this->queue; }

    this->queue = new_queue;
    this->queue_size = size;
    this->front = 0;
    this->back = index;
}

void SeriesWork::push_front(SubTask *task) {
    this->mutex.lock();
    if (--this->front == -1) { this->front = this->queue_size - 1; }

    task->set_pointer(this);
    this->queue[this->front] = task;
    if (this->front == this->back) { this->expand_queue(); } // 队列满, 扩容

    this->mutex.unlock();
}

void SeriesWork::push_back(SubTask *task) {
    this->mutex.lock();
    task->set_pointer(this);
    this->queue[this->back++] = task;
    if (this->back == this->queue_size) { this->back = 0; }

    if (this->front == this->back) { this->expand_queue(); }

    this->mutex.unlock();
}

SubTask *SeriesWork::pop() {
    SubTask *task = this->pop_task();

    if (!this->canceled) { return task; } // 直接返回该任务, 由调用者执行

    // this->canceled == true, 说明该串行任务流已经被取消
    while (task) {
        delete task; // 立即销毁当前取出的任务
        task = this->pop_task(); // 继续获取下一个任务
    }

    return nullptr; // 返回空指针，表示没有需要执行的任务
}

// 从串行工作流中取出下一个待执行的任务, 并在所有任务完成后触发清理工作
SubTask *SeriesWork::pop_task() {
    SubTask *task;

    this->mutex.lock();
    if (this->front != this->back) {
        // 第一步：从环形队列中获取常规任务
        task = this->queue[this->front++];
        if (this->front == this->queue_size) { this->front = 0; }
    } else {
        // 第二步：队列为空后，才取出特殊的 last 任务
        task = this->last;
        this->last = nullptr;
    }
    this->mutex.unlock();

    // 当 task为 nullptr（即队列和 last都为空）时, 整个任务流已经完成, 执行用户回调
    if (!task) {
        this->finished = true;

        if (this->callback) { this->callback(this); }

        // 如果该系列是某个 ParallelWork 的一部分(in_parallel为真), 则其生命周期由并行任务管理;
        // 否则，系列会自我销毁(delete this)
        if (!this->in_parallel) { delete this; }
    }

    return task;
}

ParallelWork::ParallelWork(parallel_callback_t &&cb) :
    ParallelTask(new SubTask *[2 * 4], 0), // 初始化基类. 这里SubTask数组的长度是 2 * 任务容量(因为前半部分给subtasks用, 后半部分给all_series用)
    callback(std::move(cb)) // 移动语义接管回调函数
{
    this->buf_size = 4; // 设置缓冲区基础大小
    // 让 all_series 和 subtasks 共享同一块动态分配的内存
    // subtasks 数组的前半部分(0-3索引)用于存储子任务指针, 后半部分(4-7索引)则“借用”来存储 SeriesWork 指针
    this->all_series = reinterpret_cast<SeriesWork **>(&this->subtasks[this->buf_size]);
    this->context = nullptr; // 初始化用户上下文
}

ParallelWork::ParallelWork(SeriesWork *const all_series[], size_t n, parallel_callback_t &&cb) :
    ParallelTask(new SubTask *[2 * (n > 4 ? n : 4)], n), callback(std::move(cb)) {
    size_t i;

    this->buf_size = (n > 4 ? n : 4);
    this->all_series = reinterpret_cast<SeriesWork **>(&this->subtasks[this->buf_size]);
    for (i = 0; i < n; i++) {
        assert(!all_series[i]->in_parallel);
        all_series[i]->in_parallel = this;
        this->all_series[i] = all_series[i];
        this->subtasks[i] = all_series[i]->first;
    }

    this->context = nullptr;
}

// 扩展任务缓冲区
void ParallelWork::expand_buf() {
    SubTask **buf;
    size_t size;

    this->buf_size *= 2;
    buf = new SubTask *[2 * this->buf_size];
    size = this->subtasks_nr * sizeof(void *); // size基于实际元素数量计算, 而非总容量, 避免拷贝未使用的空间
    memcpy(buf, this->subtasks, size);
    memcpy(buf + this->buf_size, this->all_series, size); // 将原有的 all_series数组拷贝到新内存的后半部分

    // 释放原有数据
    delete []this->subtasks;
    // 更新指针
    this->subtasks = buf;
    this->all_series = reinterpret_cast<SeriesWork **>(&buf[this->buf_size]);
}

void ParallelWork::add_series(SeriesWork *series) {
    // 缓冲区满, 扩容
    if (this->subtasks_nr == this->buf_size) { this->expand_buf(); }

    // 确保待添加的系列当前不属于任何并行流
    assert(!series->in_parallel);
    series->in_parallel = this;
    this->all_series[this->subtasks_nr] = series;
    this->subtasks[this->subtasks_nr] = series->first;
    this->subtasks_nr++;
}

SubTask *ParallelWork::done() {
    // 找到当前ParallelWork对象所属的父级SeriesWork
    SeriesWork *series = series_of(this);

    // 如果用户设置了并行流完成时的回调函数（parallel_callback_t），此时会执行它
    if (this->callback) { this->callback(this); }

    // 它遍历all_series数组, 删除所有内部的SeriesWork对象
    size_t i;
    for (i = 0; i < this->subtasks_nr; i++) { delete this->all_series[i]; }

    this->subtasks_nr = 0;
    delete this;
    // 实现流式处理的关键一步, 调用父级系列的pop()方法, 获取并返回该系列中的下一个任务
    return series->pop();
}

ParallelWork::~ParallelWork() {
    size_t i;

    // 销毁所有子任务
    for (i = 0; i < this->subtasks_nr; i++) {
        this->all_series[i]->in_parallel = nullptr; // 解除关联
        this->all_series[i]->dismiss_recursive(); // 递归地销毁该任务流中所有尚未执行的任务
    }

    delete []this->subtasks;
}