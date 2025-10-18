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

#ifndef MYWORKFLOW_WORKFLOW_H
#define MYWORKFLOW_WORKFLOW_H

#include <cassert>
#include <cstddef>
#include <utility>
#include <functional>
#include <mutex>
#include "SubTask.h"

class SeriesWork;
class ParallelWork;

using series_callback_t = std::function<void(const SeriesWork *)>;
using parallel_callback_t = std::function<void(const ParallelWork *)>;

class Workflow {
public:
    static SeriesWork *create_series_work(SubTask *first, series_callback_t _callback);

    static void start_series_work(SubTask *first, series_callback_t _callback);

    static ParallelWork *create_parallel_work(parallel_callback_t _callback);

    static ParallelWork *create_parallel_work(SeriesWork *const all_series[], size_t n, parallel_callback_t _callback);

    static void start_parallel_work(SeriesWork *const all_series[], size_t n, parallel_callback_t _callback);

public:
    static SeriesWork *create_series_work(SubTask *first, SubTask *last, series_callback_t callback);

    static void start_series_work(SubTask *first, SubTask *last, series_callback_t callback);
};

// 管理串行任务流
class SeriesWork {
public:
    void start() {
        assert(!this->in_parallel);
        this->first->dispatch(); // 触发第一个任务的执行
    }

    // 用于任务流未启动时, 取消所有任务
    void dismiss() {
        assert(!this->in_parallel);
        this->dismiss_recursive();
    }

public:
    // 将新任务添加到队列末尾
    void push_back(SubTask *task);
    // 将新任务添加到队列头
    void push_front(SubTask *task);

    [[nodiscard]] void *get_content() const { return this->context; }
    void set_context(void *_context) { this->context = _context; }

    void set_callback(series_callback_t _callback) { this->callback = std::move(_callback); }

    /* Cancel a running series. Typically, called in the callback of a task
     * that belongs to the series. All subsequent tasks in the series will be
     * destroyed immediately and recursively (ParallelWork), without callback.
     * But the callback of this canceled series will still be called. */

    /**将 canceled 标志设为 true. 此后, 当pop()被调用时, 如果工作流已被取消,
     * 它会跳过所有剩余任务并将其删除, 但系列完成时的回调函数callback依然会被执行 */
    virtual void cancel() { this->canceled = true; }

    /* Parallel work's callback may check the cancellation state of each
     * sub-series, and cancel it's super-series recursively. */
    [[nodiscard]] bool is_canceled() const { return this->canceled; }

    /* 'false' until the time of callback. Mainly for sub-class. */
    [[nodiscard]] bool is_finished() const { return this->finished; }

public:
    virtual void *get_specific(const char *key) { return nullptr; }

    /* The following functions are intended for task implementations only. */
public:
    // 从内部队列中取出下一个任务并返回
    SubTask *pop();

    [[nodiscard]] SubTask *get_last_task() const { return this->last; }

    void set_last_task(SubTask *_last) {
        _last->set_pointer(this);
        this->last = _last;
    }

    void unset_last_task() { this->last = nullptr; }

    // 获取所属的并行任务
    [[nodiscard]] const ParallelTask *get_in_parallel() const { return this->in_parallel; }

protected:
    // 设置与并行任务的关联(主要供ParallelWork类内部使用)
    void set_in_parallel(const ParallelTask *task) { this->in_parallel = task; }

    // 用于递归地取消一个尚未启动的系列工作流及其所有子任务, 并释放相关资源. 它通常只在你不打算启动一个已创建的系列时调用
    void dismiss_recursive();

protected:
    void *context;
    series_callback_t callback;

private:
    SubTask *pop_task();
    // 当队列已满时, 此方法会被调用. 它会将当前队列的容量扩大一倍, 并将原有任务拷贝到新空间, 以支持动态扩容
    void expand_queue();

private:
    SubTask *buf[4]{nullptr}; // 初始的静态缓冲区, 避免小规模任务时的频繁内存分配
    SubTask *first; // 指向第一个要执行的任务, 是工作流的起点. 该任务不在队列中, 和队列独立分开管理
    SubTask *last; // 指向串行队列中最后一个任务？？？
    SubTask **queue; // 指向一个动态数组, 作为任务队列的核心存储
    int queue_size; // 队列容量
    int front; // 队首索引
    int back; // 队尾索引
    bool canceled; // 取消标志, 为true时会中止工作流并跳过后续所有任务
    bool finished; // 标记任务流是否完成？
    const ParallelTask *in_parallel; // 指向该任务流所属的并行任务流
    std::mutex mutex;

protected:
    SeriesWork(SubTask *first, series_callback_t &&callback);
    virtual ~SeriesWork();

    friend class ParallelWork;
    friend class Workflow;
};

static inline SeriesWork *series_of(const SubTask *task) {
    return static_cast<SeriesWork *>(task->get_pointer());
}

// 解引用运算符重载
static inline SeriesWork &operator*(const SubTask &task) {
    return *series_of(&task);
}

// 左移运算符重载（series << task）
static inline SeriesWork &operator<<(SeriesWork &series, SubTask *task) {
    series.push_back(task);
    return series;
}

inline SeriesWork *Workflow::create_series_work(SubTask *first, series_callback_t callback) {
    return new SeriesWork(first, std::move(callback));
}

inline void Workflow::start_series_work(SubTask *first, series_callback_t callback) {
    new SeriesWork(first, std::move(callback)); // 将任务first放入串行任务流里
    first->dispatch();
}

inline SeriesWork *Workflow::create_series_work(SubTask *first, SubTask *last, series_callback_t callback) {
    auto *series = new SeriesWork(first, std::move(callback));
    series->set_last_task(last);
    return series;
}

inline void Workflow::start_series_work(SubTask *first, SubTask *last, series_callback_t callback) {
    auto *series = new SeriesWork(first, std::move(callback));
    series->set_last_task(last);
    first->dispatch();
}

class ParallelWork : public ParallelTask {
public:
    // 启动并行工作流, 将其放入一个串行流中开始调度
    void start() {
        assert(!series_of(this));
        Workflow::start_series_work(this, nullptr);
    }

    // 取消整个并行工作流（包括所有子系列）并释放资源
    void dismiss() {
        assert(!series_of(this));
        delete this;
    }

    // 向并行流中添加一个新的串行流
    void add_series(SeriesWork *series);

    [[nodiscard]] void *get_context() const { return this->context; }
    void set_context(void *_context) { this->context = _context; }

    SeriesWork *series_at(size_t index) {
        if (index < this->subtasks_nr) {
            return this->all_series[index];
        } else { return nullptr; }
    }

    [[nodiscard]] const SeriesWork *series_at(size_t index) const {
        if (index < this->subtasks_nr) {
            return this->all_series[index];
        } else { return nullptr; }
    }

    // 重载下标运算符, 方便访问 (非const版本)
    SeriesWork &operator[](size_t index) {
        auto *seriesWork = this->series_at(index);
        if (seriesWork) {
            return *seriesWork;
        } else {
            assert(false);
        }
    }

    // 重载下标运算符, 方便访问 (const版本, const对象会调用该版本)
    const SeriesWork &operator[](size_t index) const {
        auto *seriesWork = this->series_at(index);
        if (seriesWork) {
            return *seriesWork;
        } else {
            assert(false);
        }
    }

    // 返回当前并行流中包含的并行任务流数量
    [[nodiscard]] size_t size() const { return this->subtasks_nr; }

public:
    void set_callback(parallel_callback_t _callback) {
        this->callback = std::move(_callback);
    }

protected:
    SubTask *done() override;

    void *context; // 用户自定义上下文数据，便于在回调中传递信息
    parallel_callback_t callback; // 整个并行工作流完成时执行的回调函数

private:
    void expand_buf();

private:
    size_t buf_size; // 任务流容量
    SeriesWork **all_series; // 存储所有并行任务流（SeriesWork）的元数据指针数组

protected:
    explicit ParallelWork(parallel_callback_t &&callback);
    ParallelWork(SeriesWork *const all_series[], size_t n, parallel_callback_t &&callback);
    ~ParallelWork() override;
    friend class Workflow;
};

inline ParallelWork *Workflow::create_parallel_work(parallel_callback_t callback) {
    return new ParallelWork(std::move(callback));
}

inline ParallelWork *Workflow::create_parallel_work(SeriesWork *const all_series[], size_t n, parallel_callback_t callback) {
    return new ParallelWork(all_series, n, std::move(callback));
}

// 快速创建并立即启动一个并行工作流
inline void Workflow::start_parallel_work(SeriesWork *const all_series[], size_t n, parallel_callback_t callback) {
    auto *p = new ParallelWork(all_series, n, std::move(callback));
    Workflow::start_series_work(p, nullptr); // 将并行任务封装入串行流
}

#endif //MYWORKFLOW_WORKFLOW_H