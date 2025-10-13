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

#ifndef MYWORKFLOW_EXECUTOR_H
#define MYWORKFLOW_EXECUTOR_H

#include <cstddef>
#include "list.h"

// 会话队列管理, 只允许友元类Executor操作, 其他类无法正常使用
class ExecQueue {
public:
    int init();
    void deinit();

private:
    list_head session_list{}; // 双向循环链表
    pthread_mutex_t mutex;

public:
    virtual ~ExecQueue() = default;
    friend class Executor;
};

#define ES_STATE_FINISHED	0
#define ES_STATE_ERROR		1
#define ES_STATE_CANCELED	2

// 主要负责业务逻辑
class ExecSession {
    // 这个类采用了 模板方法模式:
    // 框架固定流程:
    //      Workflow 的框架代码（如 Executor）负责整个任务的调度周期.
    //      它会先调用execute()方法执行任务, 无论其成功与否, 紧接着都会调用handle(int state, int error)方法. 这个顺序和时机由框架严格保证
    // 子类专注业务:
    //      作为开发者, 当你需要创建一个具体任务(如一个GoTask或网络请求)时, 只需继承ExecSession并实现这两个纯虚函数。
    //      在execute()中编写你的业务逻辑(例如, 两个数相加), 在handle()中编写处理结果的逻辑(例如, 打印结果或处理错误).
    //      你不需要关心任务是如何被线程池调度、如何被异步执行的
    // 实现了业务和框架的解耦
private:
    // 任务具体的业务逻辑
    virtual void execute() = 0;
    // 在任务执行后(无论成功失败)被调用, 用于状态通知和资源清理
    virtual void handle(int state, int error) = 0;

protected:
    // 供子类获取当前任务所归属的 ExecQueue
    ExecQueue *get_queue();

private:
    ExecQueue *queue{nullptr}; // 记录本任务由哪个 ExecQueue管理

public:
    virtual ~ExecSession() = default;
    friend class Executor;
};

// 管理底层线程池并调度异步任务的执行
class Executor {
public:
    int init(size_t nthreads);
    void deinit();
    int request(ExecSession *session, ExecQueue *queue);

    int increase_thread();
    int decrease_thread();

private:
    threadpool *thrdpool{nullptr}; // 线程池, 在init()函数中被初始化
    // 静态回调函数
    static void executor_thread_routine(void *context); // 线程池中工作线程的入口函数
    static void executor_cancel(const thrdpool_task *task); // 任务取消回调

public:
    virtual ~Executor() = default;
};

#endif //MYWORKFLOW_EXECUTOR_H