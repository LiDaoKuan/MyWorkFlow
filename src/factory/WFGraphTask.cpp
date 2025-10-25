//
// Created by ldk on 10/19/25.
//

/*
  Copyright (c) 2020 Sogou, Inc.

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

#include <vector>
#include "Workflow.h"
#include "WFGraphTask.h"

SubTask *WFGraphNode::done() {
    SeriesWork *series = series_of(this);

    if (!this->user_data) {
        // 首次完成: 初始化并标记, 但不销毁
        // 首次完成指: 任务完成后执行一次done(), 视为首次完成. 因为是第一次调用done(), 所以会进入if语句, 不会执行else语句中的delete
        this->value = 1;
        // 标记user_data为非空, 这样下次就不会再进入这个if分支了
        this->user_data = reinterpret_cast<void *>(1);
    } else {
        // 最终完成：自我销毁
        delete this;
    }
    // 继续执行下一个任务
    return series->pop();
}

WFGraphNode::~WFGraphNode() {
    if (!this->user_data) {
        if (series_of(this)->is_canceled()) {
            for (auto node : this->successors) {
                series_of(node)->SeriesWork::cancel();
            }
        }
        for (auto node : this->successors) {
            node->WFCounterTask::count(); // 将所有直接后继节点的计数器-1
        }
    }
}

WFGraphNode &WFGraphTask::create_graph_node(SubTask *task) {
    auto *node = new WFGraphNode; // 创建图调度单元
    // 封装执行上下文. 将node本身作为串行工作流的第一个任务, 创建一个SeriesWork
    auto *series = Workflow::create_series_work(node, node, nullptr);

    // 将用户实际的业务任务(如HTTP请求、计算函数)加入到该系列中, 排在 node 之后.
    // 这样, 业务任务 task 就成为图节点 node 的直接后继任务
    series->push_back(task);
    // 将封装好的串行工作流添加到 WFGraphTask 内部的 ParallelWork 中
    this->parallel_work->add_series(series);
    return *node;
}

void WFGraphTask::dispatch() {
    SeriesWork *series = series_of(this); // 获取所属的串行任务流
    // 图任务parallel_work第一次调用dispatch(), 进入if语句
    if (this->parallel_work) {
        /**先将图任务加入串行任务流头部, 再将parrllel_work加入串行任务流头部, 即:
         * 先执行 parallel_work, 再执行图任务自身
         * 这意味着框架会先并发执行图中的所有节点任务,
         * 待所有节点完成后，才执行WFGraphTask自身的done()方法进行收尾工作 */
        series->push_front(this); // 将图任务自身加入串行任务的前端
        series->push_front(this->parallel_work); // 将并行工作流加入串行任务的前端
        this->parallel_work = nullptr; // 置空, 确保parallel_work不会被错误地多次加入到同一个或多个系列中
    } else { this->state = WFT_STATE_SUCCESS; } // parallel_work第二次调用dispatch, 进入else分支, 标记已完成

    this->subtask_done();
}

SubTask *WFGraphTask::done() {
    SeriesWork *series = series_of(this);
    // 只有当任务状态为WFT_STATE_SUCCESS(成功)时, 才会执行回调函数并触发自我销毁.
    // 如果任务因错误、取消或其他原因终止(状态为 WFT_STATE_SYS_ERROR, WFT_STATE_ABORTED等),
    // 则不会执行回调, 也不会销毁对象. 这种设计允许在外部根据不同的状态进行不同的错误处理或资源回收
    if (this->state == WFT_STATE_SUCCESS) {
        if (this->callback) {
            this->callback(this);
        }
        delete this;
    }

    return series->pop(); // 取出下一个待执行的任务并返回
}

WFGraphTask::~WFGraphTask() {
    // 如果 parallel_work 为空, 说明该图任务要么从未被成功初始化, 要么其管理的并行工作流已经被转移或清理
    if (this->parallel_work) {
        size_t i;
        SeriesWork *series;
        for (i = 0; i < this->parallel_work->size(); i++) {
            //
            series = this->parallel_work->series_at(i);
            // 一个 SeriesWork 通常会有一个特殊的 last 任务(例如, 在服务器任务中, 这是一个负责回复客户端的任务)
            series->unset_last_task();

            /**为什么此处需要unset_last_task() ???
             * 如果不进行这一步, 当后续调用 parallel_work->dismiss() 时, ParallelWork会递归地销毁其包含的所有 SeriesWork.？？？
             * 如果某个 SeriesWork 仍然持有 last 任务, 它会试图在自身的析构函数中 delete 这个任务.
             * 然而, 这个 last 任务很可能同时也是一个 WFGraphNode, 而该节点的生命周期本应由图任务的整体调度逻辑(如依赖计数器)来管理.
             * 这种双重所有权的混淆会导致一个任务被删除两次, 引发未定义行为(通常是程序崩溃).
             * unset_last_task()就像一把安全锁，提前解除了这种潜在的危险关系 */
        }

        this->parallel_work->dismiss();
    }
}