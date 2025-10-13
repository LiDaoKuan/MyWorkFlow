//
// Created by ldk on 9/28/25.
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

#include "SubTask.h"

void SubTask::subtask_done() {
    SubTask *cur = this;
    ParallelTask *parent = nullptr;
    while (true) {
        parent = cur->parent_; // 记录当前任务的父任务
        cur = cur->done(); // 此处是多态。
        // cur->done()返回下一个要执行的任务。如果不存在则返回nullptr
        if (cur) {
            cur->parent_ = parent; // 关键代码：保证父任务的指针能够正确传递下去
            cur->dispatch(); // 执行子任务。非阻塞？
        }
        // 没有下一个要执行的任务，并且父任务的指针不为nullptr
        // 说明该任务是某个并行任务组(Parallel)的一员。
        else if (parent) {
            // 完成了并行任务组中的某个子任务，令父任务的nleft-1
            // __sync_sub_and_fetch()是gcc内置的原子操作，返回操作后的值
            if (__sync_sub_and_fetch(&parent->nleft, 1) == 0) {
                // 所有子任务都已经完成
                cur = parent;
                continue; // 继续执行父任务
            }
        }
        /**找不到可以执行的任务。部分任务可能在并行执行
         * 可以break。当并行执行的任务完成后，又会回调subtask_done()函数，再次进入该循环 */
        break;
    }
}


void ParallelTask::dispatch() {
    // 计算subtasks数据右边界
    SubTask **end = this->subtasks + subtask_nr;
    // 遍历subtasks用的指针
    SubTask **p = this->subtasks;

    this->nleft = this->subtask_nr; // 确保开始之前nleft==subtask_nr
    // 只比较一次nleft，然后用循环将子任务全部处理完
    if (this->nleft != 0) {
        do {
            (*p)->parent_ = this; // p指向的SubTask的父任务为this
            (*p)->dispatch(); // 执行子任务（此处是多态）
        } while (++p != end); // 先++p，再比较p和end
    } else {
        this->subtask_done(); // 子任务全部完成。父任务执行善后处理
    }
}