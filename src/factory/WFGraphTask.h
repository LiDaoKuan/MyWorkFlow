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

#ifndef MYWORKFLOW_WFGRAPHTASK_H
#define MYWORKFLOW_WFGRAPHTASK_H

#include <vector>
#include <utility>
#include <functional>

#include "WFGraphTask.h"
#include "Workflow.h"
#include "WFTask.h"

// 用于构建复杂依赖关系任务图. 通过精巧的计数器机制和前驱后继关系管理, 实现了有向无环图(DAG)结构的任务流调度
class WFGraphNode : public WFCounterTask {
public:
    // 建立"当前节点 -> 目标节点"的依赖关系. 使 node 成为当前节点的后继, 并递增 node 的计数器
    void precede(WFGraphNode &node) {
        ++node.value; // 目标节点的依赖数+1
        this->successors.push_back(&node); // 将目标节点加入后继列表
    }

    // 建立"目标节点 -> 当前节点"的依赖关系. 是 precede() 的逆向操作, 用于更直观的链式调用
    void succeed(WFGraphNode &node) {
        node.precede(*this);
    }

protected:
    // 图节点完成时的核心处理(虚函数).负责递减后继节点的计数器, 并在计数器归零时触发后继任务的调度
    SubTask *done() override;

protected:
    std::vector<WFGraphNode *> successors; // 存储所有直接后继节点. 定义了当前节点执行完成后, 哪些节点有资格被激活

protected:
    WFGraphNode() : WFCounterTask(0, nullptr) {}
    ~WFGraphNode() override;
    // protected属性的构造和析构函数. 确保 WFGraphNode 只能被其友元类(如 WFGraphTask)或派生类创建和管理
    friend class WFGraphTask;
};

/**用于构建声明式DAG(有向无环图)工作流的语法糖
 * node1 --> node2, 表示先执行 任务node1 再执行 任务node2.
 * node1 <-- node2, 表示先执行 任务node2 再执行 任务node1. */

static inline WFGraphNode &operator --(WFGraphNode &node, int) {
    return node;
}

static inline WFGraphNode &operator >(WFGraphNode &prec, WFGraphNode &succ) {
    prec.succeed(succ);
    return succ;
}

static inline WFGraphNode &operator <(WFGraphNode &succ, WFGraphNode &prec) {
    succ.succeed(prec);
    return prec;
}

static inline WFGraphNode &operator --(WFGraphNode &node) {
    return node;
}

// 有向无环图(DAG)工作流
class WFGraphTask : public WFGenericTask {
public:
    // 将单个任务（SubTask*）封装为DAG图中的一个节点
    WFGraphNode &create_graph_node(SubTask *task);

    void set_callback(std::function<void(WFGraphTask *)> cb) { this->callback = std::move(cb); }

protected:
    // 任务调度入口. 被框架调用, 启动整个图任务的执行
    void dispatch() override;
    // 在所有节点执行完毕后触发用户回调, 并进行资源清理
    SubTask *done() override;

protected:
    ParallelWork *parallel_work; // 内部并行工作流指针. 用于实际执行和管理图中的所有任务节点
    std::function<void(WFGraphTask *)> callback; // 图任务完成时的回调函数. 在整个DAG的所有节点都执行完毕后被调用

public:
    explicit WFGraphTask(std::function<void (WFGraphTask *)> &&cb) : callback(std::move(cb)) {
        this->parallel_work = Workflow::create_parallel_work(nullptr); // 常见空的并行任务(没有任何子任务), 并设置并行任务的回调函数为空
    }

protected:
    ~WFGraphTask() override;
};

#endif //MYWORKFLOW_WFGRAPHTASK_H