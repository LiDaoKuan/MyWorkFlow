//
// Created by ldk on 10/13/25.
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

#include <cerrno>
#include <cstdlib>
#include <pthread.h>
#include "list.h"
#include "threadpool.h"
#include "Executor.h"

struct ExecSessionEntry {
    list_head list;
    ExecSession *session;
    thrdpool_t *thrdpool;
};

// 初始化队列
int ExecQueue::init() {
    const int ret = pthread_mutex_init(&this->mutex, nullptr);
    if (ret == 0) {
        INIT_LIST_HEAD(&this->session_list);
        return 0;
    }
    errno = ret;
    return -1;
}

// 销毁队列
void ExecQueue::deinit() {
    pthread_mutex_destroy(&this->mutex);
}

// 创建含有nthreads个线程的线程池
int Executor::init(const size_t nthreads) {
    this->thrdpool = thrdpool_create(nthreads, 0);
    if (this->thrdpool) {
        return 0;
    }
    return -1;
}

// 销毁线程池
void Executor::deinit() {
    thrdpool_destroy(Executor::executor_cancel, this->thrdpool);
}

extern "C" void __thrdpool_schedule(const struct thrdpool_task *, void *, thrdpool_t *);

// 任务调度执行的核心函数
void Executor::executor_thread_routine(void *context) {
    auto *queue = static_cast<ExecQueue *>(context);
    // 取出队列中第一个节点所属的ExecSessionEntry的地址
    ExecSessionEntry *entry = list_entry(queue->session_list.next, struct ExecSessionEntry, list);
    // 队列上锁
    pthread_mutex_lock(&queue->mutex);
    list_del(&entry->list); // 删除第一个元素
    const int is_empty = list_is_empty(&queue->session_list); // 判断队列是否为空
    pthread_mutex_unlock(&queue->mutex);

    ExecSession *session = entry->session;
    if (!is_empty) {
        // 队列不为空,
        const thrdpool_task task = {
            .routine = Executor::executor_thread_routine, // 回调函数是这个函数本身！
            .context = queue
        };
        __thrdpool_schedule(&task, entry, entry->thrdpool); // 线程池会接管entry的内存, 在使用完成后释放
    } else { free(entry); } // 如果队列已空, 则当前线程直接调用free(entry)释放内存

    // 执行具体任务. 通常由具体子类实现该函数
    session->execute();
    // 无论execute()执行成功与否, 都会调用session->handle()方法. 参数 ES_STATE_FINISHED 表示任务正常完成
    session->handle(ES_STATE_FINISHED, 0);
}

// 取消所有未完成任务
void Executor::executor_cancel(const thrdpool_task *task) {
    auto *queue = static_cast<ExecQueue *>(task->context);
    ExecSessionEntry *entry;
    list_head *pos, *tmp;
    ExecSession *session;
    // 遍历任务队列
    list_for_each_safe(pos, tmp, &queue->session_list) {
        entry = list_entry(pos, struct ExecSessionEntry, list); // 获取pos所在的ExecSessionEntry
        list_del(pos); // 从链表中移除节点
        session = entry->session;
        free(entry); // 释放节点内存

        session->handle(ES_STATE_CANCELED, 0); // 调用回调通知session这个任务被取消
    }
}

// 将任务session提交到任务队列queue中
int Executor::request(ExecSession *session, ExecQueue *queue) {
    session->queue = queue;
    auto *entry = static_cast<ExecSessionEntry *>(malloc(sizeof(ExecSessionEntry)));
    if (entry) {
        entry->session = session; // 绑定session
        entry->thrdpool = this->thrdpool;
        pthread_mutex_lock(&queue->mutex);
        list_add_tail(&entry->list, &queue->session_list); // 将entry插入队列尾部
        if (queue->session_list.next == &entry->list) {
            // 新加入的 entry是队列中的第一个任务(即链表在添加前为空). 此时需要主动启动执行循环
            const thrdpool_task task = {
                .routine = Executor::executor_thread_routine,
                .context = queue
            };
            if (thrdpool_schedule(&task, this->thrdpool) < 0) {
                // 调度失败, 清理刚刚加入的entry
                list_del(&entry->list);
                free(entry);
                entry = nullptr;
            }
        }
        pthread_mutex_unlock(&queue->mutex);
    }
    return -!entry;
    /**这段逻辑等同于:
     * if(entry==nullptr){
     *      return -1;
     * }
     * else{
     *      return 0;
     * } */
}

// 增加线程
int Executor::increase_thread() {
    return thrdpool_increase(this->thrdpool);
}

// 减少线程
int Executor::decrease_thread() {
    return thrdpool_decrease(this->thrdpool);
}