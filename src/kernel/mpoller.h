//
// Created by ldk on 10/3/25.
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

#ifndef MYWORKFLOW_MPOLLER_H
#define MYWORKFLOW_MPOLLER_H

#include <stddef.h>
#include "poller.h"

typedef struct __mpoller mpoller_t;

#ifdef __cplusplus
extern "C" {
#endif

mpoller_t *mpoller_create(const struct poller_params *params, size_t nthreads);
int mpoller_start(const mpoller_t *mpoller);
void mpoller_set_callback(void (*callback)(struct poller_result *, void *), mpoller_t *mpoller);
void mpoller_stop(mpoller_t *mpoller);
void mpoller_destroy(mpoller_t *mpoller);

#ifdef __cplusplus
}
#endif

/* 多线程poller的管理器，承载所有线程上下文和共享资源 */
struct __mpoller {
    void **nodes_buf; // 所有线程共享的节点缓冲区. 与 struct __poller 的 nodes 指针指向同一块内存
    unsigned int nthreads; // poller线程的数量
    poller_t *poller[1]; //【关键】柔性数组，实际指向nthreads个poller实例
};

/* 以下函数的共同特点: 将I/O操作根据文件描述符进行哈希, 路由到特定的poller线程 */

static inline int mpoller_add(const struct poller_data *data, int timeout, mpoller_t *mpoller) {
    int index = (unsigned int)data->fd % mpoller->nthreads;
    /* 同一个文件描述符上的所有操作(ADD、DEL、MOD)都会被定向到同一个poller线程.
     * 这是实现线程安全的关键, 它保证了对于同一个连接的生命周期管理总是在同一个线程内顺序进行, 完全避免了竞态条件(Race Condition) */
    return poller_add(data, timeout, mpoller->poller[index]);
}

static inline int mpoller_del(const int fd, mpoller_t *mpoller) {
    int index = (unsigned int)fd % mpoller->nthreads;
    return poller_del(fd, mpoller->poller[index]);
}

static inline int mpoller_mod(const struct poller_data *data, int timeout, mpoller_t *mpoller) {
    int index = (unsigned int)data->fd % mpoller->nthreads;
    return poller_mod(data, timeout, mpoller->poller[index]);
}

static inline int mpoller_set_timeout(const int fd, const int timeout, mpoller_t *mpoller) {
    int index = (unsigned int)fd % mpoller->nthreads;
    return poller_set_timeout(fd, timeout, mpoller->poller[index]);
}

static inline int mpoller_add_timer(const struct timespec *value, void *context, void **timer, int *index, mpoller_t *mpoller) {
    static unsigned int n = 0;
    *index = n++ % mpoller->nthreads; // 轮询分配定时器任务. 因为定时器任务不和任何fd绑定, 轮询可以让定时任务均匀分配给所有线程
    return poller_add_timer(value, context, timer, mpoller->poller[*index]);
}

static inline int mpoller_del_timer(void *timer, int index, mpoller_t *mpoller) {
    return poller_del_timer(timer, mpoller->poller[index]);
}

#endif //MYWORKFLOW_MPOLLER_H