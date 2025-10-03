//
// Created by ldk on 10/3/25.
//

#include <stddef.h>
#include <stdlib.h>
#include "poller.h"
#include "mpoller.h"

extern poller_t *__poller_create(void **, const struct poller_params *);
extern void __poller_destroy(poller_t *poller);

/* 根据传入的参数创建poller_t. 成功返回0, 失败返回-1 */
static int __mpoller_create(const struct poller_params *params, mpoller_t *mpoller) {
    void **nodes_buf = (void **)calloc(params->max_open_file, sizeof(void *));
    if (nodes_buf) {
        unsigned int i = 0;
        for (i = 0; i < mpoller->nthreads; ++i) {
            mpoller->poller[i] = __poller_create(nodes_buf, params);
            if (!mpoller->poller[i]) { break; }
        }
        if (i == mpoller->nthreads) {
            mpoller->nodes_buf = nodes_buf;
            return 0;
        }
        // i>0 但是 i!=mpoller->nthreads, 说明只创建了一部分.
        while (i > 0) {
            // 删除所有创建成功的poller_t
            __poller_destroy(mpoller->poller[--i]);
        }
        // 释放之前分配的内存
        free(nodes_buf);
    }
    return -1;
}

/* 创建mpoller和所有的poller */
mpoller_t *mpoller_create(const struct poller_params *params, size_t nthreads) {
    if (nthreads == 0) { nthreads = 1; }
    // offsetof(type, member): 获得成员member在 结构体/类type 里面的偏移量
    const size_t size = offsetof(mpoller_t, poller) + nthreads * sizeof(void *);
    mpoller_t *mpoller = (mpoller_t *)malloc(size);
    if (mpoller) {
        mpoller->nthreads = (unsigned int)nthreads;
        if (__mpoller_create(params, mpoller) >= 0) {
            // 创建成功
            return mpoller;
        }
        // 创建失败, 释放内存
        free(mpoller);
    }
    return NULL;
}

/* 创建并开启所有poller线程 */
int mpoller_start(const mpoller_t *mpoller) {
    unsigned int i = 0;
    for (i = 0; i < mpoller->nthreads; ++i) {
        if (poller_start(mpoller->poller[i]) < 0) {
            // 返回值=-1表示创建失败
            break;
        }
    }
    if (i == mpoller->nthreads) {
        // nthreads个线程都开启成功
        return 0;
    }
    // 部分线程开启失败. 停止所有已开启线程
    while (i > 0) { poller_stop(mpoller->poller[--i]); }
    return -1;
}

/* 设置所有poller的回调函数 */
void mpoller_set_callback(void (*callback)(struct poller_result *, void *), mpoller_t *mpoller) {
    unsigned int i;
    for (i = 0; i < mpoller->nthreads; ++i) { poller_set_callback(callback, mpoller->poller[i]); }
}

/* 停止所有poller线程 */
void mpoller_stop(mpoller_t *mpoller) {
    unsigned int i;
    for (i = 0; i < mpoller->nthreads; ++i) { poller_stop(mpoller->poller[i]); }
}

/* 回收所有poller线程以及mpoller的资源 */
void mpoller_destroy(mpoller_t *mpoller) {
    unsigned int i;

    for (i = 0; i < mpoller->nthreads; i++) { __poller_destroy(mpoller->poller[i]); }

    free(mpoller->nodes_buf);
    free(mpoller);
}