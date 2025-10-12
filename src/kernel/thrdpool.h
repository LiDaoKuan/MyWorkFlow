//
// Created by ldk on 10/7/25.
//

#ifndef MYWORKFLOW_THRDPOOL_H
#define MYWORKFLOW_THRDPOOL_H

#include <stddef.h>

typedef struct __thrdpool thrdpool_t;

struct thrdpool_task {
    void (*routine)(void *);
    void *context;
};

struct __thrdpool_task_entry {
    void *link;
    struct thrdpool_task task;
};

#ifdef __cplusplus
extern "C" {

#endif

thrdpool_t *thrdpool_create(size_t nthreads, size_t stacksize);
int thrdpool_schedule(const struct thrdpool_task *task, thrdpool_t *pool);
int thrdpool_in_pool(thrdpool_t *pool);
int thrdpool_increase(thrdpool_t *pool);
int thrdpool_decrease(thrdpool_t *pool);
void thrdpool_exit(thrdpool_t *pool);
void thrdpool_destroy(void (*pending)(const struct thrdpool_task *), thrdpool_t *pool);

#ifdef __cplusplus
}
#endif

#endif //MYWORKFLOW_THRDPOOL_H