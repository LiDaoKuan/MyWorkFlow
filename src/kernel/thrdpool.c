//
// Created by ldk on 10/7/25.
//

#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include "msgqueue.h"
#include "thrdpool.h"

struct __thrdpool {
    msgqueue_t *msgqueue;
    size_t nthreads;
    size_t stacksize; // 线程的调用栈的大小
    pthread_t tid;
    pthread_mutex_t mutex; // 控制不同线程对公共变量(msgqueue, nthreads, stacksize, tid...)的修改
    pthread_key_t key;
    pthread_cond_t *terminate;
};

struct __thrdpool_task_entry {
    void *link;
    struct thrdpool_task task;
};

static pthread_t __zero_tid;

// 实现线程优雅退出和链式等待机制
static void __thrdpool_exit_routine(void *_pool) {
    thrdpool_t *pool = (thrdpool_t *)_pool;
    pthread_t tid;
    pthread_mutex_lock(&pool->mutex);
    tid = pool->tid; // 取出当前线程池中记录的线程ID. 这个ID代表之前退出的那个线程. 如果是第一个退出的线程, 这里取到的是初始值__zero_tid(全0)
    pool->tid = pthread_self(); // 将当前线程自己的ID设置到线程池中. 这样, 下一个要退出的线程就会拿到当前线程的ID, 并负责等待当前线程结束
    // 减少活跃线程数, 如果这是最后一个退出的线程(nthreads == 0)并且终止条件变量terminate已设置, 就发送信号通知等待者(通常是调用thrdpool_destroy的线程)
    if (--pool->nthreads == 0 && pool->terminate) {
        pthread_cond_signal(pool->terminate);
    }
    pthread_mutex_unlock(&pool->mutex);
    // 检查取出的tid是否等于__zero_tid, 如果不等于, 说明当前线程需要等待前一个退出的线程（tid）真正结束
    // 如果等于, 说明当前线程是第一个退出的线程, 无需等待任何人
    if (!pthread_equal(tid, __zero_tid)) {
        pthread_join(tid, NULL);
    }
    pthread_exit(NULL);
}

static void *__thrdpool_routine(void *arg) {
    thrdpool_t *pool = (thrdpool_t *)arg;
    // ReSharper disable once CppJoinDeclarationAndAssignment
    struct __thrdpool_task_entry *entry;
    // ReSharper disable once CppJoinDeclarationAndAssignment
    void (*task_routine)(void *);
    // ReSharper disable once CppJoinDeclarationAndAssignment
    void *task_context;
    pthread_setspecific(pool->key, pool); // 将线程池指针pool与特定的键pool->key关联起来
    while (!pool->terminate) {
        // 获取消息
        entry = (struct __thrdpool_task_entry *)msgqueue_get(pool->msgqueue);
        if (!entry) { break; } // entry为空, 说明没获取到消息
        task_routine = entry->task.routine; // 提取出任务要执行的函数指针
        task_context = entry->task.context; // 获取任务的上下文数据
        free(entry); // 调用任务函数前, 先释放entry本身的内存, 防止任务执行过长导致内存延迟释放
        task_routine(task_context); // 执行任务
        if (pool->nthreads == 0) {
            // pool->nthreads == 0, 说明线程池已被销毁, 并且当前线程是池中最后一个活跃的线程
            // 当前线程需要负责释放线程池结构体. 其余相关数据的清理工作已经在销毁函数中完成.
            free(pool);
            return NULL;
        }
    }
    __thrdpool_exit_routine(pool); // 链式等待退出
    return NULL;
}

/* 终止线程池 */
static void __thrdpool_terminate(const int in_pool, thrdpool_t *pool) {
    pthread_cond_t term = PTHREAD_COND_INITIALIZER; // 创建线程间通知机制，并立即加锁确保后续操作原子性
    pthread_mutex_lock(&pool->mutex);
    msgqueue_set_nonblock(pool->msgqueue); // 设置消息队列为非阻塞模式, 使工作线程的msgqueue_get返回NULL, 从而促使它们主动退出
    pool->terminate = &term; // 将内部终止条件变量指向本地变量，为后续等待所有线程退出做准备
    if (in_pool) {
        // 若调用者自身是池内线程, 则分离自己并减少计数, 避免等待自己结束导致死锁
        pthread_detach(pthread_self());
        pool->nthreads--;
    }
    // 等待所有线程退出
    while (pool->nthreads > 0) {
        pthread_cond_wait(&term, &pool->mutex);
    }
    pthread_mutex_unlock(&pool->mutex);
    // 等待最后一个退出线程的结束
    if (!pthread_equal(pool->tid, __zero_tid)) {
        pthread_join(pool->tid, NULL);
    }
    pthread_cond_destroy(&term);
}

/* 为线程池pool创建最多nthreads个线程 */
static int __thrdpool_create_threads(size_t nthreads, thrdpool_t *pool) {
    pthread_attr_t attr;
    pthread_t tid;
    int ret;
    // 初始化一个线程属性对象attr. 这是配置线程特性(如栈大小、调度策略等)的标准第一步
    ret = pthread_attr_init(&attr);
    if (ret == 0) {
        if (pool->stacksize) {
            // 如果创建线程池时指定了stacksize(非零),则通过此调用设置线程的栈大小.
            // 这为需要较大栈空间的任务提供了灵活性. 如果未指定，则使用系统默认值
            ret = pthread_attr_setstacksize(&attr, pool->stacksize);
        }
        if (ret == 0) {
            // 加锁, 因为要修改nthreads
            pthread_mutex_lock(&pool->mutex);
            // 创建线程, 直到线程数量足够
            while (pool->nthreads < nthreads) {
                /**tid: pthread_t类型
                 * attr: 线程属性
                 * __thrdpool_routine: 线程启动时执行的函数
                 * pool: 传递给__thrdpool_routine的参数 */
                ret = pthread_create(&tid, &attr, __thrdpool_routine, pool);
                if (ret == 0) {
                    pool->nthreads++;
                } else { break; }
            }
            pthread_mutex_unlock(&pool->mutex);
        }

        pthread_attr_destroy(&attr); // 无论创建成功与否, 都需要销毁线程属性对象attr以释放相关资源
        if (ret == 0) { return 0; }

        // 如果因为错误导致未能创建足够线程(例如只创建了3个, 但目标nthreads是5), 则调用__thrdpool_terminate(0, pool)
        __thrdpool_terminate(0, pool);
    }

    errno = ret;
    return -1;
}

/* 创建线程池. 最多有nthreads个线程, 每个线程的栈大小为stacksize */
thrdpool_t *thrdpool_create(size_t nthreads, size_t stacksize) {
    thrdpool_t *pool = (thrdpool_t *)malloc(sizeof(thrdpool_t));
    if (!pool) { return NULL; }

    pool->msgqueue = msgqueue_create(0, 0); // 创建消息队列
    if (pool->msgqueue) {
        int ret = pthread_mutex_init(&pool->mutex, NULL); // 初始化互斥锁
        if (ret == 0) {
            ret = pthread_key_create(&pool->key, NULL); // 创建TSD
            if (ret == 0) {
                pool->stacksize = stacksize;
                pool->nthreads = 0; // 初始化线程数量为0
                pool->tid = __zero_tid;
                pool->terminate = NULL;
                // 为线程池创建线程
                if (__thrdpool_create_threads(nthreads, pool) >= 0) { return pool; }
                // 如果线程TSD创建成功但后续失败，需删除TSD
                pthread_key_delete(pool->key);
            }
            // 如果互斥锁初始化成功但后续失败，需销毁互斥锁
            pthread_mutex_destroy(&pool->mutex);
        }
        errno = ret;
        // 如果消息队列创建成功但后续失败，需销毁
        msgqueue_destroy(pool->msgqueue);
    }
    // 创建失败, 释放空间, 返回NULL
    free(pool);
    return NULL;
}

/* 将任务task放入buf中, 然后添加到消息队列 */
void __thrdpool_schedule(const struct thrdpool_task *task, void *buf, thrdpool_t *pool) {
    ((struct __thrdpool_task_entry *)buf)->task = *task;
    msgqueue_put(buf, pool->msgqueue);
}

/* 向线程池中添加任务task */
int thrdpool_schedule(const struct thrdpool_task *task, thrdpool_t *pool) {
    void *buf = malloc(sizeof(struct __thrdpool_task_entry)); // 分配空间, 用于存储任务内容
    if (buf) {
        // 分配成功, 将任务加入消息队列
        __thrdpool_schedule(task, buf, pool);
        return 0;
    }
    return -1;
}

/* 判断调用者线程在不在线程池中 */
int thrdpool_in_pool(thrdpool_t *pool) {
    return pthread_getspecific(pool->key) == pool;
}

// 增加线程
int thrdpool_increase(thrdpool_t *pool) {
    pthread_attr_t attr;
    pthread_t tid;

    int ret = pthread_attr_init(&attr);
    if (ret == 0) {
        if (pool->stacksize) { ret = pthread_attr_setstacksize(&attr, pool->stacksize); }

        if (ret == 0) {
            pthread_mutex_lock(&pool->mutex);
            ret = pthread_create(&tid, &attr, __thrdpool_routine, pool);
            if (ret == 0) { pool->nthreads++; }

            pthread_mutex_unlock(&pool->mutex);
        }

        pthread_attr_destroy(&attr);
        if (ret == 0) return 0;
    }

    errno = ret;
    return -1;
}

// 减少线程
int thrdpool_decrease(thrdpool_t *pool) {
    void *buf = malloc(sizeof(struct __thrdpool_task_entry));
    if (buf) {
        struct __thrdpool_task_entry *entry = (struct __thrdpool_task_entry *)buf;
        entry->task.routine = __thrdpool_exit_routine;
        entry->task.context = pool;
        msgqueue_put_head(entry, pool->msgqueue);
        return 0;
    }
    return -1;
}

/* 终止线程池 */
void thrdpool_exit(thrdpool_t *pool) {
    if (thrdpool_in_pool(pool)) { __thrdpool_exit_routine(pool); }
}

/* 销毁线程池(释放资源) */
void thrdpool_destroy(void (*pending)(const struct thrdpool_task *), thrdpool_t *pool) {
    const int in_pool = thrdpool_in_pool(pool);
    // ReSharper disable once CppJoinDeclarationAndAssignment
    struct __thrdpool_task_entry *entry;
    // 关闭其他线程
    __thrdpool_terminate(in_pool, pool);
    // 处理未完成任务
    while (1) {
        entry = (struct __thrdpool_task_entry *)msgqueue_get(pool->msgqueue);
        if (!entry) { break; }

        if (pending && entry->task.routine != __thrdpool_exit_routine) { pending(&entry->task); }

        free(entry);
    }
    // 资源清理
    pthread_key_delete(pool->key);
    pthread_mutex_destroy(&pool->mutex);
    msgqueue_destroy(pool->msgqueue);
    if (!in_pool) { free(pool); }
}