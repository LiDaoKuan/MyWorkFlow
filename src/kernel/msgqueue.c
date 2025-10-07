//
// Created by ldk on 10/6/25.
//

#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include "msgqueue.h"

struct __msgqueue {
    size_t msg_max; // 生产者队列（put队列）的最大消息数量
    size_t msg_cnt; // 生产者队列中的当前消息数量
    int linkoff; // 链接偏移量. 用于在不侵入消息体本身的情况下，将其链入队列，是实现零拷贝的关键
    int nonblock; // 为0时, 可能在队列满/空时阻塞线程; 为1时, 队列操作非阻塞; 只有在线程池准备退出时, 才会设置消息队列非阻塞
    void *head1; // 两个链表的头指针，是 get_head和 put_head指向的物理基础
    void *head2;
    void **get_head; // 消费者队列头指针: 指向head1, 消费者从此队列取消息
    void **put_head; // 生产者队列头指针: 指向head2, 生产者向此队列添加消息
    void **put_tail; // 生产者队列尾指针: 指向生产者队列的尾部，用于快速实现O(1)时间复杂度的入队操作
    pthread_mutex_t get_mutex; // 保护消费者队列（get_head）的互斥访问，保证多个消费者线程安全
    pthread_mutex_t put_mutex; // 保护生产者队列（put_head, put_tail, msg_cnt）的互斥访问
    pthread_cond_t get_cond; // 消费者条件变量: 当消费者队列为空时，消费者线程在此等待被唤醒
    pthread_cond_t put_cond; // 生产者条件变量: 当生产者队列满时，生产者线程在此等待被唤醒
};


void msgqueue_set_nonblock(msgqueue_t *queue) {
    queue->nonblock = 1;
    pthread_mutex_lock(&queue->put_mutex);
    // 唤醒可能等待的消费者. 因为模式切换后, 即使队列为空, 消费者也不应再阻塞等待
    pthread_cond_signal(&queue->get_cond);
    // 唤醒所有可能等待的生产者. 当队列从满状态切换到非阻塞模式时，所有因队列满而阻塞的生产者都需要被唤醒，以便他们可以重新尝试入队操作或处理非阻塞的返回逻辑
    pthread_cond_broadcast(&queue->put_cond);
    pthread_mutex_unlock(&queue->put_mutex);
}

void msgqueue_set_block(msgqueue_t *queue) {
    queue->nonblock = 0;
}

// 生产者生产消息
void msgqueue_put(void *msg, msgqueue_t *queue) {
    // 找到消息体(msg)中用于连接下一个消息的指针的地址
    void **link = (void **)((char *)msg + queue->linkoff);
    *link = NULL; // 将消息的链接指针设置为 NULL，表明当前消息是链表中的最后一个节点
    pthread_mutex_lock(&queue->put_mutex);
    // 如果队列已满或者将满, 并且队列处于阻塞模式, 则释放锁并且等待信号量.
    // 如果队列已满或者将满, 但是队列处于非阻塞模式, 则不进入循环, 直接执行后面的插入操作？？？？？
    while (queue->msg_cnt > queue->msg_max - 1 && !queue->nonblock) { pthread_cond_wait(&queue->put_cond, &queue->put_mutex); }
    // 执行插入操作
    *queue->put_tail = link;
    queue->put_tail = link;
    queue->msg_cnt++;
    pthread_mutex_unlock(&queue->put_mutex);
    pthread_cond_signal(&queue->get_cond);
}

// 生产者生产高优先级消息, 放入生产者消息队列头部(或者直接放入消费者消息队列)
void msgqueue_put_head(void *msg, msgqueue_t *queue) {
    void **link = (void **)((char *)msg + queue->linkoff);
    pthread_mutex_lock(&queue->put_mutex);
    while (*queue->get_head) {
        // 如果消费者消息队列不为空, 说明有消息正在等待被消费或有消费者可能正在操作
        // 尝试获取消费者消息队列锁, 该函数是非阻塞的, 获取不到锁立即返回
        if (pthread_mutex_trylock(&queue->get_mutex) == 0) {
            // 如果获取到了get_mutex, 则应该立即释放put_mutex, 防止持有两把锁导致复杂度和死锁风险
            pthread_mutex_unlock(&queue->put_mutex);
            // 将新消息直接放在了消费者即将获取的下一个位置
            *link = *queue->get_head;
            *queue->get_head = link;
            pthread_mutex_unlock(&queue->get_mutex); // 释放消费者消息队列锁, 然后return
            return;
        }
    }
    // 插入到生产者消息队列
    while (queue->msg_cnt > queue->msg_max - 1 && !queue->nonblock) { pthread_cond_wait(&queue->put_cond, &queue->put_mutex); }
    // 将新节点插入到生产者消息队列的头部
    *link = *queue->put_head; // 令该消息的next字段指针指向生产者消息队列的头部
    if (*link == NULL) { queue->put_tail = link; } // 原生产者消息队列为空
    *queue->put_head = link; // 更新queue中生产者消息队列的头部
    queue->msg_cnt++; // 消息数量+1
    pthread_mutex_unlock(&queue->put_mutex); // 解锁
    pthread_cond_signal(&queue->get_cond); // 通知一个消费者
}

/**交换生产者和消费者队列, 巧妙地减少了锁竞争,
 *
 * 该函数只能在消费者消息队列为空时调用 */
static size_t __msgqueue_swap(msgqueue_t *queue) {
    void **get_head = queue->get_head; // 获取消费者消息队列头

    pthread_mutex_lock(&queue->put_mutex);
    /* 只要当前生产者队列(put队列)中的消息数量(msg_cnt)为0(空队列)并且队列处于阻塞模式(nonblock为0)，
     * 当前线程就会在get_cond条件变量上等待 */
    while (queue->msg_cnt == 0 && !queue->nonblock) {
        /* 当有生产者线程通过msgqueue_put放入新消息时, 它会调用pthread_cond_signal(&queue->get_cond),
         * 这会唤醒一个在此条件变量上等待的消费者线程. 被唤醒的线程会重新检查循环条件,
         * 如果msg_cnt大于0, 就会退出循环继续执行 */
        pthread_cond_wait(&queue->get_cond, &queue->put_mutex);
    }
    // ReSharper disable once CppLocalVariableMayBeConst
    size_t cnt = queue->msg_cnt;
    if (cnt > queue->msg_max - 1) {
        /**反向流量控制机制
         * 如果put队列中的消息数量超过了设定的容量阈值, 说明在交换之前队列已满, 可能有生产者线程因为队列满而在put_cond上等待.
         * 此时应使用pthread_cond_broadcast唤醒所有等待的生产者线程. 如果只唤醒一个, 其他生产者可能无法及时感知到队列已空闲 */
        pthread_cond_broadcast(&queue->put_cond);
    }
    // 交换消费者消息队列和生产者消息队列
    queue->get_head = queue->put_head;
    queue->put_head = get_head;
    queue->put_tail = get_head;
    queue->msg_cnt = 0; // 生产者消息队列消息数量置为0
    pthread_mutex_unlock(&queue->put_mutex);
    return cnt;
}

/* 消费者消费消息 */
void *msgqueue_get(msgqueue_t *queue) {
    void *msg;

    pthread_mutex_lock(&queue->get_mutex);
    // 先检查消费者消息队列是否为空
    // 如果为空, 则交换生产者消息队列
    if (*queue->get_head || __msgqueue_swap(queue) > 0) {
        msg = (char *)*queue->get_head - queue->linkoff; // 获取消息
        *queue->get_head = *(void **)*queue->get_head; // 更新队列头
    } else {
        // 两个队列都为空, 没有消息
        msg = NULL;
    }

    pthread_mutex_unlock(&queue->get_mutex);
    return msg;
}

/* 创建消息队列 */
msgqueue_t *msgqueue_create(const size_t max_len, const int linkoff) {
    msgqueue_t *queue = (msgqueue_t *)malloc(sizeof(msgqueue_t));

    if (!queue) { return nullptr; }

    int ret = pthread_mutex_init(&queue->get_mutex, nullptr); // 初始化消费者队列的互斥锁
    if (ret == 0) {
        ret = pthread_mutex_init(&queue->put_mutex, nullptr); // 初始化生产者队列的互斥锁
        if (ret == 0) {
            ret = pthread_cond_init(&queue->get_cond, nullptr); // 初始化消费者条件变量
            if (ret == 0) {
                ret = pthread_cond_init(&queue->put_cond, nullptr); // 初始化生产者条件变量
                if (ret == 0) {
                    queue->msg_max = max_len;
                    queue->linkoff = linkoff;
                    queue->head1 = NULL;
                    queue->head2 = NULL;
                    queue->get_head = &queue->head1;
                    queue->put_head = &queue->head2;
                    queue->put_tail = &queue->head2;
                    queue->msg_cnt = 0;
                    queue->nonblock = 0; // 默认阻塞
                    return queue;
                }
                // 如果初始化失败 ret==0, 销毁上一个创建成功的锁(本次互斥锁创建失败, 所以不需要销毁, 但是需要销毁上一个创建成功的互斥锁)
                pthread_cond_destroy(&queue->get_cond);
            }
            pthread_mutex_destroy(&queue->put_mutex);
        }
        pthread_mutex_destroy(&queue->get_mutex);
    }

    errno = ret;
    free(queue);
    return nullptr;
}

/* 销毁消息队列 */
void msgqueue_destroy(msgqueue_t *queue) {
    pthread_cond_destroy(&queue->put_cond);
    pthread_cond_destroy(&queue->get_cond);
    pthread_mutex_destroy(&queue->put_mutex);
    pthread_mutex_destroy(&queue->get_mutex);
    free(queue);
}