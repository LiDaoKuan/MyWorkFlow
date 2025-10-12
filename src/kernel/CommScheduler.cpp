//
// Created by ldk on 10/12/25.
//

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include "CommScheduler.h"

#include <algorithm>

// 原子地解锁 mutex 并使当前线程阻塞在 cond 条件变量上
#define PTHREAD_COND_TIMEDWAIT(cond, mutex, abstime) \
    ( (abstime) ? pthread_cond_timedwait(cond, mutex, abstime) : pthread_cond_wait(cond, mutex) )

// 根据传入的timeout返回一个timespec
static timespec get_abstime(const int timeout) {
    timespec ts = {};
    if (timeout < 0) {
        return ts;
    }
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout / 1000;
    ts.tv_nsec += timeout % 1000 * 1000000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_nsec -= 1000000000;
        ts.tv_sec += 1;
    }
    return ts;
}

// 初始化
int CommSchedTarget::init(const sockaddr *addr, socklen_t addrlen, int connect_timeout, int response_timeout, size_t max_connections) {
    if (max_connections == 0) {
        errno = EINVAL;
        return -1;
    }
    if (this->CommTarget::init(addr, addrlen, connect_timeout, response_timeout) >= 0) {
        int ret = pthread_mutex_init(&this->mutex, nullptr);
        if (ret == 0) {
            ret = pthread_cond_init(&this->cond, nullptr);
            if (ret == 0) {
                this->max_load = max_connections; // 最大负载(连接池容量上限)为最大连接数
                this->cur_load = 0;
                this->wait_cnt = 0;
                this->group = nullptr; // 所属调度组，初始为null
                return 0;
            }
            pthread_mutex_destroy(&this->mutex);
        }
        errno = ret;
        this->CommTarget::deinit();
    }
    return -1;
}

// 销毁
void CommSchedTarget::deinit() {
    pthread_cond_destroy(&this->cond);
    pthread_mutex_destroy(&this->mutex);
    this->CommTarget::deinit();
}

// 指定时间内获取连接
CommTarget *CommSchedTarget::acquire(int _wait_timeout) {
    pthread_mutex_t *_mutex = &this->mutex;
    int ret = 0;

    pthread_mutex_lock(_mutex); // 先锁住当前目标
    if (this->group) {
        // 如果存在组，则连接池的容量和调度决策需要放在组的全局视角下进行，因此需要将锁升级为范围更大的组锁.
        // 这确保了在检查负载和修改组内堆结构时，组的状态是一致的
        _mutex = &this->group->mutex; // 将操作锁升级为组锁
        pthread_mutex_lock(_mutex);
        pthread_mutex_unlock(&this->mutex); // 释放原本的目标锁
    }
    if (this->cur_load >= this->max_load) {
        if (_wait_timeout != 0) {
            timespec abstime = get_abstime(_wait_timeout);
            timespec *ts = &abstime;
            // 使用循环防止虚假唤醒
            do {
                this->wait_cnt++;
                ret = PTHREAD_COND_TIMEDWAIT(&this->cond, _mutex, ts);
                this->wait_cnt--;
            } while (this->cur_load >= this->max_load && ret == 0);
        } else {
            // _wait_timeout==0, 表示调用方不想等待, 此时应返回EAGAIN错误码, 告知调用方资源暂时不可用
            ret = EAGAIN;
        }
    }
    if (this->cur_load < this->max_load) {
        this->cur_load++; // 增加当前目标的负载
        if (this->group) {
            this->group->cur_load++; // 增加组的全局负载
            this->group->heapify(this->index); // 调整堆结构
        }
        ret = 0;
    }
    pthread_mutex_unlock(_mutex);

    if (ret) {
        errno = ret;
        return nullptr;
    }
    return this;
}

// 向连接池中归还连接, 同时唤醒正在等待的线程
void CommSchedTarget::release() {
    pthread_mutex_lock(&this->mutex);
    if (this->group) { pthread_mutex_lock(&this->group->mutex); }
    this->cur_load--; // 减少当前负载
    if (this->wait_cnt > 0) { pthread_cond_signal(&this->cond); } // 通知等待线程
    if (this->group) {
        this->group->cur_load--; // 减少组的全局负载
        if (this->wait_cnt == 0 && this->group->wait_cnt > 0) {
            // this->wait_cnt == 0表示当前这个特定的目标没有线程在等待, 但是组级别有线程在等待可用的目标
            pthread_cond_signal(&this->group->cond); // 通知组等待线程
        }
        this->group->heap_adjust(this->index, this->has_idle_conn()); // 调整堆结构
        pthread_mutex_unlock(&this->group->mutex); // 释放组锁
    }
    pthread_mutex_unlock(&this->mutex);
}

/**比较两个对象的优先级
 * @return int
 *  - -1: target1的优先级更高(target1相对负载更低)
 *  - 0: 两个对象的优先级相同(相对负载相等)
 *  - 1: target2的优先级更高(target2相对负载更低) */
int CommSchedGroup::target_cmp(const CommSchedTarget *target1, const CommSchedTarget *target2) {
    // 本质是需要比较: cur1/max1 和 cur2/max2 的大小, 即target1和target2的相对负载的大小(比较负载不能只比较当前负载, 还要考虑最大负载)
    // 但是如果直接计算, 需要使用除法, 对得到的浮点数比较大小. 而浮点数比较大小又容易出现精度问题.
    // 所以此处通过交叉相称比较大小: cur1/max1 < cur2/max2 等同于 cur1*max2 < cur2*max1. (两边同乘以 max1 * max2 )
    const size_t load1 = target1->cur_load * target2->max_load;
    const size_t load2 = target2->cur_load * target1->max_load;

    if (load1 < load2) {
        // load1优先级更高, 因为load1的相对负载更低！
        return -1;
    }
    if (load1 > load2) {
        return 1;
    }
    return 0;
}

/**将堆中指定元素上移, 直到找到其正确的位置.
 * @param index 需要调整的元素在数组tg_heap中的位置
 * @param swap_on_equal 决定了当目标节点与其父节点优先级"相等"时, 是否进行交换
 */
void CommSchedGroup::heap_adjust(int index, bool swap_on_equal) {
    CommSchedTarget *target = this->tg_heap[index];
    CommSchedTarget *parent;
    while (index > 0) {
        parent = this->tg_heap[(index - 1) / 2]; // 找到父亲节点
        // 比较优先级
        if (CommSchedGroup::target_cmp(target, parent) < swap_on_equal) {
            // 父节点下移(此时目标节点的指针已经用target指针保存, 可以直接覆盖tg_heap[index])
            this->tg_heap[index] = parent;
            parent->index = index;
            index = (index - 1) / 2; // index指向父节点位置, 继续循环比较是否需要与更上层交换
        } else {
            // 上移完成
            break;
        }
    }
    this->tg_heap[index] = target; // 将target放到合适位置
    target->index = index; // 更新上移后的位置
}

// 将指定元素下沉到合适位置(下沉调整)
void CommSchedGroup::heapify(int top) const {
    CommSchedTarget *target = this->tg_heap[top]; // 获取目标节点
    int last = this->heap_size - 1; // 堆的最后一个有效索引
    CommSchedTarget **child; // 二级指针, 这样child[0]和child[1]就可以分别表示左右子节点
    int i;

    // 如果当前top指向的节点存在两个子节点(i+1<=last), 就继续循环
    while (i = 2 * top + 1, i < last) {
        child = &this->tg_heap[i]; // 左子节点
        if (CommSchedGroup::target_cmp(child[0], target) < 0) {
            // child[0]负载比target低
            if (CommSchedGroup::target_cmp(child[1], child[0]) < 0) {
                // child[1]负载比child[0]低
                // 将target和child[1]交换
                this->tg_heap[top] = child[1];
                child[1]->index = top;
                top = i + 1; // top指向child[1], 但不立即更新target位置, 而是循环继续尝试能否下移
            } else {
                // target和child[0]交换
                this->tg_heap[top] = child[0];
                child[0]->index = top;
                top = i; // top指向child[0]
            }
        } else {
            if (CommSchedGroup::target_cmp(child[1], target) < 0) {
                this->tg_heap[top] = child[1];
                child[1]->index = top;
                top = i + 1;
            } else {
                // target比是负载最低的, 找到了target的目标位置
                this->tg_heap[top] = target; // 将target放入最终位置
                target->index = top; // 更新target位置
                return;
            }
        }
    }
    // 边界情况: 刚好遇到了当前节点只有左孩子的情况
    if (i == last) {
        child = &this->tg_heap[i];
        if (CommSchedGroup::target_cmp(child[0], target) < 0) {
            this->tg_heap[top] = child[0];
            child[0]->index = top;
            top = i;
        }
    }
    // 再循环内没有找到合适的位置, 此时一定是叶子结点
    this->tg_heap[top] = target; // 将target放入最终位置
    target->index = top; // 更新target位置
}

// 向堆中插入新目标target
int CommSchedGroup::heap_insert(CommSchedTarget *target) {
    if (this->heap_size == this->heap_buf_size) {
        // 如果堆已满, 将堆缓冲区扩充为原来的两倍
        const int new_size = 2 * this->heap_buf_size;
        // 重新分配内存
        void *new_base = realloc(this->tg_heap, new_size * sizeof(void *));
        if (new_base) {
            // 更新堆指针
            this->tg_heap = static_cast<CommSchedTarget **>(new_base);
            this->heap_buf_size = new_size; // 更新堆容量
        } else { return -1; }
    }

    this->tg_heap[this->heap_size] = target; // 将新节点插入堆的最后
    target->index = this->heap_size++; // 更新target的位置和堆大小
    this->heap_adjust(target->index, false); // 新插入节点上浮, 维持堆的特性
    return 0;
}

// 从堆中移除位置为index的目标
void CommSchedGroup::heap_remove(int index) {
    this->heap_size--; // 减小堆大小
    // 保证节点在堆内
    if (index != this->heap_size) {
        CommSchedTarget *target = this->tg_heap[this->heap_size]; // 获取堆最后一个节点
        this->tg_heap[index] = target; // 用堆最后一个节点target覆盖要删除的节点
        target->index = index; // 更新target的位置
        this->heap_adjust(index, false); // 先尝试上移
        this->heapify(target->index); // 再尝试下移
    }
}

#define COMMGROUP_INIT_SIZE 4

// 初始化
int CommSchedGroup::init() {
    constexpr size_t size = COMMGROUP_INIT_SIZE * sizeof(void *);
    this->tg_heap = static_cast<CommSchedTarget **>(malloc(size)); // 初始化堆
    if (this->tg_heap) {
        int ret = pthread_mutex_init(&this->mutex, nullptr);
        if (ret == 0) {
            ret = pthread_cond_init(&this->cond, nullptr);
            if (ret == 0) {
                this->heap_buf_size = COMMGROUP_INIT_SIZE; // 堆的容量
                this->heap_size = 0;
                this->max_load = 0; // 最大负载初始化为0, 插入节点时增加, 删除节点时减少
                this->cur_load = 0;
                this->wait_cnt = 0; // 当前等待的线程数
                return 0;
            }
            pthread_mutex_destroy(&this->mutex);
        }
        errno = ret;
        free(this->tg_heap);
    }
    return -1;
}

// 销毁
void CommSchedGroup::deinit() {
    pthread_cond_destroy(&this->cond);
    pthread_mutex_destroy(&this->mutex);
    free(this->tg_heap);
}

// 向调度组添加目标
int CommSchedGroup::add(CommSchedTarget *target) {
    int ret = -1;

    pthread_mutex_lock(&target->mutex); // target->mutex保护单个CommSchedTarget的内部状态(如 wait_cnt, group)
    pthread_mutex_lock(&this->mutex); // this->mutex保护 CommSchedGroup的共享状态(如 tg_heap, heap_size, max_load, cur_load)
    if (target->group == nullptr && target->wait_cnt == 0) {
        // 尝试插入
        if (this->heap_insert(target) >= 0) {
            target->group = this; // 建立归属关系
            this->max_load += target->max_load; // 更新组最大负载
            this->cur_load += target->cur_load; // 更新组当前负载
            if (this->wait_cnt > 0 && this->cur_load < this->max_load) {
                // 如果有线程等待并且当前组的负载低于最大负载
                pthread_cond_signal(&this->cond);
            }
            ret = 0; // 标记操作成功
        }
    } else if (target->group == this) {
        // 目标已在本组
        errno = EEXIST;
    } else if (target->group) {
        // 目标已属于其他组
        errno = EINVAL;
    } else { errno = EBUSY; } // 目标有线程正在等待(target->wait_cnt != 0)

    pthread_mutex_unlock(&this->mutex);
    pthread_mutex_unlock(&target->mutex);
    return ret;
}

// 从调度组中移除目标对象
int CommSchedGroup::remove(CommSchedTarget *target) {
    int ret = -1;

    pthread_mutex_lock(&target->mutex);
    pthread_mutex_lock(&this->mutex);
    if (target->group == this && target->wait_cnt == 0) {
        // 执行删除操作
        this->heap_remove(target->index); // 从堆结构中移除
        this->max_load -= target->max_load; // 更新组最大负载
        this->cur_load -= target->cur_load; // 更新组当前负载
        target->group = nullptr; // 解除关联
        ret = 0; // 标记操作成功
    } else if (target->group != this) {
        // 目标不属于本组
        errno = ENOENT;
    } else { errno = EBUSY; } // 目标有等待者

    pthread_mutex_unlock(&this->mutex);
    pthread_mutex_unlock(&target->mutex);
    return ret;
}

// 在指定时间内从调度组中获取一个可用目标
CommTarget *CommSchedGroup::acquire(const int wait_timeout) {
    pthread_mutex_t *_mutex = &this->mutex; // 获取锁
    CommSchedTarget *target = nullptr;
    int ret = -1;

    pthread_mutex_lock(_mutex); // 保护组内资源
    if (this->cur_load >= this->max_load) {
        // 当前负载高于最大负载
        if (wait_timeout != 0) {
            timespec abstime = get_abstime(wait_timeout);
            timespec *ts = &abstime;

            do {
                this->wait_cnt++;
                ret = PTHREAD_COND_TIMEDWAIT(&this->cond, _mutex, ts); // 原子地解锁_mutex并使当前线程阻塞, 当被唤醒或超时后, 在返回前它会重新获取_mutex锁
                this->wait_cnt--;
            } while (this->cur_load >= this->max_load && ret == 0);
        } else { ret = EAGAIN; } // wait_timeout为0时, 表示调用方不希望等待. 此时立即返回EAGAIN错误码, 告知调用方资源暂时不可用
    }

    if (this->cur_load < this->max_load) {
        target = this->tg_heap[0]; // 获取堆顶元素（最优目标）
        target->cur_load++; // 增加目标负载
        this->cur_load++; // 增加组负载
        this->heapify(0); // 从位置0开始调整堆
        ret = 0; // 标记成功
    }

    pthread_mutex_unlock(_mutex);
    if (ret) {
        errno = ret;
        return nullptr;
    }

    return target;
}