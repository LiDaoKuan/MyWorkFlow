//
// Created by ldk on 10/25/25.
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

  Authors: Xie Han (xiehan@sogou-inc.com)
*/

#include <sys/types.h>
#include <cerrno>
#include <ctime>
#include <utility>
#include <string>
#include <mutex>
#include <atomic>
#include "list.h"
#include "rbtree.h"
#include "WFGlobal.h"
#include "WFTaskFactory.h"

// 通用定时器(主要用于创建匿名定时器任务)
class __WFTimerTask : public WFTimerTask {
protected:
    int duration(timespec *value) override {
        value->tv_sec = this->seconds;
        value->tv_nsec = this->nanoseconds;
        return 0;
    }

protected:
    time_t seconds;
    long nanoseconds;

public:
    __WFTimerTask(time_t seconds, long nanoseconds, CommScheduler *scheduler, timer_callback_t &&cb) :
        WFTimerTask(scheduler, std::move(cb)) {
        this->seconds = seconds;
        this->nanoseconds = nanoseconds;
    }
};

// 立即取消的定时器任务
class __WFCanceledTimerTask : public __WFTimerTask {
protected:
    void dispatch() override {
        if (this->scheduler->sleep(this) >= 0) {
            this->cancel(); // 调度成功, 立即取消自身
        } else {
            // 调度失败
            this->handle(WFT_STATE_SYS_ERROR, errno);
        }
    }

public:
    __WFCanceledTimerTask(CommScheduler *scheduler, timer_callback_t &&cb) :
        __WFTimerTask(-1, 0, scheduler, std::move(cb)) {}
};

WFTimerTask *WFTaskFactory::create_timer_task(time_t seconds, long nanoseconds, timer_callback_t callback) {
    return new __WFTimerTask(seconds, nanoseconds, WFGlobal::get_scheduler(), std::move(callback));
}

WFTimerTask *WFTaskFactory::create_timer_task(timer_callback_t callback) {
    return new __WFCanceledTimerTask(WFGlobal::get_scheduler(), std::move(callback));
}

/* Deprecated. 已弃用 */
WFTimerTask *WFTaskFactory::create_timer_task(unsigned int microseconds, timer_callback_t callback) {
    return WFTaskFactory::create_timer_task(microseconds / 1000000,
                                            microseconds % 1000000 * 1000,
                                            std::move(callback));
}

/* ***************** Named Tasks ***************** */

/**对链表的封装. 同时也可以作为节点被插入到红黑树中. 用于管理一组具有相同名称的对象. 泛型T必须具备 list_head list 成员**/
template <typename T>
struct __NamedObjectList {
    __NamedObjectList(const std::string &str) :
        name(str) {
        INIT_LIST_HEAD(&this->head);
    }

    // 向链表中添加节点node
    void push_back(T *node) {
        list_add_tail(&node->list, &this->head);
    }

    [[nodiscard]] bool empty() const {
        return list_is_empty(&this->head);
    }

    /**从链表中删除节点node, 链表必须在红黑树root中
     * @return true 表示链表已经为空, 并且已从红黑树删除, 需要额外清理
     * @return false 表示链表不为空 */
    bool del(T *node, rb_root *root) {
        list_del(&node->list);
        if (this->empty()) {
            // 如果链表为空, 则将该链表从红黑树中删除
            rb_erase(&this->rb, root);
            return true;
        } else {
            return false;
        }
    }

    rb_node rb; // 侵入式红黑树节点, 记录链表在红黑树中的位置, 由外部进行赋值
    list_head head; // 双向链表头
    std::string name; // 组名称, 作为唯一标识
};

// 查找红黑树 root 中 名字为 name 的 T类型 链表, 如果不存在, 根据 insert 参数选择性插入一个新链表. 返回查找到的链表的链表头地址
template <typename T>
static T *__get_object_list(const std::string &name, struct rb_root *root, bool insert) {
    rb_node **p = &root->rb_node;
    rb_node *parent = nullptr;
    T *objs;
    int n;

    while (*p) {
        parent = *p;
        objs = rb_entry(*p, T, rb); // 找到*p指向的T类型对象入口地址
        n = name.compare(objs->name); // 比较name字段
        if (n < 0) {
            p = &(*p)->rb_left;
        } else if (n > 0) {
            p = &(*p)->rb_right;
        } else {
            return objs; // 找到了指定对象
        }
    }
    // 没有找到指定对象, 根据参数决定是否创建T类型对象并插入
    if (insert) {
        objs = new T(name);
        rb_link_node(&objs->rb, parent, p);
        rb_insert_color(&objs->rb, root);
        return objs; // 返回创建的T类型对象
    }
    // 没有找到指定对象并且拒绝创建新对象
    return nullptr;
}

/****************** Named Timer ******************/

class __WFNamedTimerTask;

// 连接器. 作为节点同时存在于红黑树管理的链表和任务对象中. 在任务对象和链表之间建立联系.
// 为什么不直接在任务对象中采用侵入式链表？？？ 因为侵入式链表严重依赖宏 list_entry, 而该宏仅仅只能作用于标准布局下的对象
struct __timer_node {
    list_head list; // 链表节点. 记录在链表中的位置
    __WFNamedTimerTask *task; // 记录所在的任务对象
};

// 全局单例, 负责管理所有命名定时器. 内部通过红黑树按名称组织定时器组, 提供创建和取消接口
static class __NamedTimerMap {
public:
    using TimerList = __NamedObjectList<struct __timer_node>;

public:
    WFTimerTask *create(const std::string &name, time_t seconds, long nanoseconds,
                        CommScheduler *scheduler, timer_callback_t &&cb);

public:
    int cancel(const std::string &name, size_t max);

private:
    rb_root root_{nullptr};
    std::mutex mutex_{};

public:
    __NamedTimerMap() = default;

    friend class __WFNamedTimerTask;
} __timer_map;

// 具体的命名定时任务. 继承自通用定时器, 增加了名称标识和所属组的指针, 重写了生命周期方法
class __WFNamedTimerTask : public __WFTimerTask {
public:
    __WFNamedTimerTask(time_t seconds, long nanoseconds, CommScheduler *scheduler, timer_callback_t &&cb) :
        __WFTimerTask(seconds, nanoseconds, scheduler, std::move(cb)), flag_(false) {
        node_.task = this; // 建立节点node_和对象自身的连接
    }

    // 将该对象添加到链表 timers 中（采用侵入式链表设计）
    void push_to(__NamedTimerMap::TimerList *timers) {
        timers->push_back(&node_);
        timers_ = timers; // 记录所在链表
    }

    ~__WFNamedTimerTask() override {
        if (node_.task) {
            bool empty = false;

            __timer_map.mutex_.lock(); // 全局锁
            if (node_.task) {
                empty = timers_->del(&node_, &__timer_map.root_);
            }
            __timer_map.mutex_.unlock(); // 全局锁

            if (empty) {
                delete timers_;
            }
        }
    }

protected:
    void dispatch() override;
    void handle(int state, int error) override;

private:
    __timer_node node_{}; // 用于将对象自身和链表中的节点联系起来
    __NamedTimerMap::TimerList *timers_{nullptr}; // 链表. 存储所有共享同一名称的定时器任务
    std::atomic<bool> flag_{}; // 标记定时器是否已经被取消
    std::mutex mutex_{};
    friend class __NamedTimerMap;
};

void __WFNamedTimerTask::dispatch() {
    int ret;

    mutex_.lock();
    // 将定时任务提交给通信调度器的休眠队列, 开始异步定时等待
    ret = this->scheduler->sleep(this);
    // 如果任务提交成功(ret>=0)且flag_原值为true（表示任务已被标记取消）
    if (ret >= 0 && flag_.exchange(true)) {
        this->cancel(); // 执行取消
    }
    mutex_.unlock();

    // 任务提交失败
    if (ret < 0) {
        this->handle(WFT_STATE_SYS_ERROR, errno);
    }
}

void __WFNamedTimerTask::handle(int state, int error) {
    bool canceled = true;
    // 第一重检查: 判断任务节点是否还存在（是否已被cancel()函数置空）
    if (node_.task) {
        bool empty = false;
        __timer_map.mutex_.lock(); // 加锁
        // 加锁后再次判断任务节点是否存在
        if (node_.task) {
            // 走到这里说明任务未被提前取消, 标记为非取消状态
            canceled = false;
            // 删除本节点
            empty = timers_->del(&node_, &__timer_map.root_);
            node_.task = nullptr; // 置nullptr
        }
        __timer_map.mutex_.unlock(); // 解锁
        // 链表在删除后为空, 释放链表
        if (empty) {
            delete timers_;
        }
    }
    // 如果任务是被取消的, 则统一状态为"系统错误", 错误码为"已取消"
    if (canceled) {
        state = WFT_STATE_SYS_ERROR;
        error = ECANCELED;
    }
    // 加锁后立即解锁. 目的是等待可能正在dispatch中运行的代码段执行完毕
    mutex_.lock();
    mutex_.unlock();
    // 调用基类的handle方法: 最终触发用户设置的回调函数, 并执行任务流的后续操作
    this->__WFTimerTask::handle(state, error);
}

// 创建和注册命名定时器
WFTimerTask *__NamedTimerMap::create(const std::string &name, time_t seconds, long nanoseconds,
                                     CommScheduler *scheduler, timer_callback_t &&cb) {
    auto *task = new __WFNamedTimerTask(seconds, nanoseconds, scheduler, std::move(cb)); // 创建定时器
    mutex_.lock();
    // 将新创建的定时器添加到全局管理组中
    task->push_to(__get_object_list<TimerList>(name, &root_, true));
    mutex_.unlock();
    return task;
}

int __NamedTimerMap::cancel(const std::string &name, size_t max) {
    struct __timer_node *node;
    TimerList *timer_list;
    int ret = 0;

    mutex_.lock();
    timer_list = __get_object_list<TimerList>(name, &root_, false); // 获取name对应的链表
    if (timer_list) {
        while (true) {
            if (max == 0) {
                // 所有要取消的任务都已经被取消, 跳出循环
                timer_list = nullptr;
                break;
            }
            node = list_entry(timer_list->head.next, struct __timer_node, list); // 获取链表第一个节点所在的__timer_node的地址
            list_del(&node->list); // 从链表中删除该节点
            if (node->task->flag_.exchange(true)) {
                // flag_在if语句之前已经被标记为true（dispatch()中标记）, 说明任务在其他地方被标记取消, 此处进行真正的取消
                node->task->cancel(); // 取消任务
            }
            // 如果没有进入上方if语句内部, 说明任务正在运行, 此处通过exchange()将flag_标记为true, 表示标记取消, 真正的取消在dispatch()函数中
            node->task = nullptr; // 置nullptr,
            max--;
            ret++;
            // 整个链表中的任务都已经取消, 链表为空
            if (timer_list->empty()) {
                rb_erase(&timer_list->rb, &root_); // 从红黑树中删除链表
                break; // 跳出循环
            }
        }
    }
    mutex_.unlock();

    delete timer_list;
    return ret;
}

WFTimerTask *WFTaskFactory::create_timer_task(const std::string &name, time_t seconds, long nanoseconds,
                                              timer_callback_t callback) {
    return __timer_map.create(name, seconds, nanoseconds, WFGlobal::get_scheduler(), std::move(callback));
}

int WFTaskFactory::cancel_by_name(const std::string &name, size_t max) {
    return __timer_map.cancel(name, max);
}

/****************** Named Counter ******************/

class __WFNamedCounterTask;

// 连接器. 在计数器任务和链表之间建立联系. 同时也保存了真正的计数次数
struct __counter_node {
    list_head list; // 侵入式链表
    unsigned int target_value; // 计数达到此值时触发回调.
    __WFNamedCounterTask *task; // 指向拥有此节点的计数器任务
};

// 全局单例. 用于管理命名计数器, 同时也负责命名计数器的计数？？？
static class __NamedCounterMap {
public:
    using CounterList = __NamedObjectList<struct __counter_node>;

public:
    // 创建并注册新计数器
    WFCounterTask *create(const std::string &name, unsigned int target_value, counter_callback_t &&cb);

    int count_n(const std::string &name, unsigned int n);
    // 单次计数
    void count(CounterList *counter_list, struct __counter_node *node);
    // 从链表counter_list中删除节点node
    void remove(CounterList *counter_list, __counter_node *node) {
        bool empty;
        mutex_.lock();
        empty = counter_list->del(node, &root_);
        mutex_.unlock();
        if (empty) {
            // 删除后链表为空, 释放链表
            delete counter_list;
        }
    }

private:
    bool count_n_locked(CounterList *counter_list, unsigned int n, list_head *task_list);
    rb_root root_{nullptr}; // 红黑树根节点
    std::mutex mutex_;

public:
    __NamedCounterMap() = default;
} __counter_map;

// 命名计数器.
class __WFNamedCounterTask : public WFCounterTask {
public:
    __WFNamedCounterTask(unsigned int target_value, counter_callback_t &&cb) :
        WFCounterTask(1, std::move(cb)) // 注意父类的target_value初始值为1, 也就是说父类只计数一次
    {
        node_.target_value = target_value; // 此处才是真正的计数次数
        node_.task = this;
    }

    // 将计数器任务本身添加到链表counter_list中
    void push_to(__NamedCounterMap::CounterList *counter_list) {
        counter_list->push_back(&node_);
        counter_list = counter_list; // 记录所在链表
    }

    // 重写的count(). 将计数操作交给了 __NamedCounterMap,
    // 而 __NamedCounterMap 又会在计数归零时通知 WFCounterTask(父类), 进行父类的单次计数
    void count() override {
        __counter_map.count(counter_list, &node_);
    }

    ~__WFNamedCounterTask() override {
        // this->value != 0, 说明并未完成计数, 此时计数器一定还在链表中, 需要将其从链表中移除.\
        // value其实定义在父类中, 子类继承后并未覆盖
        if (this->value != 0) {
            __counter_map.remove(counter_list, &node_);
        }
    }

private:
    __counter_node node_;
    __NamedCounterMap::CounterList *counter_list{nullptr}; // 记录该对象所在的链表
};

WFCounterTask *__NamedCounterMap::create(const std::string &name, unsigned int target_value, counter_callback_t &&cb) {
    if (target_value == 0) {
        return new WFCounterTask(0, std::move(cb)); // 计数0次, 直接返回父类对象
    }
    auto *task = new __WFNamedCounterTask(target_value, std::move(cb));
    mutex_.lock();
    task->push_to(__get_object_list<CounterList>(name, &root_, true)); // 将计数器对象添加到链表中
    mutex_.unlock();
    return task;
}

/**对 counter_list 中的计数器计数 n 次, 将计数完成的计数器放入 task_list 中
 * @return - true 表示在计数完成后 counter_list 为空
 * @return - false 表示在计数完成后 counter_list 不为空 */
bool __NamedCounterMap::count_n_locked(CounterList *counter_list, unsigned int n, list_head *task_list) {
    __counter_node *current_node;

    while (n > 0) {
        // 获取链表头结点所在的 __counter_node 的地址
        current_node = list_entry(counter_list->head.next, struct __counter_node, list);
        // 剩余计数值 > 当前节点的计数值
        if (n >= current_node->target_value) {
            n -= current_node->target_value;
            // 当前节点计数归零
            current_node->target_value = 0;
            // 当前节点放入task_list链表中（同时从counter_list中删除）
            list_move_tail(&current_node->list, task_list);
            // 如果counter_list为空, 则从红黑树中删除
            if (counter_list->empty()) {
                rb_erase(&counter_list->rb, &root_);
                return true;
            }
        }
        // 剩余计数值 < 当前节点的计数值
        else {
            current_node->target_value -= n;
            break;
        }
    }

    return false;
}

/**对名字为name的计数器组计数n次
 * @return 到达目标值的计数器数量 */
int __NamedCounterMap::count_n(const std::string &name, unsigned int n) {
    LIST_HEAD(task_list); // 定义双向循环链表
    __counter_node *node;
    CounterList *counter_list;
    bool empty = false;
    int ret = 0;

    mutex_.lock();
    counter_list = __get_object_list<CounterList>(name, &root_, false); // 获取name对应的链表
    if (counter_list) {
        empty = count_n_locked(counter_list, n, &task_list);
    }
    mutex_.unlock();

    if (empty) {
        delete counter_list;
    }
    // 对计数到达目标值的计数器, 调用父类的count(), 触发后续任务
    while (!list_is_empty(&task_list)) {
        node = list_entry(task_list.next, struct __counter_node, list);
        list_del(&node->list);
        node->task->WFCounterTask::count();
        ret++;
    }

    return ret;
}

// 对node所在的计数器进行单次计数
void __NamedCounterMap::count(CounterList *counter_list, __counter_node *node) {
    __WFNamedCounterTask *task = nullptr;
    bool empty = false;

    mutex_.lock();
    if (--node->target_value == 0) {
        // 计数归零, 取出计数任务, 同时从链表中删除节点
        task = node->task;
        empty = counter_list->del(node, &root_);
    }
    mutex_.unlock();

    if (empty) {
        delete counter_list;
    }
    // 如果task不为nullptr, 则说明计数到达了目标值(归零), 通知父类进行单次计数, 同时启动后续任务
    if (task) {
        task->WFCounterTask::count();
    }
}

WFCounterTask *WFTaskFactory::create_counter_task(const std::string &name, unsigned int target_value, counter_callback_t callback) {
    return __counter_map.create(name, target_value, std::move(callback));
}

int WFTaskFactory::count_by_name(const std::string &name, unsigned int n) {
    return __counter_map.count_n(name, n);
}

/****************** Named Mailbox ******************/

class __WFNamedMailboxTask;

// 将任务对象和链表节点联系起来
struct __mailbox_node {
    list_head list; // 侵入式链表
    __WFNamedMailboxTask *task;
};

static class __NamedMailboxMap {
public:
    using MailboxList = __NamedObjectList<struct __mailbox_node>;

public:
    WFMailboxTask *create(const std::string &name, void **mailbox, mailbox_callback_t &&cb);
    WFMailboxTask *create(const std::string &name, mailbox_callback_t &&cb);

    int send(const std::string &name, void *const msg[], size_t max, int inc);
    void send(MailboxList *mailbox_list, __mailbox_node *node, void *msg);

    void remove(MailboxList *mailbox_list, __mailbox_node *node) {
        bool empty;
        mutex_.lock();
        empty = mailbox_list->del(node, &root_);
        mutex_.unlock();
        if (empty) {
            delete mailbox_list;
        }
    }

private:
    bool send_max_locked(MailboxList *mailbox_list, size_t max, list_head *task_list);
    rb_root root_;
    std::mutex mutex_;

public:
    __NamedMailboxMap() {
        root_.rb_node = nullptr;
    }
} __mailbox_map;

class __WFNamedMailboxTask : public WFMailboxTask {
public:
    __WFNamedMailboxTask(void **mailbox, mailbox_callback_t &&cb) :
        WFMailboxTask(mailbox, std::move(cb)) {
        node_.task = this;
    }

    __WFNamedMailboxTask(mailbox_callback_t &&cb) :
        WFMailboxTask(std::move(cb)) {
        node_.task = this;
    }

    // 将对象本身插入到 mailbox_list 中
    void push_to(__NamedMailboxMap::MailboxList *mailbox_list) {
        mailbox_list->push_back(&node_);
        mailbox_list_ = mailbox_list; // 记录所在的链表
    }

    // 重写的send方法, 将消息发送委托给了 __NamedMailboxMap
    void send(void *msg) override {
        __mailbox_map.send(mailbox_list_, &node_, msg);
    }

    ~__WFNamedMailboxTask() override {
        if (!this->flag) {
            // flag为false, 说明消息未发送, 任务还在链表中, 将任务从链表中删除
            __mailbox_map.remove(mailbox_list_, &node_);
        }
    }

private:
    __mailbox_node node_;
    __NamedMailboxMap::MailboxList *mailbox_list_; // 指向对象所在的链表
};

WFMailboxTask *__NamedMailboxMap::create(const std::string &name, void **mailbox, mailbox_callback_t &&cb) {
    auto *task = new __WFNamedMailboxTask(mailbox, std::move(cb));
    mutex_.lock();
    task->push_to(__get_object_list<MailboxList>(name, &root_, true));
    mutex_.unlock();
    return task;
}

WFMailboxTask *__NamedMailboxMap::create(const std::string &name, mailbox_callback_t &&cb) {
    auto *task = new __WFNamedMailboxTask(std::move(cb));
    mutex_.lock();
    task->push_to(__get_object_list<MailboxList>(name, &root_, true));
    mutex_.unlock();
    return task;
}

/**向链表 mailbox_list 中最多 max 个任务发送消息, 将发送过消息的任务都移动到 task_list 链表中
 * @return true 表示发送完消息后链表 mailbox_list 为空
 * @return false 表示发送完消息后链表 mailbox_list 不为空 */
bool __NamedMailboxMap::send_max_locked(MailboxList *mailbox_list, size_t max, list_head *task_list) {
    if (max == (size_t)-1) {
        // 向链表中所有任务发送消息
        list_splice(&mailbox_list->head, task_list);
    } else {
        do {
            if (max == 0) {
                return false;
            }
            // 将发送过消息的任务都移动到 task_list 链表中（此处实际并未发送消息, 真正发送消息的操作由外部调用着通过遍历 task_list 完成）
            list_move_tail(mailbox_list->head.next, task_list);
            max--;
        } while (!mailbox_list->empty());
    }

    rb_erase(&mailbox_list->rb, &root_);
    return true;
}

// 向最多 max 个名字为 name 的任务广播消息. 每广播一次消息, msg 指针就向右偏移 inc 个单位, 这可以控制不同任务接收到的消息是否相同
int __NamedMailboxMap::send(const std::string &name, void *const msg[], size_t max, int inc) {
    LIST_HEAD(task_list);
    __mailbox_node *node;
    MailboxList *mailboxes;
    bool empty = false;
    int ret = 0;

    mutex_.lock();
    mailboxes = __get_object_list<MailboxList>(name, &root_, false);
    if (mailboxes) {
        empty = send_max_locked(mailboxes, max, &task_list);
    }
    mutex_.unlock();

    if (empty) {
        delete mailboxes;
    }

    while (!list_is_empty(&task_list)) {
        node = list_entry(task_list.next, struct __mailbox_node, list);
        list_del(&node->list); // 删除发送过消息的节点
        node->task->WFMailboxTask::send(*msg); // 发送消息
        msg += inc; // 向右偏移
        ret++;
    }

    return ret;
}

// 向 node 所在的任务单播一条消息 msg
void __NamedMailboxMap::send(MailboxList *mailbox_list, __mailbox_node *node, void *msg) {
    bool empty;

    mutex_.lock();
    empty = mailbox_list->del(node, &root_);
    mutex_.unlock();
    if (empty) {
        delete mailbox_list;
    }
    node->task->WFMailboxTask::send(msg);
}

WFMailboxTask *WFTaskFactory::create_mailbox_task(const std::string &name, void **mailbox, mailbox_callback_t callback) {
    return __mailbox_map.create(name, mailbox, std::move(callback));
}

WFMailboxTask *WFTaskFactory::create_mailbox_task(const std::string &name, mailbox_callback_t callback) {
    return __mailbox_map.create(name, std::move(callback));
}

int WFTaskFactory::send_by_name(const std::string &name, void *msg, size_t max) {
    return __mailbox_map.send(name, &msg, max, 0);
}

template <>
int WFTaskFactory::send_by_name(const std::string &name, void *const msg[], size_t max) {
    return __mailbox_map.send(name, msg, max, 1);
}

/* ***************** Named Conditional ***************** */

class __WFNamedConditional;

struct __conditional_node {
    list_head list; // 侵入式链表
    __WFNamedConditional *cond;
};

// 全局单例类.
static class __NamedConditionalMap {
public:
    using ConditionalList = __NamedObjectList<struct __conditional_node>;

public:
    WFConditional *create(const std::string &name, SubTask *task, void **msgbuf);
    WFConditional *create(const std::string &name, SubTask *task);

    int signal(const std::string &name, void *const msg[], size_t max, int inc);
    void signal(ConditionalList *conds, __conditional_node *node, void *msg);

    void remove(ConditionalList *conds, __conditional_node *node) {
        bool empty;

        mutex_.lock();
        empty = conds->del(node, &root_);
        mutex_.unlock();
        if (empty) {
            delete conds;
        }
    }

private:
    bool signal_max_locked(ConditionalList *conds, size_t max,
                           struct list_head *cond_list);
    rb_root root_;
    std::mutex mutex_;

public:
    __NamedConditionalMap() {
        root_.rb_node = nullptr;
    }
} __conditional_map;

// 命名条件任务
class __WFNamedConditional : public WFConditional {
public:
    __WFNamedConditional(SubTask *task, void **msgbuf) :
        WFConditional(task, msgbuf) {
        node_.cond = this;
    }

    __WFNamedConditional(SubTask *task) :
        WFConditional(task) {
        node_.cond = this;
    }

    void push_to(__NamedConditionalMap::ConditionalList *conds) {
        conds->push_back(&node_);
        conds_ = conds;
    }

    // 重写的 signal 方法, 将 signal 委托给了 __NamedConditionalMap
    void signal(void *msg) override {
        __conditional_map.signal(conds_, &node_, msg);
    }

    ~__WFNamedConditional() override {
        if (!this->flag) {
            __conditional_map.remove(conds_, &node_);
        }
    }

private:
    __conditional_node node_;
    __NamedConditionalMap::ConditionalList *conds_;
};

WFConditional *__NamedConditionalMap::create(const std::string &name, SubTask *task, void **msgbuf) {
    auto *cond = new __WFNamedConditional(task, msgbuf);
    mutex_.lock();
    cond->push_to(__get_object_list<ConditionalList>(name, &root_, true));
    mutex_.unlock();
    return cond;
}

WFConditional *__NamedConditionalMap::create(const std::string &name, SubTask *task) {
    auto *cond = new __WFNamedConditional(task);
    mutex_.lock();
    cond->push_to(__get_object_list<ConditionalList>(name, &root_, true));
    mutex_.unlock();
    return cond;
}

bool __NamedConditionalMap::signal_max_locked(ConditionalList *conds,
                                              size_t max,
                                              struct list_head *cond_list) {
    if (max == (size_t)-1) {
        list_splice(&conds->head, cond_list);
    } else {
        do {
            if (max == 0) {
                return false;
            }

            list_move_tail(conds->head.next, cond_list);
            max--;
        } while (!conds->empty());
    }

    rb_erase(&conds->rb, &root_);
    return true;
}

// 向名字为 name 的最多 max 个条件任务发送消息
int __NamedConditionalMap::signal(const std::string &name, void *const msg[], size_t max, int inc) {
    LIST_HEAD(cond_list);
    __conditional_node *node;
    ConditionalList *conditional_list;
    bool empty = false;
    int ret = 0;

    mutex_.lock();
    conditional_list = __get_object_list<ConditionalList>(name, &root_, false);
    if (conditional_list) {
        empty = signal_max_locked(conditional_list, max, &cond_list);
    }

    mutex_.unlock();
    if (empty) {
        delete conditional_list;
    }

    while (!list_is_empty(&cond_list)) {
        node = list_entry(cond_list.next, struct __conditional_node, list);
        list_del(&node->list);
        node->cond->WFConditional::signal(*msg);
        msg += inc;
        ret++;
    }

    return ret;
}

void __NamedConditionalMap::signal(ConditionalList *conds, __conditional_node *node, void *msg) {
    bool empty;

    mutex_.lock();
    empty = conds->del(node, &root_);
    mutex_.unlock();
    if (empty) {
        delete conds;
    }

    node->cond->WFConditional::signal(msg);
}

WFConditional *WFTaskFactory::create_conditional(const std::string &name, SubTask *task, void **msgbuf) {
    return __conditional_map.create(name, task, msgbuf);
}

WFConditional *WFTaskFactory::create_conditional(const std::string &name, SubTask *task) {
    return __conditional_map.create(name, task);
}

int WFTaskFactory::signal_by_name(const std::string &name, void *msg, size_t max) {
    return __conditional_map.signal(name, &msg, max, 0);
}

template <>
int WFTaskFactory::signal_by_name(const std::string &name, void *const msg[], size_t max) {
    return __conditional_map.signal(name, msg, max, 1);
}

/****************** Named Guard ******************/

class __WFNamedGuard;

struct __guard_node {
    list_head list;
    __WFNamedGuard *guard;
};

static class __NamedGuardMap {
public:
    struct GuardList : public __NamedObjectList<struct __guard_node> {
        GuardList(const std::string &name) :
            __NamedObjectList(name) {
            acquired = false; // 初始未获取状态
            ref_cnt = 0; // 初始引用计数为0
        }

        bool acquired; // 守卫是否已被获取
        size_t ref_cnt; // 引用计数
        std::mutex mutex; // 守卫专属互斥锁
    };

public:
    // 创建指定名称的守卫条件变量
    WFConditional *create(const std::string &name, SubTask *task);
    // 创建指定名称的守卫条件变量, 可传递指针大小的数据
    WFConditional *create(const std::string &name, SubTask *task, void **msgbuf);

    // 唤醒name对应的链表中的第一个任务, 返回应该被唤醒的任务. 没有任务则返回nullptr
    __guard_node *release(const std::string &name);

    // 令guards_list引用计数-1, 仅在 __WFNamedGuard 的析构函数中被调用
    void unref(GuardList *guards_list) {
        mutex_.lock();
        if (--guards_list->ref_cnt == 0) {
            // 如果引用数归零, 则将该列表从红黑树中移除
            rb_erase(&guards_list->rb, &root_);
        } else {
            guards_list = nullptr;
        }

        mutex_.unlock();
        // 两种情况:
        // 1. guards_list 不为 nullptr, 说明引用计数归零, 链表已经被清空（仅剩一个头结点）, 并且已经从红黑树中删除
        // 2. guards_list 为 nullptr, 说明执行了 --guards_list->ref_cnt 但并不满足 ==0 条件, 进入了 else 分支, 被置为nullptr
        delete guards_list;
    }

private:
    rb_root root_; // 红黑树根节点
    std::mutex mutex_;

public:
    __NamedGuardMap() {
        root_.rb_node = nullptr;
    }
} __guard_map;

// 命名守卫任务
class __WFNamedGuard : public WFConditional {
public:
    __WFNamedGuard(SubTask *task) :
        WFConditional(task) {
        node_.guard = this;
    }

    __WFNamedGuard(SubTask *task, void **msgbuf) :
        WFConditional(task, msgbuf) {
        node_.guard = this;
    }

    ~__WFNamedGuard() override {
        if (!this->flag) {
            __guard_map.unref(guards_list);
        }
    }

protected:
    void dispatch() override;
    // signal重写为空实现
    void signal(void *msg) override {}

private:
    __guard_node node_;
    __NamedGuardMap::GuardList *guards_list; // 记录任务所在的链表(也即: 等待队列)
    friend __NamedGuardMap;
};

void __WFNamedGuard::dispatch() {
    guards_list->mutex.lock();
    // 判断当前资源是否已经被占用
    if (guards_list->acquired) {
        guards_list->push_back(&node_); // 将当前任务加入等待队列
    } else {
        guards_list->acquired = true; // 占用当前资源
        this->WFConditional::signal(nullptr); // 激活条件变量, 标记条件为"已满足"状态, 这样才能使后面的dispatch()触发后续任务流程
        /**在锁内调用signal, 确保:
         * 状态修改与条件触发的原子性
         * 避免唤醒丢失(wakeup loss)问题
         * 保证后面的dispatch()能够触发后续任务流程 */
    }
    guards_list->mutex.unlock();
    /**dispatch()调用的两种情况:
     * 资源空闲: 会进入前面的if语句, 然后调用signal(), dispatch直接继续执行后续任务
     * 资源繁忙: 将任务加入任务流, 但因为没有执行过父类的signal(), 所以任务会阻塞, 直到被release()唤醒 */
    this->WFConditional::dispatch();
}

WFConditional *__NamedGuardMap::create(const std::string &name, SubTask *task) {
    auto *guard = new __WFNamedGuard(task);
    mutex_.lock();
    guard->guards_list = __get_object_list<GuardList>(name, &root_, true); // 获取name对应的链表, 没有则创建新的并插入红黑树
    guard->guards_list->ref_cnt++; // 引用数+1
    mutex_.unlock();
    return guard;
}

WFConditional *__NamedGuardMap::create(const std::string &name, SubTask *task, void **msgbuf) {
    auto *guard = new __WFNamedGuard(task, msgbuf);
    mutex_.lock();
    guard->guards_list = __get_object_list<GuardList>(name, &root_, true);
    guard->guards_list->ref_cnt++;
    mutex_.unlock();
    return guard;
}

struct __guard_node *__NamedGuardMap::release(const std::string &name) {
    __guard_node *node = nullptr;
    GuardList *guard_list;

    mutex_.lock();
    // 获取name对应的链表
    guard_list = __get_object_list<GuardList>(name, &root_, false);
    if (guard_list) {
        // 引用数-1, 如果归零, 则从红黑树中删除
        if (--guard_list->ref_cnt == 0) {
            rb_erase(&guard_list->rb, &root_);
        } else {
            // 引用数不为0, 删除一个节点
            guard_list->mutex.lock();
            // 判断是否有任务在等待此资源
            if (!guard_list->empty()) {
                node = list_entry(guard_list->head.next, struct __guard_node, list);
                list_del(&node->list); // 删除链表中第一个等待节点
            } else {
                guard_list->acquired = false; // 没有任务等待次资源, 标记为false
            }
            guard_list->mutex.unlock();
            guard_list = nullptr;
        }
    }
    // 没有获取到guards, 不做任何操作
    mutex_.unlock();

    // 只有两种情况:
    // 1. guard_list 中没有其他节点(引用计数归0)
    // 2. guard_list 为 nullptr (引用计数不为0, 但在删除节点后将 guard_list 置为空)
    delete guard_list;
    return node;
}

WFConditional *WFTaskFactory::create_guard(const std::string &name, SubTask *task) {
    return __guard_map.create(name, task);
}

WFConditional *WFTaskFactory::create_guard(const std::string &name, SubTask *task, void **msgbuf) {
    return __guard_map.create(name, task, msgbuf);
}

int WFTaskFactory::release_guard(const std::string &name, void *msg) {
    struct __guard_node *node = __guard_map.release(name);

    if (!node) {
        return 0;
    }

    node->guard->WFConditional::signal(msg); // 唤醒任务
    return 1;
}

int WFTaskFactory::release_guard_safe(const std::string &name, void *msg) {
    struct __guard_node *node = __guard_map.release(name);
    WFTimerTask *timer;
    if (!node) {
        return 0;
    }
    // 创建立即取消的定时器, 令唤醒操作在定时器任务的回调中执行. 定时器任务会单独交给某个线程执行
    timer = WFTaskFactory::create_timer_task([node](WFTimerTask *timer) {
        node->guard->WFConditional::signal(timer->user_data);
    });
    timer->user_data = msg;
    timer->start(); // 启动定时器
    return 1;
}

/**************** Timed Go Task *****************/

/* ------------------以下四个函数的实现参考 __WFTimedThreadTask 类中的同名函数------------------ */

void __WFTimedGoTask::dispatch() {
    WFTimerTask *timer;

    timer = WFTaskFactory::create_timer_task(this->seconds, this->nanoseconds, __WFTimedGoTask::timer_callback);
    timer->user_data = this;

    this->__WFGoTask::dispatch();
    timer->start();
}

SubTask *__WFTimedGoTask::done() {
    if (this->callback) {
        this->callback(this);
    }
    return series_of(this)->pop();
}

void __WFTimedGoTask::handle(int state, int error) {
    if (--this->ref == 3) {
        this->state = state;
        this->error = error;
        this->subtask_done();
    }
    if (--this->ref == 0) {
        delete this;
    }
}

void __WFTimedGoTask::timer_callback(WFTimerTask *timer) {
    auto *task = static_cast<__WFTimedGoTask *>(timer->user_data);
    if (--task->ref == 3) {
        if (timer->get_state() == WFT_STATE_SUCCESS) {
            task->state = WFT_STATE_SYS_ERROR;
            task->error = ETIMEDOUT;
        } else {
            task->state = timer->get_state();
            task->error = timer->get_error();
        }
        task->subtask_done();
    }
    if (--task->ref == 0) {
        delete task; // 所有子任务完成, 销毁
    }
}