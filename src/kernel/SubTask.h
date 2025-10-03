//
// Created by ldk on 9/28/25.
//

#ifndef MYWORKFLOW_SUBTASK_H
#define MYWORKFLOW_SUBTASK_H

#include <cstddef>

class SubTask {
public:
    // 任务启动接口。派生类必须实现，包含任务的主要执行逻辑。
    // 推测该方法应该是非阻塞的
    virtual void dispatch() = 0;

private:
    /**@brief 任务完成回调. 框架在任务完成后自动调用，用于通知或链式触发后续任务
     * @return 下一个要执行的任务的指针。具体返回父任务，还是子任务，亦或是兄弟任务。
     *          由具体的业务逻辑和任务流的组织方式确定，而并非一成不变
     */
    virtual SubTask *done() = 0;

protected:
    // 完成通知机制。子任务完成后应调用此函数，它会触发done()并通知父任务。
    void subtask_done();

public:
    [[nodiscard]] void *get_pointer() const { return pointer_; }

    void set_pointer(void *pointer) { this->pointer_ = pointer; }

private:
    // 关键枢纽。指向父任务（通常是ParallelTask），用于在子任务完成时向上回调。
    class ParallelTask *parent_;
    // 用户数据指针. 提供get/set_pointer()方法，让任务能携带任意用户数据
    void *pointer_;
    /* 使用pointer指针注意事项:
     * 1. 你需要确保在回调函数中，将 void*指针转换回它原本的、正确的类型
     * 2. pointer指针指向的内存如果是由用户动态创建的，那也应该由用户动态释放（谁创建，谁释放）*/

public:
    SubTask() {
        this->parent_ = nullptr;
        this->pointer_ = nullptr;
    }

    virtual ~SubTask() = default;
    friend class ParallelTask; // 方便ParallelTask访问SubTask的私有成员
};

// parallel: 平行
// 并行任务
class ParallelTask : public SubTask {
public:
    /**dispatch()方法是 ParallelTask 的发动机。
     * 主要实现 子任务的派发和执行
     */
    void dispatch() override;

protected:
    // 子任务数组指针: 指向一个由子任务指针构成的数组，是并行执行的实体
    SubTask **subtasks;
    // 子任务数量: 明确本次并行操作需要管理的子任务总数
    size_t subtask_nr;

private:
    /**剩余任务计数器: 用于同步. 追踪尚未完成的子任务数量
     * nleft初始值==subtask_nr, 每完成一个子任务， nleft-1
     * 当nleft==0时，意味着所有子任务都已经完成
     * 这正是 CountDownLatch（闭锁）同步模式的经典实现
     */
    size_t nleft;

public:
    ParallelTask(SubTask **subtasks_, size_t n)
        : SubTask() {
        this->subtasks = subtasks_;
        this->subtask_nr = n;
        this->nleft = n;
    }

    ~ParallelTask() override = default;
    // ParallelTask和SubTask互为友元类
    friend class SubTask;
};

#endif //MYWORKFLOW_SUBTASK_H