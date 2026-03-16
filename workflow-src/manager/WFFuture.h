//
// Created by ldk on 12/20/25.
//

#ifndef MYWORKFLOW_WFFUTURE_H
#define MYWORKFLOW_WFFUTURE_H

#include <future>
#include <chrono>
#include <utility>
#include "CommScheduler.h"
#include "WFGlobal.h"

template <typename RES>
class WFFuture {
public:
    explicit WFFuture(std::future<RES> &&fr) :
        future(std::move(fr)) {}

    WFFuture() = default;
    WFFuture(const WFFuture &) = delete;
    WFFuture(WFFuture &&move) = default;

    WFFuture &operator=(const WFFuture &) = delete;
    WFFuture &operator=(WFFuture &&move) = default;

    void wait() const;

    template <class REP, class PERIOD>
    std::future_status wait_for(const std::chrono::duration<REP, PERIOD> &time_duration) const;

    template <class CLOCK, class DURATION>
    std::future_status wait_until(const std::chrono::time_point<CLOCK, DURATION> &timeout_time) const;

    RES get() {
        this->wait();
        return this->future.get();
    }

    [[nodiscard]] bool valid() const { return this->future.valid(); }

private:
    std::future<RES> future;
};

template <typename RES>
class WFPromise {
public:
    WFPromise() = default;
    WFPromise(const WFPromise &promise) = delete;
    WFPromise(WFPromise &&move) = default;
    WFPromise &operator=(const WFPromise &promise) = delete;
    WFPromise &operator=(WFPromise &&move) = default;

    /**
     * @brief 获取关联的Future对象
     * @return WFFuture<RES> 生成的future
     * @note 每个promise只能调用一次
     */
    WFFuture<RES> get_future() {
        return WFFuture<RES>(this->promise.get_future());
    }

    /**
     * @brief 设置左值结果
     * @param value 左值引用
     * @throw future_error 如果已设置值
     */
    void set_value(const RES &value) { this->promise.set_value(value); }

    /**
     * @brief 设置右值结果
     * @param value 右值引用
     * @throw future_error 如果已设置值
     */
    void set_value(RES &&value) { this->promise.set_value(std::move(value)); }

private:
    std::promise<RES> promise;
};

// WFFuture阻塞等待
template <typename RES>
void WFFuture<RES>::wait() const {
    // 快速检查: 是否已就绪（非阻塞调用）
    if (this->future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        // 通知调度器: 当前线程进入同步等待状态
        int cookie = WFGlobal::sync_operation_begin();
        // 实际阻塞等待（期间线程可处理其他任务）
        this->future.wait();
        // 恢复线程的异步处理能力
        WFGlobal::sync_operation_end(cookie);
    }
}

// 带超时的等待实现
template <typename RES>
template <class REP, class PERIOD>
std::future_status WFFuture<RES>::wait_for(const std::chrono::duration<REP, PERIOD> &time_duration) const {
    std::future_status status = std::future_status::ready;
    // 快速检查未就绪
    if (this->future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        int cookie = WFGlobal::sync_operation_begin();
        // 实际带超时等待
        status = this->future.wait_for(time_duration);
        WFGlobal::sync_operation_end(cookie);
    }

    return status;
}

// 带截止时间的等待实现
template <typename RES>
template <class CLOCK, class DURATION>
std::future_status WFFuture<RES>::wait_until(const std::chrono::time_point<CLOCK, DURATION> &timeout_time) const {
    std::future_status status = std::future_status::ready;
    // 快速检查未就绪
    if (this->future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        int cookie = WFGlobal::sync_operation_begin();
        // 实际带截止时间等待
        status = this->future.wait_until(timeout_time);
        WFGlobal::sync_operation_end(cookie);
    }

    return status;
}

///// WFFuture<void> template specialization
/**
 * @brief void类型Future特化
 *
 * 解决void类型无返回值的特殊处理：
 * - 重写get()方法（不返回值）
 * - 保持等待语义
 */
template <>
inline void WFFuture<void>::get() {
    this->wait();
    this->future.get();
}

/**
 * @brief void类型Promise特化
 *
 * 适配void类型的无值设置：
 * - 仅提供无参set_value()
 * - 保持与通用模板一致的接口风格
 */
template <>
class WFPromise<void> {
public:
    WFPromise() = default;
    WFPromise(const WFPromise &promise) = delete;
    WFPromise(WFPromise &&move) = default;
    WFPromise &operator=(const WFPromise &promise) = delete;
    WFPromise &operator=(WFPromise &&move) = default;

    WFFuture<void> get_future() {
        return WFFuture<void>(this->promise.get_future());
    }

    /**
     * @brief 设置void类型结果（无值）
     *
     * 仅表示操作完成，不携带数据
     */
    void set_value() { this->promise.set_value(); }
    //	void set_value(const RES& value) { this->promise.set_value(value); }
    //	void set_value(RES&& value) { this->promise.set_value(std::move(value)); }

private:
    std::promise<void> promise; // void类型的底层promise
};

#endif //MYWORKFLOW_WFFUTURE_H