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
    WFFuture(std::future<RES> &&fr) :
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

    bool valid() const { return this->future.valid(); }

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

    WFFuture<RES> get_future() {
        return WFFuture<RES>(this->promise.get_future());
    }

    void set_value(const RES &value) { this->promise.set_value(value); }
    void set_value(RES &&value) { this->promise.set_value(std::move(value)); }

private:
    std::promise<RES> promise;
};

template <typename RES>
void WFFuture<RES>::wait() const {
    if (this->future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        int cookie = WFGlobal::sync_operation_begin();
        this->future.wait();
        WFGlobal::sync_operation_end(cookie);
    }
}

template <typename RES>
template <class REP, class PERIOD>
std::future_status WFFuture<RES>::wait_for(const std::chrono::duration<REP, PERIOD> &time_duration) const {
    std::future_status status = std::future_status::ready;

    if (this->future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        int cookie = WFGlobal::sync_operation_begin();
        status = this->future.wait_for(time_duration);
        WFGlobal::sync_operation_end(cookie);
    }

    return status;
}

template <typename RES>
template <class CLOCK, class DURATION>
std::future_status WFFuture<RES>::wait_until(const std::chrono::time_point<CLOCK, DURATION> &timeout_time) const {
    std::future_status status = std::future_status::ready;

    if (this->future.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
        int cookie = WFGlobal::sync_operation_begin();
        status = this->future.wait_until(timeout_time);
        WFGlobal::sync_operation_end(cookie);
    }

    return status;
}

///// WFFuture<void> template specialization
template <>
inline void WFFuture<void>::get() {
    this->wait();
    this->future.get();
}

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

    void set_value() { this->promise.set_value(); }
    //	void set_value(const RES& value) { this->promise.set_value(value); }
    //	void set_value(RES&& value) { this->promise.set_value(std::move(value)); }

private:
    std::promise<void> promise;
};

#endif //MYWORKFLOW_WFFUTURE_H