//
// Created by ldk on 12/20/25.
//

/*
  Copyright (c) 2020 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Li Yingxin (liyingxin@sogou-inc.com)
           Wu Jiaxu (wujiaxu@sogou-inc.com)
*/

/**
 * @brief 同步微秒级睡眠（阻塞实现）
 *
 * 通过异步睡眠+立即等待实现，本质是：
 *   1. 创建定时器任务
 *   2. 阻塞当前线程直到任务完成
 *
 * @warning 严重性能警告:
 *   - 在IO线程调用会导致整个Reactor停摆
 *   - 仅适用于初始化/销毁等非关键路径
 */
inline void WFFacilities::usleep(unsigned int microseconds) {
    async_usleep(microseconds).get();
}

/**
 * @brief 异步微秒级睡眠（非阻塞实现）
 *
 * 核心流程:
 *   1. 创建promise/future对
 *   2. 构建定时器任务（底层基于timerfd/kevent）
 *   3. 将promise绑定到任务user_data
 *   4. 启动任务并返回future
 *
 * @note 资源管理: promise在回调中delete, 避免内存泄漏
 */
inline WFFuture<void> WFFacilities::async_usleep(unsigned int microseconds) {
    auto *pr = new WFPromise<void>();
    auto fr = pr->get_future();
    auto *task = WFTaskFactory::create_timer_task(microseconds, __timer_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

template <class FUNC, class... ARGS>
void WFFacilities::go(const std::string &queue_name, FUNC &&func, ARGS &&... args) {
    WFTaskFactory::create_go_task(queue_name, std::forward<FUNC>(func), std::forward<ARGS>(args)...)->start();
}

template <class REQ, class RESP>
WFFacilities::WFNetworkResult<RESP> WFFacilities::request(enum TransportType type, const std::string &url, REQ &&req, int retry_max) {
    return async_request<REQ, RESP>(type, url, std::forward<REQ>(req), retry_max).get();
}

template <class REQ, class RESP>
WFFuture<WFFacilities::WFNetworkResult<RESP> > WFFacilities::async_request(enum TransportType type, const std::string &url, REQ &&req, int retry_max) {
    ParsedURI uri;
    auto *pr = new WFPromise<WFNetworkResult<RESP> >();
    auto fr = pr->get_future();
    auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, [pr](WFNetworkTask<REQ, RESP> *task) {
        WFNetworkResult<RESP> res;

        res.seqid = task->get_task_seq();
        res.task_state = task->get_state();
        res.task_error = task->get_error();
        if (res.task_state == WFT_STATE_SUCCESS) {
            res.resp = std::move(*task->get_resp());
        }

        pr->set_value(std::move(res));
        delete pr;
    });

    URIParser::parse(url, uri);
    task->init(std::move(uri));
    task->set_transport_type(type);
    *task->get_req() = std::forward<REQ>(req);
    task->start();
    return fr;
}

inline WFFuture<ssize_t> WFFacilities::async_pread(int fd, void *buf, size_t count, off_t offset) {
    auto *pr = new WFPromise<ssize_t>();
    auto fr = pr->get_future();
    auto *task = WFTaskFactory::create_pread_task(fd, buf, count, offset, __fio_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

inline WFFuture<ssize_t> WFFacilities::async_pwrite(int fd, const void *buf, size_t count, off_t offset) {
    auto *pr = new WFPromise<ssize_t>();
    auto fr = pr->get_future();
    auto *task = WFTaskFactory::create_pwrite_task(fd, buf, count, offset, __fio_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

inline WFFuture<ssize_t> WFFacilities::async_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    auto *pr = new WFPromise<ssize_t>();
    auto fr = pr->get_future();
    auto *task = WFTaskFactory::create_preadv_task(fd, iov, iovcnt, offset, __fvio_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

inline WFFuture<ssize_t> WFFacilities::async_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    auto *pr = new WFPromise<ssize_t>();
    auto fr = pr->get_future();
    auto *task = WFTaskFactory::create_pwritev_task(fd, iov, iovcnt, offset, __fvio_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

inline WFFuture<int> WFFacilities::async_fsync(int fd) {
    auto *pr = new WFPromise<int>();
    auto fr = pr->get_future();
    auto *task = WFTaskFactory::create_fsync_task(fd, __fsync_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

inline WFFuture<int> WFFacilities::async_fdatasync(int fd) {
    auto *pr = new WFPromise<int>();
    auto fr = pr->get_future();
    auto *task = WFTaskFactory::create_fdsync_task(fd, __fsync_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

/**
 * @brief 定时器任务回调
 *
 * 将timer task结果转换为future<void>
 * @param task 完成的timer task
 */
inline void WFFacilities::__timer_future_callback(WFTimerTask *task) {
    auto *pr = static_cast<WFPromise<void> *>(task->user_data);

    pr->set_value();
    delete pr;
}

/**
 * @brief 常规文件I/O回调
 *
 * 处理pread/pwrite等操作结果
 * @param task 完成的file I/O task
 */
inline void WFFacilities::__fio_future_callback(WFFileIOTask *task) {
    auto *pr = static_cast<WFPromise<ssize_t> *>(task->user_data);

    pr->set_value(task->get_retval());
    delete pr;
}

/**
 * @brief 向量文件I/O回调
 *
 * 处理preadv/pwritev等操作结果
 * @param task 完成的file vector I/O task
 */
inline void WFFacilities::__fvio_future_callback(WFFileVIOTask *task) {
    auto *pr = static_cast<WFPromise<ssize_t> *>(task->user_data);

    pr->set_value(task->get_retval());
    delete pr;
}

/**
 * @brief 文件同步操作回调
 *
 * 处理fsync/fdatasync结果
 * @param task 完成的file sync task
 */
inline void WFFacilities::__fsync_future_callback(WFFileSyncTask *task) {
    auto *pr = static_cast<WFPromise<int> *>(task->user_data);

    pr->set_value(task->get_retval());
    delete pr;
}

inline WFFacilities::WaitGroup::WaitGroup(int n) :
    nleft(n) {
    if (n <= 0) {
        this->nleft = -1;
        return;
    }

    auto *pr = new WFPromise<void>();

    this->task = WFTaskFactory::create_counter_task(1, __wait_group_callback);
    this->future = pr->get_future();
    this->task->user_data = pr;
    this->task->start();
}

inline WFFacilities::WaitGroup::~WaitGroup() {
    if (this->nleft > 0) {
        this->task->count();
    }
}

inline void WFFacilities::WaitGroup::wait() const {
    if (this->nleft < 0) {
        return;
    }

    this->future.wait();
}

inline std::future_status WFFacilities::WaitGroup::wait(int timeout) const {
    if (this->nleft < 0) return std::future_status::ready;

    if (timeout < 0) {
        this->future.wait();
        return std::future_status::ready;
    }

    return this->future.wait_for(std::chrono::milliseconds(timeout));
}

inline void WFFacilities::WaitGroup::add(int n) {
    if ((this->nleft += n) == 0) {
        this->task->count();
    }
}

inline void WFFacilities::WaitGroup::done() {
    this->add(-1);
}

inline void WFFacilities::WaitGroup::__wait_group_callback(WFCounterTask *task) {
    auto *pr = static_cast<WFPromise<void> *>(task->user_data);

    pr->set_value();
    delete pr;
}