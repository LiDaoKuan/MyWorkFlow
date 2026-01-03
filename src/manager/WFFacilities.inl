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
    auto *pr = new WFPromise<void>(); // 手动分配，回调中释放
    auto fr = pr->get_future();
    // 创建定时器任务，__timer_future_callback完成时调用
    auto *task = WFTaskFactory::create_timer_task(microseconds, __timer_future_callback);

    task->user_data = pr; // 传递promise到回调
    task->start();        // 提交任务到调度器
    return fr;            // 返回可等待的future
}

/**
 * @brief 在指定队列执行计算任务
 *
 * 实现要点:
 *   - 使用std::forward实现完美转发
 *   - 任务创建后立即启动（fire-and-forget模式）
 *   - 计算任务在独立线程池执行，不阻塞IO线程
 *
 * 典型场景:
 *   WFFacilities::go("crypto", [](const string& data){
 *       return heavy_decrypt(data);
 *   }, encrypted_data);
 */
template <class FUNC, class... ARGS>
void WFFacilities::go(const std::string &queue_name, FUNC &&func, ARGS &&... args) {
    // 创建计算任务（内部使用std::bind+完美转发）
    WFTaskFactory::create_go_task(queue_name, std::forward<FUNC>(func), std::forward<ARGS>(args)...
        )->start(); // 立即启动
}

/**
 * @brief 同步网络请求（阻塞实现）
 *
 * 通过异步请求+立即等待实现，注意：
 *   - 会阻塞当前线程（禁止在IO线程调用！）
 *   - 自动处理重试逻辑（由底层task实现）
 *   - 返回完整结果（含状态/错误码）
 */
template <class REQ, class RESP>
WFFacilities::WFNetworkResult<RESP> WFFacilities::request(enum TransportType type, const std::string &url, REQ &&req, int retry_max) {
    // 阻塞等待异步请求完成
    return async_request<REQ, RESP>(type, url, std::forward<REQ>(req), retry_max).get();
}

/**
 * @brief 异步网络请求（非阻塞实现）
 *
 * 复杂度最高函数，处理:
 *   1. URL解析
 *   2. 传输类型设置
 *   3. 请求体绑定
 *   4. 重试策略
 *   5. 结果封装
 *
 * @tparam REQ 请求类型（如HttpRequest）
 * @tparam RESP 响应类型（如HttpResponse）
 * @param type 传输协议（TT_TCP/TT_UDP等）
 * @param url 目标地址
 * @param req 请求对象（移动语义）
 * @param retry_max 重试次数（-1=无限重试）
 *
 * @note 生命周期管理：
 *   - promise在回调中delete
 *   - 任务自动回收（框架保证）
 */
template <class REQ, class RESP>
WFFuture<WFFacilities::WFNetworkResult<RESP> > WFFacilities::async_request(enum TransportType type, const std::string &url, REQ &&req, int retry_max) {
    ParsedURI uri;
    // 创建promise/future
    auto *pr = new WFPromise<WFNetworkResult<RESP> >();
    auto fr = pr->get_future();

    // 创建复杂客户端任务（支持重试/超时/重定向）
    auto *task = new WFComplexClientTask<REQ, RESP>(retry_max, [pr](WFNetworkTask<REQ, RESP> *task) {
        WFNetworkResult<RESP> res;

        // 封装结果
        res.seqid = task->get_task_seq();   // 获取全局序列ID
        res.task_state = task->get_state(); // 任务状态
        res.task_error = task->get_error(); // 错误码

        // 仅当成功时移动响应（避免无效移动）
        if (res.task_state == WFT_STATE_SUCCESS) {
            res.resp = std::move(*task->get_resp());
        }
        // 设置future结果并清理资源
        pr->set_value(std::move(res));
        delete pr; // 匹配上方new, 防止泄漏
    });
    // 解析URL并初始化任务
    URIParser::parse(url, uri);
    task->init(std::move(uri));                // 转移URI所有权
    task->set_transport_type(type);            // 设置传输类型
    *task->get_req() = std::forward<REQ>(req); // 绑定请求体（移动语义优化）
    task->start();                             // 启动任务
    return fr;
}

/*
 * @brief 通用文件I/O模式
 *
 * 所有文件操作遵循相同模式:
 *   1. 创建promise/future
 *   2. 生成特定I/O任务
 *   3. 绑定__xxx_future_callback
 *   4. 传递promise到user_data
 *   5. 启动任务
 *
 * @note 关键设计:
 *   - 不管理文件描述符生命周期（调用者负责open/close）
 *   - 错误处理统一在回调中完成
 *   - 使用原始指针（buf/iov）避免拷贝开销
 */

// async_pread 实现
inline WFFuture<ssize_t> WFFacilities::async_pread(int fd, void *buf, size_t count, off_t offset) {
    auto *pr = new WFPromise<ssize_t>();
    auto fr = pr->get_future();
    auto *task = WFTaskFactory::create_pread_task(fd, buf, count, offset, __fio_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

// async_pwrite 实现（与pread对称）
inline WFFuture<ssize_t> WFFacilities::async_pwrite(int fd, const void *buf, size_t count, off_t offset) {
    auto *pr = new WFPromise<ssize_t>();
    auto fr = pr->get_future();
    // 创建pread任务（底层使用io_uring或aio）
    auto *task = WFTaskFactory::create_pwrite_task(fd, buf, count, offset, __fio_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

// async_preadv 实现（支持分散读）
inline WFFuture<ssize_t> WFFacilities::async_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    auto *pr = new WFPromise<ssize_t>();
    auto fr = pr->get_future();
    auto *task = WFTaskFactory::create_preadv_task(fd, iov, iovcnt, offset, __fvio_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

// async_pwritev 实现（支持集中写）
inline WFFuture<ssize_t> WFFacilities::async_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset) {
    auto *pr = new WFPromise<ssize_t>();
    auto fr = pr->get_future();
    auto *task = WFTaskFactory::create_pwritev_task(fd, iov, iovcnt, offset, __fvio_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

// async_fsync 实现（元数据+数据同步）
inline WFFuture<int> WFFacilities::async_fsync(int fd) {
    auto *pr = new WFPromise<int>();
    auto fr = pr->get_future();
    // 创建fsync任务（底层使用fsync系统调用）
    auto *task = WFTaskFactory::create_fsync_task(fd, __fsync_future_callback);

    task->user_data = pr;
    task->start();
    return fr;
}

// async_fdatasync 实现（仅数据同步，性能更高）
inline WFFuture<int> WFFacilities::async_fdatasync(int fd) {
    auto *pr = new WFPromise<int>();
    auto fr = pr->get_future();
    // 创建fdatasync任务
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
    auto *pr = static_cast<WFPromise<void> *>(task->user_data); // 获取任务创建时传入的promise

    pr->set_value();
    delete pr; // 必须delete否则会内存泄漏
}

/**
 * @brief 常规文件I/O回调
 *
 * 处理pread/pwrite等操作结果
 * @param task 完成的file I/O task
 */
inline void WFFacilities::__fio_future_callback(WFFileIOTask *task) {
    auto *pr = static_cast<WFPromise<ssize_t> *>(task->user_data); // 获取任务创建时传入的promise

    pr->set_value(task->get_retval());
    delete pr; // 必须delete否则会内存泄漏
}

/**
 * @brief 向量文件I/O回调(iovec)
 *
 * 处理preadv/pwritev等操作结果
 * @param task 完成的file vector I/O task
 */
inline void WFFacilities::__fvio_future_callback(WFFileVIOTask *task) {
    auto *pr = static_cast<WFPromise<ssize_t> *>(task->user_data); // 获取任务创建时传入的promise

    pr->set_value(task->get_retval());
    delete pr; // 必须delete否则会内存泄漏
}

/**
 * @brief 文件同步操作回调
 *
 * 处理fsync/fdatasync结果
 * @param task 完成的file sync task
 */
inline void WFFacilities::__fsync_future_callback(WFFileSyncTask *task) {
    auto *pr = static_cast<WFPromise<int> *>(task->user_data); // 获取任务创建时传入的promise

    pr->set_value(task->get_retval()); // 设置I/O操作结果
    delete pr;                         // 必须delete否则会内存泄漏
}

/**
 * 双重状态设计:
 *   - nleft > 0: 正常计数模式
 *   - nleft = -1: 空状态（立即完成）
 *
 * @param n 初始任务数
 * @note 当n<=0时, 所有wait()立即返回
 */
inline WFFacilities::WaitGroup::WaitGroup(int n) :
    nleft(n) {
    if (n <= 0) {
        this->nleft = -1; // 标记为空状态
        return;
    }

    // 创建promise/future
    auto *pr = new WFPromise<void>();
    // 创建计时器任务（初始计数1）
    this->task = WFTaskFactory::create_counter_task(1, __wait_group_callback);
    this->future = pr->get_future();
    this->task->user_data = pr; // 绑定promise
    this->task->start();        // 启动计数器
}

inline WFFacilities::WaitGroup::~WaitGroup() {
    if (this->nleft > 0) {
        this->task->count(); // 触发计数器完成
    }
}

/**
 * @brief 无超时等待
 *
 * 优化点:
 *   - 空状态(nleft=-1)直接返回
 *   - 避免不必要的future操作
 */
inline void WFFacilities::WaitGroup::wait() const {
    if (this->nleft < 0) {
        return;
    }

    this->future.wait();
}

/**
 * @brief 带超时的等待
 *
 * 精细控制:
 *   - 负超时 = 无限等待
 *   - 0超时 = 立即返回状态
 *   - 正超时 = 精确毫秒控制
 *
 * @return std::future_status 等待结果
 */
inline std::future_status WFFacilities::WaitGroup::wait(int timeout) const {
    if (this->nleft < 0) {
        return std::future_status::ready;
    }

    if (timeout < 0) {
        this->future.wait(); // 无限等待
        return std::future_status::ready;
    }

    // 有限超时等待
    return this->future.wait_for(std::chrono::milliseconds(timeout));
}

/**
 * @brief 原子增加计数器
 *
 * 线程安全实现:
 *   - 使用原子操作修改nleft
 *   - 当计数归零时触发完成
 *
 * @warning 在wait()后调用是未定义行为
 */
inline void WFFacilities::WaitGroup::add(int n) {
    int new_val = (this->nleft += n); // 原子加
    if (new_val == 0)                 // 恰好归零
    {
        this->task->count(); // 触发计数器完成
    }
}

// done()是add(-1)的快捷方式
inline void WFFacilities::WaitGroup::done() {
    this->add(-1);
}

/**
 * @brief WaitGroup内部回调
 *
 * 关键职责:
 *   - 当计数器归零时唤醒所有等待者
 *   - 清理promise资源
 */
inline void WFFacilities::WaitGroup::__wait_group_callback(WFCounterTask *task) {
    auto *pr = static_cast<WFPromise<void> *>(task->user_data);

    pr->set_value(); // 设置空值唤醒等待者
    delete pr;       // 释放资源
}