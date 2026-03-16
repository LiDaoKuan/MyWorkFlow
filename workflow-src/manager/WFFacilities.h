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
           Xie Han (xiehan@sogou-inc.com)
*/

#ifndef MYWORKFLOW_WFFACILITIES_H
#define MYWORKFLOW_WFFACILITIES_H

#include <cassert>
#include "WFFuture.h"
#include "WFTaskFactory.h"

/**
 * @file WFFacilities.h
 */

/**
 * @brief Workflow核心工具集
 *
 * 本类提供高层抽象工具，简化异步编程：
 * 1. 同步/异步原语封装（睡眠、文件I/O）
 * 2. 网络请求统一接口
 * 3. 任务编排工具（WaitGroup）
 * 4. 无栈协程友好设计
 *
 * 设计原则：
 * - 保持接口简洁（隐藏底层任务细节）
 * - 统一错误处理模型
 * - 资源自动管理（RAII）
 */
class WFFacilities {
public:
    /**
     * @brief 同步微秒级睡眠
     *
     * @warning 阻塞当前线程！仅适用于:
     *   - 调试场景
     *   - 非IO线程的短暂等待
     *   - 与遗留同步代码交互
     *
     * @param microseconds 等待微秒数
     */
    static void usleep(unsigned int microseconds);

    /**
     * @brief 异步微秒级睡眠
     *
     * 非阻塞实现, 返回future对象:
     *   auto fut = WFFacilities::async_usleep(1000);
     *   fut.wait(); // 同步等待
     *   fut.get();  // 获取结果（总是成功）
     *
     * @param microseconds 等待微秒数
     * @return WFFuture<void> 可等待的future对象
     */
    static WFFuture<void> async_usleep(unsigned int microseconds);

public:
    /**
     * @brief 在指定计算队列执行函数
     *
     * 核心价值:
     *   - 将CPU密集型任务卸载到专用队列
     *   - 避免阻塞IO线程
     *   - 实现资源隔离（如不同业务使用不同队列）
     *
     * 使用示例:
     *   WFFacilities::go("image_process", []{  <CPU密集型任务逻辑>  });
     *
     * @tparam FUNC 可调用对象类型
     * @tparam ARGS 参数类型包
     * @param queue_name 计算队列名称（空字符串=默认队列）
     * @param func 待执行函数
     * @param args 函数参数（完美转发）
     */
    template <class FUNC, class... ARGS>
    static void go(const std::string &queue_name, FUNC &&func, ARGS &&... args);

public:
    /**
     * @brief 网络请求结果封装
     *
     * 统一返回结构，包含：
     *   - 响应消息（RESP类型，如ProtocolMessage）
     *   - 序列ID（用于追踪请求链）
     *   - 任务状态（WFT_STATE_SUCCESS等）
     *   - 系统错误码（errno）
     *
     * @tparam RESP 响应类型（通常为协议消息类）
     */
    template <class RESP>
    struct WFNetworkResult {
        RESP resp;       // 协议响应对象
        long long seqid; // 全局唯一序列ID
        int task_state;  // 任务最终状态
        int task_error;  // 错误码（非0表示失败）
    };

    /**
     * @brief 同步网络请求
     *
     * 阻塞直到请求完成，自动处理重试：
     *   auto result = WFFacilities::request(TT_TCP, "http://example.com", req, 2);
     *   if (result.task_state == WFT_STATE_SUCCESS) {  <处理响应>  }
     *
     * @tparam REQ 请求类型（通常为ProtocolMessage）
     * @tparam RESP 响应类型
     * @param type 传输类型（TT_TCP/TT_UDP/TT_SCTP等）
     * @param url 目标URL（格式：scheme://host:port/path）
     * @param req 请求对象（移动语义）
     * @param retry_max 最大重试次数（-1=无限重试）
     * @return WFNetworkResult<RESP> 封装的结果
     */
    template <class REQ, class RESP>
    static WFNetworkResult<RESP> request(enum TransportType type, const std::string &url, REQ &&req, int retry_max);

    /**
     * @brief 异步网络请求
     *
     * 非阻塞实现，返回future：
     *   auto fut = WFFacilities::async_request(...);
     *   fut.wait();
     *   auto result = fut.get();
     *
     * @tparam REQ 请求类型
     * @tparam RESP 响应类型
     * @param type 传输类型
     * @param url 目标URL
     * @param req 请求对象
     * @param retry_max 最大重试次数
     * @return WFFuture<WFNetworkResult<RESP>> 可等待的future
     */
    template <class REQ, class RESP>
    static WFFuture<WFNetworkResult<RESP> > async_request(enum TransportType type, const std::string &url, REQ &&req, int retry_max);

public:
    /*
     * @name 异步文件I/O操作
     *
     * 统一返回future<ssize_t>：
     *   - 正值：成功操作的字节数
     *   - -1：系统错误（通过errno获取详情）
     *   - 其他负值：框架内部错误
     *
     * @note 所有操作基于文件描述符，不管理FD生命周期
     */

    /**
     * @brief 异步pread（带偏移量读取）
     * @param fd 文件描述符
     * @param buf 读取缓冲区
     * @param count 读取字节数
     * @param offset 文件偏移量
     * @return WFFuture<ssize_t> 结果future
     */
    static WFFuture<ssize_t> async_pread(int fd, void *buf, size_t count, off_t offset);

    /**
     * @brief 异步pwrite（带偏移量写入）
     * @param fd 文件描述符
     * @param buf 写入缓冲区
     * @param count 写入字节数
     * @param offset 文件偏移量
     * @return WFFuture<ssize_t> 结果future
     */
    static WFFuture<ssize_t> async_pwrite(int fd, const void *buf, size_t count, off_t offset);

    /**
     * @brief 异步preadv（分散读）
     * @param fd 文件描述符
     * @param iov iovec数组
     * @param iovcnt 数组长度
     * @param offset 文件偏移量
     * @return WFFuture<ssize_t> 结果future
     */
    static WFFuture<ssize_t> async_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);

    /**
     * @brief 异步pwritev（集中写）
     * @param fd 文件描述符
     * @param iov iovec数组
     * @param iovcnt 数组长度
     * @param offset 文件偏移量
     * @return WFFuture<ssize_t> 结果future
     */
    static WFFuture<ssize_t> async_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);

    /**
     * @brief 异步fsync（数据+元数据同步）
     * @param fd 文件描述符
     * @return WFFuture<int> 0=成功，-1=失败
     */
    static WFFuture<int> async_fsync(int fd);

    /**
     * @brief 异步fdatasync（仅数据同步）
     * @param fd 文件描述符
     * @return WFFuture<int> 0=成功，-1=失败
     */
    static WFFuture<int> async_fdatasync(int fd);

public:
    /**
     * @brief 任务同步原语（类似Go的WaitGroup）
     *
     * 核心能力:
     *   - 等待任意数量的异步任务完成
     *   - 支持超时控制
     *   - 线程安全
     *
     * 典型用例：
     *   WFFacilities::WaitGroup wg(3);  // 需等待3个任务
     *   start_async_task1([&]{ wg.done(); });
     *   start_async_task2([&]{ wg.done(); });
     *   start_async_task3([&]{ wg.done(); });
     *   wg.wait();  // 阻塞直到所有任务完成
     */
    class WaitGroup {
    public:
        /**
         * @param n 初始计数器值（需等待的任务数）
         * @note 若n<=0，wait()会立即返回
         */
        explicit WaitGroup(int n);

        /**
         * @warning 如果析构时计数器未归零:
         *   - 阻塞直到所有任务完成
         *   - 避免悬挂指针（内部counter task需安全回收）
         */
        ~WaitGroup();

        /**
         * @brief 阻塞等待所有任务完成
         *
         * @note 无超时控制, 可能永久阻塞
         */
        void wait() const;

        /**
         * @brief 带超时的等待
         *
         * @param timeout 毫秒级超时
         * @return std::future_status
         *   - ready：所有任务完成
         *   - timeout：超时
         *   - deferred：永不返回此状态
         */
        [[nodiscard]] std::future_status wait(int timeout) const;

        /**
         * @brief 增加计数器
         *
         * @param n 增加值（可为负数）
         * @warning 在wait()后调用会导致未定义行为
         */
        void add(int n);

        /**
         * @brief 减少计数器（单个任务完成）
         *
         * 等价于 add(-1)
         * @warning 当计数器为0时调用会导致未定义行为
         */
        void done();

    private:
        /**
         * @brief 内部回调函数
         *
         * 当counter task完成时触发，唤醒所有等待者
         * @param task 完成的counter task
         */
        static void __wait_group_callback(WFCounterTask *task);

        std::atomic<int> nleft; // 剩余任务计数
        WFCounterTask *task;    // 底层计数器任务
        WFFuture<void> future;  // 用于等待的future
    };

private:
    /* 内部回调函数（连接底层任务与future） */

    static void __timer_future_callback(WFTimerTask *task);

    static void __fio_future_callback(WFFileIOTask *task);

    static void __fvio_future_callback(WFFileVIOTask *task);

    static void __fsync_future_callback(WFFileSyncTask *task);
};

#include "WFFacilities.inl" /* 实现分离: 内联函数放在单独文件避免头文件膨胀 */

#endif //MYWORKFLOW_WFFACILITIES_H