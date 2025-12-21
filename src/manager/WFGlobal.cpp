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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
           Xie Han (xiehan@sogou-inc.com)
           Liu Kai (liukaidx@sogou-inc.com)
*/

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <csignal>
#include <pthread.h>
#include <cstdio>
#include <cctype>
#include <string>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <ranges>
#include <openssl/ssl.h>
#if OPENSSL_VERSION_NUMBER < 0x10100000L
# include <openssl/err.h>
# include <openssl/engine.h>
# include <openssl/conf.h>
# include <openssl/crypto.h>
#endif
#include "CommScheduler.h"
#include "Executor.h"
#include "WFResourcePool.h"
#include "WFTaskError.h"
#include "WFDnsClient.h"
#include "WFGlobal.h"
#include "URIParser.h"

class __WFGlobal {
public:
    static __WFGlobal *get_instance() {
        static __WFGlobal kInstance;
        return &kInstance;
    }

    const char *get_default_port(const std::string &scheme) {
        // 先查询内置的静态协议端口映射
        const auto it = static_scheme_port_.find(scheme);
        if (it != static_scheme_port_.end()) {
            return it->second;
        }

        // 再查询用户动态注册的协议端口映射（需要加锁）
        const char *port = nullptr;
        user_scheme_port_mutex_.lock();
        const auto it2 = user_scheme_port_.find(scheme);
        if (it2 != user_scheme_port_.end()) {
            port = it2->second.c_str();
        }
        user_scheme_port_mutex_.unlock();

        return port;
    }

    /**
     * @brief      注册自定义协议的端口号
     * @param[in]  scheme  协议名称
     * @param[in]  port    对应的端口号
     * @note       会覆盖已存在的相同协议注册
     * @warning    内置协议（http/https等）的注册会被忽略（在WFGlobal层面限制）
     */
    void register_scheme_port(const std::string &scheme, unsigned short port) {
        user_scheme_port_mutex_.lock();
        user_scheme_port_[scheme] = std::to_string(port);
        user_scheme_port_mutex_.unlock();
    }

    /**
     * @brief   开始同步操作
     * @details 用于管理同步任务（如WFTaskFactory::create_sync_task）的资源分配
     *          当同步操作数超过历史峰值时, 自动增加handler线程
     * @note    必须与 sync_operation_end 成对调用
     */
    void sync_operation_begin() {
        bool inc;

        sync_mutex_.lock();
        inc = (++sync_count_ > sync_max_); // 更新同步操作计数器
        if (inc) {
            sync_max_ = sync_count_; // 更新历史峰值
        }

        sync_mutex_.unlock();
        if (inc) {
            WFGlobal::increase_handler_thread(); // 增加处理线程以应对负载
        }
    }

    /**
     * @brief   结束同步操作
     * @details 当同步操作数量显著减少时, 回收多余的handler线程
     *          采用滞后策略: 当当前数量小于峰值一半时, 回收多余线程
     * @note    必须与 sync_operation_begin 成对调用
     */
    void sync_operation_end() {
        int dec = 0;

        sync_mutex_.lock();
        // 检查是否可以减少线程: 当活跃同步数低于峰值的一半时
        if (--sync_count_ < (sync_max_ + 1) / 2) {
            // 计算可回收的线程数：(sync_max_ - sync_count_) - sync_count_
            // 即保留约2*sync_count_的峰值容量
            dec = sync_max_ - 2 * sync_count_;
            sync_max_ -= dec; // 降低峰值
        }
        sync_mutex_.unlock();
        // 逐步回收线程资源
        while (dec > 0) {
            WFGlobal::decrease_handler_thread();
            dec--;
        }
    }

private:
    __WFGlobal();

private:
    std::unordered_map<std::string, const char *> static_scheme_port_; // 内置协议与端口的映射表（只读？无需加锁访问）
    std::unordered_map<std::string, std::string> user_scheme_port_;    // 用户注册的协议与端口映射表（需互斥访问）
    std::mutex user_scheme_port_mutex_;                                // 保护用户协议映射表的互斥锁
    std::mutex sync_mutex_;                                            // 保护同步操作计数器的互斥锁
    int sync_count_;                                                   // 当前活跃的同步操作数量
    int sync_max_;                                                     // 历史同步操作峰值（用于线程资源弹性伸缩）
};

__WFGlobal::__WFGlobal() {
    static_scheme_port_["dns"] = "53";
    static_scheme_port_["Dns"] = "53";
    static_scheme_port_["DNS"] = "53";

    static_scheme_port_["dnss"] = "853";
    static_scheme_port_["Dnss"] = "853";
    static_scheme_port_["DNSs"] = "853";
    static_scheme_port_["DNSS"] = "853";

    static_scheme_port_["http"] = "80";
    static_scheme_port_["Http"] = "80";
    static_scheme_port_["HTTP"] = "80";

    static_scheme_port_["https"] = "443";
    static_scheme_port_["Https"] = "443";
    static_scheme_port_["HTTPs"] = "443";
    static_scheme_port_["HTTPS"] = "443";

    static_scheme_port_["redis"] = "6379";
    static_scheme_port_["Redis"] = "6379";
    static_scheme_port_["REDIS"] = "6379";

    static_scheme_port_["rediss"] = "6379";
    static_scheme_port_["Rediss"] = "6379";
    static_scheme_port_["REDISs"] = "6379";
    static_scheme_port_["REDISS"] = "6379";

    static_scheme_port_["mysql"] = "3306";
    static_scheme_port_["Mysql"] = "3306";
    static_scheme_port_["MySql"] = "3306";
    static_scheme_port_["MySQL"] = "3306";
    static_scheme_port_["MYSQL"] = "3306";

    static_scheme_port_["mysqls"] = "3306";
    static_scheme_port_["Mysqls"] = "3306";
    static_scheme_port_["MySqls"] = "3306";
    static_scheme_port_["MySQLs"] = "3306";
    static_scheme_port_["MYSQLs"] = "3306";
    static_scheme_port_["MYSQLS"] = "3306";

    static_scheme_port_["kafka"] = "9092";
    static_scheme_port_["Kafka"] = "9092";
    static_scheme_port_["KAFKA"] = "9092";

    static_scheme_port_["kafkas"] = "9093";
    static_scheme_port_["Kafkas"] = "9093";
    static_scheme_port_["KAFKAs"] = "9093";
    static_scheme_port_["KAFKAS"] = "9093";

    sync_count_ = 0;
    sync_max_ = 0;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static std::mutex *__ssl_mutex;

static void ssl_locking_callback(int mode, int type, const char *file, int line) {
    if (mode & CRYPTO_LOCK) __ssl_mutex[type].lock();
    else if (mode & CRYPTO_UNLOCK) __ssl_mutex[type].unlock();
}
#endif

/**
 * @brief   SSL/TLS资源管理单例类
 * @details 负责OpenSSL库的全局初始化、客户端上下文管理及线程安全配置
 * @note    内部使用，外部应通过WFGlobal::get_ssl_client_ctx()等接口访问
 */
class __SSLManager {
public:
    static __SSLManager *get_instance() {
        static __SSLManager kInstance;
        return &kInstance;
    }

    /**
     * @brief   获取预初始化的SSL客户端上下文
     * @return  全局共享的客户端SSL上下文指针
     * @note    返回值不应被释放, 由单例生命周期管理
     * @warning 此上下文为全局共享, 不应修改其配置
     */
    [[nodiscard]] SSL_CTX *get_ssl_client_ctx() const { return ssl_client_ctx_; }

    /**
     * @brief   创建新的SSL服务器上下文
     * @return  新分配的服务器SSL上下文指针
     * @note    调用者负责释放返回的上下文（通过SSL_CTX_free）
     * @warning 每次调用创建独立上下文, 适合不同虚拟主机/证书配置
     */
    SSL_CTX *new_ssl_server_ctx() { return SSL_CTX_new(SSLv23_server_method()); }

private:
    /**
     * @brief   私有构造函数（单例初始化）
     * @details 执行OpenSSL库初始化和全局资源分配
     *          针对不同OpenSSL版本采用不同初始化策略
     * @warning 构造失败时（如SSL_CTX_new返回nullptr）会直接终止程序
     */
    __SSLManager() {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        // 旧版OpenSSL（<1.1.0）需要手动配置线程安全机制
        __ssl_mutex = new std::mutex[CRYPTO_num_locks()];  // 创建足够的互斥锁
        CRYPTO_set_locking_callback(ssl_locking_callback); // 设置锁回调函数
        SSL_library_init();                                // 初始化SSL库
        SSL_load_error_strings();                          // 加载错误字符串
        // 注意: 以下被注释的函数已过时或由上述函数替代
        //ERR_load_crypto_strings();
        //OpenSSL_add_all_algorithms();
#endif

        // 创建客户端SSL上下文（SSLv23_method支持协议协商）
        ssl_client_ctx_ = SSL_CTX_new(SSLv23_client_method());
        if (ssl_client_ctx_ == nullptr) {
            // 上下文创建失败通常意味着OpenSSL初始化问题
            // 由于SSL是核心功能, 直接终止比继续运行更安全
            abort();
        }
    }

    ~__SSLManager() {
        SSL_CTX_free(ssl_client_ctx_);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        //free ssl to avoid memory leak
        FIPS_mode_set(0); // 禁用FIPS模式

        // 移除线程安全回调
        CRYPTO_set_locking_callback(NULL);
# ifdef CRYPTO_LOCK_ECDH
        CRYPTO_THREADID_set_callback(NULL); // OpenSSL 1.0.0+
# else
        CRYPTO_set_id_callback(NULL); // OpenSSL 0.9.8
# endif
        // 逐步清理OpenSSL各子系统
        ENGINE_cleanup();       // 清理ENGINE API
        CONF_modules_unload(1); // 卸载配置模块
        ERR_free_strings();     // 释放错误字符串
        EVP_cleanup();          // 清理对称加密库

        // 移除线程特定错误状态
# ifdef CRYPTO_LOCK_ECDH
        ERR_remove_thread_state(NULL); // OpenSSL 1.0.0+
# else
        ERR_remove_state(0); // OpenSSL 0.9.8
# endif
        CRYPTO_cleanup_all_ex_data();                         // 清理所有扩展数据
        sk_SSL_COMP_free(SSL_COMP_get_compression_methods()); // 释放压缩方法
        delete []__ssl_mutex;                                 // 释放锁数组
#endif
    }

private:
    SSL_CTX *ssl_client_ctx_; ///< 全局共享的SSL客户端上下文
    // 注意: __ssl_mutex在类外定义, 用于旧版OpenSSL的线程安全
    // static std::mutex *__ssl_mutex;
};

class __FileIOService : public IOService {
public:
    __FileIOService(CommScheduler *scheduler) :
        scheduler_(scheduler),
        flag_(true) // flag_=true表示当前未绑定到调度器
    {}

    /**
     * @brief   绑定到调度器
     * @return  绑定结果
     * @retval  >=0  成功
     * @retval  <0   失败
     * @note    线程安全, 修改内部状态标志
     */
    int bind() {
        mutex_.lock();
        flag_ = false; // 标记为已绑定状态

        int ret = scheduler_->io_bind(this); // 尝试绑定到调度器

        if (ret < 0) {
            flag_ = true; // 绑定失败, 恢复未绑定状态
        }

        mutex_.unlock();
        return ret;
    }

    /**
     * @brief   安全销毁I/O服务
     */
    void deinit() {
        std::unique_lock<std::mutex> lock(mutex_);
        // 等待服务完全解绑（flag_变为true）
        while (!flag_) {
            cond_.wait(lock); // 阻塞直到handle_unbound()被调用
        }

        // 注意: 此处显式解锁避免在父类方法中可能的死锁
        lock.unlock();
        // 手动调用父类的deinit(), 确保解绑完成后, 进行基础资源清理
        IOService::deinit();
    }

private:
    /**
     * @brief   处理解绑事件
     * @details 由调度器在I/O服务解绑完成后调用
     * @note    该回调保证在IO线程中执行
     */
    void handle_unbound() override {
        mutex_.lock();
        flag_ = true;       // 标记为已解绑状态
        cond_.notify_one(); // 通知可能阻塞在deinit()中的线程
        mutex_.unlock();
    }

    /**
     * @brief   处理停止事件
     * @param[in] error  停止原因错误码
     * @details 当I/O服务收到停止请求时, 主动从调度器解绑
     */
    void handle_stop(int error) override {
        scheduler_->io_unbind(this); // 请求调度器解绑此服务
    }

    CommScheduler *scheduler_;     // 关联的通信调度器
    std::mutex mutex_;             // 保护flag_状态的互斥锁
    std::condition_variable cond_; // 状态变化通知条件变量
    bool flag_;                    // 服务绑定状态：true=已解绑/可销毁, false=已绑定
};

/**
 * @brief   DNS解析线程资源管理器
 * @details 单例模式管理DNS专用的任务队列和线程池
 * @note    内部使用, 通过WFGlobal的get_dns_queue()/get_dns_executor()访问
 */
class __ThreadDnsManager {
public:
    static __ThreadDnsManager *get_instance() {
        static __ThreadDnsManager kInstance;
        return &kInstance;
    }

    ExecQueue *get_dns_queue() { return &dns_queue_; }
    Executor *get_dns_executor() { return &dns_executor_; }

    __ThreadDnsManager() {
        int ret;
        // 初始化任务队列
        ret = dns_queue_.init();
        if (ret < 0) {
            abort();
        }
        // 初始化线程池, 线程数来自全局配置
        ret = dns_executor_.init(WFGlobal::get_global_settings()->dns_threads);
        if (ret < 0) {
            abort();
        }
    }

    ~__ThreadDnsManager() {
        dns_executor_.deinit(); // 先停止线程池
        dns_queue_.deinit();    // 再销毁队列
        /* 如果先销毁消息队列, 可能有线程正在使用消息队列 */
    }

private:
    ExecQueue dns_queue_;
    Executor dns_executor_;
};

// 单例类, 仅内部使用
class __CommManager {
public:
    static __CommManager *get_instance() {
        static __CommManager kInstance;
        __CommManager::created_ = true; // 标记通信系统已创建
        return &kInstance;
    }

    CommScheduler *get_scheduler() { return &scheduler_; }
    IOService *get_io_service();
    // 检查通信管理器是否已创建
    static bool is_created() { return created_; }

private:
    __CommManager() :
        fio_service_(nullptr), fio_flag_(false) {
        const auto *settings = WFGlobal::get_global_settings();
        // 初始化调度器: poller线程处理I/O事件, handler线程处理业务逻辑
        if (scheduler_.init(settings->poller_threads, settings->handler_threads) < 0) {
            abort();
        }
        // 忽略SIGPIPE信号: 防止写入已关闭的socket导致进程终止. 确保服务稳定性
        signal(SIGPIPE, SIG_IGN);
    }

    ~__CommManager() {
        // scheduler_.deinit() will triger fio_service to stop
        // 注意: scheduler_.deinit()会触发所有已绑定的I/O服务停止
        scheduler_.deinit();
        // 清理文件I/O服务（如果已创建）
        if (fio_service_) {
            fio_service_->deinit(); // 确保服务完全停止
            delete fio_service_;    // 释放内存
        }
    }

private:
    CommScheduler scheduler_;      // 核心调度器, 管理网络I/O事件循环
    __FileIOService *fio_service_; // 文件I/O服务指针（延迟初始化）
    volatile bool fio_flag_;       // 文件I/O服务初始化标志（双重检查锁定用）
    std::mutex fio_mutex_;         // 保护fio_service_初始化的互斥锁

    static bool created_; // 全局标志, 标记通信管理器是否已创建
};

bool __CommManager::created_ = false;

/**
 * @brief   获取文件I/O服务（延迟初始化实现）
 * @return  初始化完成的文件I/O服务指针
 * @details 采用双重检查锁定模式保证线程安全的延迟初始化
 * @note    初始化流程：
 *          1. 尝试以配置的maxevents初始化
 *          2. 失败时自适应调整参数重试
 *          3. 绑定到核心调度器
 * @warning 初始化失败时直接终止程序
 */
inline IOService *__CommManager::get_io_service() {
    // 第一次检查（无锁, 快速路径）
    if (!fio_flag_) {
        fio_mutex_.lock();
        // 第二次检查（有锁, 确保只有一个线程进行初始化操作）
        if (!fio_flag_) {
            // 获取全局配置中的文件I/O事件数限制
            int maxevents = WFGlobal::get_global_settings()->fio_max_events;
            int n = 65536; // 初始尝试值
            // 创建文件I/O服务实例
            fio_service_ = new __FileIOService(&scheduler_);
            // 自适应初始化: 当失败时动态减少maxevents
            while (fio_service_->init(maxevents) < 0) {
                // 检查是否为不可恢复错误或已到最小值
                if ((errno != EAGAIN && errno != EINVAL) || maxevents <= 16) {
                    abort(); // 不可恢复错误, 终止程序
                }

                // 按2的幂次减少, 快速找到系统支持的最大值
                while (n >= maxevents) {
                    n /= 2;
                }
                maxevents = n;
            }

            // 将文件I/O服务绑定到调度器
            if (fio_service_->bind() < 0) {
                abort();
            }
            // 标记初始化完成
            fio_flag_ = true;
        }
        fio_mutex_.unlock();
    }
    return fio_service_;
}

// 内部类. 管理命名执行队列和计算密集型任务线程池
class __ExecManager {
protected:
    // 执行队列映射类型: 队列名称 -> 队列指针
    using ExecQueueMap = std::unordered_map<std::string, ExecQueue *>;

public:
    static __ExecManager *get_instance() {
        static __ExecManager kInstance;
        return &kInstance;
    }

    ExecQueue *get_exec_queue(const std::string &queue_name);
    /**
     * @brief   获取计算密集型任务执行器
     * @return  全局共享的计算线程池
     * @note    线程数根据系统CPU核心数自适应配置
     */
    Executor *get_compute_executor() { return &compute_executor_; }

private:
    __ExecManager() :
        rwlock_(PTHREAD_RWLOCK_INITIALIZER) // 静态初始化读写锁
    {
        // 从全局配置获取计算线程数, 负值表示使用CPU核心数
        int compute_threads = WFGlobal::get_global_settings()->compute_threads;
        if (compute_threads < 0) {
            compute_threads = sysconf(_SC_NPROCESSORS_ONLN); // 获取在线CPU核心数
        }
        // 初始化计算线程池
        if (compute_executor_.init(compute_threads) < 0) {
            abort();
        }
    }

    ~__ExecManager() {
        compute_executor_.deinit(); // 先停止计算线程池
        // 遍历并清理所有命名队列
        for (auto &kv : queue_map_) {
            kv.second->deinit(); // 停止队列
            delete kv.second;    // 释放内存
        }
        /* 另一种写法
        for (const auto &val : queue_map_ | std::views::values) {
            val->deinit(); // 停止队列
            delete val;    // 释放内存
        }*/

        pthread_rwlock_destroy(&rwlock_); // 销毁读写锁
    }

private:
    pthread_rwlock_t rwlock_; // 保护queue_map_的读写锁（高性能读多写少场景）
    ExecQueueMap queue_map_;
    Executor compute_executor_;
};

/**
 * @brief   获取或创建命名执行队列
 * @param[in] queue_name  队列唯一标识名称
 * @return   对应的执行队列指针
 * @retval   nullptr  初始化失败
 * @note     线程安全, 使用双重检查锁定模式
 * @warning  返回的队列由管理器生命周期管理, 调用者不应删除
 */
inline ExecQueue *__ExecManager::get_exec_queue(const std::string &queue_name) {
    ExecQueue *queue = nullptr;
    ExecQueueMap::const_iterator iter;

    // 尝试读锁快速查找
    pthread_rwlock_rdlock(&rwlock_);
    iter = queue_map_.find(queue_name);
    if (iter != queue_map_.cend()) {
        queue = iter->second;
    }
    pthread_rwlock_unlock(&rwlock_);
    if (queue) {
        // 队列已经存在
        return queue;
    }

    // 写锁保护下的创建流程
    pthread_rwlock_wrlock(&rwlock_);
    // 双重检查: 防止在释放读锁到获取写锁期间, 其他线程已创建
    iter = queue_map_.find(queue_name);
    if (iter == queue_map_.cend()) {
        // 创建新队列
        queue = new ExecQueue();
        if (queue->init() >= 0) {
            // 初始化成功，注册到映射表
            queue_map_.emplace(queue_name, queue);
        } else {
            // 初始化失败, 清理资源
            delete queue;
            queue = nullptr;
        }
    } else {
        // 其他线程已创建, 使用现有队列
        queue = iter->second;
    }
    pthread_rwlock_unlock(&rwlock_);

    return queue;
}

/**
 * @brief   将DNS服务器地址格式化为标准URL
 * @param[in] url    原始DNS服务器地址（可能为IP、主机名或带协议的URL）
 * @param[in] hints  地址解析提示（指定协议族等）
 * @return   标准化的dns://或dnss://格式URL
 * @retval   ""      地址无效(不可达)或无法解析
 * @details  处理三种输入格式：
 *           1. 已带协议的URL（dns://或dnss://）- 直接验证
 *           2. IPv6地址 - 包装为dns://[IPv6]
 *           3. 普通字符串 - 添加dns://前缀
 *           验证过程: 解析主机名并检查是否为有效DNS服务器
 */
static std::string __dns_server_url(const std::string &url, const struct addrinfo *hints) {
    std::string host;
    ParsedURI uri;
    struct addrinfo *res;
    struct in6_addr buf; // 用于IPv6地址解析

    // 情况1: 已带协议的URL (dns:// 或 dnss://)
    if (strncasecmp(url.c_str(), "dns://", 6) == 0 ||
        strncasecmp(url.c_str(), "dnss://", 7) == 0) {
        host = url; // 直接使用原始URL
    }
    // 情况2: IPv6地址 (如 2001:db8::1)
    else if (inet_pton(AF_INET6, url.c_str(), &buf) > 0) {
        // IPv6地址必须用[]括起来: dns://[2001:db8::1]
        host = "dns://[" + url + "]";
    }
    // 情况3: IPv4地址或主机名
    else {
        host = "dns://" + url; // 添加标准前缀
    }

    // 验证格式化后的URL是否有效
    // 1. 解析URI结构
    if (URIParser::parse(host, uri) == 0 && uri.host && uri.host[0]) {
        // 2. 尝试解析主机名（端口固定为53/DNS标准端口）
        // 注意: 这里仅验证地址可达性, 不保存结果
        if (getaddrinfo(uri.host, "53", hints, &res) == 0) {
            freeaddrinfo(res); // 立即释放地址信息，仅需验证
            return host;       // 验证成功, 返回标准化URL
        }
    }

    // 任一验证步骤失败, 返回空字符串
    return "";
}

/**
 * @brief   解析resolv.conf中的配置行, 提取有效条目
 * @param[in] p             配置行内容的起始指针
 * @param[in] is_nameserver 是否处理nameserver条目
 * @param[in] hints         DNS服务器地址解析提示
 * @param[out] result       合并后的有效条目（逗号分隔）
 * @details  算法流程：
 *          1. 跳过行首空白
 *          2. 循环提取以空白分隔的token
 *          3. 跳过注释部分（#或;之后的内容）
 *          4. 对nameserver条目进行URL标准化
 *          5. 将有效条目合并到结果（逗号分隔）
 * @note    设计为可重入, 每次调用处理单行
 */
static void __split_merge_str(const char *p, bool is_nameserver,
                              const struct addrinfo *hints,
                              std::string &result) {
    const char *start;

    // 安全检查: 行首必须是空白（符合resolv.conf格式规范）
    if (!isspace(*p)) {
        return;
    }

    while (true) {
        // 步骤1: 跳过连续空白字符
        while (isspace(*p)) {
            p++;
        }

        // 保存token起始位置
        start = p;

        // 步骤2: 找到token结束位置（空白/注释/字符串结束）
        while (*p && *p != '#' && *p != ';' && !isspace(*p)) {
            p++;
        }

        // 终止条件: 无有效token
        if (start == p) {
            break;
        }

        // 提取当前token
        std::string str(start, p);

        // 步骤3: 特殊处理nameserver条目
        if (is_nameserver) {
            str = __dns_server_url(str, hints); // 标准化并验证
        }

        // 步骤4: 合并有效条目
        if (!str.empty()) {
            // 添加逗号分隔符（非首项）
            if (!result.empty()) {
                result.push_back(',');
            }
            result.append(str);
        }
    }
}

/**
 * @brief   尝试匹配配置选项
 * @param[in] p   选项字符串起始位置
 * @param[in] q   选项字符串结束位置（用于边界检查）
 * @param[in] r   要匹配的选项名（如"ndots:"）
 * @return   选项值的起始指针
 * @retval   nullptr 匹配失败
 * @details  严格检查选项前缀匹配, 防止部分匹配错误
 *          例如: 避免将"attempts2:"误认为"attempts:"
 */
static inline const char *__try_options(const char *p, const char *q, const char *r) {
    const size_t len = strlen(r);
    if ((size_t)(q - p) >= len && // 检查剩余长度是否足够
        strncmp(p, r, len) == 0)  // 严格比较前缀
    {
        return p + len; // 返回选项值的起始位置
    }
    return nullptr; // 匹配失败
}

/**
 * @brief   解析resolv.conf中的options行
 * @param[in] p        options行内容指针
 * @param[out] ndots   域名分段阈值（影响搜索算法）
 * @param[out] attempts 单个查询最大尝试次数
 * @param[out] rotate   是否启用轮询策略
 * @details  支持三个标准选项：
 *          - ndots:N   : 当域名包含少于N个点时, 先尝试搜索域
 *          - attempts:N: 单个查询最大重试次数
 *          - rotate    : 在多个nameserver间轮询
 * @note    未指定的选项保持原值, 仅覆盖明确指定的选项
 */
static void __set_options(const char *p, int *ndots, int *attempts, bool *rotate) {
    const char *start;
    const char *opt;

    // 安全检查: 行首必须是空白
    if (!isspace(*p)) {
        return;
    }

    while (true) {
        // 跳过空白
        while (isspace(*p)) {
            p++;
        }

        start = p;
        // 读取完整选项（直到空白/注释/行尾）
        while (*p && *p != '#' && *p != ';' && !isspace(*p)) {
            p++;
        }

        if (start == p) {
            // 无更多选项
            break;
        }

        // 逐个尝试匹配支持的选项
        if ((opt = __try_options(start, p, "ndots:")) != nullptr) {
            *ndots = atoi(opt); // 转换数值
        } else if ((opt = __try_options(start, p, "attempts:")) != nullptr) {
            *attempts = atoi(opt);
        } else if ((opt = __try_options(start, p, "rotate")) != nullptr) {
            *rotate = true; // 布尔选项, 存在即启用
        }
        // 未知选项被静默忽略（符合resolv.conf规范）
    }
}

/**
 * @brief   解析resolv.conf配置文件
 * @param[in] path        配置文件路径（通常为/etc/resolv.conf）
 * @param[out] url        合并后的DNS服务器URL列表（逗号分隔）
 * @param[out] search_list 合并后的搜索域列表（逗号分隔）
 * @param[out] ndots      域名分段阈值（默认通常为1）
 * @param[out] attempts   查询重试次数（默认通常为2）
 * @param[out] rotate     是否启用服务器轮询
 * @return    操作状态
 * @retval    0   成功
 * @retval    -1  失败（文件不存在或读取错误）
 * @details   处理标准resolv.conf指令:
 *            - nameserver: DNS服务器列表
 *            - search: 域名搜索列表
 *            - options: 调整解析行为
 * @note      线程安全设计:
 *            1. 使用局部变量避免共享状态
 *            2. 不修改全局设置, 仅填充输出参数
 *            3. 严格遵循文件格式规范
 */
static int __parse_resolv_conf(const char *path, std::string &url, std::string &search_list,
                               int *ndots, int *attempts, bool *rotate) {
    size_t bufsize = 0;   // getline自动调整缓冲区
    char *line = nullptr; // getline分配的行缓冲区
    FILE *fp;
    int ret;

    // 打开配置文件
    fp = fopen(path, "r");
    if (!fp) {
        return -1; // 文件不存在或权限不足
    }

    // 获取全局DNS配置作为地址解析提示
    const struct WFGlobalSettings *settings = WFGlobal::get_global_settings();
    struct addrinfo hints = {
        .ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST | AI_NUMERICSERV, // 优化解析
        .ai_family = settings->dns_server_params.address_family,     // 地址族限制
        .ai_socktype = SOCK_STREAM,                                  // 强制TCP（DNS-over-TCP）
    };

    // 逐行读取配置
    while ((ret = getline(&line, &bufsize, fp)) > 0) {
        // 处理nameserver行（DNS服务器列表）
        if (strncmp(line, "nameserver", 10) == 0) {
            __split_merge_str(line + 10, true, &hints, url);
        }
        // 处理search行（域名搜索列表）
        else if (strncmp(line, "search", 6) == 0) {
            __split_merge_str(line + 6, false, &hints, search_list);
        }
        // 处理options行（解析行为调整）
        else if (strncmp(line, "options", 7) == 0) {
            __set_options(line + 7, ndots, attempts, rotate);
        }
        // 其他行（domain, sortlist等）被忽略, 保持兼容性
    }

    // 检查文件读取错误
    ret = ferror(fp) ? -1 : 0;

    // 清理资源
    free(line); // getline分配的缓冲区
    fclose(fp); // 关闭文件
    return ret;
}

/**
 * @brief   DNS客户端资源管理器
 * @details 单例模式管理DNS解析核心组件，包括：
 *          - WFDnsClient: DNS协议客户端
 *          - WFResourcePool: DNS连接资源池
 * @note    内部使用, 通过WFGlobal接口访问DNS功能
 * @warning 生命周期与程序相同, 应在所有DNS请求完成后销毁
 */
class __DnsClientManager {
public:
    static __DnsClientManager *get_instance() {
        static __DnsClientManager kInstance;
        return &kInstance;
    }

public:
    [[nodiscard]] WFDnsClient *get_dns_client() const { return client_; }
    [[nodiscard]] WFResourcePool *get_dns_respool() { return &respool_; };

private:
    __DnsClientManager() :
        // 根据全局配置初始化资源池（控制最大并发DNS查询数）
        respool_(WFGlobal::get_global_settings()->dns_server_params.max_connections) {
        // 从全局配置获取resolv.conf路径
        const char *path = WFGlobal::get_global_settings()->resolv_conf_path;

        client_ = nullptr;
        // 仅当配置了有效路径时尝试加载
        if (path && path[0]) {
            // 初始化resolv.conf解析参数
            int ndots = 1;       // 默认: 至少1个点才直接查询
            int attempts = 2;    // 默认: 每个服务器尝试2次
            bool rotate = false; // 默认: 不轮询DNS服务器
            std::string url;     // 存储解析得到的DNS服务器URL
            std::string search;  // 存储域名搜索列表

            // 解析resolv.conf文件
            __parse_resolv_conf(path, url, search, &ndots, &attempts, &rotate);

            // 安全回退: 当无法获取DNS服务器时使用Google公共DNS
            if (url.empty()) {
                url = "8.8.8.8"; // IPv4公共DNS
            }

            // 创建DNS客户端实例
            client_ = new WFDnsClient;

            // 初始化客户端（配置服务器、搜索域、策略等）
            if (client_->init(url, search, ndots, attempts, rotate) >= 0) {
                return; // 成功初始化，构造完成
            }

            // 初始化失败: 清理已分配资源
            delete client_;
            client_ = nullptr;
            // 注意：不abort(), 允许系统在无DNS情况下运行
        }
    }

    ~__DnsClientManager() {
        if (client_) {
            client_->deinit(); // 停止客户端（清理内部线程/连接）
            delete client_;    // 释放内存
        }
    }

    WFDnsClient *client_;
    WFResourcePool respool_;
};

struct WFGlobalSettings WFGlobal::settings_ = GLOBAL_SETTINGS_DEFAULT;
RouteManager WFGlobal::route_manager_;
DnsCache WFGlobal::dns_cache_;
WFDnsResolver WFGlobal::dns_resolver_;
WFNameService WFGlobal::name_service_(&WFGlobal::dns_resolver_);

bool WFGlobal::is_scheduler_created() {
    return __CommManager::is_created();
}

CommScheduler *WFGlobal::get_scheduler() {
    return __CommManager::get_instance()->get_scheduler();
}

SSL_CTX *WFGlobal::get_ssl_client_ctx() {
    return __SSLManager::get_instance()->get_ssl_client_ctx();
}

SSL_CTX *WFGlobal::new_ssl_server_ctx() {
    return __SSLManager::get_instance()->new_ssl_server_ctx();
}

ExecQueue *WFGlobal::get_exec_queue(const std::string &queue_name) {
    return __ExecManager::get_instance()->get_exec_queue(queue_name);
}

Executor *WFGlobal::get_compute_executor() {
    return __ExecManager::get_instance()->get_compute_executor();
}

IOService *WFGlobal::get_io_service() {
    return __CommManager::get_instance()->get_io_service();
}

ExecQueue *WFGlobal::get_dns_queue() {
    return __ThreadDnsManager::get_instance()->get_dns_queue();
}

Executor *WFGlobal::get_dns_executor() {
    return __ThreadDnsManager::get_instance()->get_dns_executor();
}

WFDnsClient *WFGlobal::get_dns_client() {
    return __DnsClientManager::get_instance()->get_dns_client();
}

WFResourcePool *WFGlobal::get_dns_respool() {
    return __DnsClientManager::get_instance()->get_dns_respool();
}

const char *WFGlobal::get_default_port(const std::string &scheme) {
    return __WFGlobal::get_instance()->get_default_port(scheme);
}

void WFGlobal::register_scheme_port(const std::string &scheme, unsigned short port) {
    __WFGlobal::get_instance()->register_scheme_port(scheme, port);
}

int WFGlobal::sync_operation_begin() {
    if (WFGlobal::is_scheduler_created() &&             // 调度器是否已创建（系统是否已初始化）
        WFGlobal::get_scheduler()->is_handler_thread()) // 当前线程是否为调度器的处理线程（worker thread）
    {
        // 通知系统开始同步操作（可能涉及挂起调度/保存上下文等）
        __WFGlobal::get_instance()->sync_operation_begin();
        return 1; // 同步操作开启成功
    }

    return 0;
}

void WFGlobal::sync_operation_end(const int cookie) {
    // 仅当cookie有效时（即在处理线程中开始了同步操作）
    if (cookie) {
        // 通知全局状态管理器结束同步操作
        __WFGlobal::get_instance()->sync_operation_end();
    }
}

static inline const char *__get_ssl_error_string(int error) {
    switch (error) {
    case SSL_ERROR_NONE: return "SSL Error None";

    case SSL_ERROR_ZERO_RETURN: return "SSL Error Zero Return";

    case SSL_ERROR_WANT_READ: return "SSL Error Want Read";

    case SSL_ERROR_WANT_WRITE: return "SSL Error Want Write";

    case SSL_ERROR_WANT_CONNECT: return "SSL Error Want Connect";

    case SSL_ERROR_WANT_ACCEPT: return "SSL Error Want Accept";

    case SSL_ERROR_WANT_X509_LOOKUP: return "SSL Error Want X509 Lookup";

#ifdef SSL_ERROR_WANT_ASYNC
    case SSL_ERROR_WANT_ASYNC: return "SSL Error Want Async";
#endif

#ifdef SSL_ERROR_WANT_ASYNC_JOB
    case SSL_ERROR_WANT_ASYNC_JOB: return "SSL Error Want Async Job";
#endif

#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    case SSL_ERROR_WANT_CLIENT_HELLO_CB: return "SSL Error Want Client Hello CB";
#endif

    case SSL_ERROR_SYSCALL: return "SSL System Error";

    case SSL_ERROR_SSL: return "SSL Error SSL";

    default: break;
    }

    return "Unknown";
}

static inline const char *__get_task_error_string(int error) {
    switch (error) {
    case WFT_ERR_URI_PARSE_FAILED: return "URI Parse Failed";

    case WFT_ERR_URI_SCHEME_INVALID: return "URI Scheme Invalid";

    case WFT_ERR_URI_PORT_INVALID: return "URI Port Invalid";

    case WFT_ERR_UPSTREAM_UNAVAILABLE: return "Upstream Unavailable";

    case WFT_ERR_HTTP_BAD_REDIRECT_HEADER: return "Http Bad Redirect Header";

    case WFT_ERR_HTTP_PROXY_CONNECT_FAILED: return "Http Proxy Connect Failed";

    case WFT_ERR_REDIS_ACCESS_DENIED: return "Redis Access Denied";

    case WFT_ERR_REDIS_COMMAND_DISALLOWED: return "Redis Command Disallowed";

    case WFT_ERR_MYSQL_HOST_NOT_ALLOWED: return "MySQL Host Not Allowed";

    case WFT_ERR_MYSQL_ACCESS_DENIED: return "MySQL Access Denied";

    case WFT_ERR_MYSQL_INVALID_CHARACTER_SET: return "MySQL Invalid Character Set";

    case WFT_ERR_MYSQL_COMMAND_DISALLOWED: return "MySQL Command Disallowed";

    case WFT_ERR_MYSQL_QUERY_NOT_SET: return "MySQL Query Not Set";

    case WFT_ERR_MYSQL_SSL_NOT_SUPPORTED: return "MySQL SSL Not Supported";

    case WFT_ERR_KAFKA_PARSE_RESPONSE_FAILED: return "Kafka parse response failed";

    case WFT_ERR_KAFKA_PRODUCE_FAILED: return "Kafka produce api failed";

    case WFT_ERR_KAFKA_FETCH_FAILED: return "Kafka fetch api failed";

    case WFT_ERR_KAFKA_CGROUP_FAILED: return "Kafka cgroup failed";

    case WFT_ERR_KAFKA_COMMIT_FAILED: return "Kafka commit api failed";

    case WFT_ERR_KAFKA_META_FAILED: return "Kafka meta api failed";

    case WFT_ERR_KAFKA_LEAVEGROUP_FAILED: return "Kafka leavegroup failed";

    case WFT_ERR_KAFKA_API_UNKNOWN: return "Kafka api type unknown";

    case WFT_ERR_KAFKA_VERSION_DISALLOWED: return "Kafka broker version not supported";

    case WFT_ERR_KAFKA_SASL_DISALLOWED: return "Kafka sasl disallowed";

    case WFT_ERR_KAFKA_ARRANGE_FAILED: return "Kafka arrange failed";

    case WFT_ERR_KAFKA_LIST_OFFSETS_FAILED: return "Kafka list offsets failed";

    case WFT_ERR_KAFKA_CGROUP_ASSIGN_FAILED: return "Kafka cgroup assign failed";

    case WFT_ERR_CONSUL_API_UNKNOWN: return "Consul api type unknown";

    case WFT_ERR_CONSUL_CHECK_RESPONSE_FAILED: return "Consul check response failed";

    default: break;
    }

    return "Unknown";
}

const char *WFGlobal::get_error_string(int state, int error) {
    switch (state) {
    case WFT_STATE_SUCCESS: return "Success";

    case WFT_STATE_TOREPLY: return "To Reply";

    case WFT_STATE_NOREPLY: return "No Reply";

    case WFT_STATE_SYS_ERROR: return strerror(error);

    case WFT_STATE_SSL_ERROR: return __get_ssl_error_string(error);

    case WFT_STATE_DNS_ERROR: return gai_strerror(error);

    case WFT_STATE_TASK_ERROR: return __get_task_error_string(error);

    case WFT_STATE_ABORTED: return "Aborted";

    case WFT_STATE_UNDEFINED: return "Undefined";

    default: break;
    }

    return "Unknown";
}

void WORKFLOW_library_init(const struct WFGlobalSettings *settings) {
    WFGlobal::set_global_settings(settings);
}