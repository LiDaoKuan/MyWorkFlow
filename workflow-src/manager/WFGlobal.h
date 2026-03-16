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
*/

#ifndef MYWORKFLOW_WFGLOBAL_H
#define MYWORKFLOW_WFGLOBAL_H

#if __cplusplus < 201100
#error CPLUSPLUS VERSION required at least C++11. Please use "-std=c++11".
#include <C++11_REQUIRED>
#endif

#include <openssl/ssl.h>
#include <string>
#include "CommScheduler.h"
#include "DnsCache.h"
#include "RouteManager.h"
#include "Executor.h"
#include "EndpointParams.h"
#include "WFResourcePool.h"
#include "WFNameService.h"
#include "WFDnsResolver.h"

/**
 * @file    WFGlobal.h
 * @brief   Workflow Global Settings & Workflow Global APIs
 */

/**@brief   全局配置.
 * @details
 * 如果想要自定义设置, 需要在程序开头调用 WORKFLOW_library_init() 函数
 */
struct WFGlobalSettings {
    struct EndpointParams endpoint_params;   ///< 通用网络端点参数（连接超时、传输超时等）
    struct EndpointParams dns_server_params; ///< DNS 服务器专用端点参数
    unsigned int dns_ttl_default;            ///< DNS 成功查询的TTL缓存时间（秒）
    unsigned int dns_ttl_min;                ///< DNS 查询失败时的最小TTL缓存时间（秒）
    int dns_threads;                         ///< DNS 解析线程池大小
    int poller_threads;                      ///< I/O 事件轮询线程数
    int handler_threads;                     ///< 任务处理线程池大小
    int compute_threads;                     ///< 计算任务线程池大小（ <0 时自动根据 CPU 核心数设置）
    int fio_max_events;                      ///< 文件 I/O 事件队列最大容量
    const char *resolv_conf_path;            ///< DNS 配置文件路径（默认/etc/resolv.conf）
    const char *hosts_path;                  ///< hosts 文件路径（默认/etc/hosts）
};

/**
 * @brief 默认全局配置
 */
static constexpr struct WFGlobalSettings GLOBAL_SETTINGS_DEFAULT =
{
    .endpoint_params = ENDPOINT_PARAMS_DEFAULT,
    .dns_server_params = ENDPOINT_PARAMS_DEFAULT, ///< DNS 服务器使用相同默认参数
    .dns_ttl_default = 3600,                      ///< 成功 DNS 记录缓存1小时
    .dns_ttl_min = 60,                            ///< 失败 DNS 记录最小缓存60秒
    .dns_threads = 4,                             ///< 4个 DNS 解析线程
    .poller_threads = 4,                          ///< 4个 I/O 轮询线程
    .handler_threads = 20,                        ///< 20个任务处理线程
    .compute_threads = -1,                        ///< 自动根据 CPU 核心数设置计算线程
    .fio_max_events = 4096,                       ///< 文件 I/O 队列最大4096事件
    .resolv_conf_path = "/etc/resolv.conf",
    .hosts_path = "/etc/hosts",
};

/**
 * @brief      重置Workflow库全局配置
 * @param[in]  settings  指向自定义配置结构体的指针（nullptr时使用默认配置）
 * @warning    必须在进程初始化阶段、任何Workflow操作前调用
 */
extern void WORKFLOW_library_init(const struct WFGlobalSettings *settings);

/**
 * @brief   Workflow全局管理中心
 * @details 提供线程安全的全局配置访问、协议端口注册、资源管理等核心功能
 */
class WFGlobal {
public:
    /**
     * @brief      注册自定义协议的默认端口号
     * @param[in]  scheme  协议标识字符串（如"ftp"、"mqtt"）
     * @param[in]  port    对应协议的默认端口号
     * @warning    对内置协议("http"/"https"/"redis"等)无效，仅影响自定义协议
     * @note       多次注册同协议会覆盖先前设置
     */
    static void register_scheme_port(const std::string &scheme, unsigned short port);

    /**
     * @brief      获取协议对应的标准端口号
     * @param[in]  scheme  协议标识字符串
     * @return     端口号字符串指针
     * @retval     nullptr    未找到对应协议的注册端口
     * @retval     非nullptr  成功获取端口字符串（如"http"返回"80"）
     * @note       内置协议自动返回标准端口, 自定义协议需先注册
     */
    static const char *get_default_port(const std::string &scheme);

    /**
     * @brief      获取当前生效的全局配置
     * @return     指向全局配置结构体的常量指针
     * @note       保证返回非空指针, 线程安全
     */
    static const struct WFGlobalSettings *get_global_settings() {
        return &settings_;
    }

    /**
     * @brief      内部设置全局配置
     * @param[in]  settings 配置结构体指针
     * @warning    仅限内部初始化使用, 外部应调用 WORKFLOW_library_init
     */
    static void set_global_settings(const struct WFGlobalSettings *settings) {
        settings_ = *settings;
    }

    /**
     * @brief      获取错误描述字符串
     * @param[in]  state  任务状态码
     * @param[in]  error  系统错误码
     * @return     对应错误的可读字符串
     * @note       线程安全, 返回字符串常量
     */
    static const char *get_error_string(int state, int error);

    /**
     * @brief      动态增加任务处理线程
     * @return     操作结果
     * @retval     true   成功增加线程
     * @retval     false  已达最大线程数或内部错误
     */
    static bool increase_handler_thread() {
        return WFGlobal::get_scheduler()->increase_handler_thread() == 0;
    }

    /**
     * @brief      动态减少任务处理线程
     * @return     操作结果
     * @retval     true   成功减少线程
     * @retval     false  低于最小线程数或内部错误
     * @note       闲置线程会逐渐退出
     */
    static bool decrease_handler_thread() {
        return WFGlobal::get_scheduler()->decrease_handler_thread() == 0;
    }

    /**
     * @brief      动态增加计算线程
     * @return     操作结果
     * @retval     true   成功增加计算线程
     * @retval     false  已达上限或内部错误
     */
    static bool increase_compute_thread() {
        return WFGlobal::get_compute_executor()->increase_thread() == 0;
    }

    /**
     * @brief      动态增加计算线程
     * @return     操作结果
     * @retval     true   成功增加计算线程
     * @retval     false  已达上限或内部错误
     */
    static bool decrease_compute_thread() {
        return WFGlobal::get_compute_executor()->decrease_thread() == 0;
    }

    // Internal usage only
    // 以下为内部组件访问接口, 应用层不应直接调用
public:
    /**
     * @brief      检查调度器是否已创建
     * @return     创建状态
     * @retval     true   调度器已初始化
     * @retval     false  调度器未创建
     * @internal   仅限内部使用
     */
    static bool is_scheduler_created();

    /**
     * @brief      获取核心调度器实例
     * @return     全局唯一的调度器对象
     * @internal   仅限内部使用
     */
    static class CommScheduler *get_scheduler();

    /**
     * @brief      获取SSL客户端上下文
     * @return     预初始化的SSL客户端上下文
     * @internal   仅限内部使用
     */
    static SSL_CTX *get_ssl_client_ctx();

    /**
     * @brief      创建新的SSL服务端上下文
     * @return     新初始化的SSL服务端上下文
     * @internal   仅限内部使用
     */
    static SSL_CTX *new_ssl_server_ctx();

    /**
     * @brief      获取命名执行队列
     * @param[in]  queue_name  队列名称标识
     * @return     对应名称的执行队列
     * @internal   仅限内部使用
     */
    static class ExecQueue *get_exec_queue(const std::string &queue_name);

    /**
     * @brief      获取计算任务执行器
     * @return     全局计算线程池执行器
     * @internal   仅限内部使用
     */
    static class Executor *get_compute_executor();

    /**
     * @brief      获取文件I/O服务实例
     * @return     全局唯一的IOService对象
     * @internal   仅限内部使用
     */
    static class IOService *get_io_service();

    /**
     * @brief      获取DNS解析专用队列
     * @return     DNS任务执行队列
     * @internal   仅限内部使用
     */
    static class ExecQueue *get_dns_queue();

    /**
     * @brief      获取DNS解析执行器
     * @return     DNS专用线程池
     * @internal   仅限内部使用
     */
    static class Executor *get_dns_executor();

    /**
     * @brief      获取全局DNS客户端
     * @return     预初始化的DNS客户端实例
     * @internal   仅限内部使用
     */
    static class WFDnsClient *get_dns_client();

    /**
     * @brief      获取DNS资源池
     * @return     用于限制DNS并发请求的资源池
     * @internal   仅限内部使用
     */
    static class WFResourcePool *get_dns_respool();

    /**
     * @brief      获取路由管理器
     * @return     全局路由规则管理实例
     * @internal   仅限内部使用
     */
    static class RouteManager *get_route_manager() {
        return &route_manager_;
    }

    /**
     * @brief      获取DNS缓存
     * @return     全局DNS缓存管理器
     * @internal   仅限内部使用
     */
    static class DnsCache *get_dns_cache() {
        return &dns_cache_;
    }

    /**
     * @brief      获取DNS解析器
     * @return     全局DNS解析器实例
     * @internal   仅限内部使用
     */
    static class WFDnsResolver *get_dns_resolver() {
        return &dns_resolver_;
    }

    /**
     * @brief      获取名称服务
     * @return     全局名称解析服务（整合DNS/hosts/自定义解析）
     * @internal   仅限内部使用
     */
    static class WFNameService *get_name_service() {
        return &name_service_;
    }

    /**
     * @brief      开始同步操作
     * @return     操作cookie标识
     * @internal   用于内部同步原语，应用层不应调用
     */
    static int sync_operation_begin();

    /**
     * @brief      结束同步操作
     * @param[in]  cookie  由sync_operation_begin返回的标识
     * @internal   配合同步原语使用
     */
    static void sync_operation_end(int cookie);

private:
    static struct WFGlobalSettings settings_; // 当前生效的全局配置
    static RouteManager route_manager_;       // 路由规则管理器
    static DnsCache dns_cache_;               // DNS缓存管理
    static WFDnsResolver dns_resolver_;       // DNS解析器
    static WFNameService name_service_;       // 名称解析服务
};

#endif //MYWORKFLOW_WFGLOBAL_H