//
// Created by ldk on 12/20/25.
//

#ifndef MYWORKFLOW_WFDNSRESOLVER_H
#define MYWORKFLOW_WFDNSRESOLVER_H

#include <string>
#include <functional>
#include "EndpointParams.h"
#include "WFNameService.h"

// DNS解析路由任务
class WFResolverTask : public WFRouterTask {
public:
    /**@brief DNS解析任务
     * @param ns_params 命名服务参数, 包含目标URI等信息
     * @param dns_ttl_default 默认DNS缓存TTL(秒)
     * @param dns_ttl_min 最小DNS缓存TTL(秒), 防止过短的TTL
     * @param ep_params 端点参数, 控制连接行为
     * @param cb 路由完成回调
     *
     * 特殊处理：
     * - 当 fixed_conn=true 时, 强制 max_connections=1, 实现连接独占 */
    WFResolverTask(const struct WFNSParams *ns_params,
                   unsigned int dns_ttl_default, unsigned int dns_ttl_min,
                   const struct EndpointParams *ep_params,
                   router_callback_t &&cb) :
        WFRouterTask(std::move(cb)),
        ns_params_(*ns_params),
        ep_params_(*ep_params) {
        // 特殊模式: 固定连接（通常用于测试或固定场景？？？）
        if (ns_params_.fixed_conn) {
            ep_params_.max_connections = 1; // 限制为单连接
        }

        dns_ttl_default_ = dns_ttl_default;
        dns_ttl_min_ = dns_ttl_min;
        has_next_ = false; // 初始无备用解析结果
        in_guard_ = false; // 未进入保护状态
        msg_ = nullptr;    // 无DNS消息缓存
    }

    /**@brief 简化构造函数. 使用默认的DNS TTL和端点参数
     * @param ns_params 命名服务参数
     * @param cb 路由完成回调 */
    WFResolverTask(const struct WFNSParams *ns_params, router_callback_t &&cb) :
        WFRouterTask(std::move(cb)),
        ns_params_(*ns_params) {
        if (ns_params_.fixed_conn) {
            ep_params_.max_connections = 1;
        }

        has_next_ = false;
        in_guard_ = false;
        msg_ = nullptr;
    }

protected:
    /**@brief 任务启动函数（启动DNS解析）
     * 由框架调用. 根据 fixed_addr 标志决定是否跳过DNS查询 */
    void dispatch() override;
    /**@brief 任务完成处理
     * @return 任务流中下一个任务 */
    SubTask *done() override;

private:
    void thread_dns_callback(void *thrd_dns_task);
    void dns_single_callback(void *net_dns_task);
    static void dns_partial_callback(void *net_dns_task);
    void dns_parallel_callback(const void *parallel);
    void dns_callback(void *dns_output, unsigned int ttl_default, unsigned int ttl_min);
    void request_dns();
    void task_callback();

protected:
    WFNSParams ns_params_;         // 命名服务参数（目标URI、协议类型等）
    unsigned int dns_ttl_default_; // DNS缓存默认TTL
    unsigned int dns_ttl_min_;     // DNS缓存最小TTL
    EndpointParams ep_params_;     // 端点参数（连接池大小、超时等）

private:
    const char *host_;    // 从URI解析出的主机名
    unsigned short port_; // 从URI解析出的端口号
    bool has_next_;       // 是否有备用解析结果
    bool in_guard_;       // 保护状态标志, 防止重复处理
    void *msg_;           // DNS查询/响应消息指针
};

/**DNS解析策略实现
 *
 * WFDnsResolver是WFNSPolicy的具体实现, 专注于DNS主机名解析.
 * 它负责创建DNS解析路由任务, 将主机名转换为IP地址
 *
 * 同时它遵循策略模式 */
class WFDnsResolver : public WFNSPolicy {
public:
    /**@brief 创建DNS解析路由任务
     *
     * 根据命名服务参数创建适当的DNS解析任务
     * @param params 命名服务请求参数
     * @param callback 任务完成回调
     * @return 新创建的路由任务
     *
     * 策略选择：
     * - 当 fixed_addr=true 时, 直接使用IP地址, 跳过DNS查询
     * - 否则, 创建完整的DNS解析任务
     */
    WFRouterTask *create_router_task(const struct WFNSParams *params, router_callback_t callback) override;
};
#endif //MYWORKFLOW_WFDNSRESOLVER_H