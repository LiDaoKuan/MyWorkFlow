//
// Created by ldk on 12/20/25.
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

#ifndef MYWORKFLOW_WFHTTPSERVER_H
#define MYWORKFLOW_WFHTTPSERVER_H

#include <utility>
#include <functional>
#include "WFServer.h"
#include "HttpMessage.h"
#include "WFTaskFactory.h"

using http_process_t = std::function<void (WFHttpTask *)>;
using WFHttpServer = WFServer<protocol::HttpRequest, protocol::HttpResponse>;

// HTTP服务器默认配置参数
static constexpr struct WFServerParams HTTP_SERVER_PARAMS_DEFAULT =
{
    .transport_type = TT_TCP,           // 纯TCP传输（非SSL）
    .max_connections = 2000,            // 默认最大并发连接数
    .peer_response_timeout = 10 * 1000, // 10秒响应超时
    .receive_timeout = -1,              // 使用系统默认接收超时
    .keep_alive_timeout = 60 * 1000,    // 60秒保持连接超时
    .request_size_limit = (size_t)-1,   // 无请求大小限制（最大值）
    .ssl_accept_timeout = 10 * 1000,    // SSL握手超时（备用）
};

/** @brief WFHttpServer构造函数特化
 * @param proc HTTP请求处理函数, 接收WFHttpTask指针 */
template <> inline
WFHttpServer::WFServer(http_process_t proc) :
    WFServerBase(&HTTP_SERVER_PARAMS_DEFAULT), process(std::move(proc)) {}

/**@brief 创建新的HTTP会话
 *
 * @param seq 会话序列号(唯一标识)
 * @param conn 底层连接对象
 * @return 新创建的会话对象（实际为Http任务对象）*/
template <> inline
CommSession *WFHttpServer::new_session(long long seq, CommConnection *conn) {
    WFHttpTask *task = WFServerTaskFactory::create_http_task(this, this->process); // 创建http任务对象
    task->set_keep_alive(this->params.keep_alive_timeout);                         // 配置保活时间
    task->set_receive_timeout(this->params.receive_timeout);                       // 配置接收超时
    task->get_req()->set_size_limit(this->params.request_size_limit);              // 配置请求体大小限制

    return task; // 返回任务对象作为Session
}

#endif //MYWORKFLOW_WFHTTPSERVER_H