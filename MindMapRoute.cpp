//
// Created by ldk on 3/15/26.
//

#include "MindMapRoute.h"

void MindMapRoute::registerRoute(HttpMethod method, const std::string &pattern, Handler handler) {
    // 提取路径中的参数名
    RouteInfo info;
    info.method = method;
    info.pattern = pattern;
    info.handler = std::move(handler);

    // 将路径模式转换为正则表达式
    parsePathParameters(pattern, info.param_names);

    // 将 {param} 转为正则表达式捕获组 (.+)
    info.regex_pattern = buildRegex(pattern);

    // 存储路由信息
    routes_.insert({method, std::move(info)});
}

void MindMapRoute::registerRoute(const HttpMethod method, const std::vector<std::string> &patternVec, const Handler &handler) {
    for (auto &pattern : patternVec) {
        registerRoute(method, pattern, handler);
    }
}

bool MindMapRoute::route(const std::string &uri, const std::string &method, protocol::HttpResponse *response) {
    HttpMethod http_method = stringToHttpMethod(method);

    // 查找匹配的路由
    auto range = routes_.equal_range(http_method);
    for (auto it = range.first; it != range.second; ++it) {
        const RouteInfo &route_info = it->second;
        std::smatch matches;

        if (std::regex_match(uri, matches, route_info.regex_pattern)) {
            PLOG_INFO << "DEBUG: Pattern matched: " << route_info.pattern;
            // 提取路径参数并存入上下文
            auto params = extractParameters(matches, route_info.param_names);

            // Call the handler function
            route_info.handler(response);
            return true;
        }
    }
    PLOG_INFO << "uri unmatched: " << uri;
    return false;
}

// 获取所有用户
void handleGetUsers(protocol::HttpResponse *resp) {
    //
}

// 获取用户信息
void handleGetUserById(protocol::HttpResponse *resp) {
    //
}

// 获取用户所有思维导图
void handleGetUserMaps(protocol::HttpResponse *resp) {
    //
}

// 根据id获取思维导图信息
void handleGetMapById(protocol::HttpResponse *resp) {
    //
}