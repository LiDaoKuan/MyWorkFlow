//
// Created by ldk on 3/15/26.
//

#ifndef MYWORKFLOW_HTTPROUTE_H
#define MYWORKFLOW_HTTPROUTE_H

#include <functional>
#include <cstring>
#include <map>
#include <regex>
#include <utility>

#include "WFFacilities.h"
#include "WFTaskFactory.h"

#include <plog/Log.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Initializers/ConsoleInitializer.h>

#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/builder/basic/kvp.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/uri.hpp>

/**要实现的功能：根据请求的URL和HTTP方法，将请求路由到对应的处理函数进行处理。处理函数可以由外部注入
 * 例如：
 *  GET /api/users/{userid}         获取用户信息
 *  PUT /api/users/{userid}         更新用户信息
 *  GET /api/users/{userid}/mindmap/{mapid}  获取某个思维导图信息
 *  GET /api/users/{userid}/mindmap/         获取该用户所有思维导图信息
 *  GET /api/users/{userid}/mindmap/{mapid}/nodes/{nodeid}  获取节点信息
 *  PUT /api/users/{userid}/mindmap/{mapid}/nodes/{nodeid}  更新节点信息
 * 上方的例子都可以用下面的方法注册到路由管理器中，然后在合适的时机调用路由管理器的route方法，将请求路由到对应的处理函数进行处理。
 *  register("GET, "/api/users/{userid}", [](WFHttpTask* http_task){
 *      // 处理逻辑
 *  } )
 */
#define HTTP_METHOD_LIST \
    X(GET) \
    X(POST) \
    X(PUT) \
    X(PATCH) \
    X(DELETE) \
    X(HEAD) \
    X(OPTIONS) \
    X(CONNECT) \
    X(TRACE)

enum class HttpMethod {
#define X(method) method,
    HTTP_METHOD_LIST
#undef X
};

// 将 HttpMethod 枚举类转化为 string
inline std::string httpMethodToString(HttpMethod method) {
    switch (method) {
#define X(name) case HttpMethod::name: return #name;
    HTTP_METHOD_LIST
#undef X
    default: return "UNKUOWN";
    }
}

static std::map<std::string, HttpMethod> httpMethodMap = {
    {"GET", HttpMethod::GET},
    {"PUT", HttpMethod::PUT},
    {"POST", HttpMethod::POST},
    {"PATCH", HttpMethod::PATCH},
    {"HEAD", HttpMethod::HEAD},
    {"OPTIONS", HttpMethod::OPTIONS},
    {"CONNECT", HttpMethod::CONNECT},
    {"DELETE", HttpMethod::DELETE},
    {"TARCE", HttpMethod::TRACE},
};

inline HttpMethod stringToHttpMethod(const std::string &method) {
    return httpMethodMap[method];
}

// 路由处理器
using Handler = std::function<void (protocol::HttpResponse *httpResponse)>;

struct RouteInfo {
    HttpMethod method;
    std::string pattern;
    std::regex regex_pattern;
    std::vector<std::string> param_names;  // 存储路径中的参数名. 例如: /api/users/{userid}/mindmap/{mapid} 中的 userid 和 mapid
    std::vector<std::string> params_value; // 存储路径中的参数值
    Handler handler;
};

class MindMapRoute {
public:
    static MindMapRoute &getInstance() {
        static MindMapRoute instance;
        return instance;
    }

    void registerRoute(HttpMethod method, const std::string &pattern, Handler handler);

    void registerRoute(const HttpMethod method, const std::vector<std::string> &patternVec, const Handler &handler);

    /*
    bool route(WFHttpTask *httpTask) {
        // 从任务中提取 URI 和 HTTP 方法
        auto *req = httpTask->get_req();
        std::string uri = req->get_request_uri();
        HttpMethod method = stringToHttpMethod(req->get_method());

        // 查找匹配的路由
        auto range = routes_.equal_range(method);
        for (auto it = range.first; it != range.second; ++it) {
            std::smatch matches;
            if (std::regex_match(uri, matches, it->second.regex_pattern)) {
                // 提取路径参数并存入上下文
                auto params = extractParameters(matches, it->second.param_names);

                // 调用处理函数
                it->second.handler(httpTask->get_resp());
                return true;
            }
        }

        // 未找到匹配的路由，返回 404
        return false;
    }*/

    bool route(const std::string &uri, const std::string &method, protocol::HttpResponse *response);

    // 禁用拷贝构造函数
    MindMapRoute(const MindMapRoute &) = delete;

    // 禁用赋值运算符
    MindMapRoute &operator=(const MindMapRoute &) = delete;

private:
    MindMapRoute() = default;

    // 使用 multimap 存储路由信息，key 为 HttpMethod，value 为 RouteInfo
    std::unordered_multimap<HttpMethod, RouteInfo> routes_;

    // 辅助函数，解析路径参数名
    void parsePathParameters(const std::string &pattern, std::vector<std::string> &param_names) {
        std::regex param_regex(R"(\{(\w+)\})");
        std::sregex_iterator it(pattern.begin(), pattern.end(), param_regex);
        const std::sregex_iterator end;
        while (it != end) {
            param_names.push_back((*it)[1].str());
            ++it;
        }
    }

    //  辅助函数，构建正则表达式
    std::regex buildRegex(const std::string &pattern) {
        std::string regex_str = std::regex_replace(pattern, std::regex(R"(\{\w+\})"), "(.+)");
        return std::regex("^" + regex_str + "$");
    }

    // 辅助函数，将路由信息存储到 multimap 中
    std::map<std::string, std::string> extractParameters(const std::smatch &matchs, const std::vector<std::string> &param_names) {
        std::map<std::string, std::string> params;
        for (size_t i = 0; i < param_names.size(); ++i) {
            params[param_names[i]] = matchs[i + 1].str();
        }
        return params;
    }
};

// 获取所有用户
void handleGetUsers(protocol::HttpResponse *resp);

// 获取用户信息
void handleGetUserById(protocol::HttpResponse *resp);

// 获取用户所有思维导图
void handleGetUserMaps(protocol::HttpResponse *resp);

void handleGetMapById(protocol::HttpResponse *resp);

#endif //MYWORKFLOW_HTTPROUTE_H