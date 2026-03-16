//
// Created by ldk on 3/15/26.
//

#ifndef MYWORKFLOW_HTTPROUTE_H
#define MYWORKFLOW_HTTPROUTE_H

#include <functional>
#include <iostream>
#include <map>
#include <regex>
#include <utility>

#include "WFFacilities.h"
#include "WFTaskFactory.h"

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
    std::vector<std::string> param_names;
    Handler handler;
};

class MindMapRoute {
public:
    static MindMapRoute &getInstance() {
        static MindMapRoute instance;
        return instance;
    }

    void registerRoute(HttpMethod method, const std::string &pattern, Handler handler) {
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

    void registerRoute(HttpMethod method, const std::vector<std::string>& patternVec, Handler handler) {
        for (auto &pattern: patternVec) {
            registerRoute(method, pattern, handler);
        }
    }

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
    }

    bool route(const std::string &uri, const std::string &method, protocol::HttpResponse *response) {
        HttpMethod http_method = stringToHttpMethod(method);

        // 查找匹配的路由
        // Iterate only over routes matching the specific HTTP method to avoid mismatched regex patterns.
        // Added explicit flushing and newline to ensure output appears before potential SIGILL.
        auto range = routes_.equal_range(http_method);
        for (auto it = range.first; it != range.second; ++it) {
            const RouteInfo &route_info = it->second;
            std::smatch matches;

            // Use fprintf to stderr with newline and flush to guarantee visibility before crash
            fprintf(stderr, "DEBUG: Checking pattern: %s\n", route_info.pattern.c_str());
            fflush(stderr);

            // The SIGILL (Illegal Instruction) often stems from regex engine issues or corrupted regex objects.
            // We attempt to catch standard exceptions, but note that SIGILL is a signal and cannot be caught by try/catch.
            // However, we ensure the logic is as safe as possible.
            try {
                if (std::regex_match(uri, matches, route_info.regex_pattern)) {
                    fprintf(stderr, "DEBUG: Pattern matched: %s\n", route_info.pattern.c_str());
                    fflush(stderr);

                    // Extract path parameters and store in context
                    auto params = extractParameters(matches, route_info.param_names);

                    // Call the handler function
                    route_info.handler(response);
                    return true;
                } else {
                    fprintf(stderr, "DEBUG: unmatched: %s\n", route_info.pattern.c_str());
                    fflush(stderr);
                }
            } catch (const std::regex_error &e) {
                fprintf(stderr, "Regex error during matching: %s\n", e.what());
                fflush(stderr);
                continue;
            } catch (...) {
                fprintf(stderr, "Unknown exception during regex matching.\n");
                fflush(stderr);
                continue;
            }
        }
    }

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
            printf("it: %s\n", (*it)[1].str().c_str());
            param_names.push_back((*it)[1].str());
            ++it;
        }
    }

    //  辅助函数，构建正则表达式
    std::regex buildRegex(const std::string &pattern) {
        std::string regex_str = std::regex_replace(pattern, std::regex(R"(\{\w+\})"), "(.+)");
        printf("regex: %s\n", regex_str.c_str());
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


#endif //MYWORKFLOW_HTTPROUTE_H