#include <csignal>
#include <iostream>
#include <csignal>
#include <unordered_set>
#include <arpa/inet.h>

#include <bsoncxx/builder/basic/document.hpp>
#include <bsoncxx/builder/basic/kvp.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/uri.hpp>

#include "nlohmann/json.hpp"

#include "HttpMessage.h"
#include "HttpUtil.h"
#include "MindMapRoute.h"
#include "WFHttpServer.h"
#include "WFTaskFactory.h"
#include "Workflow.h"
#include "WFFacilities.h"
#include "StringUtil.h"

using std::cout;
using std::endl;
using std::string;
using std::vector;

WFHttpServer *server_p = nullptr;

auto getCurrentTime() {
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm *now_time = std::localtime(&now_c);
    return std::put_time(now_time, "%Y-%m-%d %H:%M:%S");
}

string slipIpFromUri(const char *uri) {
    if (!uri) {
        PLOG_ERROR << "error: uri is null!";
        return "";
    }
    auto first = const_cast<char *>(uri);
    // 检查是否有 '/'
    while (*first != '\0' && *first != '/') {
        first++;
    }
    first++;
    if (*first != '/') {
        return {}; // 没有找到 '/'
    }
    first++; // 跳过 '/'

    char *last = first;
    while (*last != ':') {
        last += 1;
    }
    // get ip between first and last
    auto str = string(first, last);
    return std::move(str);
}

// 从 sockaddr 提取 ip 地址
void *get_addr_in(sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(reinterpret_cast<sockaddr_in *>(sa)->sin_addr);
    }
    return &(reinterpret_cast<sockaddr_in6 *>(sa)->sin6_addr);
}

// 获取对端地址
static void getPeerAddr(WFHttpTask *serverTask, char *peer_addr) {
    sockaddr addr;
    socklen_t addr_len = sizeof(addr);
    serverTask->get_peer_addr(&addr, &addr_len);
    inet_ntop(AF_INET, get_addr_in(&addr), peer_addr, INET_ADDRSTRLEN);
}

bool handleRequest(protocol::HttpRequest *request, WFHttpTask *serverTask) {
    auto method = request->get_method();   // 请求方法
    auto uri = request->get_request_uri(); // 请求URI

    char peerAddr[INET_ADDRSTRLEN];
    getPeerAddr(serverTask, peerAddr);
    PLOG_INFO << "request from: " << peerAddr << " method: " << method;
    PLOG_INFO << "request uri: " << uri;

    MindMapRoute::getInstance().route(uri, method, serverTask->get_resp());

    auto pathVec = StringUtil::split_filter_empty(uri, '/');

    // uri 不以 /api 开头. 访问出错
    int err_bak = errno;
    errno = ENOENT;
    perror("uri invalid");
    errno = err_bak;

    return false;
}

void server_process(WFHttpTask *serverTask, const char *root) {
    PLOG_INFO << "--------------------------------------------------------->";

    auto request = serverTask->get_req(); // 请求对象

    handleRequest(request, serverTask);

    auto response = serverTask->get_resp(); // 响应对象
    PLOG_INFO << "--------------------------------------------------------->";
}

static WFFacilities::WaitGroup wait_group(1); /* NOLINT */

void sig_handler(int signum) { /* NOLINT */
    wait_group.done();
}

void mongocxxTest();

int main() {
    plog::init<plog::TxtFormatter>(plog::debug, plog::streamStdOut);

    // mongocxx::instance instance{}; // 必须初始化一次, 即便instance没用过
    // const mongocxx::uri uri{"mongodb://localhost:27017/?maxPoolSize=20"};
    // mongocxx::pool pool{uri}; // 连接池



    signal(SIGINT, sig_handler);
    mongocxxTest();

    constexpr unsigned int port = 8080;
    const char *root = ".";

    MindMapRoute::getInstance().
        registerRoute(HttpMethod::GET,
                      vector<string>{"/", "/favicon.ico"}, std::move([](protocol::HttpResponse *resp) {
                          PLOG_INFO << "404 not found";
                          nlohmann::json req_uri_json = nlohmann::json::parse(R"({"happy": true, "pi": 3.141})");
                          resp->append_output_body("<h1>404 not found</h1>");
                          resp->append_output_body(req_uri_json.dump());
                      }));

    MindMapRoute::getInstance().
        registerRoute(HttpMethod::GET,
                      vector<std::string>{"/api", "/api/"},
                      std::move([](protocol::HttpResponse *resp) {
                          PLOG_INFO << "路由到 GET /api 处理函数";
                          resp->append_output_body("<h1>route /api</h1>");
                      }));

    MindMapRoute::getInstance().
        registerRoute(HttpMethod::GET,
                      vector<string>{"/api/users/{userid}", "/api/users/{userid}/"},
                      [](protocol::HttpResponse *resp) {
                          PLOG_INFO << "路由到 GET /api/users/{userid} 处理函数";
                          resp->append_output_body("<h1>route /api/users/{userid}</h1>");
                      });

    MindMapRoute::getInstance().
        registerRoute(HttpMethod::GET,
                      vector<string>{"/api/users/{userid}/mindmap", "/api/users/{userid}/mindmap/"},
                      [](protocol::HttpResponse *resp) {
                          PLOG_INFO << "路由到 GET /api/users/{userid}/mindmap/ 处理函数";
                          resp->append_output_body("<h1>route /api/users/{userid}/mindmap/</h1>");
                      });

    MindMapRoute::getInstance().
        registerRoute(HttpMethod::GET,
                      vector<string>{"/api/users/{userid}/mindmap/{mindmapid}", "/api/users/{userid}/mindmap/{mindmapid}/"},
                      [](protocol::HttpResponse *resp) {
                          PLOG_INFO << "路由到 GET /api/users/{userid}/mindmap/{mindmapid} 处理函数";
                          resp->append_output_body("<h1>route /api/users/{userid}/mindmap/{mindmapid}/</h1>");
                      });

    // 服务器处理逻辑
    auto &&server_proc = [root]<typename T>(T &&PH1) {
        server_process(std::forward<T>(PH1), root); // 完美转发
    };
    // auto &&proc = std::bind(server_process, std::placeholders::_1, root); // 也可以用std::bind， 但是这个版本不能处理右值

    WFHttpServer server(server_proc);

    // int ret = server.start(port, argv[3], argv[4]); /* https server */
    int ret = server.start(port);
    if (ret < 0) {
        PLOG_ERROR << "error starting server";
        exit(-1);
    } else {
        PLOG_INFO << "server started successfully";
    }

    wait_group.wait();
    server.stop();

    return 0;
}

void mongocxxTest() {
    mongocxx::instance instance{};
    mongocxx::uri uri{"mongodb://localhost:27017/?maxPoolSize=20"};
    mongocxx::pool pool{uri};

    std::vector<std::thread> threads;

    for (int i = 0; i < 100; ++i) {
        threads.emplace_back(
            [&pool, i]() {
                auto client = pool.acquire();
                auto collection = client->database("testDB").collection("collection_1");
                std::stringstream ss;
                ss << getCurrentTime();
                // Insert a simple document
                auto result = collection.insert_one(bsoncxx::builder::basic::make_document(
                        bsoncxx::builder::basic::kvp("thread_id: ", i),
                        bsoncxx::builder::basic::kvp("time: ", ss.str()),
                        bsoncxx::builder::basic::kvp("time: ", "test")      // 新值将覆盖旧值。即：每个 key-value 的 key 都唯一
                        // bsoncxx::builder::basic::kvp("test",bsoncxx::builder::basic::kvp("test","test"))
                        )
                    );

                ss.clear();

                if (result) {
                    PLOG_DEBUG << "Thread " << i << " inserted a document";
                }
            }
            );
    }

    for (auto &thread : threads) {
        thread.join();
    }

    PLOG_DEBUG << "All threads completed";
}

void plogTest() {
    plog::init<plog::TxtFormatter>(plog::debug, plog::streamStdOut); // Initialize logging

    std::unordered_map<std::string, int> unorderedMap;
    unorderedMap["red"] = 1;
    unorderedMap["green"] = 2;
    unorderedMap["blue"] = 4;
    PLOG_INFO << unorderedMap;

    std::unordered_set<std::string> unorderedSet;
    unorderedSet.insert("red");
    unorderedSet.insert("green");
    unorderedSet.insert("blue");
    PLOG_INFO << unorderedSet;

    std::array<int, 4> array = {{1, 2, 3, 4}};
    PLOG_INFO << array;
}