#include <csignal>
#include <iostream>
#include <csignal>
#include <arpa/inet.h>

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

bool handleGetMethod() {
    return false;
}

bool handlePostMethod() {
    return false;
}

bool handlePutMethod() {
    return false;
}

bool handlePatchMethod() {
    return false;
}

bool handleDeleteMethod() {
    return false;
}

bool handleHeadMethod() {
    return false;
}

string slipIpFromUri(const char *uri) {
    if (!uri) {
        fprintf(stderr, "error: uri is null!\n");
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
    printf("request from: %s, method: %s\n", peerAddr, method);
    printf("request uri: %s\n", uri);

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
    printf("--------------------------------------------------------->\n");

    auto request = serverTask->get_req(); // 请求对象
    handleRequest(request, serverTask);

    auto response = serverTask->get_resp(); // 响应对象
    printf("---------------------------------------------------------<\n");
}

static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signum) {
    wait_group.done();
    printf("signal_handler received %d\n", signum);
}

int main() {
    signal(SIGINT, sig_handler);

    unsigned int port = 8080;
    const char *root = ".";

    MindMapRoute::getInstance().
        registerRoute(HttpMethod::GET,
                      vector<std::string>{"/api", "/api/"},
                      std::move([](protocol::HttpResponse *resp) {
                          printf("路由到 GET /api 处理函数\n");
                          resp->append_output_body("<h1>route /api</h1>");
                      }));

    MindMapRoute::getInstance().
        registerRoute(HttpMethod::GET,
                      vector<string>{"/api/users/{userid}", "/api/users/{userid}/"},
                      [](protocol::HttpResponse *resp) {
                          printf("路由到 GET /api/users/{userid} 处理函数\n");
                          resp->append_output_body("<h1>route /api/users/{userid}</h1>");
                      });

    MindMapRoute::getInstance().
        registerRoute(HttpMethod::GET,
                      vector<string>{"/api/users/{userid}/mindmap", "/api/users/{userid}/mindmap/"},
                      [](protocol::HttpResponse *resp) {
                          printf("路由到 GET /api/users/{userid}/mindmap/ 处理函数\n");
                          resp->append_output_body("<h1>route /api/users/{userid}/mindmap/</h1>");
                      });

    MindMapRoute::getInstance().
        registerRoute(HttpMethod::GET,
                      vector<string>{"/api/users/{userid}/mindmap/{mindmapid}", "/api/users/{userid}/mindmap/{mindmapid}/"},
                      [](protocol::HttpResponse *resp) {
                          printf("路由到 GET /api/users/{userid}/mindmap/{mindmapid} 处理函数\n");
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
        fprintf(stderr, "error starting server\n");
        exit(-1);
    } else {
        printf("server started successfully\n");
    }

    wait_group.wait();
    server.stop();

    return 0;
}