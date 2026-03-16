#include <csignal>
#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <utility>
#include <string>
#include <filesystem>
#include <iostream>
#include "HttpMessage.h"
#include "HttpUtil.h"
#include "WFHttpServer.h"
#include "WFTaskFactory.h"
#include "Workflow.h"
#include "WFFacilities.h"

using namespace protocol;

void pread_callback(WFFileIOTask *fileIOTask) {
    const FileIOArgs *args = fileIOTask->get_args();
    const long ret = fileIOTask->get_retval();
    auto *resp = static_cast<HttpResponse *>(fileIOTask->user_data);

    close(args->fd);
    if (fileIOTask->get_state() != WFT_STATE_SUCCESS || ret < 0) {
        resp->set_status_code("503");
        resp->append_output_body("<html>503 Internal Server Error.</html>");
    } else /* Use '_nocopy' carefully. */ {
        resp->append_output_body_nocopy(args->buf, ret);
    }
}

void server_process(WFHttpTask *server_task, const char *root) {
    auto req = server_task->get_req();
    auto resp = server_task->get_resp();

    const char *uri = req->get_request_uri();
    std::string method = req->get_method();
    printf("request method: %s\n", method.c_str());
    const char *p = uri;

    printf("Request-URI: %s\n", uri);
    while (*p && *p != '?') {
        p++;
    }

    std::string abs_path(uri, p - uri);
    abs_path = root + abs_path;
    if (abs_path.back() == '/') {
        abs_path += "index.html";
    }

    printf("abs_path:  %s", (abs_path + "\n").c_str());

    resp->add_header_pair("Server", "Sogou C++ Workflow Server");

    const int fd = open(abs_path.c_str(), O_RDONLY); // 文件描述符将在回调函数中关闭
    if (fd >= 0) {
        const size_t size = lseek(fd, 0, SEEK_END); // 将文件指针移动到文件尾部，方便获取文件大小
        void *buf = malloc(size);                   /* As an example, assert(buf != NULL); */
        assert(buf != nullptr);

        WFFileIOTask *pread_task = WFTaskFactory::create_pread_task(fd, buf, size, 0, pread_callback);
        /* To implement a more complicated server, please use series' context
         * instead of tasks' user_data to pass/store internal data. */
        pread_task->user_data = resp; /* pass resp pointer to pread task. */
        server_task->user_data = buf; /* to free() in callback() */
        server_task->set_callback([](WFHttpTask *t) {
            free(t->user_data);
        });
        series_of(server_task)->push_back(pread_task);
    } else {
        resp->set_status_code("404");
        resp->append_output_body("<html>404 Not Found.</html>");
    }
}

static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int sign) {
    wait_group.done();
    printf("sig received: %d", sign);
}

int main(const int argc, char *argv[]) {
    if (argc != 2 && argc != 3 && argc != 5) {
        fprintf(stderr, "%s <port> [root path] [cert file] [key file]\n", argv[0]);
        exit(1);
    }

    signal(SIGINT, sig_handler);

    unsigned short port = atoi(argv[1]);
    const char *root = (argc >= 3 ? argv[2] : ".");
    auto &&proc = [root]<typename T>(T &&PH1) {
        server_process(std::forward<T>(PH1), root);
    };
    WFHttpServer server(proc);
    std::string scheme;
    int ret;

    if (argc == 5) {
        ret = server.start(port, argv[3], argv[4]); /* https server */
        scheme = "https://";
    } else {
        ret = server.start(port);
        scheme = "http://";
    }

    if (ret < 0) {
        perror("start server");
        exit(1);
    }

    /* Test the server. */
    auto &&repeaterTask = [&scheme, port](WFRepeaterTask *) -> SubTask * {
        char buf[1024];
        *buf = '\0';
        printf("Input file name: (Ctrl-D to exit): ");
        scanf("%1023s", buf);
        if (*buf == '\0') {
            printf("\n");
            return nullptr;
        }

        std::string url = scheme + "127.0.0.1:" + std::to_string(port) + "/" + buf;
        WFHttpTask *task = WFTaskFactory::create_http_task(url, 0, 0,
                                                           [](WFHttpTask *task) {
                                                               auto *resp = task->get_resp();
                                                               if (strcmp(resp->get_status_code(), "200") == 0) {
                                                                   std::string body = protocol::HttpUtil::decode_chunked_body(resp);
                                                                   fwrite(body.c_str(), body.size(), 1, stdout);
                                                                   printf("\n");
                                                                   printf("callback finish\n");
                                                               } else {
                                                                   printf("%s %s\n", resp->get_status_code(), resp->get_reason_phrase());
                                                               }
                                                           });

        return task;
    };

    WFFacilities::WaitGroup wg(1);
    WFRepeaterTask *repeater = WFTaskFactory::create_repeater_task(repeaterTask, [&wg](WFRepeaterTask *) {
        wg.done();
    });

    repeater->start();
    wg.wait();

    server.stop();

    return 0;
}