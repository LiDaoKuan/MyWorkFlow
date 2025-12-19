#include <iostream>
#include <unistd.h>

#include "src/kernel/CommRequest.h"

namespace TEST1 {
    class Father {
    public:
        virtual ~Father() = default;
        int a = 12;

        virtual void func() {
            this->func1();
            this->func2();
        }

        virtual void func1() {
            std::cout << "Father::func1()" << std::endl;
        }

        virtual void func2() {
            std::cout << "Father::func2()" << std::endl;
        }
    };

    class Child : public Father {
    public:
        int b{0};

        Child() {
            b = 10;
        }

        void func() override {
            this->func1();
            this->func2();
        }

        void func2() override {
            std::cout << "Child::func2()" << std::endl;
        }

        ~Child() override = default;
    };


    void Test() {
        Father *b = new Child();
        b->func();
        delete b;
    }
}

namespace TEST2 {
    void Test() {
        const char *str = " 2030300 This is test";
        char *ptr;
        unsigned long ret;

        ret = strtoul(str, &ptr, 16);
        printf("数字（无符号长整数）是 %lu\n", ret);
        printf("字符串部分是 |%s|\n", ptr);

        printf("%lu", static_cast<size_t>(-1));
    }
}

namespace TEST3 {
    class myClass {
    public:
        int a = 0;

        void test() {
            a = 10;
            std::cout << "myclass::test" << std::endl;
        }

    protected:
        ~myClass() {
            delete this;
            std::cout << "~myClass() called" << std::endl;
        }
    };

    class myClass2 : public myClass {
    public:
        void test() {
            a = 20;
            std::cout << "myclass2::test" << std::endl;
        }

        ~myClass2() { std::cout << "~myClass2() called" << std::endl; }
    };

    void Test() {}
}

/*
namespace TEST4 {
    void Test() {
        // 1. 创建文件读取任务
        FileReadArgs args{"example.txt", 0, 4096}; // 文件名、偏移量、读取长度
        auto *task = WFTaskFactory::create_file_task(
            FILE_TASK_READ, // 任务类型
            &args, // 参数结构体
            [](WFFileTask<FileReadArgs> *task) {
                // 2. 在回调函数中处理结果
                int state = task->get_state();
                if (state == WFT_STATE_SUCCESS) {
                    long bytes_read = task->get_retval(); // 实际读取的字节数
                    fprintf(stderr, "Read %ld bytes from file\n", bytes_read);
                    // 读取的数据通过 task->get_args()->buf 访问
                } else {
                    fprintf(stderr, "File read failed: state=%d, error=%d\n",
                            state, task->get_error());
                }
            }
            );

        // 3. 启动任务（异步执行）
        task->start();

        // 主线程可继续执行其他逻辑，不会被文件IO阻塞
        pause();
    }
}*/

namespace TEST5 {
    static inline void _append_uint8(std::string &s, uint8_t tmp) {
        // 将tmp转换为C风格字符串(取地址后转为const char*), 然后插入
        s.append(reinterpret_cast<const char *>(&tmp), sizeof(uint8_t));
    }

    void test() {
        std::string str = "123";
        _append_uint8(str, 100);
        std::cout << str << std::endl;
        if (str.at(3) == 100) {
            std::cout << static_cast<int>(str.at(3)) << std::endl;
        }
    }
};

namespace TEST6 {
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <utility>
#include <string>
#include "HttpMessage.h"
#include "HttpUtil.h"
#include "WFHttpServer.h"
#include "WFTaskFactory.h"
#include "Workflow.h"
#include "WFFacilities.h"

    using namespace protocol;

    void pread_callback(WFFileIOTask *task) {
        FileIOArgs *args = task->get_args();
        long ret = task->get_retval();
        HttpResponse *resp = (HttpResponse *)task->user_data;

        close(args->fd);
        if (task->get_state() != WFT_STATE_SUCCESS || ret < 0) {
            resp->set_status_code("503");
            resp->append_output_body("<html>503 Internal Server Error.</html>");
        } else /* Use '_nocopy' carefully. */
            resp->append_output_body_nocopy(args->buf, ret);
    }

    void process(WFHttpTask *server_task, const char *root) {
        HttpRequest *req = server_task->get_req();
        HttpResponse *resp = server_task->get_resp();
        const char *uri = req->get_request_uri();
        const char *p = uri;

        printf("Request-URI: %s\n", uri);
        while (*p && *p != '?') p++;

        std::string abs_path(uri, p - uri);
        abs_path = root + abs_path;
        if (abs_path.back() == '/') abs_path += "index.html";

        resp->add_header_pair("Server", "Sogou C++ Workflow Server");

        int fd = open(abs_path.c_str(), O_RDONLY);
        if (fd >= 0) {
            size_t size = lseek(fd, 0, SEEK_END);
            void *buf = malloc(size); /* As an example, assert(buf != NULL); */
            WFFileIOTask *pread_task;

            pread_task = WFTaskFactory::create_pread_task(fd, buf, size, 0,
                                                          pread_callback);
            /* To implement a more complicated server, please use series' context
             * instead of tasks' user_data to pass/store internal data. */
            pread_task->user_data = resp; /* pass resp pointer to pread task. */
            server_task->user_data = buf; /* to free() in callback() */
            server_task->set_callback([](WFHttpTask *t) { free(t->user_data); });
            series_of(server_task)->push_back(pread_task);
        } else {
            resp->set_status_code("404");
            resp->append_output_body("<html>404 Not Found.</html>");
        }
    }

    static WFFacilities::WaitGroup wait_group(1);

    void sig_handler(int signo) {
        wait_group.done();
    }

    int test(int argc, char *argv[]) {
        if (argc != 2 && argc != 3 && argc != 5) {
            fprintf(stderr, "%s <port> [root path] [cert file] [key file]\n",
                    argv[0]);
            exit(1);
        }

        signal(SIGINT, sig_handler);

        unsigned short port = atoi(argv[1]);
        const char *root = (argc >= 3 ? argv[2] : ".");
        auto &&proc = std::bind(process, std::placeholders::_1, root);
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
        auto &&create = [&scheme, port](WFRepeaterTask *) -> SubTask * {
            char buf[1024];
            *buf = '\0';
            printf("Input file name: (Ctrl-D to exit): ");
            scanf("%1023s", buf);
            if (*buf == '\0') {
                printf("\n");
                return NULL;
            }

            std::string url = scheme + "127.0.0.1:" + std::to_string(port) + "/" + buf;
            WFHttpTask *task = WFTaskFactory::create_http_task(url, 0, 0,
                                                               [](WFHttpTask *task) {
                                                                   auto *resp = task->get_resp();
                                                                   if (strcmp(resp->get_status_code(), "200") == 0) {
                                                                       std::string body = protocol::HttpUtil::decode_chunked_body(resp);
                                                                       fwrite(body.c_str(), body.size(), 1, stdout);
                                                                       printf("\n");
                                                                   } else {
                                                                       printf("%s %s\n", resp->get_status_code(), resp->get_reason_phrase());
                                                                   }
                                                               });

            return task;
        };

        WFFacilities::WaitGroup wg(1);
        WFRepeaterTask *repeater;
        repeater = WFTaskFactory::create_repeater_task(create, [&wg](WFRepeaterTask *) { wg.done(); });

        repeater->start();
        wg.wait();

        server.stop();
        return 0;
    }
}

int main(int argc, char *argv[]) {
    // TEST3::Test();
    TEST6::test(argc, argv);
    return 0;
}