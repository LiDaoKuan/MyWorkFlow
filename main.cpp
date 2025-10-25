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

    void Test() {
    }
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

int main() {
    TEST3::Test();
    return 0;
}