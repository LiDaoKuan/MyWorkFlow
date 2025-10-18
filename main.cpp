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
    protected:
        ~myClass() {
            delete this;
            std::cout << "~myClass() called" << std::endl;
        }
    };

    class myClass2 {
        ~myClass2() { std::cout << "~myClass2() called" << std::endl; }
    };

    void Test() {
        myClass *m1 = new myClass();
    }
}

int main() {
    TEST3::Test();
    return 0;
}