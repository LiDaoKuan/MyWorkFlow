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
        int b = 0;

    public:
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

int main() {
    TEST1::Test();
    return 0;
}