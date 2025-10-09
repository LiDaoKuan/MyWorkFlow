#include <iostream>
#include "src/kernel/IOService_linux.h"

class A {
public:
    int a = 12;
};

class B : private A {
    int b = 0;

public:
    [[nodiscard]] int get_a() const {
        return a;
    }
};


void Test() {
    A *_a = new A;
    B *_b = reinterpret_cast<B *>(_a);
    std::cout << "b: " << _b->get_a() << std::endl;
    delete _a;
}

int main() {
    //test();
    Test();
    return 0;
}