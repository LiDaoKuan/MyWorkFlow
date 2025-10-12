#include <iostream>
#include <unistd.h>

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
    int fd = 0;
    int copy_fd = dup(fd);
    std::cout << copy_fd << std::endl;
    close(copy_fd);
}

int main() {
    //test();
    Test();
    return 0;
}