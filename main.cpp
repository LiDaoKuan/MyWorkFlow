#include <iostream>
#include <unistd.h>

#include "src/kernel/CommRequest.h"

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
    pthread_mutex_t mutex;
    pthread_mutex_lock(&mutex);
    pthread_mutex_lock(&mutex);
    std::cout << "test" << std::endl;
    pthread_mutex_unlock(&mutex);
}

int main() {
    Test();
    return 0;
}