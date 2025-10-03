cmake_minimum_required(VERSION 4.0)
project(myWorkFlow)

set(CMAKE_CXX_STANDARD 26)

add_executable(myWorkFlow main.cpp
        src/kernel/SubTask.h
        src/kernel/SubTask.cpp
        src/kernel/Communicator.h
        src/kernel/list.h
        src/kernel/poller.h
        src/kernel/poller.c
        src/kernel/rbtree.h
        src/kernel/rbtree.c
        src/kernel/IOService_linux.h
        src/kernel/mpoller.h
        src/kernel/mpoller.c
        src/kernel/IOService_linux.cpp)

find_package(OpenSSL REQUIRED)

target_link_libraries(myWorkFlow PRIVATE OpenSSL::SSL OpenSSL::Crypto)
