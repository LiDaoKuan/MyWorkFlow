cmake_minimum_required(VERSION 4.0)
project(myWorkFlow)

set(CMAKE_CXX_STANDARD 26)

set(COMMON_KERNEL_HEADERS
        src/kernel/Communicator.h
        src/kernel/list.h
        src/kernel/mpoller.h
        src/kernel/poller.h
        src/kernel/msgqueue.h
        src/kernel/rbtree.h
        src/kernel/SubTask.h
        src/kernel/threadpool.h
        src/kernel/CommRequest.h
        src/kernel/CommScheduler.h
        src/kernel/Executor.h
        src/kernel/IORequest.h
        src/kernel/ExecRequest.h
        src/kernel/SleepRequest.h
)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(INCLUDE_KERNEL_HEADERS ${COMMON_KERNEL_HEADERS} src/kernel/IOService_linux.h)
    set(PLATFORM_IO_SOURCE src/kernel/IOService_linux.cpp)
elseif (UNIX)
    set(INCLUDE_KERNEL_HEADERS ${COMMON_KERNEL_HEADERS} src/kernel/IOService_thread.h)
    set(PLATFORM_IO_SOURCE src/kernel/IOService_thread.cpp)
else ()
    message(FATAL_ERROR "IOService unsupported.")
endif ()

set(INCLUDE_HEADERS
        ${INCLUDE_KERNEL_HEADERS}
        src/protocol/ProtocolMessage.h
        src/protocol/PackageWrapper.h
        src/protocol/HttpMessage.h
        src/protocol/http_parser.h
        src/protocol/HttpUtil.h
        src/util/URIParser.h
        src/util/StringUtil.h
        src/factory/Workflow.h
        src/factory/WFConnection.h
        src/factory/WFTask.inl
        src/factory/WFTask.h
)

include_directories(${CMAKE_SOURCE_DIR}/src/kernel)
include_directories(${CMAKE_SOURCE_DIR}/src/protocol)

add_executable(myWorkFlow main.cpp
        ${INCLUDE_HEADERS}
        ${PLATFORM_IO_SOURCE}
        src/kernel/SubTask.cpp
        src/kernel/poller.c
        src/kernel/rbtree.c
        src/kernel/mpoller.c
        src/kernel/msgqueue.c
        src/kernel/threadpool.c
        src/kernel/Communicator.cpp
        src/kernel/CommRequest.cpp
        src/kernel/CommScheduler.cpp
        src/kernel/Executor.cpp
        src/protocol/http_parser.c
        src/protocol/PackageWrapper.cpp
        src/protocol/HttpMessage.cpp
        src/protocol/HttpUtil.cpp
        src/util/URIParser.cpp
        src/util/StringUtil.cpp
        src/factory/Workflow.cpp
)

find_package(OpenSSL REQUIRED)

target_link_libraries(myWorkFlow PRIVATE OpenSSL::SSL OpenSSL::Crypto)
