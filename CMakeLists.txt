cmake_minimum_required(VERSION 3.31)
project(myWorkFlow)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Debug)
# 可选：为Debug模式添加更具体的选项（GDB友好）
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g -ggdb")

set(COMMON_KERNEL_HEADERS
        workflow-src/kernel/Communicator.h
        workflow-src/kernel/list.h
        workflow-src/kernel/mpoller.h
        workflow-src/kernel/poller.h
        workflow-src/kernel/msgqueue.h
        workflow-src/kernel/rbtree.h
        workflow-src/kernel/SubTask.h
        workflow-src/kernel/threadpool.h
        workflow-src/kernel/CommRequest.h
        workflow-src/kernel/CommScheduler.h
        workflow-src/kernel/Executor.h
        workflow-src/kernel/IORequest.h
        workflow-src/kernel/ExecRequest.h
        workflow-src/kernel/SleepRequest.h
)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(INCLUDE_KERNEL_HEADERS ${COMMON_KERNEL_HEADERS} workflow-src/kernel/IOService_linux.h)
    set(PLATFORM_IO_SOURCE workflow-src/kernel/IOService_linux.cpp)
elseif (UNIX)
    set(INCLUDE_KERNEL_HEADERS ${COMMON_KERNEL_HEADERS} workflow-src/kernel/IOService_thread.h)
    set(PLATFORM_IO_SOURCE workflow-src/kernel/IOService_thread.cpp)
else ()
    message(FATAL_ERROR "IOService unsupported.")
endif ()

# file(GLOB_RECURSE PLOG_HEADERS src/3rd-party/plog/include/*.h)

set(INCLUDE_HEADERS
        ${INCLUDE_KERNEL_HEADERS}
        ${PLOG_HEADERS}
        workflow-src/protocol/ProtocolMessage.h
        workflow-src/protocol/PackageWrapper.h
        workflow-src/protocol/SSLWrapper.h
        workflow-src/protocol/HttpMessage.h
        workflow-src/protocol/http_parser.h
        workflow-src/protocol/HttpUtil.h
        workflow-src/protocol/dns_parser.h
        workflow-src/protocol/dns_types.h
        workflow-src/protocol/DnsMessage.h

        workflow-src/util/URIParser.h
        workflow-src/util/StringUtil.h
        workflow-src/util/LRUCache.h
        workflow-src/util/DnsUtil.h

        workflow-src/factory/Workflow.h
        workflow-src/factory/WFConnection.h
        workflow-src/factory/WFTask.inl  # .inl文件 放在此处？？？
        workflow-src/factory/WFTask.h
        workflow-src/factory/WFGraphTask.h
        workflow-src/factory/WFTaskFactory.h
        workflow-src/factory/WFResourcePool.cpp
        workflow-src/factory/WFResourcePool.h
        workflow-src/factory/WFTaskFactory.inl
        workflow-src/factory/WFTaskError.h

        workflow-src/manager/DnsCache.h
        workflow-src/manager/EndpointParams.h
        workflow-src/manager/RouteManager.h
        workflow-src/manager/WFGlobal.h
        workflow-src/manager/WFFacilities.h
        workflow-src/manager/WFFacilities.inl
        workflow-src/manager/WFFuture.h

        workflow-src/nameservice/WFNameService.h
        workflow-src/nameservice/WFDnsResolver.h

        workflow-src/client/WFDnsClient.h

        workflow-src/server/WFServer.h
        workflow-src/server/WFHttpServer.h
)

set(MINDMAP_INCLUDE_HEADERS MindMapRoute.h
)

set(MINDMAP_SRC MindMapRoute.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/workflow-src/kernel)
include_directories(${CMAKE_SOURCE_DIR}/workflow-src/protocol)
include_directories(${CMAKE_SOURCE_DIR}/workflow-src/factory)
include_directories(${CMAKE_SOURCE_DIR}/workflow-src/util)
include_directories(${CMAKE_SOURCE_DIR}/workflow-src/manager)
include_directories(${CMAKE_SOURCE_DIR}/workflow-src/nameservice)
include_directories(${CMAKE_SOURCE_DIR}/workflow-src/client)
include_directories(${CMAKE_SOURCE_DIR}/workflow-src/server)
include_directories(${CMAKE_SOURCE_DIR}/src/3rd-party/)

set(WORKFLOW-SRC
        workflow-src/kernel/SubTask.cpp
        workflow-src/kernel/poller.c
        workflow-src/kernel/rbtree.c
        workflow-src/kernel/mpoller.c
        workflow-src/kernel/msgqueue.c
        workflow-src/kernel/threadpool.c
        workflow-src/kernel/Communicator.cpp
        workflow-src/kernel/CommRequest.cpp
        workflow-src/kernel/CommScheduler.cpp
        workflow-src/kernel/Executor.cpp

        workflow-src/protocol/http_parser.c
        workflow-src/protocol/PackageWrapper.cpp
        workflow-src/protocol/HttpMessage.cpp
        workflow-src/protocol/HttpUtil.cpp
        workflow-src/protocol/dns_parser.c
        workflow-src/protocol/DnsMessage.cpp
        workflow-src/protocol/SSLWrapper.cpp

        workflow-src/util/URIParser.cpp
        workflow-src/util/StringUtil.cpp
        workflow-src/util/DnsUtil.cpp

        workflow-src/factory/Workflow.cpp
        workflow-src/factory/WFTaskFactory.cpp
        workflow-src/factory/WFGraphTask.cpp
        workflow-src/factory/FileTaskImpl.cpp
        workflow-src/factory/HttpTaskImpl.cpp
        workflow-src/factory/DnsTaskImpl.cpp

        workflow-src/manager/RouteManager.cpp
        workflow-src/manager/WFGlobal.cpp
        workflow-src/manager/DnsCache.cpp
        workflow-src/nameservice/WFDnsResolver.cpp

        workflow-src/nameservice/WFNameService.cpp

        workflow-src/client/WFDnsClient.cpp

        workflow-src/server/WFServer.cpp
)
# ------------------------ nlohmann config ------------------------
set(NLOHMANN_HEADER src/3rd-party/)
# -----------------------------------------------------------------

# -------------------------- plog config --------------------------
add_subdirectory(src/3rd-party/plog)
# -----------------------------------------------------------------

# ------------------------ mongocxx config ------------------------
find_package(mongocxx REQUIRED)
find_package(bsoncxx REQUIRED)
include_directories(${LIBMONGOCXX_INCLUDE_DIR})
include_directories(${LIBBSONCXX_INCLUDE_DIR})
include_directories("/usr/local/include/mongocxx/v_noabi")
include_directories("/usr/local/include/bsoncxx/v_noabi")
include_directories("/usr/local/include/libmongoc-1.0")
include_directories("/usr/local/include/libbson-1.0")
include_directories("/usr/local/lib")
link_directories(
        /usr/local/lib/mongocxx/v_noabi
        /usr/local/lib/bsoncxx/v_noabi
)
# -----------------------------------------------------------------

add_executable(server server.cpp
        ${INCLUDE_HEADERS}
        ${PLATFORM_IO_SOURCE}
        ${WORKFLOW-SRC}
        ${NLOHMANN_HEADER}
)

add_executable(client client.cpp
        ${INCLUDE_HEADERS}
        ${PLATFORM_IO_SOURCE}
        ${WORKFLOW-SRC}
        ${NLOHMANN_HEADER}
)

add_executable(main main.cpp
        ${INCLUDE_HEADERS}
        ${PLATFORM_IO_SOURCE}
        ${WORKFLOW-SRC}
        ${NLOHMANN_HEADER}
        ${MINDMAP_SRC}
        ${MINDMAP_INCLUDE_HEADERS}
)

find_package(OpenSSL REQUIRED)

target_link_libraries(server PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_link_libraries(client PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_link_libraries(main PRIVATE OpenSSL::SSL OpenSSL::Crypto plog::plog mongoc2 bsoncxx mongocxx)