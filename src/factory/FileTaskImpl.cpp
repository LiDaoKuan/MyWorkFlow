//
// Created by ldk on 12/20/25.
//

/*
  Copyright (c) 2019 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Authors: Xie Han (xiehan@sogou-inc.com)
           Li Jinghao (lijinghao@sogou-inc.com)
*/

/**
 * @file file_task.h
 * @brief Workflow文件异步I/O任务实现
 *
 * 本文件实现POSIX文件操作的异步封装，核心特性：
 * 1. 支持pread/pwrite等偏移量操作
 * 2. 自动管理文件描述符生命周期（路径模式）
 * 3. 与Workflow调度器深度集成
 * 4. 分层设计：基础I/O任务 vs 路径管理任务
 *
 * 设计哲学：
 * - 通过继承实现功能组合（I/O操作 + 资源管理）
 * - 分离关注点: 基础任务只处理I/O，路径任务专注FD管理
 * - 保持接口一致性：相同操作无论fd/path模式都返回相同基类
 */

#include <fcntl.h>
#include <unistd.h>
#include <string>
#include "WFGlobal.h"
#include "WFTaskFactory.h"

/**
 * @brief 异步pread任务（基于文件描述符）
 *
 * 封装Linux pread系统调用, 特点：
 * - 位置偏移量操作，不改变文件偏移指针
 * - 适用于多线程/异步环境
 */
class WFFilepreadTask : public WFFileIOTask {
public:
    /**
     * @param fd 文件描述符
     * @param buf 读取缓冲区
     * @param count 读取字节数
     * @param offset 文件偏移量
     * @param service IO服务（由框架提供）
     * @param cb 完成回调
     */
    WFFilepreadTask(int fd, void *buf, size_t count, off_t offset,
                    IOService *service, fio_callback_t &&cb) :
        WFFileIOTask(service, std::move(cb)) {
        this->args.fd = fd;
        this->args.buf = buf;
        this->args.count = count;
        this->args.offset = offset;
    }

protected:
    /**
     * @brief 任务准备阶段
     *
     * 设置具体的I/O操作参数, 由调度器在执行前调用
     * @return int 0=成功，-1=失败
     */
    int prepare() override {
        this->prep_pread(this->args.fd, this->args.buf, this->args.count, this->args.offset);
        return 0;
    }
};

/**
 * @brief 异步pwrite任务（基于文件描述符）
 *
 * 封装Linux pwrite系统调用，特点：
 * - 位置偏移量写入，不改变文件偏移指针
 * - const_cast处理: 写操作需要可修改缓冲区，但接口保持const语义
 */
class WFFilepwriteTask : public WFFileIOTask {
public:
    WFFilepwriteTask(int fd, const void *buf, size_t count, off_t offset,
                     IOService *service, fio_callback_t &&cb) :
        WFFileIOTask(service, std::move(cb)) {
        this->args.fd = fd;
        // 关键设计: 保留const语义接口, 内部转换为可写指针
        this->args.buf = const_cast<void *>(buf);
        this->args.count = count;
        this->args.offset = offset;
    }

protected:
    /**
     * @brief 任务准备阶段
     *
     * 设置具体的I/O操作参数, 由调度器在执行前调用
     * @return int 0=成功，-1=失败
     */
    int prepare() override {
        this->prep_pwrite(this->args.fd, this->args.buf, this->args.count, this->args.offset);
        return 0;
    }
};

/**
 * @brief 异步preadv任务（分散读，基于文件描述符）
 *
 * 封装preadv系统调用，特点：
 * - 支持iovec结构的分散读取
 * - 适用于多缓冲区读取场景（如协议解析）
 */
class WFFilepreadvTask : public WFFileVIOTask {
public:
    WFFilepreadvTask(int fd, const struct iovec *iov, int iovcnt, off_t offset,
                     IOService *service, fvio_callback_t &&cb) :
        WFFileVIOTask(service, std::move(cb)) {
        this->args.fd = fd;
        this->args.iov = iov;       // iovec数组
        this->args.iovcnt = iovcnt; // 数组长度
        this->args.offset = offset;
    }

protected:
    int prepare() override {
        this->prep_preadv(this->args.fd, this->args.iov, this->args.iovcnt, this->args.offset);
        return 0;
    }
};

/**
 * @brief 异步fsync任务
 *
 * 封装fsync系统调用，特点：
 * - 确保文件元数据和数据持久化
 * - 适用于关键数据落盘场景
 */
class WFFilepwritevTask : public WFFileVIOTask {
public:
    WFFilepwritevTask(int fd, const struct iovec *iov, int iovcnt, off_t offset,
                      IOService *service, fvio_callback_t &&cb) :
        WFFileVIOTask(service, std::move(cb)) {
        this->args.fd = fd;
        this->args.iov = iov;
        this->args.iovcnt = iovcnt;
        this->args.offset = offset;
    }

protected:
    int prepare() override {
        this->prep_pwritev(this->args.fd, this->args.iov, this->args.iovcnt, this->args.offset);
        return 0;
    }
};

/**
 * @brief 异步fsync任务
 *
 * 封装fsync系统调用，特点：
 * - 确保文件元数据和数据持久化
 * - 适用于关键数据落盘场景
 */
class WFFilefsyncTask : public WFFileSyncTask {
public:
    WFFilefsyncTask(int fd, IOService *service, fsync_callback_t &&cb) :
        WFFileSyncTask(service, std::move(cb)) {
        this->args.fd = fd;
    }

protected:
    int prepare() override {
        // 配置fsync操作
        this->prep_fsync(this->args.fd);
        return 0;
    }
};

/**
 * @brief 异步fdatasync任务
 *
 * 封装fdatasync系统调用，特点：
 * - 仅确保文件数据持久化（不包含元数据）
 * - 比fsync性能更高，适用于非关键元数据场景
 */
class WFFilefdsyncTask : public WFFileSyncTask {
public:
    WFFilefdsyncTask(int fd, IOService *service, fsync_callback_t &&cb) :
        WFFileSyncTask(service, std::move(cb)) {
        this->args.fd = fd;
    }

protected:
    int prepare() override {
        this->prep_fdsync(this->args.fd);
        return 0;
    }
};

/* File tasks created with path name. */

/**
 * @brief 带文件路径管理的pread任务
 *
 * 关键增强:
 * 1. 自动open/close文件
 * 2. 错误处理: open失败时任务直接失败
 * 3. 资源安全: 确保FD在任务结束时关闭
 */
class __WFFilepreadTask : public WFFilepreadTask {
public:
    /**
     * @param path 文件路径
     * @param buf 读取缓冲区
     * @param count 读取字节数
     * @param offset 文件偏移量
     * @param service IO服务
     * @param cb 完成回调
     */
    __WFFilepreadTask(const std::string &path, void *buf, size_t count,
                      off_t offset, IOService *service, fio_callback_t &&cb) :
        WFFilepreadTask(-1, buf, count, offset, service, std::move(cb)),
        pathname(path) {}

protected:
    /**
     * @brief 准备阶段增强
     *
     * 1. 打开文件（只读模式）
     * 2. 失败时返回-1触发错误流程
     * 3. 成功则委托给基类准备I/O
     */
    int prepare() override {
        // O_RDONLY | O_CLOEXEC: 安全打开文件
        this->args.fd = open(this->pathname.c_str(), O_RDONLY);
        if (this->args.fd < 0) {
            return -1; // 触发WFT_STATE_SYS_ERROR
        }

        return WFFilepreadTask::prepare();
    }

    /**
     * @brief 任务完成钩子
     *
     * 资源清理保证:
     * 1. 无论成功/失败都关闭FD
     * 2. 重置FD为-1防止重复关闭
     * 3. 透传到基类完成后续处理
     */
    SubTask *done() override {
        if (this->args.fd >= 0) {
            close(this->args.fd);
            this->args.fd = -1;
        }

        return WFFilepreadTask::done();
    }

protected:
    std::string pathname; // 文件路径
};

/**
 * @brief 带文件路径管理的pwrite任务
 *
 * 关键增强：
 * 1. 自动创建文件（O_CREAT | 0644）
 * 2. 写入模式（O_WRONLY）
 * 3. 同样保证FD生命周期管理
 */
class __WFFilepwriteTask : public WFFilepwriteTask {
public:
    __WFFilepwriteTask(const std::string &path, const void *buf, size_t count,
                       off_t offset, IOService *service, fio_callback_t &&cb) :
        WFFilepwriteTask(-1, buf, count, offset, service, std::move(cb)),
        pathname(path) {}

protected:
    int prepare() override {
        // O_WRONLY | O_CREAT | O_CLOEXEC：安全创建/打开文件
        this->args.fd = open(this->pathname.c_str(), O_WRONLY | O_CREAT, 0644); // 0644默认权限
        if (this->args.fd < 0) {
            return -1;
        }

        return WFFilepwriteTask::prepare();
    }

    SubTask *done() override {
        if (this->args.fd >= 0) {
            close(this->args.fd);
            this->args.fd = -1;
        }

        return WFFilepwriteTask::done();
    }

protected:
    std::string pathname;
};

class __WFFilepreadvTask : public WFFilepreadvTask {
public:
    __WFFilepreadvTask(const std::string &path, const struct iovec *iov,
                       int iovcnt, off_t offset, IOService *service,
                       fvio_callback_t &&cb) :
        WFFilepreadvTask(-1, iov, iovcnt, offset, service, std::move(cb)),
        pathname(path) {}

protected:
    int prepare() override {
        this->args.fd = open(this->pathname.c_str(), O_RDONLY);
        if (this->args.fd < 0) return -1;

        return WFFilepreadvTask::prepare();
    }

    SubTask *done() override {
        if (this->args.fd >= 0) {
            close(this->args.fd);
            this->args.fd = -1;
        }

        return WFFilepreadvTask::done();
    }

protected:
    std::string pathname;
};

class __WFFilepwritevTask : public WFFilepwritevTask {
public:
    __WFFilepwritevTask(const std::string &path, const struct iovec *iov,
                        int iovcnt, off_t offset, IOService *service,
                        fvio_callback_t &&cb) :
        WFFilepwritevTask(-1, iov, iovcnt, offset, service, std::move(cb)),
        pathname(path) {}

protected:
    int prepare() override {
        this->args.fd = open(this->pathname.c_str(), O_WRONLY | O_CREAT, 0644);
        if (this->args.fd < 0) return -1;

        return WFFilepwritevTask::prepare();
    }

protected:
    SubTask *done() override {
        if (this->args.fd >= 0) {
            close(this->args.fd);
            this->args.fd = -1;
        }

        return WFFilepwritevTask::done();
    }

protected:
    std::string pathname;
};

/********** 任务工厂（用户接口） **********/

/* 基于文件描述符的工厂函数 */

/**
 * @brief 创建pread任务（fd模式）
 *
 * @param fd 文件描述符（需调用者保证生命周期）
 * @param buf 读取缓冲区
 * @param count 读取字节数
 * @param offset 文件偏移量
 * @param callback 完成回调
 * @return WFFileIOTask* 任务对象
 *
 * 使用场景:
 * - 已有打开的文件描述符
 * - 需要精细控制FD生命周期
 */
WFFileIOTask *WFTaskFactory::create_pread_task(int fd, void *buf, size_t count,
                                               off_t offset, fio_callback_t callback) {
    return new WFFilepreadTask(fd, buf, count, offset, WFGlobal::get_io_service(), std::move(callback));
}

/**
 * @brief 创建pwrite任务（fd模式）
 *
 * @param fd 文件描述符
 * @param buf 写入缓冲区（const语义保证数据不被意外修改）
 * @param count 写入字节数
 * @param offset 文件偏移量
 * @param callback 完成回调
 * @return WFFileIOTask* 任务对象
 */
WFFileIOTask *WFTaskFactory::create_pwrite_task(int fd, const void *buf, size_t count,
                                                off_t offset, fio_callback_t callback) {
    return new WFFilepwriteTask(fd, buf, count, offset, WFGlobal::get_io_service(), std::move(callback));
}

/**
 * @brief 异步分散读. 将文件数据一次性读入多个不连续的缓冲区（iov）
 *
 * @param fd 文件描述符
 * @param iovec 读缓冲区数组
 * @param iovcnt 读缓冲区数组大小
 * @param offset 文件偏移量
 * @param callback 完成回调
 * @return WFFileIOTask* 任务对象
 */
WFFileVIOTask *WFTaskFactory::create_preadv_task(int fd, const struct iovec *iovec, int iovcnt,
                                                 off_t offset, fvio_callback_t callback) {
    return new WFFilepreadvTask(fd, iovec, iovcnt, offset, WFGlobal::get_io_service(), std::move(callback));
}

/**
 * @brief 异步聚集写. 将多个缓冲区的数据一次性写入文件（fd模式）
 *
 * @param fd 文件描述符
 * @param iovec 写缓冲区数组（const保证数据不被意外修改）
 * @param iovcnt 写缓冲区数组大小
 * @param offset 文件偏移量
 * @param callback 完成回调
 * @return WFFileIOTask* 任务对象
 */
WFFileVIOTask *WFTaskFactory::create_pwritev_task(int fd, const struct iovec *iovec, int iovcnt,
                                                  off_t offset, fvio_callback_t callback) {
    return new WFFilepwritevTask(fd, iovec, iovcnt, offset, WFGlobal::get_io_service(), std::move(callback));
}

WFFileSyncTask *WFTaskFactory::create_fsync_task(int fd, fsync_callback_t callback) {
    return new WFFilefsyncTask(fd, WFGlobal::get_io_service(), std::move(callback));
}

WFFileSyncTask *WFTaskFactory::create_fdsync_task(int fd, fsync_callback_t callback) {
    return new WFFilefdsyncTask(fd, WFGlobal::get_io_service(), std::move(callback));
}

/* 基于文件路径的工厂函数 */

/**
 * @brief 创建pread任务（路径模式）
 *
 * @param path 文件路径
 * @param buf 读取缓冲区
 * @param count 读取字节数
 * @param offset 文件偏移量
 * @param callback 完成回调
 * @return WFFileIOTask* 任务对象
 *
 * 核心价值：
 * - 自动管理FD生命周期
 * - 错误处理封装（open失败自动设置错误状态）
 * - 资源安全（保证close执行）
 */
WFFileIOTask *WFTaskFactory::create_pread_task(const std::string &path, void *buf, size_t count,
                                               off_t offset, fio_callback_t callback) {
    return new __WFFilepreadTask(path, buf, count, offset,
                                 WFGlobal::get_io_service(), std::move(callback));
}

WFFileIOTask *WFTaskFactory::create_pwrite_task(const std::string &path, const void *buf, size_t count,
                                                off_t offset, fio_callback_t callback) {
    return new __WFFilepwriteTask(path, buf, count, offset,
                                  WFGlobal::get_io_service(), std::move(callback));
}

WFFileVIOTask *WFTaskFactory::create_preadv_task(const std::string &path, const struct iovec *iovec, int iovcnt,
                                                 off_t offset, fvio_callback_t callback) {
    return new __WFFilepreadvTask(path, iovec, iovcnt, offset,
                                  WFGlobal::get_io_service(), std::move(callback));
}

WFFileVIOTask *WFTaskFactory::create_pwritev_task(const std::string &path, const struct iovec *iovec, int iovcnt,
                                                  off_t offset, fvio_callback_t callback) {
    return new __WFFilepwritevTask(path, iovec, iovcnt, offset,
                                   WFGlobal::get_io_service(), std::move(callback));
}