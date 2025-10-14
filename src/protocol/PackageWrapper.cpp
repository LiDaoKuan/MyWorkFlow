//
// Created by ldk on 10/13/25.
//

#include <cerrno>
#include "PackageWrapper.h"

namespace protocol {
    // 链式编码函数. 实现了在有限缓冲区空间内连续编码多个协议消息的功能.
    // 其核心设计思想是通过循环和指针算术, 将一个大任务分解为多个小消息的连续编码, 直到缓冲区耗尽或没有更多消息需要处理
    int PackageWrapper::encode(iovec io_vec[], int max) {
        int cnt = 0;
        int ret = 0;
        // 数字8是一个经验性的阈值, 它表示编码单个消息头或最小消息单元所需的最大iovec结构数量.
        // 这确保了即使是最小的协议头或数据片段也有足够的空间被编码, 避免了缓冲区溢出的风险
        while (max >= 8) {
            // 显式地调用了基类ProtocolWrapper的encode方法
            // 这是一种常见的模板方法模式的应用, 基类负责单个消息的编码, 派生类负责消息链的调度
            ret = this->ProtocolWrapper::encode(io_vec, max);
            if (static_cast<unsigned int>(ret) > static_cast<unsigned int>(max)) {
                if (ret < 0) { return ret; } // 立即返回错误
                // 如果 ret 是正数但大于 max，说明编码当前消息需要比剩余空间(max)更多的iovec单元.
                // 这被视为一种正常情况, 循环通过break退出, 后续会返回 EOVERFLOW
                break;
            }

            cnt += ret; // 累计已使用的iovec数量
            this->set_message(this->next_out(this->message)); // 获取下一个消息
            if (!this->message) { return cnt; } // 没有更多消息，成功返回
            io_vec += ret; // 移动iovec数组指针
            max -= ret; // 更新剩余空间
        }
        errno = EOVERFLOW; // 缓冲区溢出
        return -1;
    }

    // 链式协议消息处理
    // 实现了数据包在多个协议层之间传递的机制。其核心逻辑是：当当前协议消息成功解析完一段数据后，自动将剩余数据传递给下一个协议消息进行处理
    int PackageWrapper::append(const void *buf, size_t *size) {
        // 调用基类的append方法, 基类的append方法会将buf和size委托给this->message->append()处理
        const int ret = this->ProtocolWrapper::append(buf, size);
        // ret>0说明当前消息已经成功解析并完成(如一个完整的数据包已经解析完毕)
        if (ret > 0) {
            // 当前协议消息 已成功处理完一个完整数据单元 时, 才进入链式处理逻辑, 表明当前层的协议解析工作已经完成, 数据可以传递给下一个处理环节
            // 根据当前消息(this->message)决定下一个要处理的协议消息是什么. 具体的路由逻辑由PackageWrapper的子类实现
            this->set_message(this->next_in(this->message));
            if (this->message) {
                // 如果成功获取到下一个消息(this->message不为nullptr), 则调用renew()方法
                // renew()通常用于重置新消息的内部状态, 清理可能残留的解析状态, 使其准备好接收新的数据
                this->renew();
                return 0; // 返回0, 表示当前append调用已结束
            }
        }
        // 如果当前消息解析未完成(ret <= 0)或者没有下一个消息需要处理(this->message为nullptr), 函数直接返回ret
        // 对于调用者来说, ret <= 0意味着本次数据追加操作要么还在进行中(需要更多数据), 要么已经结束(错误或整个链处理完毕)
        return ret;
    }
}