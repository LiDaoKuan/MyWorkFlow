//
// Created by ldk on 10/13/25.
//

#ifndef MYWORKFLOW_PACKAGEWRAPPER_H
#define MYWORKFLOW_PACKAGEWRAPPER_H

#include "ProtocolMessage.h"

namespace protocol {
    // 在协议栈中充当 中间件容器 或 协议单元组装者
    class PackageWrapper : public ProtocolWrapper {
        /**PackageWrapper继承自ProtocolWrapper，这意味着它首先是一个装饰器(Decorator)
         * 但它的目标可能不止于装饰单个对象, 而是旨在包装和管理一个完整的协议处理单元或子协议栈.
         * ProtocolWrapper 已经提供了将操作委托给内部 message 的能力, 而 PackageWrapper 在此基础上,
         * 通过 next_out 和 next_in 方法，提供了 将消息路由到下一个处理节点 的潜力.
         * 这使得它能够将多个协议层或处理模块串联起来，形成一个处理管道 */
    private:
        // 预留出口: 供子类重写, 实现出站消息路由.
        virtual ProtocolMessage *next_out(ProtocolMessage *message) { return nullptr; }
        // 预留入口: 供子类重写, 实现入站消息路由. 根据传入的消息(message)决定下一个要处理的协议消息是什么
        virtual ProtocolMessage *next_in(ProtocolMessage *message) { return nullptr; }

    protected:
        // 实现出站消息的序列化逻辑
        int encode(iovec io_vec[], int max) override;
        // 实现入站消息的反序列化逻辑
        int append(const void *buf, size_t *size) override;

    public:
        explicit PackageWrapper(ProtocolMessage *message)
            : ProtocolWrapper(message) {}

        PackageWrapper(PackageWrapper &&wrapper) = default;
        PackageWrapper &operator =(PackageWrapper &&wrapper) = default;
    };
}

#endif //MYWORKFLOW_PACKAGEWRAPPER_H