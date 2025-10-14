//
// Created by ldk on 10/13/25.
//

#ifndef MYWORKFLOW_PROTOCOLMESSAGE_H
#define MYWORKFLOW_PROTOCOLMESSAGE_H

#include <cerrno>
#include <cstddef>
#include <utility>
#include "Communicator.h"

namespace protocol {
    // 实现自定义通信协议的基类
    class ProtocolMessage : public CommMessageOut, public CommMessageIn {
    public:
        ProtocolMessage() {
            this->size_limit = static_cast<size_t>(-1);
            this->attachment = nullptr;
            this->wrapper = nullptr;
        }

        ~ProtocolMessage() override { delete this->attachment; }

        // 移动构造
        ProtocolMessage(ProtocolMessage &&message) noexcept {
            this->size_limit = message.size_limit;
            this->attachment = message.attachment; // 窃取传入对象的attachment指针
            message.attachment = nullptr; // 将传入对象的attachment指针置为nullptr
            this->wrapper = nullptr;
        }

        // 移动赋值
        ProtocolMessage &operator =(ProtocolMessage &&message) noexcept {
            if (&message != this) {
                this->size_limit = message.size_limit;
                delete this->attachment;
                this->attachment = message.attachment;
                message.attachment = nullptr;
            }
            return *this;
        }

    protected:
        // 定义如何从字节流解析（反序列化）
        // 对数据进行编码, 编码后的数据放入参数数组io_vec[]中, 返回编码成功后的数组长度
        int encode(iovec io_vec[], int max) override {
            errno = ENOSYS; // 设计为出错是希望子类能够重写该方法(因为此父类需要使用多态, 所以该函数不能直接实现为纯虚函数)
            return -1;
        }

        // 定义消息如何转换为字节流（序列化）
        int append(const void *buf, size_t *size) override { return this->append(buf, *size); }

        virtual int append(const void *buf, size_t size) {
            errno = ENOSYS; // 期待子类重写
            return -1;
        }

    public:
        void set_size_limit(size_t limit) { this->size_limit = limit; }
        [[nodiscard]] size_t get_size_limit() const { return this->size_limit; }

    public:
        // 允许用户在处理协议消息的整个生命周期内，附加任意自定义的上下文信息
        class Attachment {
        public:
            virtual ~Attachment() = default;
        };

        // 通过设置指针传入自定义数据, 避免为了传递少量数据而不得不修改协议消息结构本身
        void set_attachment(Attachment *att) { this->attachment = att; }
        Attachment *get_attachment() { return this->attachment; }
        [[nodiscard]] const Attachment *get_attachment() const { return this->attachment; }

    protected:
        // 委托模式
        // 可在接收过程中发送小数据包. 即时反馈, 用于协议交互(如ACK).
        int feedback(const void *buf, size_t size) override {
            if (this->wrapper) {
                return this->wrapper->feedback(buf, size);
            }
            return this->CommMessageIn::feedback(buf, size);
        }

        // 委托模式
        // 重置接收超时计时. 当收到部分数据时调用renew(), 可以防止因网络延迟或传输大消息时间过长而导致连接被误关闭
        void renew() override {
            if (this->wrapper) {
                return this->wrapper->renew(); // 递归刷新
            }
            return this->CommMessageIn::renew();
        }

        ProtocolMessage *inner() override { return this; }

    protected:
        size_t size_limit;

    private:
        Attachment *attachment;
        ProtocolMessage *wrapper; // 支持消息被装饰或包装，实现功能增强（如加密、压缩）

        friend class ProtocolWrapper;
    };

    // 装饰器模式: 通过包装ProtocolMessage对象来增强或修改其行为, 同时保持与原始对象相同的接口
    class ProtocolWrapper : public ProtocolMessage {
    protected:
        // 委托调用: 直接调用 message->encode(...)
        int encode(iovec vectors[], int max) override { return this->message->encode(vectors, max); }
        // 委托调用: 直接调用 message->append(...)
        int append(const void *buf, size_t *size) override { return this->message->append(buf, size); }
        // 委托调用: 直接调用 message->inner()
        ProtocolMessage *inner() override { return this->message->inner(); }

        // 这个set函数竟然是protected的, 意味着这个方法主要供框架内部(如派生类或在友元类中)调用, 而不是暴露给外部用户随意调用
        // 设置被包装对象，并建立反向指针 (message->wrapper = this)
        void set_message(ProtocolMessage *_message) {
            this->message = _message;
            if (_message) { _message->wrapper = this; }
        }

    protected:
        ProtocolMessage *message{nullptr};

    public:
        explicit ProtocolWrapper(ProtocolMessage *message) {
            this->set_message(message);
        }

        ProtocolWrapper(ProtocolWrapper &&wrapper) noexcept
            : ProtocolMessage(std::move(wrapper)) // 移动基类部分(调用基类的移动构造)
        {
            this->set_message(wrapper.message); // 转移资源所有权
            wrapper.message = nullptr; // 置空源对象，防止重复释放
        }

        ProtocolWrapper &operator =(ProtocolWrapper &&wrapper) noexcept {
            if (&wrapper != this) {
                *static_cast<ProtocolMessage *>(this) = static_cast<ProtocolMessage>(std::move(wrapper));
                this->set_message(wrapper.message);
                wrapper.message = nullptr;
            }
            return *this;
        }
    };
}

#endif //MYWORKFLOW_PROTOCOLMESSAGE_H