//
// Created by ldk on 10/25/25.
//

#ifndef MYWORKFLOW_DNS_TYPE_H
#define MYWORKFLOW_DNS_TYPE_H

enum {
    DNS_TYPE_A = 1, // IPv4地址记录
    DNS_TYPE_NS, // 权威名称服务器记录
    DNS_TYPE_MD, // 邮件目的地记录. 已废弃, 由 MX记录取代
    DNS_TYPE_MF, // 邮件转发器记录. 已废弃, 由 MX记录取代
    DNS_TYPE_CNAME, // 规范名称记录. 为一个域名创建别名(alias),指向另一个“正式”的域名
    DNS_TYPE_SOA = 6, // 起始授权机构记录
    DNS_TYPE_MB, // 邮箱域名记录. 试验性, 很少使用
    DNS_TYPE_MG, // 邮件组成员记录. 试验性, 很少使用
    DNS_TYPE_MR, // 邮件重命名域名记录, 试验性, 很少使用
    DNS_TYPE_NULL, // 空资源记录. 试验性, 很少使用
    DNS_TYPE_WKS = 11, // 众所周知的服务记录. 描述某IP地址上由某个协议(如TCP或UDP)提供的网络服务
    DNS_TYPE_PTR, // 指针记录. 主要用于反向解析, 将IP地址映射回域名
    DNS_TYPE_HINFO, // 主机信息记录. 记录主机的CPU类型和操作系统信息
    DNS_TYPE_MINFO, // 邮箱或邮件列表信息记录.
    DNS_TYPE_MX, // 邮件交换记录. 指定负责接收该域邮件的服务器及其优先级
    DNS_TYPE_TXT = 16, // 文本记录. 存储任意文本信息，常用于域名所有权验证、SPF记录等

    DNS_TYPE_AAAA = 28, // IPv6地址记录
    DNS_TYPE_SRV = 33, // 服务定位记录. 用于查找提供特定服务(如VoIP、即时通讯)的服务器地址和端口

    DNS_TYPE_AXFR = 252, // 完全区域传输. 用于在主从DNS服务器之间传输整个区域的数据
    DNS_TYPE_MAILB = 253, // 邮件相关记录. 已废弃
    DNS_TYPE_MAILA = 254, // 邮件相关记录. 已废弃
    DNS_TYPE_ALL = 255 // 所有记录. 在查询中表示请求返回所有类型的记录
};

enum {
    DNS_CLASS_IN = 1, // Internet类别. 用于互联网系统, 是绝大多数DNS查询和记录使用的类别
    DNS_CLASS_CS, // CSNET类别. 历史遗留, 现已很少使用
    DNS_CLASS_CH, // CHAOS类别. 历史遗留, 现已很少使用
    DNS_CLASS_HS, // Hesiod类别. 历史遗留, 现已很少使用

    DNS_CLASS_ALL = 255 // 所有类别. 在查询中表示请求返回所有类别的记录
};

enum {
    DNS_OPCODE_QUERY = 0, // 标准查询. 最常见的查询类型, 用于根据域名请求IP地址等信息
    DNS_OPCODE_IQUERY, // 反向查询. 根据IP地址查询域名, 现已过时, 通常使用PTR记录进行反向解析
    DNS_OPCODE_STATUS, // 状态查询. 用于请求DNS服务器的状态信息
};

// DNS 返回码
enum {
    DNS_RCODE_NO_ERROR = 0,
    DNS_RCODE_FORMAT_ERROR, // 格式错误
    DNS_RCODE_SERVER_FAILURE, // 服务器失败
    DNS_RCODE_NAME_ERROR, // 名称错误. 所查询的域名不存在。此代码仅在权威DNS服务器的响应中有意义
    DNS_RCODE_NOT_IMPLEMENTED, // 未实现. DNS服务器不支持所请求的查询类型
    DNS_RCODE_REFUSED // 拒绝. DNS服务器由于策略原因（如访问控制）拒绝执行查询
};

// DNS 报文区段. 用于标识或处理DNS报文中的不同部分
enum {
    DNS_ANSWER_SECTION = 1, // 回答区段. 包含直接回答查询问题的资源记录
    DNS_AUTHORITY_SECTION = 2, // 权威区段. 包含指向查询域权威名称服务器的记录
    DNS_ADDITIONAL_SECTION = 3, // 附加区段. 包含对查询可能有用的额外信息, 例如在返回MX记录时, 附加区段可能包含对应邮件服务器的A记录
};

#endif //MYWORKFLOW_DNS_TYPE_H