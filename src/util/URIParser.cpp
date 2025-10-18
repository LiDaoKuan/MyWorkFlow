//
// Created by ldk on 10/17/25.
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

  Authors: Wu Jiaxu (wujiaxu@sogou-inc.com)
           Wang Zhulei (wangzhulei@sogou-inc.com)
           Xie Han (xiehan@sogou-inc.com)
*/

#include <cstring>
#include <cerrno>
#include <utility>
#include <vector>
#include <map>
#include "StringUtil.h"
#include "URIParser.h"


/**
枚举值            对应的 URI 组件                                               含义与示例
URI_SCHEME          协议/方案       指定访问资源所使用的协议，如 http，https，ftp，mailto。例如在 https://example.com中，scheme 是 https。
URI_USERINFO        用户信息        包含访问资源所需的身份验证信息，格式通常为 username:password。例如在 ftp://user:pass@host.com中，userinfo 是 user:pass。
URI_HOST            主机名         资源所在的主机域名或 IP 地址。例如在 https://www.example.com:8080/path中，host 是 www.example.com。它也支持 IPv6 地址，如 [2001:db8::1]。
URI_PORT            端口号         如果省略，将使用对应 scheme 的默认端口（如 HTTP 为 80，HTTPS 为 443）。例如在 https://www.example.com:8080/path中，port 是 8080。
URI_PATH            路径          指定主机上资源的具体位置，通常模拟文件系统的目录结构。例如在 https://example.com/api/v1/users中，path 是 /api/v1/users。
URI_QUERY           查询字符串     用于向服务器传递参数，格式为 ?key1=value1&key2=value2。例如在 https://example.com/search?q=workflow&lang=zh中，query 是 q=workflow&lang=zh。
URI_FRAGMENT        片段          指向资源内部的某个锚点（如 HTML 页面中的某个章节），浏览器会自动滚动到该位置。例如在 https://example.com/doc#chapter1中，fragment 是 chapter1。
URI_PART_ELEMENTS   (非组件)       一个计数常量，其值等于上述组件类型的总数（在此例中为 7）。它通常用于定义数组大小或循环边界，以便处理所有可能的 URI 组件类型。
*/

enum {
    URI_SCHEME,
    URI_USERINFO,
    URI_HOST,
    URI_PORT,
    URI_QUERY,
    URI_FRAGMENT, // 片段
    URI_PATH,
    URI_PART_ELEMENTS,
};

//scheme://[userinfo@]host[:port][/path][?query][#fragment]
//0-6 (scheme, userinfo, host, port, path, query, fragment)
static constexpr unsigned char valid_char[4][256] = {
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    },
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    },
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    },
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    },
};

//
static unsigned char authority_map[256] = {
    URI_PART_ELEMENTS, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, URI_FRAGMENT, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, URI_PATH,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, URI_HOST, 0, 0, 0, 0, URI_QUERY,
    URI_USERINFO, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

ParsedURI::ParsedURI(ParsedURI &&uri) noexcept {
    this->scheme = uri.scheme;
    this->userinfo = uri.userinfo;
    this->host = uri.host;
    this->port = uri.port;
    this->path = uri.path;
    this->query = uri.query;
    this->fragment = uri.fragment;
    this->state = uri.state;
    this->error = uri.error;
    uri.init(); // 将uri置为初始状态
}

ParsedURI &ParsedURI::operator=(ParsedURI &&uri) noexcept {
    if (this != &uri) {
        this->deinit(); // 先释放自身原有的资源
        this->scheme = uri.scheme;
        this->userinfo = uri.userinfo;
        this->host = uri.host;
        this->port = uri.port;
        this->path = uri.path;
        this->query = uri.query;
        this->fragment = uri.fragment;
        this->state = uri.state;
        this->error = uri.error;
        uri.init(); // 将uri置为初始状态
    }

    return *this;
}

void ParsedURI::copy(const ParsedURI &uri) {
    this->init();
    this->state = uri.state;
    this->error = uri.error;
    if (this->state == URI_STATE_SUCCESS) {
        bool success = false;

        do {
            if (uri.scheme) {
                this->scheme = strdup(uri.scheme);
                if (!this->scheme) { break; }
            }

            if (uri.userinfo) {
                this->userinfo = strdup(uri.userinfo);
                if (!this->userinfo) { break; }
            }

            if (uri.host) {
                this->host = strdup(uri.host);
                if (!this->host) { break; }
            }

            if (uri.port) {
                this->port = strdup(uri.port);
                if (!this->port) { break; }
            }

            if (uri.path) {
                this->path = strdup(uri.path);
                if (!this->path) { break; }
            }

            if (uri.query) {
                this->query = strdup(uri.query);
                if (!this->query) { break; }
            }

            if (uri.fragment) {
                this->fragment = strdup(uri.fragment);
                if (!this->fragment) { break; }
            }

            success = true;
        } while (false);

        if (!success) {
            deinit();
            init();
            this->state = URI_STATE_ERROR;
            this->error = errno;
        }
    }
}

// URI解析
int URIParser::parse(const char *str, ParsedURI &uri) {
    uri.state = URI_STATE_INVALID; // 初始化URI对象的状态为"无效"。这是一个安全措施，确保在解析失败时uri对象有明确状态

    int start_idx[URI_PART_ELEMENTS]{}; // 用于存储URI各个部分的起始索引
    int end_idx[URI_PART_ELEMENTS]{}; // 用于存储URI各个部分的结束索引
    int pre_state = URI_SCHEME; // pre_state表示当前解析状态（初始为协议解析）
    bool in_ipv6 = false; // 标记是否正在解析IPv6地址
    int index;

    // 找到scheme字段的结束位置
    for (index = 0; str[index]; index++) {
        if (str[index] == ':') {
            // 将scheme的结束索引设置为当前位置, 然后i++移动到冒号后的字符, 跳出循环
            end_idx[URI_SCHEME] = index++;
            break;
        }
    }

    if (end_idx[URI_SCHEME] == 0) { return -1; } // 检查是否成功找到scheme. 如果end_idx[URI_SCHEME]仍为0, 说明没有找到冒号, URI格式无效, 直接返回错误

    // 检查是否存在authority部分（即//），并根据情况设置解析状态
    if (str[index] == '/' && str[index + 1] == '/') {
        pre_state = URI_HOST; // 更改当前状态
        index += 2; // 跳过//
        // 如果下一个字符是[，标记为IPv6地址模式
        if (str[index] == '[') {
            in_ipv6 = true;
        } else { start_idx[URI_USERINFO] = index; } // 设置userinfo的起始索引（可能包含用户认证信息）

        start_idx[URI_HOST] = index; // 设置host的起始索引为当前index
    } else {
        // 没有//，则直接进入path解析，设置状态为URI_PATH，path起始索引为当前index
        pre_state = URI_PATH;
        start_idx[URI_PATH] = index;
    }

    bool skip_path = false; // skip_path标志用于控制是否跳过路径解析
    // start_idx[URI_PATH] == 0: 存在authority部分（因为这说明进入了上面的if语句，而没有进入else语句）
    if (start_idx[URI_PATH] == 0) {
        for (; ; index++) {
            switch (authority_map[static_cast<unsigned char>(str[index])]) {
            case 0: // 当前字符在authority上下文中无特殊含义, 继续处理下一个字符
                continue;
            case URI_USERINFO: // 当遇到userinfo分隔符（如@）时，处理用户信息部分.
                if (str[index + 1] == '[') { in_ipv6 = true; }
                end_idx[URI_USERINFO] = index; // 标记userinfo结束位置. userinfo格式为username:password@，用于认证信息
                start_idx[URI_HOST] = index + 1; // userinfo后面(@符号之后)一般紧跟host字段
                pre_state = URI_HOST; // 准备解析host字段
                continue;
            case URI_HOST: // 处理host部分和端口分隔符
                if (str[index - 1] == ']') { in_ipv6 = false; } // 如果前一个字符是]，说明IPv6地址结束，清除IPv6标志
                if (!in_ipv6) {
                    // 要进入这个if语句有两种情况:
                    //  1. URI中没有IPV6地址, in_ipv6字段一直为false
                    //  2. URI中有IPV地址, in_ipv6字段在上一个case分支中被设置为true,
                    //     又在index走过ipv6地址后, 在这个case分支的第一个if语句被设置为false
                    end_idx[URI_HOST] = index; // 标记host字段的结束位置
                    start_idx[URI_PORT] = index + 1; // host后跟port（也可能不跟）
                    pre_state = URI_PORT;
                }
                continue;
            case URI_QUERY: // 遇到查询字符串分隔符?时，处理查询部分
                end_idx[pre_state] = index; // 因为不知道 ？ 之前的状态是什么(存在多种情况), 所以使用之前记录的pre_state
                start_idx[URI_QUERY] = index + 1;
                pre_state = URI_QUERY;
                skip_path = true;
                continue;
            case URI_FRAGMENT: // 遇到片段分隔符#时，处理片段部分
                end_idx[pre_state] = index; // 因为不知道 # 之前的状态是什么(存在多种情况), 所以使用之前记录的pre_state
                start_idx[URI_FRAGMENT] = index + 1;
                end_idx[URI_FRAGMENT] = index + strlen(str + index);
                pre_state = URI_PART_ELEMENTS;
                skip_path = true;
                break;
            case URI_PATH: // 处理路径部分
                if (skip_path) { continue; }
                // 如果未设置跳过路径，设置路径的起始索引，并跳出循环
                start_idx[URI_PATH] = index;
                break;
            case URI_PART_ELEMENTS: // 处理未知或结束状态，跳出内层循环
                skip_path = true;
                break;
            }
            break;
        }
    }
    // 如果解析没有到达最终状态，设置当前状态的结束索引为当前位置
    if (pre_state != URI_PART_ELEMENTS) end_idx[pre_state] = index;

    // 如果没有跳过路径解析, 处理路径后的查询和片段部分
    if (!skip_path) {
        pre_state = URI_PATH;
        // 遍历剩余字符串, 查找?和#
        for (; str[index]; index++) {
            // 遇到?时, 结束路径部分, 开始查询部分, 并扫描直到#或字符串结束
            if (str[index] == '?') {
                end_idx[URI_PATH] = index;
                start_idx[URI_QUERY] = index + 1;
                pre_state = URI_QUERY;
                while (str[index + 1]) {
                    if (str[++index] == '#') { break; }
                }
            }
            // 遇到#时, 结束当前部分, 开始片段部分
            if (str[index] == '#') {
                end_idx[pre_state] = index;
                start_idx[URI_FRAGMENT] = index + 1;
                pre_state = URI_FRAGMENT;
                break;
            }
        }
        // 最后设置当前状态的结束索引
        end_idx[pre_state] = index + strlen(str + index);
    }

    // 验证每个URI组件的字符合法性
    for (int i = 0; i < URI_QUERY; i++) {
        for (int j = start_idx[i]; j < end_idx[i]; j++) {
            if (!valid_char[i][static_cast<unsigned char>(str[j])]) { return -1; } //invalid char
        }
    }

    char **dst[URI_PART_ELEMENTS] = {&uri.scheme, &uri.userinfo, &uri.host, &uri.port,
                                     &uri.query, &uri.fragment, &uri.path};

    for (int i = 0; i < URI_PART_ELEMENTS; i++) {
        if (end_idx[i] > start_idx[i]) {
            size_t len = end_idx[i] - start_idx[i]; // 计算组件长度
            // 如果组件非空, 重新分配内存并复制内容
            *dst[i] = static_cast<char *>(realloc(*dst[i], len + 1));
            if (*dst[i] == nullptr) {
                uri.state = URI_STATE_ERROR;
                uri.error = errno;
                return -1;
            }
            // 对host组件特殊处理, 去除IPv6地址的方括号
            if (i == URI_HOST && str[start_idx[i]] == '[' && str[end_idx[i] - 1] == ']') {
                len -= 2;
                memcpy(*dst[i], str + start_idx[i] + 1, len); // 复制时去掉括号
            } else { memcpy(*dst[i], str + start_idx[i], len); } // 直接复制

            (*dst[i])[len] = '\0'; // 为每个组件添加字符串终止符, 方便后续使用
        } else {
            // 释放空组件的内存
            free(*dst[i]);
            *dst[i] = nullptr;
        }
    }

    uri.state = URI_STATE_SUCCESS;
    return 0;
}

// 解析URI查询字符串(即URL中 ?后面的部分). 能够处理同一个键对应多个值的情况（例如 ?key=val1&key=val2）
std::map<std::string, std::vector<std::string>> URIParser::split_query_strict(const std::string &query) {
    std::map<std::string, std::vector<std::string>> res;

    if (query.empty()) { return res; }

    std::vector<std::string> arr = StringUtil::split(query, '&'); // 按 & 分离键值对

    if (arr.empty()) { return res; }

    for (const auto &ele : arr) {
        if (ele.empty()) { continue; } // 跳过空字符串

        std::vector<std::string> kv = StringUtil::split(ele, '='); // 按 = 分离key和value
        const size_t kv_size = kv.size();
        std::string &key = kv[0];

        if (key.empty()) { continue; }

        if (kv_size == 1) {
            // 说明字符串中没有 =, 只有键名(如 "key")
            res[key].emplace_back();
            continue;
        }

        std::string &val = kv[1];

        if (val.empty()) {
            res[key].emplace_back();
        } else { res[key].emplace_back(std::move(val)); }
    }

    return res;
}

// 解析URI查询字符串(即URL中 ?后面的部分). 只能处理一个key对应一个value的情况(保留第一个出现的值, 忽略后续重复键)
std::map<std::string, std::string> URIParser::split_query(const std::string &query) {
    std::map<std::string, std::string> res;

    if (query.empty()) { return res; }

    std::vector<std::string> arr = StringUtil::split(query, '&');

    if (arr.empty()) { return res; }

    for (const auto &ele : arr) {
        if (ele.empty()) { continue; }

        std::vector<std::string> kv = StringUtil::split(ele, '=');
        const size_t kv_size = kv.size();
        std::string &key = kv[0];

        if (key.empty() || res.contains(key)) { continue; }

        if (kv_size == 1) {
            res.emplace(std::move(key), "");
            continue;
        }

        std::string &val = kv[1];

        if (val.empty()) {
            res.emplace(std::move(key), "");
        } else { res.emplace(std::move(key), std::move(val)); }
    }

    return res;
}

std::vector<std::string> URIParser::split_path(const std::string &path) {
    return StringUtil::split_filter_empty(path, '/');
}