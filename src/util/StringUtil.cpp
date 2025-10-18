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
           Xie Han (xiehan@sogou-inc.com)
*/

#include <cctype>
#include <string>
#include <vector>
#include <algorithm>
#include "StringUtil.h"

// 将一个两位的16进制数转换为10进制int
static int hex_to_int(const char s[2]) {
    int value = 16;

    // 处理高位
    if (s[0] <= '9') {
        // 如果是数字，则用 value(当前为16) 乘以该数字对应的数值 (s[0] - '0')
        value *= s[0] - '0';
    } else { value *= toupper(s[0]) - 'A' + 10; } // 字母: 转换为大写后-'A'+10, 然后再乘以16

    // 处理低位
    if (s[1] <= '9') {
        value += s[1] - '0';
    } else { value += toupper(s[1]) - 'A' + 10; }

    return value;
}

// 根据输入整数n的值, 将其映射到对应的十六进制字符
static inline char int_to_hex(int n) {
    return n <= 9 ? n + '0' : n - 10 + 'A';
}

// 对URL编码字符串进行原地解码, 返回解码后的长度
static size_t UrlDecode(char *str) {
    char *dest = str;
    char *data = str;

    while (*data) {
        if (*data == '%' && isxdigit(data[1]) && isxdigit(data[2])) {
            *dest = hex_to_int(data + 1); // 处理%XX格式
            data += 2; // 跳过已处理的两位十六进制数
        } else if (*data == '+') {
            *dest = ' '; // 将+号转换为空格
        } else { *dest = *data; } // 直接复制其他字符

        data++;
        dest++;
    }

    *dest = '\0';
    return dest - str;
}

// 对str进行解码
void StringUtil::url_decode(std::string &str) {
    str.resize(UrlDecode(const_cast<char *>(str.c_str())));
}

// URL 编码, 返回编码后的string
std::string StringUtil::url_encode(const std::string &str) {
    const char *cur = str.c_str();
    const char *end = cur + str.size();
    std::string res;

    while (cur < end) {
        if (isalnum(*cur) || *cur == '-' || *cur == '_' || *cur == '.' ||
            *cur == '!' || *cur == '~' || *cur == '*' || *cur == '\'' ||
            *cur == '(' || *cur == ')' || *cur == ':' || *cur == '/' ||
            *cur == '@' || *cur == '?' || *cur == '#' || *cur == '&') {
            // 所有不需要编码的字符.
            // 这些字符包括字母、数字以及一些在URL中有特殊含义但允许直接出现的字符（如 :、/、?、&等）
            res += *cur;
        } else if (*cur == ' ') {
            res += '+'; // 将空格字符（' '）转换为加号（'+'）
        } else {
            // 对于所有不在安全列表中的字符(通常是非ASCII字符, 如中文, 或其他特殊符号), 执行百分比编码
            res += '%';
            res += int_to_hex(static_cast<const unsigned char>(*cur) >> 4); // 取高4位
            res += int_to_hex(static_cast<const unsigned char>(*cur) % 16); // 取低4位
        }
        cur++;
    }

    return res;
}

// 编码URL中的参数部分(组件), 确保参数值不会破坏URL结构
std::string StringUtil::url_encode_component(const std::string &str) {
    const char *cur = str.c_str();
    const char *end = cur + str.size();
    std::string res;

    while (cur < end) {
        if (isalnum(*cur) || *cur == '-' || *cur == '_' || *cur == '.' ||
            *cur == '!' || *cur == '~' || *cur == '*' || *cur == '\'' ||
            *cur == '(' || *cur == ')') {
            /**当你要编码的是一个URL组件(比如查询参数name=value中的value)时,
             * 如果 value 本身包含了 & 或 = 这类在查询字符串中用于分隔不同键值对的字符, 就会引起解析歧义.
             * 例如, 如果 value 是 a&b, 不编码直接拼接成 ?name=a&b，服务器会认为有两个参数 name=a 和 b= .
             * 因此, 必须对组件内这些有特殊意义的字符进行编码（如 &编码为 %26），才能保证参数值的完整性 */
            res += *cur;
        } else if (*cur == ' ') {
            res += '+';
        } else {
            res += '%';
            res += int_to_hex(static_cast<const unsigned char>(*cur) >> 4);
            res += int_to_hex(static_cast<const unsigned char>(*cur) % 16);
        }
        cur++;
    }
    return res;
}

// C++字符串分割函数
std::vector<std::string> StringUtil::split(const std::string &str, char sep) {
    std::string::const_iterator cur = str.begin();
    std::string::const_iterator end = str.end();
    std::string::const_iterator next = find(cur, end, sep);
    std::vector<std::string> res;

    while (next != end) {
        res.emplace_back(cur, next);
        cur = next + 1;
        next = std::find(cur, end, sep);
    }

    res.emplace_back(cur, next);
    return res;
}

// 带空字符串过滤的字符串分割（例如用;分割字符串a;b;;c, 结果是: [a,b,空串,c], 该函数将会自动丢弃空串）
std::vector<std::string> StringUtil::split_filter_empty(const std::string &str, char sep) {
    std::vector<std::string> res;
    std::string::const_iterator cur = str.begin();
    std::string::const_iterator end = str.end();
    std::string::const_iterator next = find(cur, end, sep);

    while (next != end) {
        // 如果cur==next, 说明遇到了连续的两个分割符sep
        if (cur < next) { res.emplace_back(cur, next); }

        cur = next + 1;
        next = find(cur, end, sep);
    }

    if (cur < next) { res.emplace_back(cur, next); }

    return res;
}

// 去除字符串首尾的所有空白字符
std::string StringUtil::strip(const std::string &str) {
    std::string res;

    if (!str.empty()) {
        const char *cur = str.c_str();
        const char *end = cur + str.size();

        while (cur < end) {
            if (!isspace(*cur)) { break; }
            cur++;
        }

        while (end > cur) {
            if (!isspace(*(end - 1))) { break; }
            end--;
        }

        if (end > cur) { res.assign(cur, end - cur); }
    }

    return res;
}

// 判断字符串str是不是以prefix开头
bool StringUtil::start_with(const std::string &str, const std::string &prefix) {
    size_t prefix_len = prefix.size();

    if (str.size() < prefix_len) { return false; }

    for (size_t i = 0; i < prefix_len; i++) {
        if (str[i] != prefix[i]) { return false; }
    }

    return true;
}