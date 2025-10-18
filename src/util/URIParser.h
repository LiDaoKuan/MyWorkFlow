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
*/

#ifndef MYWORKFLOW_URIPARSER_H
#define MYWORKFLOW_URIPARSER_H

#include <stdlib.h>
#include <string>
#include <vector>
#include <map>

#define URI_STATE_INIT		0
#define URI_STATE_SUCCESS	1
#define URI_STATE_INVALID	2
#define URI_STATE_ERROR		3

// RAII YES
// 解析和存储URI各组成部分的数据结构
class ParsedURI {
public:
    char *scheme{nullptr};
    char *userinfo{nullptr};
    char *host{nullptr};
    char *port{nullptr};
    char *path{nullptr};
    char *query{nullptr};
    char *fragment{nullptr};
    int state{URI_STATE_INIT};
    int error{0};
    ParsedURI() { this->init(); }
    virtual ~ParsedURI() { this->deinit(); }

    // 拷贝构造
    ParsedURI(const ParsedURI &uri) { this->copy(uri); }
    // 拷贝赋值运算符
    ParsedURI &operator=(const ParsedURI &uri) {
        if (this != &uri) {
            this->deinit();
            this->copy(uri);
        }
        return *this;
    }

    // 移动构造
    ParsedURI(ParsedURI &&uri) noexcept;
    // 移动赋值运算符
    ParsedURI &operator=(ParsedURI &&uri) noexcept;

private:
    void init() {
        scheme = nullptr;
        userinfo = nullptr;
        host = nullptr;
        port = nullptr;
        path = nullptr;
        query = nullptr;
        fragment = nullptr;
        state = URI_STATE_INIT;
        error = 0;
    }

    void deinit() {
        free(scheme);
        free(userinfo);
        free(host);
        free(port);
        free(path);
        free(query);
        free(fragment);
    }

    void copy(const ParsedURI &uri);
};

// static class
// 静态工具类
class URIParser {
public:
    // return 0 mean success, -1 mean fail
    // uri解析, 解析结果通过引用传参获取
    static int parse(const char *str, ParsedURI &uri);
    // string参数重载
    static int parse(const std::string &str, ParsedURI &uri) {
        return parse(str.c_str(), uri);
    }

    //
    static std::map<std::string, std::vector<std::string>> split_query_strict(const std::string &query);

    //
    static std::map<std::string, std::string> split_query(const std::string &query);

    // 将类似/api/v1/users拆分为["api", "v1", "users"]
    static std::vector<std::string> split_path(const std::string &path);
};

#endif //MYWORKFLOW_URIPARSER_H