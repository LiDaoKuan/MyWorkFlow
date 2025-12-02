//
// Created by ldk on 11/26/25.
//

/*
  Copyright (c) 2020 Sogou, Inc.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

  Author: Xie Han (xiehan@sogou-inc.com)
*/

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <pthread.h>
#include "rbtree.h"
#include "WFNameService.h"

struct WFNSPolicyEntry {
    rb_node rb;
    WFNSPolicy *policy;
    char name[1]; // 这是一个“占位符”, 用于实现柔性数组. 它并非只存储1个字符, 而是作为一段连续内存的起始标记, 其实际长度在运行时动态分配确定
};

// 注册策略: 将一个新的策略（WFNSPolicy）与一个名称（name）绑定, 并存入红黑树
int WFNameService::add_policy(const char *name, WFNSPolicy *policy) {
    rb_node **p = &this->root.rb_node;
    rb_node *parent = nullptr;
    WFNSPolicyEntry *entry;
    int n, ret = -1;

    pthread_rwlock_wrlock(&this->rwlock); // 读写锁
    while (*p) {
        parent = *p; // 记录父亲结点
        entry = rb_entry(*p, struct WFNSPolicyEntry, rb);
        n = strcasecmp(name, entry->name); // 比较当前节点的name和要查找的name
        if (n < 0) {
            p = &(*p)->rb_left; // 目标名较小, 转向左子树
        } else if (n > 0) {
            p = &(*p)->rb_right; // 目标名较大, 转向右子树
        } else {
            break;
        }
    }

    if (!*p) {
        // *p == nullptr, 说明没有找到对应的name或者整个树为空
        const size_t len = strlen(name);
        const size_t size = offsetof(struct WFNSPolicyEntry, name) + len + 1;

        entry = static_cast<struct WFNSPolicyEntry *>(malloc(size)); // name字段的偏移量 + 字符串实际长度 + 1（用于结束符\0）
        if (entry) {
            memcpy(entry->name, name, len + 1);
            entry->policy = policy;
            rb_link_node(&entry->rb, parent, p); // 将新节点链接到树中
            rb_insert_color(&entry->rb, &this->root); // 调整树结构, 满足红黑树性质
            ret = 0;
        }
    } else {
        // 已经存在对应的name, 插入失败
        errno = EEXIST;
    }

    pthread_rwlock_unlock(&this->rwlock);
    return ret;
}

inline struct WFNSPolicyEntry *WFNameService::get_policy_entry(const char *name) const {
    rb_node *p = this->root.rb_node;
    WFNSPolicyEntry *entry;
    int n;

    while (p) {
        entry = rb_entry(p, struct WFNSPolicyEntry, rb);
        n = strcasecmp(name, entry->name);
        if (n < 0) {
            p = p->rb_left;
        } else if (n > 0) {
            p = p->rb_right;
        } else {
            return entry;
        }
    }
    // 没找到对应的name
    return nullptr;
}

// 根据名称查找对应的策略. 若未找到, 则返回默认策略
WFNSPolicy *WFNameService::get_policy(const char *name) {
    WFNSPolicy *policy = this->default_policy;
    struct WFNSPolicyEntry *entry;

    if (this->root.rb_node) {
        pthread_rwlock_rdlock(&this->rwlock);
        entry = this->get_policy_entry(name);
        if (entry) {
            policy = entry->policy;
        }

        pthread_rwlock_unlock(&this->rwlock);
    }

    return policy;
}

// 移除指定名称的策略条目
WFNSPolicy *WFNameService::del_policy(const char *name) {
    WFNSPolicy *policy = nullptr;
    struct WFNSPolicyEntry *entry;

    pthread_rwlock_wrlock(&this->rwlock);
    entry = this->get_policy_entry(name);
    if (entry) {
        policy = entry->policy;
        rb_erase(&entry->rb, &this->root);
    }

    pthread_rwlock_unlock(&this->rwlock);
    free(entry);
    return policy;
}

WFNameService::~WFNameService() {
    struct WFNSPolicyEntry *entry;
    // 删除红黑树中所有节点并且释放entry的内存
    while (this->root.rb_node) {
        entry = rb_entry(this->root.rb_node, struct WFNSPolicyEntry, rb);
        rb_erase(&entry->rb, &this->root);
        free(entry);
    }

    pthread_rwlock_destroy(&this->rwlock); // 销毁读写锁
}