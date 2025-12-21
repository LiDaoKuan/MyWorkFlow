//
// Created by ldk on 10/31/25.
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

#ifndef MYWORKFLOW_LRUCACHE_H_
#define MYWORKFLOW_LRUCACHE_H_

#include <cassert>
#include <cstddef>

#include "list.h"
#include "rbtree.h"

/**
 * @file   LRUCache.h
 * @brief  Template LRU Cache
 */

// 代表缓存中的一个条目(键值对)
// RAII: NO. Release ref by LRUCache::release
// Thread safety: NO.
// DONOT change value by handler, use Cache::put instead
template <typename KEY, typename VALUE>
class LRUHandle {
public:
    VALUE value; // 直接存储缓存项对应的值数据，允许外部直接访问

private:
    LRUHandle(const KEY &k, const VALUE &v) :
        value(v), key(k) {}

    KEY key;        // 用于唯一标识缓存项，是哈希表查找的依据
    list_head list; // 用于将 LRUHandle 对象链接到维护访问顺序的双向链表中(如LRU链表)
    rb_node rb;     // 用于将 LRUHandle 对象组织到红黑树中, 通常是为了快速查找或按序访问
    bool in_cache;  // 标记此句柄当前是否正被缓存所管理
    int ref;        // 跟踪当前有多少个地方正在使用这个句柄, 是控制其生命周期的重要依据

    template <typename, typename, class> friend class LRUCache;
};

// 不仅仅是实现标准的LRU(最近最少使用)淘汰策略, 更重要的是安全地管理被外部引用的缓存对象
// RAII: NO. Release ref by LRUCache::release
// Define ValueDeleter(VALUE& v) for value deleter
// Thread safety: NO
// Make sure KEY operator< usable
template <typename KEY, typename VALUE, class ValueDeleter>
class LRUCache {
protected:
    typedef LRUHandle<KEY, VALUE> Handle; // 缓存项的本体, 封装了键、值、引用计数(ref)、缓存状态标志(in_cache)以及嵌入链表和红黑树的节点

public:
    LRUCache() {
        INIT_LIST_HEAD(&this->not_use);
        INIT_LIST_HEAD(&this->in_use);
        this->cache_map.rb_node = nullptr;
        this->max_size = 0;
        this->size = 0;
    }

    ~LRUCache() {
        list_head *pos, *tmp;
        Handle *e;

        // Error if caller has an unreleased handle
        assert(list_is_empty(&this->in_use));
        // 对所有仅缓存引用的对象取消引用
        list_for_each_safe(pos, tmp, &this->not_use) {
            e = list_entry(pos, Handle, list);
            assert(e->in_cache); // 确保对象由缓存管理
            e->in_cache = false;
            assert(e->ref == 1); // Invariant for not_use_ list.
            this->unref(e);
        }
    }

    // default max_size=0 means no-limit cache
    // max_size means max cache number of key-value pairs
    void set_max_size(size_t _max_size) {
        this->max_size = _max_size;
    }

    // Remove all cache that are not actively in use.
    // 清理所有 not_use 链表中的缓存项, 无论其新旧程度. 这是一种强制释放内存的手段
    void prune() {
        list_head *pos, *tmp;
        Handle *e;

        list_for_each_safe(pos, tmp, &this->not_use) {
            e = list_entry(pos, Handle, list);
            assert(e->ref == 1);
            rb_erase(&e->rb, &this->cache_map);
            this->erase_node(e);
        }
    }

    // release handle by get/put
    void release(const Handle *handle) {
        this->unref(const_cast<Handle *>(handle));
    }

    // get handler
    // Need call release when handle no longer needed
    // 获取key对应的对象的句柄. 调用者必须在使用完毕后调用 release, 否则会导致内存泄漏和缓存项无法被淘汰
    const Handle *get(const KEY &key) {
        rb_node *p = this->cache_map.rb_node;
        Handle *bound = nullptr;
        Handle *e;

        // 在红黑树中查找键
        while (p) {
            e = rb_entry(p, Handle, rb);
            // 向左查找
            if (!(e->key < key)) {
                bound = e;
                p = p->rb_left;
            } else // 向右查找
            {
                p = p->rb_right;
            }
        }
        // 若找到, 调用 ref() 增加引用计数并将句柄移至 in_use 链表, 然后返回句柄
        if (bound && !(key < bound->key)) {
            this->ref(bound); // 增加引用
            return bound;
        }

        return nullptr;
    }

    // put copy
    // Need call release when handle no longer needed
    const Handle *put(const KEY &key, VALUE value) {
        rb_node **p = &this->cache_map.rb_node;
        rb_node *parent = nullptr;
        Handle *bound = nullptr;
        Handle *e;
        // 查找目标key
        while (*p) {
            parent = *p; // 记录父亲结点
            e = rb_entry(*p, Handle, rb);
            // 向左查找
            if (!(e->key < key)) {
                bound = e;
                p = &((*p)->rb_left);
            } else { p = &((*p)->rb_right); } // 向右查找
        }
        // 创建一个新的 Handle
        e = new Handle(key, value);
        e->in_cache = true;
        e->ref = 2; // 新建handle引用初始化为2: 基础值为1, 将handle返回给外部 + 1
        list_add_tail(&e->list, &this->in_use);
        ++this->size;

        // key已经存在
        if (bound && !(key < bound->key)) {
            rb_replace_node(&bound->rb, &e->rb, &this->cache_map); // 用新key替换旧key, 同时引用计数变为2
            this->erase_node(bound);                               // 删除旧key
        } else                                                     // key不存在
        {
            rb_link_node(&e->rb, parent, p);           // 将新key插入红黑树中的指定位置*p. 不关心树的平衡
            rb_insert_color(&e->rb, &this->cache_map); // 平衡新插入的节点
        }

        // 如果缓存已满(size > max_size)
        if (this->max_size > 0) {
            // 遍历 not_use 链表, 淘汰最久未使用的项直到满足容量限制
            while (this->size > this->max_size && !list_is_empty(&this->not_use)) {
                Handle *tmp = list_entry(this->not_use.next, Handle, list);
                assert(tmp->ref == 1);
                rb_erase(&tmp->rb, &this->cache_map);
                this->erase_node(tmp);
            }
        }

        return e;
    }

    // delete from cache, deleter delay called when all inuse-handle release.
    // 主动从缓存中移除一个键
    void del(const KEY &key) {
        auto *e = const_cast<Handle *>(this->get(key)); // 通过 get 获取句柄
        // 如果获取到, 说明该key存在, 执行删除操作
        if (e) {
            this->unref(e);                     // 由于 get增加了引用, 此处的 unref 会平衡这次引用
            rb_erase(&e->rb, &this->cache_map); // 从红黑树中移除
            this->erase_node(e);                // 从链表中移除并且减少引用
        }
    }

private:
    // 增加引用计数
    void ref(Handle *e) {
        // 如果是从仅缓存引用变为有外部引用
        if (e->in_cache && e->ref == 1) {
            // 移入in_use链表
            list_move_tail(&e->list, &this->in_use);
        }
        ++e->ref; // 目标的引用计数+1
    }

    // 减少引用计数
    void unref(Handle *e) {
        assert(e->ref > 0);
        // 先--, 再判读0
        // 引用降为0，彻底释放
        if (--e->ref == 0) {
            assert(!e->in_cache);          // 确保不被缓存管理, 这样才能安全调用自定义删除函数. 否则后续缓存会访问到已经被释放的资源
            this->value_deleter(e->value); // 调用自定义删除器
            delete e;
        } else if (e->in_cache && e->ref == 1) // 如果是从有外部引用变回仅缓存引用
        {
            // 移回not_use链表
            list_move_tail(&e->list, &this->not_use);
        }
    }

    // 从链表中删除指定的句柄
    void erase_node(Handle *e) {
        assert(e->in_cache); // 保证要删除的对象的句柄是被缓存管理的, 而不是缓存之外的
        list_del(&e->list);
        e->in_cache = false;
        --this->size;
        this->unref(e); // 在此之前先从链表中删除, 再取消引用
    }

    size_t max_size; // 缓存容量
    size_t size;     // 当前缓存的节点数

    // 两条双向链表共同维护缓存项的访问顺序和生命周期状态: in_use存放当前正被外部引用的活跃句柄; not_use存放仅由缓存本身持有的可淘汰候选句柄
    list_head not_use{&not_use, &not_use}; // 可淘汰的缓存项. 存放 ref >= 2的句柄. 引用计数为2表示缓存本身持有1个引用, 并且至少有1个外部引用. 只要句柄在此链表中, 就受到保护, 不会被LRU策略淘汰
    list_head in_use{&in_use, &in_use};    // 正在使用的缓存项. 存放 ref == 1的句柄. 这表示该句柄仅由缓存本身持有, 没有外部引用. 当缓存需要腾出空间时, 优先从此链表尾部淘汰最久未被访问的项
    rb_root cache_map{nullptr};            // 与标准LRU常用哈希表不同, 红黑树提供了O(log n)的查找效率, 并要求键类型支持 operator< 运算

    ValueDeleter value_deleter;
};

#endif