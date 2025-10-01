//
// Created by ldk on 9/28/25.
//

#ifndef _LINUX_LIST_H
#define _LINUX_LIST_H

/**循环双链表实现。
 * 部分内部函数（"__xxx"）在操作整个链表而非单个条目时非常有用，
 * 因为有时我们已经知道下一个/前一个条目，直接使用它们（而非使用
 * 通用的单条目例程）可以生成更高效的代码。*/

/**循环双向链表. 带头节点！即：有一个节点list，作为头结点，不存储信息，但是也在循环中 */
struct list_head {
    struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) {&(name), &(name)}

#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)

/**Initializes the list_head to point to itself.  If it is a list header,
 * the result is an empty list. */
static inline void INIT_LIST_HEAD(struct list_head *list) {
    list->next = list;
    list->prev = list;
}

/**
 * @brief This is only for internal list manipulation where we know
 * the prev/next entries already! */
static inline void __list_add(struct list_head *entry, struct list_head *prev, struct list_head *next) {
    next->prev = entry;
    entry->next = next;
    prev->next = entry;
    entry->prev = prev;
}

/**
 * @param entry: 要添加的新条目
 * @param head: 列表头，新条目将添加在此之后
 *
 * 在指定的头节点之后插入一个新条目。这有利于实现栈（后进先出，LIFO）。
 */
static inline void list_add(struct list_head *entry, struct list_head *head) {
    __list_add(entry, head, head->next);
}

/**
 * @param entry 要添加的条目
 * @param head 列表头，新条目将添加在此之后
 *
 * 在指定的头节点之前插入一个新条目。这有利于实现队列。
 */
static inline void list_add_tail(struct list_head *entry, struct list_head *head) {
    __list_add(entry, head->prev, head);
}

/* 删除prev和next之间的节点。必须确保prev和next都不为nullptr */
static inline void __list_del(struct list_head *prev, struct list_head *next) {
    next->prev = prev;
    prev->next = next;
}

static inline void list_del(struct list_head *entry) {
    __list_del(entry->prev, entry->next);
}

/* 将entry移动到链表head的头部。entry可能原本属于另一个链表 */
static inline void list_move(struct list_head *entry, struct list_head *head) {
    __list_del(entry->prev, entry->next);
    list_add(entry, head);
}

/* 将entry移动到链表head的尾部。entry可能原本属于另一个链表 */
static inline void list_move_tail(struct list_head *entry, struct list_head *head) {
    __list_del(entry->prev, entry->next);
    list_add_tail(entry, head);
}

static inline bool list_is_empty(const struct list_head *head) {
    return head->next == head;
}

/**@brief 将一整个源链表的所有节点，高效地插入到目标链表的两个已知节点之间
 * @param list 源链表的头节点。这个链表的所有节点将被移出并插入到新位置。
 * @param prev 目标位置的前驱节点。源链表将紧接在这个节点之后插入。
 * @param next 目标位置的后继节点。源链表将插入到这个节点之前 */
static inline void __list_splice(const struct list_head *list, struct list_head *prev, struct list_head *next) {
    struct list_head *first = list->next;
    struct list_head *last = list->prev;

    first->prev = prev;
    prev->next = first;

    last->next = next;
    next->prev = last;
}

/**将整个源链表 list 拼接到目标链表的 head 之后的位置*/
static inline void list_splice(const struct list_head *list, struct list_head *head) {
    if (!list_is_empty(list)) {
        __list_splice(list, head, head->next);
    }
}

static inline void list_splice_init(struct list_head *list, struct list_head *head) {
    if (!list_is_empty(list)) {
        __list_splice(list, head, head->next);
        INIT_LIST_HEAD(list);
    }
}

/* 已知一个结构体(type类型) 内某个链表成员(list_head类型的member) 的地址(ptr)，计算出该结构体的起始地址 */
#define list_entry(ptr, type, member) \
    ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**核心技巧
 * &((type *)0)->member: 将地址0强制转换为指向type结构体的指针，然后取得该“假想”结构体中member成员的地址。
 *      由于结构体首地址为0，这个成员的地址在数值上就等于member成员在type结构体内部的字节偏移量
 * (char *)(ptr) - (unsigned long)(offset): 将指向链表节点的指针 ptr转换为char *类型，以确保指针的加减运算是以字节为单位。
 *      然后，用这个地址减去第一步计算出的偏移量。这一步操作相当于将指针从成员的位置向前“回退”了偏移量那么多的字节，从而指向了包含它的结构体的起始位置
 * (type *): 最后，将计算得到的地址强制转换为指向type结构体的指针，这样我们就可以正常地访问这个结构体的所有成员了
 */

/* 利用游标pos正向遍历链表head */
#define list_for_each(pos, head) \
    for(pos=(head)->next; pos != (head); pos=pos->next)

/* 利用游标pos反向遍历链表head */
#define list_for_each_prev(pos, head) \
    for(pos = (head)->prev; pos != (head); pos = pos->prev)

/* 利用游标pos和临时游标n，循环遍历链表head. 这样可以在遍历过程中删除节点，而不影响后续遍历. 普通的list_for_each不提供删除保护 */
#define list_for_each_safe(pos, n, head) \
    for(pos = (head)->next, n=pos->next; pos != (head); \
        pos = n, n = pos->next)

/**如果遍历过程中需要删除节点，需要使用该函数的安全版本: list_for_each_entry_safe
 * @param pos 指向宿主结构体的指针，在循环中作为游标使用。
 * @param head 链表的头节点。
 * @param member 宿主结构体中 list_head类型 成员变量的名称。
 */
#define list_for_each_entry(pos, head, member) \
    for(pos = list_entry((head)->next, typeof (*pos), member); \
        &pos->member != (head); \
        pos = list_entry(pos->member.next, typeof (*pos), member))

struct slist_node {
    struct slist_node *next;
};

struct slist_head {
    struct slist_node first; // first是头结点。不是指针类型！
    struct slist_node *last;
};

#define SLIST_HEAD_INIT(name) { { (struct slist_node*)0 }, &(name).first}

#define SLIST_HEAD(name) \
    struct slist_head name = SLIST_HEAD_INIT(name)

/* 初始化链表list */
static inline void INIT_SLIST_HEAD(struct slist_head *list) {
    list->first.next = nullptr;
    list->last = &list->first;
}

/* 在单向链表list的prev节点后面插入新节点entry */
static inline void slist_add_after(struct slist_node *entry, struct slist_node *prev, struct slist_head *list) {
    entry->next = prev->next;
    prev->next = entry;
    if (entry->next == nullptr) {
        list->last = entry;
    }
}

/* 在单向链表list的头结点first后面插入新节点 */
static inline void slist_add_head(struct slist_node *entry, struct slist_head *list) {
    slist_add_after(entry, &list->first, list);
}

/* 在单向链表的尾部插入新节点entry */
static inline void slist_add_tail(struct slist_node *entry, struct slist_head *list) {
    entry->next = nullptr;
    list->last->next = entry;
    list->last = entry;
}

/* 删除单向链表中prev后面的节点 */
static inline void slist_del_after(struct slist_node *prev, struct slist_head *list) {
    prev->next = prev->next->next;
    if (!prev->next) {
        list->last = prev;
    }
}

/* 删除单向链表头节点 */
static inline void slist_del_head(struct slist_head *list) {
    slist_del_after(&list->first, list);
}

static inline bool slist_is_empty(const struct slist_head *list) {
    return !list->first.next;
}

/* 将链表list拼接进目标链表head的prev节点之后，prev->next节点之前 */
static inline void __slist_splice(const struct slist_head *list, struct slist_node *prev, struct slist_head *head) {
    list->last->next = prev->next;
    prev->next = list->first.next;
    /* 如果源链表最后一个节点的next指针现在为NULL（即list->last->next == NULL），说明拼接后源链表的尾部成为了整个新链表的尾部。
     * 此时需要更新目标链表头head的last指针，使其指向源链表的最后一个节点(list->last) */
    if (!list->last->next) {
        head->last = list->last;
    }
}

/* 如果list不为空。将链表list拼接进目标链表head的prev节点之后，prev->next节点之前。 */
static inline void slist_splice(const struct slist_head *list, struct slist_node *prev, struct slist_head *head) {
    if (!slist_is_empty(list)) {
        __slist_splice(list, prev, head);
    }
}

static inline void slist_splice_init(struct slist_head *list, struct slist_node *prev, struct slist_head *head) {
    if (!slist_is_empty(list)) {
        __slist_splice(list, prev, head);
        INIT_SLIST_HEAD(list);
    }
}

// 与list_entry宏定义原理相同
#define slist_entry(ptr, type, member) \
    ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

#define slist_for_each(pos, head) \
    for (pos = (head)->first.next; pos; pos = pos->next)

#define slist_for_each_safe(pos, prev, head) \
    for (prev = &(head)->first, pos = prev->next; pos; \
        prev = prev->next == pos ? pos : prev, pos = prev->next)

#define slist_for_each_entry(pos, head, member) \
    for (pos = slist_entry((head)->first.next, typeof (*pos), member); \
        &pos->member != (struct slist_node *)0; \
        pos = slist_entry(pos->member.next, typeof (*pos), member))

#endif // _LINUX_LIST_H