//
// Created by ldk on 9/29/25.
//

#include "rbtree.h"

#include <bits/posix2_lim.h>

/* 对node节点和node->right节点进行左旋 */
static void __rb_rotate_left(struct rb_node *node, struct rb_root *root) {
    struct rb_node *right = node->rb_right;
    // 注意if里面是 = 赋值，不是比较大小！
    if ((node->rb_right = right->rb_left)) {
        // 能进入if语句，说明旋转前 node->rb_right->rb_left != nullptr.
        // 更新 node->rb_right->rb_left的父亲指针
        right->rb_left->rb_parent = node;
    }
    right->rb_left = node; // 至此左旋已经完成，但是还需要更新父亲指针
    // 更新父亲指针, 注意是赋值而不是比大小！
    if ((right->rb_parent = node->rb_parent)) {
        // 能进入if语句，说明旋转前node节点的父节点不为空（即: 旋转前node存在父节点）
        // 判断node旋转前是其父亲的 左子节点 还是 右子结点
        if (node == node->rb_parent->rb_left) {
            node->rb_parent->rb_left = right; // node先前是左子节点。那么现在right替代node成为node->parent的左子节点
        } else {
            node->rb_parent->rb_right = right;
        }
    } else {
        // 没有进入上面的if语句。说明旋转前node是整个树的根节点。
        // 更新right为新的根节点
        root->rb_node = right;
    }
    node->rb_parent = right;
}

static void __rb_rotate_right(struct rb_node *node, struct rb_root *root) {
    struct rb_node *left = node->rb_left;
    if ((node->rb_left = left->rb_right)) {
        left->rb_right->rb_parent = node;
    }
    left->rb_right = node;
    if ((left->rb_parent = node->rb_parent)) {
        if (node->rb_parent->rb_left == node) {
            node->rb_parent->rb_left = left;
        } else {
            node->rb_parent->rb_right = left;
        }
    } else {
        root->rb_node = left;
    }
    node->rb_parent = left;
}

/* 向红黑数中插入 红色 节点 */
void rb_insert_color(struct rb_node *node, struct rb_root *root) {
    struct rb_node *parent;

    /* 如果新插入的节点是根节点，或者新插入的节点的父亲是黑色节点。则不会进入循环 */
    while (((parent = node->rb_parent)) && (parent->rb_color == RB_RED)) {
        struct rb_node *gparent = parent->rb_parent;
        // 父亲结点是爷爷节点的左子节点
        if (parent == gparent->rb_left) {
            {
                struct rb_node *uncle = gparent->rb_right;
                // 叔叔节点存在并且是红色
                if (uncle && uncle->rb_color == RB_RED) {
                    /* 叔变黑，父变黑，爷变红 */
                    uncle->rb_color = RB_BLACK;
                    parent->rb_color = RB_BLACK;
                    gparent->rb_color = RB_RED;
                    node = gparent; // 递归处理爷爷节点
                    continue;
                }
            }
            // 叔叔为黑色或者叔叔不存在
            if (parent->rb_right == node) {
                // 当前节点是 父亲节点 的 右子节点。先对parent和node进行左旋。否则不旋转
                __rb_rotate_left(parent, root);
                // 因为已经旋转完成，此时交换parent和node两个指针，方便后面对旋转后的parent进行操作
                struct rb_node *tmp = parent;
                parent = node;
                node = tmp;
            }
            // 如果之前执行了左旋: 此时再对 gparent 和 新parent(原node) 进行右旋
            // 如果之前没有执行左旋: 说明是三点共线情况. (node是parent的左子节点, parent是gparent的右子节点)
            parent->rb_color = RB_BLACK;
            gparent->rb_color = RB_RED;
            __rb_rotate_right(gparent, root);
        } else {
            // 父亲节点是爷爷节点的右子节点
            {
                struct rb_node *uncle = gparent->rb_left;
                // 叔叔存在并且是红色
                if (uncle && uncle->rb_color == RB_RED) {
                    /* 叔变黑，父变黑，爷变红 */
                    uncle->rb_color = RB_BLACK;
                    parent->rb_color = RB_BLACK;
                    gparent->rb_color = RB_RED;
                    node = gparent; // 递归处理爷爷节点
                    continue;
                }
            }

            /* 下面逻辑与上方最外层if语句类似 */
            if (parent->rb_left == node) {
                __rb_rotate_right(parent, root);
                struct rb_node *tmp = parent;
                parent = node;
                node = tmp;
            }

            parent->rb_color = RB_BLACK;
            gparent->rb_color = RB_RED;
            __rb_rotate_left(gparent, root);
        }
    }
    root->rb_node->rb_color = RB_BLACK;
}

/* 从root中删除 黑色 节点node. 其中node应当是叶子节点 */
static void __rb_erase_color(struct rb_node *node, struct rb_node *parent, struct rb_root *root) {
    struct rb_node *other;
    // 如果node==nullptr, 则 node!=root->rb_node一定成立（因为是删除函数，所以假设红黑数不为空）
    // 如果node!=nullptr, 判断node是否为黑色, 如果是黑色, 则判断是不是整个树的根节点(红色不可能是根节点), 是根节点则直接跳出循环
    while ((!node || node->rb_color == RB_BLACK) && node != root->rb_node) {
        if (parent->rb_left == node) {
            other = parent->rb_right;
            if (other->rb_color == RB_RED) {
                other->rb_color = RB_BLACK;
                parent->rb_color = RB_RED;
                __rb_rotate_left(parent, root);
                other = parent->rb_right;
            }
            if ((!other->rb_left || other->rb_left->rb_color == RB_BLACK)
                && (!other->rb_right || other->rb_right->rb_color == RB_BLACK)) {
                other->rb_color = RB_RED;
                node = parent;
                parent = node->rb_parent;
            } else {
                if (!other->rb_right || other->rb_right->rb_color == RB_BLACK) {
                    struct rb_node *o_left;
                    if ((o_left = other->rb_left)) {
                        o_left->rb_color = RB_BLACK;
                    }
                    other->rb_color = RB_RED;
                    __rb_rotate_right(other, root);
                    other = parent->rb_right;
                }
                other->rb_color = parent->rb_color;
                parent->rb_color = RB_BLACK;
                if (other->rb_right) {
                    other->rb_right->rb_color = RB_BLACK;
                }
                __rb_rotate_left(parent, root);
                node = root->rb_node;
                break;
            }
        } else {
            other = parent->rb_left;
        }
    }
    if (node) {
        node->rb_color = RB_BLACK;
    }
}

void rb_erase(struct rb_node *node, struct rb_root *root) {
    struct rb_node *child, *parent;
    int color;
    if (!node->rb_left) {
        child = node->rb_right; // 左子节点不存在, child指向右子结点
    } else if (!node->rb_right) {
        child = node->rb_left; // 右子节点不存在, child指向左子节点
    } else {
        // 左右子节点都存在
        struct rb_node *old = node; // 记录原node节点
        struct rb_node *left;
        node = node->rb_right;
        // 找到node的右子树上最小的节点
        while ((left = node->rb_left)) {
            node = left;
        }
        child = node->rb_right;
        parent = node->rb_parent;
        color = node->rb_color;

        if (child) {
            // 如果这个最小节点有没有右子结点，更新其父节点
            child->rb_parent = parent;
        }
        // workflow为了稳健性保留了这个判断。实际上if(parent)一定为true。即: else部分永远不会被执行
        if (parent) {
            if (parent->rb_left == node) {
                parent->rb_left = child; // 至此，最小节点从node的右子树中被完全删除。但还可以通过指针node访问
            } else {
                // parent->rb_left != node 说明，原node的右子树上只有一个节点
                parent->rb_right = child;
            }
        } else {
            root->rb_node = child;
        }
        if (node->rb_parent == old) {
            // 对应原node的右子树只有一个节点的情况
            parent = node; // 此句似乎无用，毕竟parent赋值完成后没用过，就又被赋值了
        }
        // 将原右子树的最小节点挂载到要删除的节点的位置上
        node->rb_parent = old->rb_parent;
        node->rb_color = old->rb_color;
        node->rb_right = old->rb_right;
        node->rb_left = old->rb_left;
        // 判断要删除的节点是不是整个树的根节点
        if (old->rb_parent) {
            // 判断要删除的节点是其父节点的 左子节点 还是 右子结点
            if (old->rb_parent->rb_left == old) {
                old->rb_parent->rb_left = node;
            } else {
                old->rb_parent->rb_right = node;
            }
        } else {
            root->rb_node = node;
        }
        // 记得更新左子节点的父节点指针
        old->rb_left->rb_parent = node;
        if (old->rb_right) {
            old->rb_right->rb_parent = node;
        }
        goto COLOR;
    }

    parent = node->rb_parent;
    color = node->rb_color;

    if (child) {
        child->rb_parent = parent;
    }
    if (parent) {
        if (parent->rb_left == node) {
            parent->rb_left = child;
        } else {
            parent->rb_right = child;
        }
    } else {
        root->rb_node = child;
    }

COLOR:
    // 此时的color是删除前右子树上的最小节点的color. 相当于将要删除节点与右子树上最小节点更换位置但是不更换颜色
    // 然后再将更换为之后的目标节点删除. 如果删掉的是黑色节点. 则必须进行调整
    if (color == RB_BLACK) {
        __rb_erase_color(child, parent, root);
    }
}

/* 获取红黑数root的最小节点 */
struct rb_node *rb_first(struct rb_root *root) {
    struct rb_node *n;

    n = root->rb_node;
    if (!n) return (struct rb_node *)0;
    while (n->rb_left) n = n->rb_left;
    return n;
}

/* 获取红黑数root的最大节点 */
struct rb_node *rb_last(struct rb_root *root) {
    struct rb_node *n;

    n = root->rb_node;
    if (!n) return (struct rb_node *)0;
    while (n->rb_right) n = n->rb_right;
    return n;
}

/* 获取红黑数中节点node的后继结点 */
struct rb_node *rb_next(struct rb_node *node) {
    /* 如果node有一个右子节点，则移动到该右子节点，然后尽可能地向左移动。 */
    if (node->rb_right) {
        node = node->rb_right;
        while (node->rb_left) node = node->rb_left;
        return node;
    }

    /* node没有右子节点。所有向左的节点都比我们小,
       因此任何 '后继' 节点必然在我们父节点的方向上
       向上遍历树：只要当前节点是其父节点的右子节点，就继续向上。
       当第一次遇到一个节点是其父节点的左子节点时，那个父节点就是我们的 '后继' 节点。 */
    while (node->rb_parent && node == node->rb_parent->rb_right) node = node->rb_parent;

    return node->rb_parent;
}

/* 获取红黑树中节点node的前序节点 */
struct rb_node *rb_prev(struct rb_node *node) {
    /* If we have a left-hand child, go down and then right as far
       as we can. */
    if (node->rb_left) {
        node = node->rb_left;
        while (node->rb_right) node = node->rb_right;
        return node;
    }

    /* No left-hand children. Go up till we find an ancestor which
       is a right-hand child of its parent */
    while (node->rb_parent && node == node->rb_parent->rb_left) node = node->rb_parent;

    return node->rb_parent;
}

/* 将红黑数root中的victim节点替换为newnode节点 */
void rb_replace_node(const struct rb_node *victim, struct rb_node *newnode, struct rb_root *root) {
    struct rb_node *parent = victim->rb_parent;
    if (parent) {
        // 更新parent的左/右子树指针指向newnode
        if (victim == parent->rb_left) {
            parent->rb_left = newnode;
        } else {
            parent->rb_right = newnode;
        }
    } else {
        root->rb_node = newnode;
    }
    // 更新原节点的左右子树的父亲节点指针指向newnode
    if (victim->rb_left) victim->rb_left->rb_parent = newnode;
    if (victim->rb_right) victim->rb_right->rb_parent = newnode;

    /* 复制原节点内的所有指针数据和颜色color到新节点中 */
    *newnode = *victim;
}