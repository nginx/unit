
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


#include <nxt_main.h>
#include "nxt_rbtree1.h"


/*
 * The red-black tree code is based on the algorithm described in
 * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
 */


nxt_inline void nxt_rbtree1_left_rotate(nxt_rbtree1_node_t **root,
    nxt_rbtree1_node_t *sentinel, nxt_rbtree1_node_t *node);
nxt_inline void nxt_rbtree1_right_rotate(nxt_rbtree1_node_t **root,
    nxt_rbtree1_node_t *sentinel, nxt_rbtree1_node_t *node);


void
nxt_rbtree1_insert(nxt_rbtree1_t *tree, nxt_rbtree1_node_t *node)
{
    nxt_rbtree1_node_t  **root, *temp, *sentinel;

    /* a binary tree insert */

    root = (nxt_rbtree1_node_t **) &tree->root;
    sentinel = tree->sentinel;

    if (*root == sentinel) {
        node->parent = NULL;
        node->left = sentinel;
        node->right = sentinel;
        nxt_rbtree1_black(node);
        *root = node;

        return;
    }

    tree->insert(*root, node, sentinel);

    /* re-balance tree */

    while (node != *root && nxt_rbtree1_is_red(node->parent)) {

        if (node->parent == node->parent->parent->left) {
            temp = node->parent->parent->right;

            if (nxt_rbtree1_is_red(temp)) {
                nxt_rbtree1_black(node->parent);
                nxt_rbtree1_black(temp);
                nxt_rbtree1_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->right) {
                    node = node->parent;
                    nxt_rbtree1_left_rotate(root, sentinel, node);
                }

                nxt_rbtree1_black(node->parent);
                nxt_rbtree1_red(node->parent->parent);
                nxt_rbtree1_right_rotate(root, sentinel, node->parent->parent);
            }

        } else {
            temp = node->parent->parent->left;

            if (nxt_rbtree1_is_red(temp)) {
                nxt_rbtree1_black(node->parent);
                nxt_rbtree1_black(temp);
                nxt_rbtree1_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    nxt_rbtree1_right_rotate(root, sentinel, node);
                }

                nxt_rbtree1_black(node->parent);
                nxt_rbtree1_red(node->parent->parent);
                nxt_rbtree1_left_rotate(root, sentinel, node->parent->parent);
            }
        }
    }

    nxt_rbtree1_black(*root);
}


void
nxt_rbtree1_insert_value(nxt_rbtree1_node_t *temp, nxt_rbtree1_node_t *node,
    nxt_rbtree1_node_t *sentinel)
{
    nxt_rbtree1_node_t  **p;

    for ( ;; ) {

        p = (node->key < temp->key) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    nxt_rbtree1_red(node);
}


void
nxt_rbtree1_insert_timer_value(nxt_rbtree1_node_t *temp,
    nxt_rbtree1_node_t *node, nxt_rbtree1_node_t *sentinel)
{
    nxt_rbtree1_node_t  **p;

    for ( ;; ) {

        /*
         * Timer values
         * 1) are spread in small range, usually several minutes,
         * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
         * The comparison takes into account that overflow.
         */

        /*  node->key < temp->key */

        p = ((nxt_rbtree1_key_int_t) (node->key - temp->key) < 0)
            ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    nxt_rbtree1_red(node);
}


void
nxt_rbtree1_delete(nxt_rbtree1_t *tree, nxt_rbtree1_node_t *node)
{
    nxt_uint_t      red;
    nxt_rbtree1_node_t  **root, *sentinel, *subst, *temp, *w;

    /* a binary tree delete */

    root = (nxt_rbtree1_node_t **) &tree->root;
    sentinel = tree->sentinel;

    if (node->left == sentinel) {
        temp = node->right;
        subst = node;

    } else if (node->right == sentinel) {
        temp = node->left;
        subst = node;

    } else {
        subst = nxt_rbtree1_min(node->right, sentinel);

        if (subst->left != sentinel) {
            temp = subst->left;
        } else {
            temp = subst->right;
        }
    }

    if (subst == *root) {
        *root = temp;
        nxt_rbtree1_black(temp);

        /* DEBUG stuff */
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        node->key = 0;

        return;
    }

    red = nxt_rbtree1_is_red(subst);

    if (subst == subst->parent->left) {
        subst->parent->left = temp;

    } else {
        subst->parent->right = temp;
    }

    if (subst == node) {

        temp->parent = subst->parent;

    } else {

        if (subst->parent == node) {
            temp->parent = subst;

        } else {
            temp->parent = subst->parent;
        }

        subst->left = node->left;
        subst->right = node->right;
        subst->parent = node->parent;
        nxt_rbtree1_copy_color(subst, node);

        if (node == *root) {
            *root = subst;

        } else {
            if (node == node->parent->left) {
                node->parent->left = subst;
            } else {
                node->parent->right = subst;
            }
        }

        if (subst->left != sentinel) {
            subst->left->parent = subst;
        }

        if (subst->right != sentinel) {
            subst->right->parent = subst;
        }
    }

    /* DEBUG stuff */
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->key = 0;

    if (red) {
        return;
    }

    /* a delete fixup */

    while (temp != *root && nxt_rbtree1_is_black(temp)) {

        if (temp == temp->parent->left) {
            w = temp->parent->right;

            if (nxt_rbtree1_is_red(w)) {
                nxt_rbtree1_black(w);
                nxt_rbtree1_red(temp->parent);
                nxt_rbtree1_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }

            if (nxt_rbtree1_is_black(w->left) && nxt_rbtree1_is_black(w->right))
            {
                nxt_rbtree1_red(w);
                temp = temp->parent;

            } else {
                if (nxt_rbtree1_is_black(w->right)) {
                    nxt_rbtree1_black(w->left);
                    nxt_rbtree1_red(w);
                    nxt_rbtree1_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }

                nxt_rbtree1_copy_color(w, temp->parent);
                nxt_rbtree1_black(temp->parent);
                nxt_rbtree1_black(w->right);
                nxt_rbtree1_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }

        } else {
            w = temp->parent->left;

            if (nxt_rbtree1_is_red(w)) {
                nxt_rbtree1_black(w);
                nxt_rbtree1_red(temp->parent);
                nxt_rbtree1_right_rotate(root, sentinel, temp->parent);
                w = temp->parent->left;
            }

            if (nxt_rbtree1_is_black(w->left) && nxt_rbtree1_is_black(w->right))
            {
                nxt_rbtree1_red(w);
                temp = temp->parent;

            } else {
                if (nxt_rbtree1_is_black(w->left)) {
                    nxt_rbtree1_black(w->right);
                    nxt_rbtree1_red(w);
                    nxt_rbtree1_left_rotate(root, sentinel, w);
                    w = temp->parent->left;
                }

                nxt_rbtree1_copy_color(w, temp->parent);
                nxt_rbtree1_black(temp->parent);
                nxt_rbtree1_black(w->left);
                nxt_rbtree1_right_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
    }

    nxt_rbtree1_black(temp);
}


nxt_inline void
nxt_rbtree1_left_rotate(nxt_rbtree1_node_t **root, nxt_rbtree1_node_t *sentinel,
    nxt_rbtree1_node_t *node)
{
    nxt_rbtree1_node_t  *temp;

    temp = node->right;
    node->right = temp->left;

    if (temp->left != sentinel) {
        temp->left->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->left) {
        node->parent->left = temp;

    } else {
        node->parent->right = temp;
    }

    temp->left = node;
    node->parent = temp;
}


nxt_inline void
nxt_rbtree1_right_rotate(nxt_rbtree1_node_t **root,
    nxt_rbtree1_node_t *sentinel, nxt_rbtree1_node_t *node)
{
    nxt_rbtree1_node_t  *temp;

    temp = node->left;
    node->left = temp->right;

    if (temp->right != sentinel) {
        temp->right->parent = node;
    }

    temp->parent = node->parent;

    if (node == *root) {
        *root = temp;

    } else if (node == node->parent->right) {
        node->parent->right = temp;

    } else {
        node->parent->left = temp;
    }

    temp->right = node;
    node->parent = temp;
}
