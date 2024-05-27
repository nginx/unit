
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_RBTREE_H_INCLUDED_
#define _NXT_RBTREE_H_INCLUDED_


typedef struct nxt_rbtree_node_s  nxt_rbtree_node_t;

struct nxt_rbtree_node_s {
    nxt_rbtree_node_t         *left;
    nxt_rbtree_node_t         *right;
    nxt_rbtree_node_t         *parent;

    uint8_t                   color;
};


typedef struct {
    nxt_rbtree_node_t         *left;
    nxt_rbtree_node_t         *right;
    nxt_rbtree_node_t         *parent;
} nxt_rbtree_part_t;


#define NXT_RBTREE_NODE(node)                                                 \
    nxt_rbtree_part_t         node;                                           \
    uint8_t                   node##_color


#define NXT_RBTREE_NODE_INIT  { NULL, NULL, NULL }, 0


typedef struct {
    nxt_rbtree_node_t         sentinel;
} nxt_rbtree_t;


/*
 * A comparison function should return intptr_t result because
 * this eliminates overhead required to implement correct addresses
 * comparison without result truncation.
 */
typedef intptr_t (*nxt_rbtree_compare_t)(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2);


#define nxt_rbtree_root(tree)                                                 \
    ((tree)->sentinel.left)


#define nxt_rbtree_sentinel(tree)                                             \
    (&(tree)->sentinel)


#define nxt_rbtree_is_empty(tree)                                             \
    (nxt_rbtree_root(tree) == nxt_rbtree_sentinel(tree))


#define nxt_rbtree_min(tree)                                                  \
    nxt_rbtree_branch_min(tree, &(tree)->sentinel)


nxt_inline nxt_rbtree_node_t *
nxt_rbtree_branch_min(nxt_rbtree_t *tree, nxt_rbtree_node_t *node)
{
    while (node->left != nxt_rbtree_sentinel(tree)) {
        node = node->left;
    }

    return node;
}


#define nxt_rbtree_is_there_successor(tree, node)                             \
    ((node) != nxt_rbtree_sentinel(tree))


nxt_inline nxt_rbtree_node_t *
nxt_rbtree_node_successor(nxt_rbtree_t *tree, nxt_rbtree_node_t *node)
{
    nxt_rbtree_node_t  *parent;

    if (node->right != nxt_rbtree_sentinel(tree)) {
        return nxt_rbtree_branch_min(tree, node->right);
    }

    for ( ;; ) {
        parent = node->parent;

        /*
         * Explicit test for a root node is not required here, because
         * the root node is always the left child of the sentinel.
         */
        if (node == parent->left) {
            return parent;
        }

        node = parent;
    }
}


NXT_EXPORT void nxt_rbtree_init(nxt_rbtree_t *tree,
    nxt_rbtree_compare_t compare);
NXT_EXPORT void nxt_rbtree_insert(nxt_rbtree_t *tree, nxt_rbtree_part_t *node);
NXT_EXPORT nxt_rbtree_node_t *nxt_rbtree_find(nxt_rbtree_t *tree,
    nxt_rbtree_part_t *node);
NXT_EXPORT nxt_rbtree_node_t *nxt_rbtree_find_less_or_equal(nxt_rbtree_t *tree,
    nxt_rbtree_part_t *node);
NXT_EXPORT nxt_rbtree_node_t
    *nxt_rbtree_find_greater_or_equal(nxt_rbtree_t *tree,
    nxt_rbtree_part_t *node);
NXT_EXPORT void nxt_rbtree_delete(nxt_rbtree_t *tree, nxt_rbtree_part_t *node);

/*
 * nxt_rbtree_destroy_next() is iterator to use only while rbtree destruction.
 * It deletes a node from rbtree and returns the node.  The rbtree is not
 * rebalanced after deletion.  At the beginning the "next" parameter should
 * be equal to rbtree root.  The iterator should be called in loop until
 * the "next" parameter will be equal to the rbtree sentinel.  No other
 * operations must be performed on the rbtree while destruction.
 */
NXT_EXPORT nxt_rbtree_node_t *nxt_rbtree_destroy_next(nxt_rbtree_t *tree,
    nxt_rbtree_node_t **next);


#endif /* _NXT_RBTREE_H_INCLUDED_ */
