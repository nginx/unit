
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


typedef nxt_uint_t  nxt_rbtree1_key_t;
typedef nxt_int_t   nxt_rbtree1_key_int_t;


typedef struct nxt_rbtree1_node_s  nxt_rbtree1_node_t;

struct nxt_rbtree1_node_s {
    nxt_rbtree1_key_t       key;
    nxt_rbtree1_node_t     *left;
    nxt_rbtree1_node_t     *right;
    nxt_rbtree1_node_t     *parent;
    u_char                  color;
    u_char                  data;
};


typedef struct nxt_rbtree1_s  nxt_rbtree1_t;

typedef void (*nxt_rbtree1_insert_pt) (nxt_rbtree1_node_t *root,
    nxt_rbtree1_node_t *node, nxt_rbtree1_node_t *sentinel);

struct nxt_rbtree1_s {
    nxt_rbtree1_node_t     *root;
    nxt_rbtree1_node_t     *sentinel;
    nxt_rbtree1_insert_pt   insert;
};


#define nxt_rbtree1_init(tree, s, i)                                          \
    nxt_rbtree1_sentinel_init(s);                                             \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i


NXT_EXPORT void nxt_rbtree1_insert(nxt_rbtree1_t *tree,
    nxt_rbtree1_node_t *node);
NXT_EXPORT void nxt_rbtree1_delete(nxt_rbtree1_t *tree,
    nxt_rbtree1_node_t *node);
NXT_EXPORT void nxt_rbtree1_insert_value(nxt_rbtree1_node_t *root,
    nxt_rbtree1_node_t *node, nxt_rbtree1_node_t *sentinel);
NXT_EXPORT void nxt_rbtree1_insert_timer_value(nxt_rbtree1_node_t *root,
    nxt_rbtree1_node_t *node, nxt_rbtree1_node_t *sentinel);


#define nxt_rbtree1_red(node)               ((node)->color = 1)
#define nxt_rbtree1_black(node)             ((node)->color = 0)
#define nxt_rbtree1_is_red(node)            ((node)->color)
#define nxt_rbtree1_is_black(node)          (!nxt_rbtree1_is_red(node))
#define nxt_rbtree1_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */

#define nxt_rbtree1_sentinel_init(node)  nxt_rbtree1_black(node)


nxt_inline nxt_rbtree1_node_t *
nxt_rbtree1_min(nxt_rbtree1_node_t *node, nxt_rbtree1_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}
