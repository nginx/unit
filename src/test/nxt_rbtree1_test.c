
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"
#include "nxt_rbtree1.h"


#define nxt_rbtree1_is_empty(tree)                                            \
    (((tree)->root) == (tree)->sentinel)


#define nxt_rbtree1_is_there_successor(tree, node)                            \
    ((node) != (tree)->sentinel)


nxt_inline nxt_rbtree1_node_t *
nxt_rbtree1_node_successor(nxt_rbtree1_t *tree, nxt_rbtree1_node_t *node)
{
    nxt_rbtree1_node_t  *parent;

    if (node->right != tree->sentinel) {
        return nxt_rbtree1_min(node->right, tree->sentinel);
    }

    for ( ;; ) {
        parent = node->parent;

        if (parent == NULL) {
            return tree->sentinel;
        }

        if (node == parent->left) {
            return parent;
        }

        node = parent;
    }
}


static void nxt_rbtree1_test_insert_value(nxt_rbtree1_node_t *temp,
    nxt_rbtree1_node_t *node, nxt_rbtree1_node_t *sentinel);
static nxt_int_t nxt_rbtree1_test_compare(nxt_rbtree1_node_t *node1,
    nxt_rbtree1_node_t *node2);
static int nxt_cdecl nxt_rbtree1_test_sort_cmp(const void *one,
    const void *two);
static nxt_rbtree1_node_t *nxt_rbtree1_test_find(nxt_rbtree1_t *tree,
    nxt_rbtree1_node_t *node);


nxt_int_t
nxt_rbtree1_test(nxt_thread_t *thr, nxt_uint_t n)
{
    uint32_t            key, *keys;
    nxt_uint_t          i;
    nxt_nsec_t          start, end;
    nxt_rbtree1_t       tree;
    nxt_rbtree1_node_t  *node, *nodes, sentinel;

    nxt_thread_time_update(thr);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "rbtree1 test started: %ui", n);

    nxt_rbtree1_init(&tree, &sentinel, nxt_rbtree1_test_insert_value);

    nodes = nxt_malloc(n * sizeof(nxt_rbtree1_node_t));
    if (nodes == NULL) {
        return NXT_ERROR;
    }

    keys = nxt_malloc(n * sizeof(uint32_t));
    if (keys == NULL) {
        nxt_free(keys);
        return NXT_ERROR;
    }

    key = 0;

    for (i = 0; i < n; i++) {
        key = nxt_murmur_hash2(&key, sizeof(uint32_t));

        keys[i] = key;
        nodes[i].key = key;
    }

    nxt_qsort(keys, n, sizeof(uint32_t), nxt_rbtree1_test_sort_cmp);

    nxt_thread_time_update(thr);
    start = nxt_thread_monotonic_time(thr);

    for (i = 0; i < n; i++) {
        nxt_rbtree1_insert(&tree, &nodes[i]);
    }

    for (i = 0; i < n; i++) {
        if (nxt_rbtree1_test_find(&tree, &nodes[i]) != &nodes[i]) {
            nxt_log_alert(thr->log, "rbtree1 test failed: %08XD not found",
                          nodes[i].key);
            goto fail;
        }
    }

    i = 0;
    node = nxt_rbtree1_min(tree.root, tree.sentinel);

    while (nxt_rbtree1_is_there_successor(&tree, node)) {

        if (keys[i] != node->key) {
            nxt_log_alert(thr->log, "rbtree1 test failed: %i: %08XD %08XD",
                          i, keys[i], node->key);
            goto fail;
        }

        i++;
        node = nxt_rbtree1_node_successor(&tree, node);
    }

    if (i != n) {
        nxt_log_alert(thr->log, "rbtree1 test failed: %ui", i);
        goto fail;
    }

    for (i = 0; i < n; i++) {
        nxt_rbtree1_delete(&tree, &nodes[i]);
        nxt_memset(&nodes[i], 0xA5, sizeof(nxt_rbtree1_node_t));
    }

    nxt_thread_time_update(thr);
    end = nxt_thread_monotonic_time(thr);

    if (!nxt_rbtree1_is_empty(&tree)) {
        nxt_log_alert(thr->log, "rbtree1 test failed: tree is not empty");
        goto fail;
    }

    nxt_free(keys);
    nxt_free(nodes);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "rbtree1 test passed %0.3fs",
                  (end - start) / 1000000000.0);

    return NXT_OK;

fail:

    nxt_free(keys);
    nxt_free(nodes);

    return NXT_ERROR;
}


static void
nxt_rbtree1_test_insert_value(nxt_rbtree1_node_t *temp,
    nxt_rbtree1_node_t *node, nxt_rbtree1_node_t *sentinel)
{
    nxt_rbtree1_node_t  **p;

    for ( ;; ) {
        nxt_prefetch(temp->left);
        nxt_prefetch(temp->right);

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


/*
 * Subtraction cannot be used in these comparison functions because the key
 * values are spread uniform in whole 0 .. 2^32 range but are not grouped
 * around some value as timeout values are.
 */

nxt_inline nxt_int_t
nxt_rbtree1_test_compare(nxt_rbtree1_node_t *node1, nxt_rbtree1_node_t *node2)
{
    if (node1->key < node2->key) {
        return -1;
    }

    if (node1->key == node2->key) {
        return 0;
    }

    return 1;
}


static int nxt_cdecl
nxt_rbtree1_test_sort_cmp(const void *one, const void *two)
{
    const uint32_t  *first, *second;

    first = one;
    second = two;

    if (*first < *second) {
        return -1;
    }

    if (*first == *second) {
        return 0;
    }

    return 1;
}


static nxt_rbtree1_node_t *
nxt_rbtree1_test_find(nxt_rbtree1_t *tree, nxt_rbtree1_node_t *node)
{
    nxt_int_t           n;
    nxt_rbtree1_node_t  *next, *sentinel;

    next = tree->root;
    sentinel = tree->sentinel;

    while (next != sentinel) {
        nxt_prefetch(next->left);
        nxt_prefetch(next->right);

        n = nxt_rbtree1_test_compare(node, next);

        if (n < 0) {
            next = next->left;

        } else if (n > 0) {
            next = next->right;

        } else {
            return next;
        }
    }

    return NULL;
}


#if (NXT_TEST_RTDTSC)

#define NXT_RBT_STEP       (21 * nxt_pagesize / 10 / sizeof(nxt_rbtree1_node_t))

static nxt_rbtree1_t       mb_tree;
static nxt_rbtree1_node_t  mb_sentinel;
static nxt_rbtree1_node_t  *mb_nodes;


nxt_int_t
nxt_rbtree1_mb_start(nxt_thread_t *thr)
{
    uint32_t    key;
    uint64_t    start, end;
    nxt_uint_t  i, n;

    n = NXT_RBT_STEP;

    mb_nodes = nxt_malloc(NXT_RBT_NODES * n * sizeof(nxt_rbtree1_node_t));
    if (mb_nodes == NULL) {
        return NXT_ERROR;
    }

    nxt_rbtree1_init(&mb_tree, &mb_sentinel, nxt_rbtree1_test_insert_value);

    key = 0;

    for (i = 0; i < NXT_RBT_NODES; i++) {
        key = nxt_murmur_hash2(&key, sizeof(uint32_t));
        mb_nodes[n * i].key = key;
    }

    for (i = 0; i < NXT_RBT_NODES - 2; i++) {
        nxt_rbtree1_insert(&mb_tree, &mb_nodes[n * i]);
    }

    n *= (NXT_RBT_NODES - 2);

    start = nxt_rdtsc();
    nxt_rbtree1_insert(&mb_tree, &mb_nodes[n]);
    end = nxt_rdtsc();

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "rbtree1 mb cached insert: %L cycles", end - start);

    return NXT_OK;
}


void
nxt_rbtree1_mb_insert(nxt_thread_t *thr)
{
    uint64_t    start, end;
    nxt_uint_t  n;

    n = NXT_RBT_STEP;
    n *= (NXT_RBT_NODES - 1);

    start = nxt_rdtsc();
    nxt_rbtree1_insert(&mb_tree, &mb_nodes[n]);
    end = nxt_rdtsc();

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "rbtree1 mb insert: %L cycles", end - start);
}


void
nxt_rbtree1_mb_delete(nxt_thread_t *thr)
{
    uint64_t    start, end;
    nxt_uint_t  n;

    n = NXT_RBT_STEP;
    n *= (NXT_RBT_NODES / 4 + 1);

    start = nxt_rdtsc();
    nxt_rbtree1_delete(&mb_tree, &mb_nodes[n]);
    end = nxt_rdtsc();

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "rbtree1 mb delete: %L cycles", end - start);

    nxt_free(mb_nodes);
}

#endif
