
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include "nxt_tests.h"


typedef struct {
    NXT_RBTREE_NODE  (node);
    uint32_t         key;
} nxt_rbtree_test_t;


static intptr_t nxt_rbtree_test_comparison(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2);
static nxt_int_t nxt_rbtree_test_compare(uint32_t key1, uint32_t key2);
static int nxt_cdecl nxt_rbtree_test_sort_cmp(const void *one, const void *two);


nxt_int_t
nxt_rbtree_test(nxt_thread_t *thr, nxt_uint_t n)
{
    void               *mark;
    uint32_t           key, *keys;
    nxt_uint_t         i;
    nxt_nsec_t         start, end;
    nxt_rbtree_t       tree;
    nxt_rbtree_node_t  *node;
    nxt_rbtree_test_t  *items, *item;

    nxt_thread_time_update(thr);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "rbtree test started: %ui", n);

    nxt_rbtree_init(&tree, nxt_rbtree_test_comparison);

    mark = tree.sentinel.right;

    items = nxt_malloc(n * sizeof(nxt_rbtree_test_t));
    if (items == NULL) {
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
        items[i].key = key;
    }

    nxt_qsort(keys, n, sizeof(uint32_t), nxt_rbtree_test_sort_cmp);

    nxt_thread_time_update(thr);
    start = nxt_thread_monotonic_time(thr);

    for (i = 0; i < n; i++) {
        nxt_rbtree_insert(&tree, &items[i].node);
    }

    for (i = 0; i < n; i++) {
        node = nxt_rbtree_find(&tree, &items[i].node);

        if (node != (nxt_rbtree_node_t *) &items[i].node) {
            nxt_log_alert(thr->log, "rbtree test failed: %08XD not found",
                          items[i].key);
            goto fail;
        }
    }

    i = 0;
    node = nxt_rbtree_min(&tree);

    while (nxt_rbtree_is_there_successor(&tree, node)) {

        item = (nxt_rbtree_test_t *) node;

        if (keys[i] != item->key) {
            nxt_log_alert(thr->log, "rbtree test failed: %i: %08XD %08XD",
                          i, keys[i], item->key);
            goto fail;
        }

        i++;
        node = nxt_rbtree_node_successor(&tree, node);
    }

    if (i != n) {
        nxt_log_alert(thr->log, "rbtree test failed: %ui", i);
        goto fail;
    }

    for (i = 0; i < n; i++) {
        nxt_rbtree_delete(&tree, &items[i].node);
        nxt_memset(&items[i], 0xA5, sizeof(nxt_rbtree_test_t));
    }

    nxt_thread_time_update(thr);
    end = nxt_thread_monotonic_time(thr);

    if (!nxt_rbtree_is_empty(&tree)) {
        nxt_log_alert(thr->log, "rbtree test failed: tree is not empty");
        goto fail;
    }

    /* Check that the sentinel callback was not modified. */

    if (mark != tree.sentinel.right) {
        nxt_log_alert(thr->log, "rbtree sentinel test failed");
        goto fail;
    }

    nxt_free(keys);
    nxt_free(items);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "rbtree test passed %0.3fs",
                  (end - start) / 1000000000.0);

    return NXT_OK;

fail:

    nxt_free(keys);
    nxt_free(items);

    return NXT_ERROR;
}


static intptr_t
nxt_rbtree_test_comparison(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2)
{
    nxt_rbtree_test_t  *item1, *item2;

    item1 = (nxt_rbtree_test_t *) node1;
    item2 = (nxt_rbtree_test_t *) node2;

    return nxt_rbtree_test_compare(item1->key, item2->key);
}


/*
 * Subtraction cannot be used in these comparison functions because
 * the key values are spread uniform in whole 0 .. 2^32 range but are
 * not grouped around some value as timeout values are.
 */

static nxt_int_t
nxt_rbtree_test_compare(uint32_t key1, uint32_t key2)
{
    if (key1 < key2) {
        return -1;
    }

    if (key1 == key2) {
        return 0;
    }

    return 1;
}


static int nxt_cdecl
nxt_rbtree_test_sort_cmp(const void *one, const void *two)
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


#if (NXT_TEST_RTDTSC)

#define NXT_RBT_STEP      (21 * nxt_pagesize / 10 / sizeof(nxt_rbtree_test_t))

static nxt_rbtree_t       mb_tree;
static nxt_rbtree_test_t  *mb_nodes;


nxt_int_t
nxt_rbtree_mb_start(nxt_thread_t *thr)
{
    uint32_t    key;
    uint64_t    start, end;
    nxt_uint_t  i, n;

    n = NXT_RBT_STEP;

    mb_nodes = nxt_malloc(NXT_RBT_NODES * n * sizeof(nxt_rbtree_test_t));
    if (mb_nodes == NULL) {
        return NXT_ERROR;
    }

    nxt_rbtree_init(&mb_tree, nxt_rbtree_test_comparison);

    key = 0;

    for (i = 0; i < NXT_RBT_NODES; i++) {
        key = nxt_murmur_hash2(&key, sizeof(uint32_t));
        mb_nodes[n * i].key = key;
    }

    for (i = 0; i < NXT_RBT_NODES - 2; i++) {
        nxt_rbtree_insert(&mb_tree, &mb_nodes[n * i].node);
    }

    n *= (NXT_RBT_NODES - 2);

    start = nxt_rdtsc();
    nxt_rbtree_insert(&mb_tree, &mb_nodes[n].node);
    end = nxt_rdtsc();

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "rbtree mb cached insert: %L cycles", end - start);

    return NXT_OK;
}


void
nxt_rbtree_mb_insert(nxt_thread_t *thr)
{
    uint64_t    start, end;
    nxt_uint_t  n;

    n = NXT_RBT_STEP;
    n *= (NXT_RBT_NODES - 1);

    start = nxt_rdtsc();
    nxt_rbtree_insert(&mb_tree, &mb_nodes[n].node);
    end = nxt_rdtsc();

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "rbtree mb insert: %L cycles", end - start);
}


void
nxt_rbtree_mb_delete(nxt_thread_t *thr)
{
    uint64_t    start, end;
    nxt_uint_t  n;

    n = NXT_RBT_STEP;
    n *= (NXT_RBT_NODES / 4 + 1);

    start = nxt_rdtsc();
    nxt_rbtree_delete(&mb_tree, &mb_nodes[n].node);
    end = nxt_rdtsc();

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "rbtree mb delete: %L cycles", end - start);

    nxt_free(mb_nodes);
}

#endif
