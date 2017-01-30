
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CACHE_INCLUDED_
#define _NXT_CACHE_INCLUDED_


typedef struct nxt_cache_query_s       nxt_cache_query_t;
typedef struct nxt_cache_query_wait_s  nxt_cache_query_wait_t;


typedef struct {
    uint32_t                  shared;        /* 1 bit */
    nxt_thread_spinlock_t     lock;

    nxt_lvlhsh_t              lvlhsh;
    const nxt_lvlhsh_proto_t  *proto;
    void                      *pool;

    nxt_queue_t               expiry_queue;

    nxt_queue_t               free_nodes;
    uint32_t                  nfree_nodes;

    uint32_t                  nfree_query_wait;
    nxt_cache_query_wait_t    *free_query_wait;

    uint64_t                  start_time;

    /* STUB: use nxt_lvlhsh_proto_t */
    void                      *(*alloc)(void *data, size_t size);
    void                      (*free)(void *data, void *p);
    void                      *data;

    nxt_work_handler_t        delete_handler;
} nxt_cache_t;


typedef struct {
    u_char                    *key_data;

    uint16_t                  key_len;       /* 16 bits */
    uint8_t                   uses;          /* 8 bits */
    uint8_t                   updating:1;
    uint8_t                   deleted:1;

    uint32_t                  count;

    /* Times relative to the cache->start_time. */
    uint32_t                  expiry;
    uint32_t                  accessed;

    nxt_off_t                 size;

    nxt_queue_link_t          link;

    nxt_cache_query_wait_t    *waiting;
} nxt_cache_node_t;


struct nxt_cache_query_wait_s {
    nxt_cache_query_t         *query;
    nxt_cache_query_wait_t    *next;

    uint8_t                   busy;          /* 1 bit */
    uint8_t                   deleted;       /* 1 bit */

    nxt_pid_t                 pid;
    nxt_event_engine_t        *engine;
    nxt_work_handler_t        handler;
    nxt_cache_t               *cache;
};


typedef struct {
    nxt_work_handler_t        nocache_handler;
    nxt_work_handler_t        ready_handler;
    nxt_work_handler_t        stale_handler;
    nxt_work_handler_t        update_stale_handler;
    nxt_work_handler_t        update_handler;
    nxt_work_handler_t        timeout_handler;
    nxt_work_handler_t        error_handler;
} nxt_cache_query_state_t;


struct nxt_cache_query_s {
    u_char                    *key_data;

    uint16_t                  key_len;       /* 16 bits */
#if (NXT_64_BIT)
    uint8_t                   hold;          /* 1 bit */
    uint8_t                   use_stale;     /* 1 bit */
    uint8_t                   update_stale;  /* 1 bit */
    uint8_t                   stale;         /* 1 bit */
#else
    uint8_t                   hold:1;
    uint8_t                   use_stale:1;
    uint8_t                   update_stale:1;
    uint8_t                   stale:1;
#endif

    nxt_cache_node_t          *node;
    nxt_cache_query_t         *next;
    nxt_cache_query_state_t   *state;

    nxt_time_t                now;

    nxt_msec_t                timeout;
    nxt_timer_t               timer;
};


NXT_EXPORT void nxt_cache_init(nxt_cache_t *cache);
NXT_EXPORT void nxt_cache_query(nxt_cache_t *cache, nxt_cache_query_t *q);
NXT_EXPORT void nxt_cache_release(nxt_cache_t *cache, nxt_cache_query_t *q);
NXT_EXPORT nxt_int_t nxt_cache_update(nxt_cache_t *cache, nxt_cache_query_t *q);


#endif /* _NXT_CACHE_INCLUDED_ */
