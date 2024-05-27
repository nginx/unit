
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_TIMER_H_INCLUDED_
#define _NXT_TIMER_H_INCLUDED_


/* Valid values are between 0ms to 255ms. */
#define NXT_TIMER_DEFAULT_BIAS  50
//#define NXT_TIMER_DEFAULT_BIAS  0


/*
 * The nxt_timer_t structure can hold up to 14 bits of change index,
 * but 0 reserved for NXT_TIMER_NO_CHANGE.
 */
#define NXT_TIMER_MAX_CHANGES  16383
#define NXT_TIMER_NO_CHANGE    0


typedef struct {
    /* The rbtree node must be the first field. */
    NXT_RBTREE_NODE           (node);

    uint8_t                   bias;

    uint16_t                  change:14;
    uint16_t                  enabled:1;
    uint16_t                  queued:1;

    nxt_msec_t                time;

    nxt_work_queue_t          *work_queue;
    nxt_work_handler_t        handler;

    nxt_task_t                *task;
    nxt_log_t                 *log;
} nxt_timer_t;


#define NXT_TIMER             { NXT_RBTREE_NODE_INIT, 0, NXT_TIMER_NO_CHANGE, \
                                0, 0, 0, NULL, NULL, NULL, NULL }


typedef enum {
    NXT_TIMER_NOPE = 0,
    NXT_TIMER_ADD,
    NXT_TIMER_DELETE,
} nxt_timer_operation_t;


typedef struct {
    nxt_timer_operation_t     change:8;
    nxt_msec_t                time;
    nxt_timer_t               *timer;
} nxt_timer_change_t;


typedef struct {
    nxt_rbtree_t              tree;

    /* An overflown milliseconds counter. */
    nxt_msec_t                now;
    nxt_msec_t                minimum;

    nxt_uint_t                mchanges;
    nxt_uint_t                nchanges;

    nxt_timer_change_t        *changes;
} nxt_timers_t;


#define nxt_timer_data(obj, type, timer)                                      \
    nxt_container_of(obj, type, timer)


/*
 * When timer resides in rbtree all links of its node are not NULL.
 * A parent link is the nearst to other timer flags.
 */

#define nxt_timer_is_in_tree(timer)                                           \
    ((timer)->node.parent != NULL)

#define nxt_timer_in_tree_set(timer)
    /* Noop, because rbtree insertion sets a node's parent link. */

#define nxt_timer_in_tree_clear(timer)                                        \
    (timer)->node.parent = NULL


nxt_int_t nxt_timers_init(nxt_timers_t *timers, nxt_uint_t mchanges);
nxt_msec_t nxt_timer_find(nxt_event_engine_t *engine);
void nxt_timer_expire(nxt_event_engine_t *engine, nxt_msec_t now);

NXT_EXPORT void nxt_timer_add(nxt_event_engine_t *engine, nxt_timer_t *timer,
    nxt_msec_t timeout);
NXT_EXPORT nxt_bool_t nxt_timer_delete(nxt_event_engine_t *engine,
    nxt_timer_t *timer);

nxt_inline void
nxt_timer_disable(nxt_event_engine_t *engine, nxt_timer_t *timer)
{
    nxt_debug(timer->task, "timer disable: %M", timer->time);

    timer->enabled = 0;
}


#endif /* _NXT_TIMER_H_INCLUDED_ */
