
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_EVENT_TIMER_H_INCLUDED_
#define _NXT_EVENT_TIMER_H_INCLUDED_


/* Valid values are between 1ms to 255ms. */
#define NXT_EVENT_TIMER_DEFAULT_PRECISION  100
//#define NXT_EVENT_TIMER_DEFAULT_PRECISION  1


#if (NXT_DEBUG)
#define NXT_EVENT_TIMER       { NXT_RBTREE_NODE_INIT, 0, 0, 0,                \
                                NULL, NULL, NULL, NULL, -1 }

#else
#define NXT_EVENT_TIMER       { NXT_RBTREE_NODE_INIT, 0, 0, 0,                \
                                NULL, NULL, NULL, NULL }
#endif


typedef struct {
    /* The rbtree node must be the first field. */
    NXT_RBTREE_NODE           (node);

    uint8_t                   state;
    uint8_t                   precision;
    nxt_msec_t                time;

    nxt_work_queue_t          *work_queue;
    nxt_work_handler_t        handler;

    nxt_task_t                *task;
    nxt_log_t                 *log;
#if (NXT_DEBUG)
    int32_t                   ident;
#endif
} nxt_event_timer_t;


typedef struct {
    nxt_msec_t                time;
    nxt_event_timer_t         *event;
} nxt_event_timer_change_t;


typedef struct {
    nxt_rbtree_t              tree;

    /* An overflown milliseconds counter. */
    nxt_msec_t                now;

    nxt_uint_t                mchanges;
    nxt_uint_t                nchanges;

    nxt_event_timer_change_t  *changes;
} nxt_event_timers_t;


#define                                                                       \
nxt_event_timer_data(ev, type, timer)                                         \
    nxt_container_of(ev, type, timer)


/*
 * When timer resides in rbtree all links of its node are not NULL.
 * A parent link is the nearst to other timer flags.
 */

#define                                                                       \
nxt_event_timer_is_in_tree(ev)                                                \
    ((ev)->node.parent != NULL)

#define                                                                       \
nxt_event_timer_in_tree_set(ev)
    /* Noop, because rbtree insertion sets a node's parent link. */

#define                                                                       \
nxt_event_timer_in_tree_clear(ev)                                             \
    (ev)->node.parent = NULL


#define NXT_EVENT_TIMER_DISABLED  0
#define NXT_EVENT_TIMER_BLOCKED   1
#define NXT_EVENT_TIMER_ACTIVE    2


#if (NXT_DEBUG)

#define                                                                       \
nxt_event_timer_ident(ev, val)                                                \
    (ev)->ident = (val)

#else

#define                                                                       \
nxt_event_timer_ident(ev, val)

#endif


nxt_inline nxt_event_timer_t *
nxt_event_timer_create(int32_t ident)
{
    nxt_event_timer_t  *ev;

    ev = nxt_zalloc(sizeof(nxt_event_timer_t));
    if (ev == NULL) {
        return NULL;
    }

    ev->precision = NXT_EVENT_TIMER_DEFAULT_PRECISION;
#if (NXT_DEBUG)
    ev->ident = ident;
#endif

    return ev;
}


nxt_int_t nxt_event_timers_init(nxt_event_timers_t *timers,
    nxt_uint_t mchanges);
NXT_EXPORT void nxt_event_timer_add(nxt_event_engine_t *engine,
    nxt_event_timer_t *ev, nxt_msec_t timer);
NXT_EXPORT void nxt_event_timer_delete(nxt_event_engine_t *engine,
    nxt_event_timer_t *ev);
nxt_msec_t nxt_event_timer_find(nxt_event_engine_t *engine);
void nxt_event_timer_expire(nxt_thread_t *thr, nxt_msec_t now);

#if (NXT_DEBUG)

NXT_EXPORT void nxt_event_timer_disable(nxt_event_timer_t *ev);

#else

#define                                                                       \
nxt_event_timer_disable(ev)                                                   \
    (ev)->state = NXT_EVENT_TIMER_DISABLED

#endif


#endif /* _NXT_EVENT_TIMER_H_INCLUDED_ */
