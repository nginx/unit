
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_APP_QUEUE_H_INCLUDED_
#define _NXT_APP_QUEUE_H_INCLUDED_


#include <nxt_app_nncq.h>


/* Using Numeric Naive Circular Queue as a backend. */

#define NXT_APP_QUEUE_SIZE      NXT_APP_NNCQ_SIZE
#define NXT_APP_QUEUE_MSG_SIZE  31

typedef struct {
    uint8_t   size;
    uint8_t   data[NXT_APP_QUEUE_MSG_SIZE];
    uint32_t  tracking;
} nxt_app_queue_item_t;


typedef struct {
    nxt_app_nncq_atomic_t  notified;
    nxt_app_nncq_t         free_items;
    nxt_app_nncq_t         queue;
    nxt_app_queue_item_t   items[NXT_APP_QUEUE_SIZE];
} nxt_app_queue_t;


nxt_inline void
nxt_app_queue_init(nxt_app_queue_t volatile *q)
{
    nxt_app_nncq_atomic_t  i;

    nxt_app_nncq_init(&q->free_items);
    nxt_app_nncq_init(&q->queue);

    for (i = 0; i < NXT_APP_QUEUE_SIZE; i++) {
        nxt_app_nncq_enqueue(&q->free_items, i);
    }

    q->notified = 0;
}


nxt_inline nxt_int_t
nxt_app_queue_send(nxt_app_queue_t volatile *q, const void *p,
    uint8_t size, uint32_t tracking, int *notify, uint32_t *cookie)
{
    int                    n;
    nxt_app_queue_item_t   *qi;
    nxt_app_nncq_atomic_t  i;

    i = nxt_app_nncq_dequeue(&q->free_items);
    if (i == nxt_app_nncq_empty(&q->free_items)) {
        return NXT_AGAIN;
    }

    qi = (nxt_app_queue_item_t *) &q->items[i];

    qi->size = size;
    nxt_memcpy(qi->data, p, size);
    qi->tracking = tracking;
    *cookie = i;

    nxt_app_nncq_enqueue(&q->queue, i);

    n = nxt_atomic_cmp_set(&q->notified, 0, 1);

    if (notify != NULL) {
        *notify = n;
    }

    return NXT_OK;
}


nxt_inline void
nxt_app_queue_notification_received(nxt_app_queue_t volatile *q)
{
    q->notified = 0;
}


nxt_inline nxt_bool_t
nxt_app_queue_cancel(nxt_app_queue_t volatile *q, uint32_t cookie,
    uint32_t tracking)
{
    nxt_app_queue_item_t  *qi;

    qi = (nxt_app_queue_item_t *) &q->items[cookie];

    return nxt_atomic_cmp_set(&qi->tracking, tracking, 0);
}


nxt_inline ssize_t
nxt_app_queue_recv(nxt_app_queue_t volatile *q, void *p, uint32_t *cookie)
{
    ssize_t                res;
    nxt_app_queue_item_t   *qi;
    nxt_app_nncq_atomic_t  i;

    i = nxt_app_nncq_dequeue(&q->queue);
    if (i == nxt_app_nncq_empty(&q->queue)) {
        *cookie = 0;
        return -1;
    }

    qi = (nxt_app_queue_item_t *) &q->items[i];

    res = qi->size;
    nxt_memcpy(p, qi->data, qi->size);
    *cookie = i;

    nxt_app_nncq_enqueue(&q->free_items, i);

    return res;
}


#endif /* _NXT_APP_QUEUE_H_INCLUDED_ */
