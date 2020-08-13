
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PORT_QUEUE_H_INCLUDED_
#define _NXT_PORT_QUEUE_H_INCLUDED_


#include <nxt_nncq.h>


/* Using Numeric Naive Circular Queue as a backend. */

#define NXT_PORT_QUEUE_SIZE      NXT_NNCQ_SIZE
#define NXT_PORT_QUEUE_MSG_SIZE  31


typedef struct {
    uint8_t   size;
    uint8_t   data[NXT_PORT_QUEUE_MSG_SIZE];
} nxt_port_queue_item_t;


typedef struct {
    nxt_nncq_atomic_t      nitems;
    nxt_nncq_t             free_items;
    nxt_nncq_t             queue;
    nxt_port_queue_item_t  items[NXT_PORT_QUEUE_SIZE];
} nxt_port_queue_t;


nxt_inline void
nxt_port_queue_init(nxt_port_queue_t volatile *q)
{
    nxt_nncq_atomic_t  i;

    nxt_nncq_init(&q->free_items);
    nxt_nncq_init(&q->queue);

    for (i = 0; i < NXT_PORT_QUEUE_SIZE; i++) {
        nxt_nncq_enqueue(&q->free_items, i);
    }

    q->nitems = 0;
}


nxt_inline nxt_int_t
nxt_port_queue_send(nxt_port_queue_t volatile *q, const void *p, uint8_t size,
    int *notify)
{
    nxt_nncq_atomic_t      i;
    nxt_port_queue_item_t  *qi;

    i = nxt_nncq_dequeue(&q->free_items);
    if (i == nxt_nncq_empty(&q->free_items)) {
        *notify = 0;
        return NXT_AGAIN;
    }

    qi = (nxt_port_queue_item_t *) &q->items[i];

    qi->size = size;
    nxt_memcpy(qi->data, p, size);

    nxt_nncq_enqueue(&q->queue, i);

    i = nxt_atomic_fetch_add(&q->nitems, 1);

    *notify = (i == 0);

    return NXT_OK;
}


nxt_inline ssize_t
nxt_port_queue_recv(nxt_port_queue_t volatile *q, void *p)
{
    ssize_t                res;
    nxt_nncq_atomic_t      i;
    nxt_port_queue_item_t  *qi;

    i = nxt_nncq_dequeue(&q->queue);
    if (i == nxt_nncq_empty(&q->queue)) {
        return -1;
    }

    qi = (nxt_port_queue_item_t *) &q->items[i];

    res = qi->size;
    nxt_memcpy(p, qi->data, qi->size);

    nxt_nncq_enqueue(&q->free_items, i);

    nxt_atomic_fetch_add(&q->nitems, -1);

    return res;
}


#endif /* _NXT_PORT_QUEUE_H_INCLUDED_ */
