
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_APP_NNCQ_H_INCLUDED_
#define _NXT_APP_NNCQ_H_INCLUDED_


/* Appilcation Numeric Naive Circular Queue */

#define NXT_APP_NNCQ_SIZE  131072

typedef uint32_t nxt_app_nncq_atomic_t;
typedef uint16_t nxt_app_nncq_cycle_t;

typedef struct {
    nxt_app_nncq_atomic_t  head;
    nxt_app_nncq_atomic_t  entries[NXT_APP_NNCQ_SIZE];
    nxt_app_nncq_atomic_t  tail;
} nxt_app_nncq_t;


static inline nxt_app_nncq_atomic_t
nxt_app_nncq_head(nxt_app_nncq_t const volatile *q)
{
    return q->head;
}


static inline nxt_app_nncq_atomic_t
nxt_app_nncq_tail(nxt_app_nncq_t const volatile *q)
{
    return q->tail;
}


static inline void
nxt_app_nncq_tail_cmp_inc(nxt_app_nncq_t volatile *q, nxt_app_nncq_atomic_t t)
{
    nxt_atomic_cmp_set(&q->tail, t, t + 1);
}


static inline nxt_app_nncq_atomic_t
nxt_app_nncq_index(nxt_app_nncq_t const volatile *q, nxt_app_nncq_atomic_t i)
{
    return i % NXT_APP_NNCQ_SIZE;
}


static inline nxt_app_nncq_atomic_t
nxt_app_nncq_map(nxt_app_nncq_t const volatile *q, nxt_app_nncq_atomic_t i)
{
    return i % NXT_APP_NNCQ_SIZE;
}


static inline nxt_app_nncq_cycle_t
nxt_app_nncq_cycle(nxt_app_nncq_t const volatile *q, nxt_app_nncq_atomic_t i)
{
    return i / NXT_APP_NNCQ_SIZE;
}


static inline nxt_app_nncq_cycle_t
nxt_app_nncq_next_cycle(nxt_app_nncq_t const volatile *q,
    nxt_app_nncq_cycle_t i)
{
    return i + 1;
}


static inline nxt_app_nncq_atomic_t
nxt_app_nncq_new_entry(nxt_app_nncq_t const volatile *q,
    nxt_app_nncq_cycle_t cycle,
    nxt_app_nncq_atomic_t i)
{
    return cycle * NXT_APP_NNCQ_SIZE + (i % NXT_APP_NNCQ_SIZE);
}


static inline nxt_app_nncq_atomic_t
nxt_app_nncq_empty(nxt_app_nncq_t const volatile *q)
{
    return NXT_APP_NNCQ_SIZE;
}


static void
nxt_app_nncq_init(nxt_app_nncq_t volatile *q)
{
    q->head = NXT_APP_NNCQ_SIZE;
    nxt_memzero((void *) q->entries,
                NXT_APP_NNCQ_SIZE * sizeof(nxt_app_nncq_atomic_t));
    q->tail = NXT_APP_NNCQ_SIZE;
}


static void
nxt_app_nncq_enqueue(nxt_app_nncq_t volatile *q, nxt_app_nncq_atomic_t val)
{
    nxt_app_nncq_cycle_t   e_cycle, t_cycle;
    nxt_app_nncq_atomic_t  n, t, e, j;

    for ( ;; ) {
        t = nxt_app_nncq_tail(q);
        j = nxt_app_nncq_map(q, t);
        e = q->entries[j];

        e_cycle = nxt_app_nncq_cycle(q, e);
        t_cycle = nxt_app_nncq_cycle(q, t);

        if (e_cycle == t_cycle) {
            nxt_app_nncq_tail_cmp_inc(q, t);
            continue;
        }

        if (nxt_app_nncq_next_cycle(q, e_cycle) != t_cycle) {
            continue;
        }

        n = nxt_app_nncq_new_entry(q, t_cycle, val);

        if (nxt_atomic_cmp_set(&q->entries[j], e, n)) {
            break;
        }
    }

    nxt_app_nncq_tail_cmp_inc(q, t);
}


static nxt_app_nncq_atomic_t
nxt_app_nncq_dequeue(nxt_app_nncq_t volatile *q)
{
    nxt_app_nncq_cycle_t   e_cycle, h_cycle;
    nxt_app_nncq_atomic_t  h, j, e;

    for ( ;; ) {
        h = nxt_app_nncq_head(q);
        j = nxt_app_nncq_map(q, h);
        e = q->entries[j];

        e_cycle = nxt_app_nncq_cycle(q, e);
        h_cycle = nxt_app_nncq_cycle(q, h);

        if (e_cycle != h_cycle) {
            if (nxt_app_nncq_next_cycle(q, e_cycle) == h_cycle) {
                return nxt_app_nncq_empty(q);
            }

            continue;
        }

        if (nxt_atomic_cmp_set(&q->head, h, h + 1)) {
            break;
        }
    }

    return nxt_app_nncq_index(q, e);
}


#endif /* _NXT_APP_NNCQ_H_INCLUDED_ */
