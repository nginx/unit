
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_NNCQ_H_INCLUDED_
#define _NXT_NNCQ_H_INCLUDED_


/* Numeric Naive Circular Queue */

#define NXT_NNCQ_SIZE  16384

typedef uint32_t nxt_nncq_atomic_t;
typedef uint16_t nxt_nncq_cycle_t;

typedef struct {
    nxt_nncq_atomic_t  head;
    nxt_nncq_atomic_t  entries[NXT_NNCQ_SIZE];
    nxt_nncq_atomic_t  tail;
} nxt_nncq_t;


static inline nxt_nncq_atomic_t
nxt_nncq_head(nxt_nncq_t const volatile *q)
{
    return q->head;
}


static inline nxt_nncq_atomic_t
nxt_nncq_tail(nxt_nncq_t const volatile *q)
{
    return q->tail;
}


static inline void
nxt_nncq_tail_cmp_inc(nxt_nncq_t volatile *q, nxt_nncq_atomic_t t)
{
    nxt_atomic_cmp_set(&q->tail, t, t + 1);
}


static inline nxt_nncq_atomic_t
nxt_nncq_index(nxt_nncq_t const volatile *q, nxt_nncq_atomic_t i)
{
    return i % NXT_NNCQ_SIZE;
}


static inline nxt_nncq_atomic_t
nxt_nncq_map(nxt_nncq_t const volatile *q, nxt_nncq_atomic_t i)
{
    return i % NXT_NNCQ_SIZE;
}


static inline nxt_nncq_cycle_t
nxt_nncq_cycle(nxt_nncq_t const volatile *q, nxt_nncq_atomic_t i)
{
    return i / NXT_NNCQ_SIZE;
}


static inline nxt_nncq_cycle_t
nxt_nncq_next_cycle(nxt_nncq_t const volatile *q, nxt_nncq_cycle_t i)
{
    return i + 1;
}


static inline nxt_nncq_atomic_t
nxt_nncq_new_entry(nxt_nncq_t const volatile *q, nxt_nncq_cycle_t cycle,
    nxt_nncq_atomic_t i)
{
    return cycle * NXT_NNCQ_SIZE + (i % NXT_NNCQ_SIZE);
}


static inline nxt_nncq_atomic_t
nxt_nncq_empty(nxt_nncq_t const volatile *q)
{
    return NXT_NNCQ_SIZE;
}


static inline void
nxt_nncq_init(nxt_nncq_t volatile *q)
{
    q->head = NXT_NNCQ_SIZE;
    nxt_memzero((void *) q->entries, NXT_NNCQ_SIZE * sizeof(nxt_nncq_atomic_t));
    q->tail = NXT_NNCQ_SIZE;
}


static inline void
nxt_nncq_enqueue(nxt_nncq_t volatile *q, nxt_nncq_atomic_t val)
{
    nxt_nncq_cycle_t   e_cycle, t_cycle;
    nxt_nncq_atomic_t  n, t, e, j;

    for ( ;; ) {
        t = nxt_nncq_tail(q);
        j = nxt_nncq_map(q, t);
        e = q->entries[j];

        e_cycle = nxt_nncq_cycle(q, e);
        t_cycle = nxt_nncq_cycle(q, t);

        if (e_cycle == t_cycle) {
            nxt_nncq_tail_cmp_inc(q, t);
            continue;
        }

        if (nxt_nncq_next_cycle(q, e_cycle) != t_cycle) {
            continue;
        }

        n = nxt_nncq_new_entry(q, t_cycle, val);

        if (nxt_atomic_cmp_set(&q->entries[j], e, n)) {
            break;
        }
    }

    nxt_nncq_tail_cmp_inc(q, t);
}


static inline nxt_nncq_atomic_t
nxt_nncq_dequeue(nxt_nncq_t volatile *q)
{
    nxt_nncq_cycle_t   e_cycle, h_cycle;
    nxt_nncq_atomic_t  h, j, e;

    for ( ;; ) {
        h = nxt_nncq_head(q);
        j = nxt_nncq_map(q, h);
        e = q->entries[j];

        e_cycle = nxt_nncq_cycle(q, e);
        h_cycle = nxt_nncq_cycle(q, h);

        if (e_cycle != h_cycle) {
            if (nxt_nncq_next_cycle(q, e_cycle) == h_cycle) {
                return nxt_nncq_empty(q);
            }

            continue;
        }

        if (nxt_atomic_cmp_set(&q->head, h, h + 1)) {
            break;
        }
    }

    return nxt_nncq_index(q, e);
}


#endif /* _NXT_NNCQ_H_INCLUDED_ */
