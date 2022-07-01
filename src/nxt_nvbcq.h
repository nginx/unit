
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_NVBCQ_H_INCLUDED_
#define _NXT_NVBCQ_H_INCLUDED_


/* Numeric VBart Circular Queue */

#define NXT_NVBCQ_SIZE  16384

typedef uint32_t nxt_nvbcq_atomic_t;

struct nxt_nvbcq_s {
    nxt_nvbcq_atomic_t  head;
    nxt_nvbcq_atomic_t  entries[NXT_NVBCQ_SIZE];
    nxt_nvbcq_atomic_t  tail;
};

typedef struct nxt_nvbcq_s nxt_nvbcq_t;


static inline nxt_nvbcq_atomic_t
nxt_nvbcq_head(nxt_nvbcq_t const volatile *q)
{
    return q->head;
}


static inline nxt_nvbcq_atomic_t
nxt_nvbcq_tail(nxt_nvbcq_t const volatile *q)
{
    return q->tail;
}


static inline void
nxt_nvbcq_tail_cmp_inc(nxt_nvbcq_t volatile *q, nxt_nvbcq_atomic_t t)
{
    nxt_atomic_cmp_set(&q->tail, t, t + 1);
}


static inline nxt_nvbcq_atomic_t
nxt_nvbcq_index(nxt_nvbcq_t const volatile *q, nxt_nvbcq_atomic_t i)
{
    return i % NXT_NVBCQ_SIZE;
}


static inline nxt_nvbcq_atomic_t
nxt_nvbcq_map(nxt_nvbcq_t const volatile *q, nxt_nvbcq_atomic_t i)
{
    return i % NXT_NVBCQ_SIZE;
}


static inline nxt_nvbcq_atomic_t
nxt_nvbcq_empty(nxt_nvbcq_t const volatile *q)
{
    return NXT_NVBCQ_SIZE;
}


static inline void
nxt_nvbcq_init(nxt_nvbcq_t volatile *q)
{
    nxt_nvbcq_atomic_t  i;

    q->head = 0;

    for (i = 0; i < NXT_NVBCQ_SIZE; i++) {
        q->entries[i] = NXT_NVBCQ_SIZE;
    }

    q->tail = NXT_NVBCQ_SIZE;
}


static inline void
nxt_nvbcq_enqueue(nxt_nvbcq_t volatile *q, nxt_nvbcq_atomic_t val)
{
    nxt_nvbcq_atomic_t  t, h, i;

    t = nxt_nvbcq_tail(q);
    h = t - NXT_NVBCQ_SIZE;

    for ( ;; ) {
        i = nxt_nvbcq_map(q, t);

        if (q->entries[i] == NXT_NVBCQ_SIZE
            && nxt_atomic_cmp_set(&q->entries[i], NXT_NVBCQ_SIZE, val))
        {
            nxt_nvbcq_tail_cmp_inc(q, t);
            return;
        }

        if ((t - h) == NXT_NVBCQ_SIZE) {
            h = nxt_nvbcq_head(q);

            if ((t - h) == NXT_NVBCQ_SIZE) {
                return;
            }
        }

        t++;
    }
}


static inline nxt_nvbcq_atomic_t
nxt_nvbcq_dequeue(nxt_nvbcq_t volatile *q)
{
    nxt_nvbcq_atomic_t  h, t, i, e;

    h = nxt_nvbcq_head(q);
    t = h + NXT_NVBCQ_SIZE;

    for ( ;; ) {
        i = nxt_nvbcq_map(q, h);
        e = q->entries[i];

        if (e < NXT_NVBCQ_SIZE
            && nxt_atomic_cmp_set(&q->entries[i], e, NXT_NVBCQ_SIZE))
        {
            nxt_atomic_cmp_set(&q->head, h, h + 1);

            return e;
        }

        if ((t - h) == NXT_NVBCQ_SIZE) {
            t = nxt_nvbcq_tail(q);

            if ((t - h) == NXT_NVBCQ_SIZE) {
                return NXT_NVBCQ_SIZE;
            }
        }

        h++;
    }
}


#endif /* _NXT_NVBCQ_H_INCLUDED_ */
