
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_HASH_H_INCLUDED_
#define _NXT_HASH_H_INCLUDED_


typedef struct {
    nxt_lvlhsh_t              lvlhsh;
    const nxt_lvlhsh_proto_t  *proto;
    void                      *pool;
} nxt_hash_t;


nxt_inline nxt_int_t
nxt_hash_find(nxt_hash_t *h, nxt_lvlhsh_query_t *lhq)
{
    lhq->proto = h->proto;

    return nxt_lvlhsh_find(&h->lvlhsh, lhq);
}


nxt_inline nxt_int_t
nxt_hash_insert(nxt_hash_t *h, nxt_lvlhsh_query_t *lhq)
{
    lhq->proto = h->proto;
    lhq->pool = h->pool;

    return nxt_lvlhsh_insert(&h->lvlhsh, lhq);
}


nxt_inline nxt_int_t
nxt_hash_delete(nxt_hash_t *h, nxt_lvlhsh_query_t *lhq)
{
    lhq->proto = h->proto;
    lhq->pool = h->pool;

    return nxt_lvlhsh_delete(&h->lvlhsh, lhq);
}


#endif /* _NXT_HASH_H_INCLUDED_ */
