
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_upstream_header_hash_test(nxt_lvlhsh_query_t *lhq,
    void *data);


const nxt_lvlhsh_proto_t  nxt_upstream_header_hash_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    0,
    nxt_upstream_header_hash_test,
    nxt_mem_lvlhsh_alloc,
    nxt_mem_lvlhsh_free,
};


nxt_int_t
nxt_upstream_header_hash_add(nxt_mp_t *mp, nxt_lvlhsh_t *lh,
    const nxt_upstream_name_value_t *unv, nxt_uint_t n)
{
    nxt_lvlhsh_query_t  lhq;

    while (n != 0) {
        lhq.key_hash = nxt_djb_hash(unv->name, unv->len);
        lhq.replace = 1;
        lhq.key.len = unv->len;
        lhq.key.data = (u_char *) unv->name;
        lhq.value = (void *) unv;
        lhq.proto = &nxt_upstream_header_hash_proto;
        lhq.pool = mp;

        if (nxt_lvlhsh_insert(lh, &lhq) != NXT_OK) {
            return NXT_ERROR;
        }

        unv++;
        n--;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_upstream_header_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_upstream_name_value_t  *unv;

    unv = data;

    if (lhq->key.len == unv->len
        && nxt_memcasecmp(lhq->key.data, unv->name, unv->len) == 0)
    {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


nxt_int_t
nxt_upstream_name_value_ignore(nxt_upstream_source_t *us, nxt_name_value_t *nv)
{
    return NXT_OK;
}
