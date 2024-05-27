
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


uint32_t
nxt_djb_hash(const void *data, size_t len)
{
    uint32_t      hash;
    const u_char  *p;

    p = data;
    hash = NXT_DJB_HASH_INIT;

    while (len != 0) {
        hash = nxt_djb_hash_add(hash, *p++);
        len--;
    }

    return hash;
}


uint32_t
nxt_djb_hash_lowcase(const void *data, size_t len)
{
    u_char        c;
    uint32_t      hash;
    const u_char  *p;

    p = data;
    hash = NXT_DJB_HASH_INIT;

    while (len != 0) {
        c = *p++;
        hash = nxt_djb_hash_add(hash, nxt_lowcase(c));
        len--;
    }

    return hash;
}
