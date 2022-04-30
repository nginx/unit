
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_DJB_HASH_H_INCLUDED_
#define _NXT_DJB_HASH_H_INCLUDED_


/* A fast and simple hash function by Daniel J. Bernstein. */


NXT_EXPORT uint32_t nxt_djb_hash(const void *data, size_t len);
NXT_EXPORT uint32_t nxt_djb_hash_lowcase(const void *data, size_t len);


#define NXT_DJB_HASH_INIT  5381


#define nxt_djb_hash_add(hash, val)                                           \
    ((uint32_t) ((((hash) << 5) + (hash)) ^ (uint32_t) (val)))


#endif /* _NXT_DJB_HASH_H_INCLUDED_ */
