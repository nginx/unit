
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_MURMUR_HASH_H_INCLUDED_
#define _NXT_MURMUR_HASH_H_INCLUDED_


NXT_EXPORT uint32_t nxt_murmur_hash2(const void *data, size_t len);
NXT_EXPORT uint32_t nxt_murmur_hash2_uint32(const void *data);


#endif /* _NXT_MURMUR_HASH_H_INCLUDED_ */
