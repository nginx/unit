
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_DYLD_H_INCLUDED_
#define _NXT_UNIX_DYLD_H_INCLUDED_


typedef struct {
    void              *handle;
    char              *name;
} nxt_dyld_t;


#define NXT_DYLD_ANY  RTLD_DEFAULT


#define nxt_dyld_is_valid(dyld)                                               \
    ((dyld)->handle != NULL)


NXT_EXPORT nxt_int_t nxt_dyld_load(nxt_dyld_t *dyld);
NXT_EXPORT void *nxt_dyld_symbol(nxt_dyld_t *dyld, const char *symbol);
NXT_EXPORT nxt_int_t nxt_dyld_unload(nxt_dyld_t *dyld);


#endif /* _NXT_UNIX_DYLD_H_INCLUDED_ */
