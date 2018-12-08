
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIT_SPTR_H_INCLUDED_
#define _NXT_UNIT_SPTR_H_INCLUDED_


#include <inttypes.h>
#include <stddef.h>
#include <string.h>

#include "nxt_unit_typedefs.h"


/* Serialized pointer. */
union nxt_unit_sptr_u {
    uint8_t   base[1];
    uint32_t  offset;
};


static inline void
nxt_unit_sptr_set(nxt_unit_sptr_t *sptr, void *ptr)
{
    sptr->offset = (uint8_t *) ptr - sptr->base;
}


static inline void *
nxt_unit_sptr_get(nxt_unit_sptr_t *sptr)
{
    return sptr->base + sptr->offset;
}


#endif /* _NXT_UNIT_SPTR_H_INCLUDED_ */
