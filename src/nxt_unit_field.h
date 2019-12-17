
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIT_FIELD_H_INCLUDED_
#define _NXT_UNIT_FIELD_H_INCLUDED_


#include <inttypes.h>

#include "nxt_unit_sptr.h"

enum {
    NXT_UNIT_HASH_CONTENT_LENGTH = 0x1EA0,
    NXT_UNIT_HASH_CONTENT_TYPE   = 0x5F7D,
    NXT_UNIT_HASH_COOKIE         = 0x23F2,
};


/* Name and Value field aka HTTP header. */
struct nxt_unit_field_s {
    uint16_t              hash;
    uint8_t               skip:1;
    uint8_t               hopbyhop:1;
    uint8_t               name_length;
    uint32_t              value_length;

    nxt_unit_sptr_t       name;
    nxt_unit_sptr_t       value;
};


#endif /* _NXT_UNIT_FIELD_H_INCLUDED_ */
