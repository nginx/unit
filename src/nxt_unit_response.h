
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIT_RESPONSE_H_INCLUDED_
#define _NXT_UNIT_RESPONSE_H_INCLUDED_


#include <inttypes.h>

#include "nxt_unit_sptr.h"
#include "nxt_unit_field.h"

struct nxt_unit_response_s {
    uint64_t              content_length;
    uint32_t              fields_count;
    uint32_t              piggyback_content_length;
    uint16_t              status;

    nxt_unit_sptr_t       piggyback_content;

    nxt_unit_field_t      fields[];
};


#endif /* _NXT_UNIT_RESPONSE_H_INCLUDED_ */
