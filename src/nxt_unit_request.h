
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIT_REQUEST_H_INCLUDED_
#define _NXT_UNIT_REQUEST_H_INCLUDED_


#include <inttypes.h>

#include "nxt_unit_sptr.h"
#include "nxt_unit_field.h"

#define NXT_UNIT_NONE_FIELD  0xFFFFFFFFU

struct nxt_unit_request_s {
    uint8_t               method_length;
    uint8_t               version_length;
    uint8_t               remote_length;
    uint8_t               local_length;
    uint8_t               tls;
    uint8_t               websocket_handshake;
    uint8_t               app_target;
    uint32_t              server_name_length;
    uint32_t              target_length;
    uint32_t              path_length;
    uint32_t              query_length;
    uint32_t              fields_count;

    uint32_t              content_length_field;
    uint32_t              content_type_field;
    uint32_t              cookie_field;
    uint32_t              authorization_field;

    uint64_t              content_length;

    nxt_unit_sptr_t       method;
    nxt_unit_sptr_t       version;
    nxt_unit_sptr_t       remote;
    nxt_unit_sptr_t       local;
    nxt_unit_sptr_t       server_name;
    nxt_unit_sptr_t       target;
    nxt_unit_sptr_t       path;
    nxt_unit_sptr_t       query;
    nxt_unit_sptr_t       preread_content;

    nxt_unit_field_t      fields[];
};


#endif /* _NXT_UNIT_REQUEST_H_INCLUDED_ */

