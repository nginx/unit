
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIT_WEBSOCKET_H_INCLUDED_
#define _NXT_UNIT_WEBSOCKET_H_INCLUDED_

#include <inttypes.h>

#include "nxt_unit_typedefs.h"
#include "nxt_websocket_header.h"


struct nxt_unit_websocket_frame_s {
    nxt_unit_request_info_t  *req;

    uint64_t                  payload_len;
    nxt_websocket_header_t    *header;
    uint8_t                   *mask;

    nxt_unit_buf_t            *content_buf;
    uint64_t                  content_length;
};


#endif /* _NXT_UNIT_WEBSOCKET_H_INCLUDED_ */
