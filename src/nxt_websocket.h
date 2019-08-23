
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_WEBSOCKET_H_INCLUDED_
#define _NXT_WEBSOCKET_H_INCLUDED_


enum {
    NXT_WEBSOCKET_ACCEPT_SIZE = 28,
};


NXT_EXPORT size_t nxt_websocket_frame_header_size(const void *data);
NXT_EXPORT uint64_t nxt_websocket_frame_payload_len(const void *data);
NXT_EXPORT void *nxt_websocket_frame_init(void *data, uint64_t payload_len);
NXT_EXPORT void nxt_websocket_accept(u_char *accept, const void *key);


#endif  /* _NXT_WEBSOCKET_H_INCLUDED_ */
