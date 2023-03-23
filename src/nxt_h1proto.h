
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_H1PROTO_H_INCLUDED_
#define _NXT_H1PROTO_H_INCLUDED_


#include <nxt_main.h>
#include <nxt_http_parse.h>
#include <nxt_http.h>
#include <nxt_router.h>


typedef struct nxt_h1p_websocket_timer_s nxt_h1p_websocket_timer_t;


struct nxt_h1proto_s {
    nxt_http_request_parse_t  parser;
    nxt_http_chunk_parse_t    chunked_parse;
    nxt_off_t                 remainder;

    uint8_t                   nbuffers;
    uint8_t                   header_buffer_slot;
    uint8_t                   large_buffer_slot;
    nxt_bool_t                keepalive;
    nxt_bool_t                chunked;
    nxt_bool_t                websocket;
    nxt_bool_t                connection_upgrade;
    nxt_bool_t                upgrade_websocket;
    nxt_bool_t                websocket_version_ok;
    nxt_http_te_t             transfer_encoding:8;  /* 2 bits */

    nxt_bool_t                websocket_cont_expected;
    nxt_bool_t                websocket_closed;

    uint32_t                  header_size;

    nxt_http_field_t          *websocket_key;
    nxt_h1p_websocket_timer_t *websocket_timer;

    nxt_http_request_t        *request;
    nxt_buf_t                 *buffers;

    nxt_buf_t                 **conn_write_tail;
    /*
     * All fields before the conn field will
     * be zeroed in a keep-alive connection.
     */
    nxt_conn_t                *conn;
};

#endif  /* _NXT_H1PROTO_H_INCLUDED_ */
