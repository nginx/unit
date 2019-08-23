
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_WEBSOCKET_HEADER_H_INCLUDED_
#define _NXT_WEBSOCKET_HEADER_H_INCLUDED_

#include <netinet/in.h>


typedef struct {
#if (BYTE_ORDER == BIG_ENDIAN)
    uint8_t fin:1;
    uint8_t rsv1:1;
    uint8_t rsv2:1;
    uint8_t rsv3:1;
    uint8_t opcode:4;

    uint8_t mask:1;
    uint8_t payload_len:7;
#endif

#if (BYTE_ORDER == LITTLE_ENDIAN)
    uint8_t opcode:4;
    uint8_t rsv3:1;
    uint8_t rsv2:1;
    uint8_t rsv1:1;
    uint8_t fin:1;

    uint8_t payload_len:7;
    uint8_t mask:1;
#endif

    uint8_t payload_len_[8];
} nxt_websocket_header_t;


enum {
    NXT_WEBSOCKET_OP_CONT   = 0x00,
    NXT_WEBSOCKET_OP_TEXT   = 0x01,
    NXT_WEBSOCKET_OP_BINARY = 0x02,
    NXT_WEBSOCKET_OP_CLOSE  = 0x08,
    NXT_WEBSOCKET_OP_PING   = 0x09,
    NXT_WEBSOCKET_OP_PONG   = 0x0A,

    NXT_WEBSOCKET_OP_CTRL   = 0x08,
};


enum {
    NXT_WEBSOCKET_CR_NORMAL                 = 1000,
    NXT_WEBSOCKET_CR_GOING_AWAY             = 1001,
    NXT_WEBSOCKET_CR_PROTOCOL_ERROR         = 1002,
    NXT_WEBSOCKET_CR_UNPROCESSABLE_INPUT    = 1003,
    NXT_WEBSOCKET_CR_RESERVED               = 1004,
    NXT_WEBSOCKET_CR_NOT_PROVIDED           = 1005,
    NXT_WEBSOCKET_CR_ABNORMAL               = 1006,
    NXT_WEBSOCKET_CR_INVALID_DATA           = 1007,
    NXT_WEBSOCKET_CR_POLICY_VIOLATION       = 1008,
    NXT_WEBSOCKET_CR_MESSAGE_TOO_BIG        = 1009,
    NXT_WEBSOCKET_CR_EXTENSION_REQUIRED     = 1010,
    NXT_WEBSOCKET_CR_INTERNAL_SERVER_ERROR  = 1011,
    NXT_WEBSOCKET_CR_TLS_HANDSHAKE_FAILED   = 1015,
};


#endif /* _NXT_WEBSOCKET_HEADER_H_INCLUDED_ */
