
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_websocket.h>
#include <nxt_websocket_header.h>


nxt_inline uint16_t
nxt_ntoh16(const uint8_t *b)
{
    return ((uint16_t) b[0]) << 8 | ((uint16_t) b[1]);
}


nxt_inline void
nxt_hton16(uint8_t *b, uint16_t v)
{
    b[0] = (v >> 8);
    b[1] = (v & 0xFFu);
}


nxt_inline uint64_t
nxt_ntoh64(const uint8_t *b)
{
    return  ((uint64_t) b[0]) << 56
          | ((uint64_t) b[1]) << 48
          | ((uint64_t) b[2]) << 40
          | ((uint64_t) b[3]) << 32
          | ((uint64_t) b[4]) << 24
          | ((uint64_t) b[5]) << 16
          | ((uint64_t) b[6]) << 8
          | ((uint64_t) b[7]);
}


nxt_inline void
nxt_hton64(uint8_t *b, uint64_t v)
{
    b[0] = (v >> 56);
    b[1] = (v >> 48) & 0xFFu;
    b[2] = (v >> 40) & 0xFFu;
    b[3] = (v >> 32) & 0xFFu;
    b[4] = (v >> 24) & 0xFFu;
    b[5] = (v >> 16) & 0xFFu;
    b[6] = (v >>  8) & 0xFFu;
    b[7] =  v        & 0xFFu;
}


size_t
nxt_websocket_frame_header_size(const void *data)
{
    size_t                        res;
    uint64_t                      p;
    const nxt_websocket_header_t  *h;

    h = data;
    p = h->payload_len;

    res = 2;

    if (p == 126) {
        res += 2;
    } else if (p == 127) {
        res += 8;
    }

    if (h->mask) {
        res += 4;
    }

    return res;
}


uint64_t
nxt_websocket_frame_payload_len(const void *data)
{
    uint64_t                      p;
    const nxt_websocket_header_t  *h;

    h = data;
    p = h->payload_len;

    if (p == 126) {
        p = nxt_ntoh16(h->payload_len_);
    } else if (p == 127) {
        p = nxt_ntoh64(h->payload_len_);
    }

    return p;
}


void *
nxt_websocket_frame_init(void *data, uint64_t payload_len)
{
    uint8_t                 *p;
    nxt_websocket_header_t  *h;

    h = data;
    p = data;

    if (payload_len < 126) {
        h->payload_len = payload_len;
        return p + 2;
    }

    if (payload_len < 65536) {
        h->payload_len = 126;
        nxt_hton16(h->payload_len_, payload_len);
        return p + 4;
    }

    h->payload_len = 127;
    nxt_hton64(h->payload_len_, payload_len);
    return p + 10;
}
