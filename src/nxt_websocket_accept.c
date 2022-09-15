
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_websocket.h>
#include <nxt_sha1.h>


static void
nxt_websocket_base64_encode(u_char *d, const uint8_t *s, size_t len)
{
    u_char               c0, c1, c2;
    static const u_char  basis[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    while (len > 2) {
        c0 = s[0];
        c1 = s[1];
        c2 = s[2];

        *d++ = basis[c0 >> 2];
        *d++ = basis[((c0 & 0x03) << 4) | (c1 >> 4)];
        *d++ = basis[((c1 & 0x0f) << 2) | (c2 >> 6)];
        *d++ = basis[c2 & 0x3f];

        s += 3;
        len -= 3;
    }

    if (len > 0) {
        c0 = s[0];
        *d++ = basis[c0 >> 2];

        if (len == 1) {
            *d++ = basis[(c0 & 0x03) << 4];
            *d++ = '=';
            *d++ = '=';

        } else {
            c1 = s[1];

            *d++ = basis[((c0 & 0x03) << 4) | (c1 >> 4)];
            *d++ = basis[(c1 & 0x0f) << 2];

            *d++ = '=';
        }
    }
}


void
nxt_websocket_accept(u_char *accept, const void *key)
{
    u_char             bin_accept[20];
    nxt_sha1_t         ctx;
    static const char  accept_guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    nxt_sha1_init(&ctx);
    nxt_sha1_update(&ctx, key, 24);
    nxt_sha1_update(&ctx, accept_guid, nxt_length(accept_guid));
    nxt_sha1_final(bin_accept, &ctx);

    nxt_websocket_base64_encode(accept, bin_accept, sizeof(bin_accept));
}


