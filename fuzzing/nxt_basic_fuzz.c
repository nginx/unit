/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_sha1.h>
#include <nxt_websocket.h>
#include <nxt_websocket_header.h>

/* DO NOT TRY THIS AT HOME! */
#include <nxt_websocket_accept.c>


#define KMININPUTLENGTH 4
#define KMAXINPUTLENGTH 128


extern int LLVMFuzzerInitialize(int *argc, char ***argv);
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

void nxt_base64_fuzz(const u_char *data, size_t size);
void nxt_djb_hash_fuzz(const u_char *data, size_t size);
void nxt_murmur_hash2_fuzz(const u_char *data, size_t size);
void nxt_parse_fuzz(const u_char *data, size_t size);
void nxt_sha1_fuzz(const u_char *data, size_t size);
void nxt_sha1_update_fuzz(const u_char *data, size_t size);
void nxt_term_fuzz(const u_char *data, size_t size);
void nxt_time_fuzz(const u_char *data, size_t size);
void nxt_uri_fuzz(const u_char *data, size_t size);
void nxt_utf8_fuzz(const u_char *data, size_t size);
void nxt_websocket_base64_fuzz(const u_char *data, size_t size);
void nxt_websocket_frame_fuzz(const u_char *data, size_t size);


extern char  **environ;


int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    if (nxt_lib_start("fuzzing", NULL, &environ) != NXT_OK) {
        return NXT_ERROR;
    }

    return 0;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < KMININPUTLENGTH || size > KMAXINPUTLENGTH) {
        return 0;
    }

    nxt_base64_fuzz(data, size);
    nxt_djb_hash_fuzz(data, size);
    nxt_murmur_hash2_fuzz(data, size);
    nxt_parse_fuzz(data, size);
    nxt_sha1_fuzz(data, size);
    nxt_sha1_update_fuzz(data, size);
    nxt_term_fuzz(data, size);
    nxt_time_fuzz(data, size);
    nxt_uri_fuzz(data, size);
    nxt_utf8_fuzz(data, size);
    nxt_websocket_base64_fuzz(data, size);
    nxt_websocket_frame_fuzz(data, size);

    return 0;
}


void
nxt_base64_fuzz(const u_char *data, size_t size)
{
    u_char   buf[256];
    ssize_t  ret;

    /*
     * Validate base64 data before decoding.
     */
    ret = nxt_base64_decode(NULL, (u_char *)data, size);
    if (ret == NXT_ERROR) {
        return;
    }

    nxt_base64_decode(buf, (u_char *)data, size);
}


void
nxt_djb_hash_fuzz(const u_char *data, size_t size)
{
    nxt_djb_hash(data, size);
    nxt_djb_hash_lowcase(data, size);
}


void
nxt_murmur_hash2_fuzz(const u_char *data, size_t size)
{
    nxt_murmur_hash2(data, size);
    nxt_murmur_hash2_uint32(data);
}


void
nxt_parse_fuzz(const u_char *data, size_t size)
{
    nxt_str_t  input;

    input.start = (u_char *)data;
    input.length = size;

    nxt_int_parse(data, size);
    nxt_size_t_parse(data, size);
    nxt_size_parse(data, size);
    nxt_off_t_parse(data, size);
    nxt_str_int_parse(&input);
    nxt_number_parse(&data, data + size);
}


void
nxt_sha1_fuzz(const u_char *data, size_t size)
{
    u_char      bin_accept[20];
    nxt_sha1_t  ctx;

    nxt_sha1_init(&ctx);
    nxt_sha1_update(&ctx, data, size);
    nxt_sha1_final(bin_accept, &ctx);
}


void
nxt_sha1_update_fuzz(const u_char *data, size_t size)
{
    u_char      bin_accept[20];
    nxt_sha1_t  ctx;

    nxt_sha1_init(&ctx);
    nxt_sha1_update(&ctx, data, size);
    nxt_sha1_update(&ctx, data, size);
    nxt_sha1_final(bin_accept, &ctx);
}


void
nxt_term_fuzz(const u_char *data, size_t size)
{
    nxt_term_parse(data, size, 0);
    nxt_term_parse(data, size, 1);
}


void
nxt_time_fuzz(const u_char *data, size_t size)
{
    nxt_time_parse(data, size);
}


void
nxt_uri_fuzz(const u_char *data, size_t size)
{
    u_char  *dst;

    dst = nxt_zalloc(size * 3);
    if (dst == NULL) {
        return;
    }

    nxt_decode_uri(dst, (u_char *)data, size);
    nxt_decode_uri_plus(dst, (u_char *)data, size);

    nxt_memzero(dst, size * 3);
    nxt_encode_uri(NULL, (u_char *)data, size);
    nxt_encode_uri(dst, (u_char *)data, size);

    nxt_free(dst);
}


void
nxt_utf8_fuzz(const u_char *data, size_t size)
{
    const u_char  *in;

    in = data;
    nxt_utf8_decode(&in, data + size);

    nxt_utf8_casecmp((const u_char *)"ABC АБВ ΑΒΓ",
                    data,
                    nxt_length("ABC АБВ ΑΒΓ"),
                    size);
}


void
nxt_websocket_base64_fuzz(const u_char *data, size_t size)
{
    u_char  *out;

    out = nxt_zalloc(size * 2);
    if (out == NULL) {
        return;
    }

    nxt_websocket_base64_encode(out, data, size);

    nxt_free(out);
}


void
nxt_websocket_frame_fuzz(const u_char *data, size_t size)
{
    u_char  *input;

    /*
     * Resolve overwrites-const-input by using a copy of the data.
     */
    input = nxt_malloc(size);
    if (input == NULL) {
        return;
    }

    nxt_memcpy(input, data, size);

    nxt_websocket_frame_init(input, 0);
    nxt_websocket_frame_header_size(input);
    nxt_websocket_frame_payload_len(input);

    nxt_free(input);
}
