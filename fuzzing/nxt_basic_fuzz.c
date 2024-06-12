/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


#define KMININPUTLENGTH 2
#define KMAXINPUTLENGTH 128


extern int LLVMFuzzerInitialize(int *argc, char ***argv);
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

void nxt_base64_fuzz(const u_char *data, size_t size);
void nxt_term_fuzz(const u_char *data, size_t size);
void nxt_time_fuzz(const u_char *data, size_t size);
void nxt_utf8_fuzz(const u_char *data, size_t size);


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
    nxt_term_fuzz(data, size);
    nxt_time_fuzz(data, size);
    nxt_utf8_fuzz(data, size);

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
nxt_utf8_fuzz(const u_char *data, size_t size)
{
    const u_char  *in;

    in = data;
    nxt_utf8_decode(&in, data + size);
}
