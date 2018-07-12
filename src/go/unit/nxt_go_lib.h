
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_GO_LIB_H_INCLUDED_
#define _NXT_GO_LIB_H_INCLUDED_


#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
    int  length;
    char  *start;
} nxt_go_str_t;

typedef uintptr_t nxt_go_request_t;

int nxt_go_response_write(nxt_go_request_t r, uintptr_t buf, size_t len);

void nxt_go_response_flush(nxt_go_request_t r);

int nxt_go_request_read(nxt_go_request_t r, uintptr_t dst, size_t dst_len);

int nxt_go_request_close(nxt_go_request_t r);

int nxt_go_request_done(nxt_go_request_t r);

void nxt_go_ready(uint32_t stream);

nxt_go_request_t nxt_go_process_port_msg(uintptr_t buf, size_t buf_len,
    uintptr_t oob, size_t oob_len);

const char *nxt_go_version();


#endif /* _NXT_GO_LIB_H_INCLUDED_ */
