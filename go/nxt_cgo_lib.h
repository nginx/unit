
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CGO_LIB_H_INCLUDED_
#define _NXT_CGO_LIB_H_INCLUDED_


#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct {
    int  length;
    char  *start;
} nxt_cgo_str_t;

int nxt_cgo_run(uintptr_t handler);

int nxt_cgo_response_create(uintptr_t req, int code, int fields,
    uint32_t fields_size);

int nxt_cgo_response_add_field(uintptr_t req, uintptr_t name, uint8_t name_len,
    uintptr_t value, uint32_t value_len);

int nxt_cgo_response_send(uintptr_t req);

ssize_t nxt_cgo_response_write(uintptr_t req, uintptr_t src, uint32_t len);

ssize_t nxt_cgo_request_read(uintptr_t req, uintptr_t dst, uint32_t dst_len);

int nxt_cgo_request_close(uintptr_t req);

void nxt_cgo_request_done(uintptr_t req, int res);

void nxt_cgo_warn(uintptr_t msg, uint32_t msg_len);

#endif /* _NXT_CGO_LIB_H_INCLUDED_ */
