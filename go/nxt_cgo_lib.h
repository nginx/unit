
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CGO_LIB_H_INCLUDED_
#define _NXT_CGO_LIB_H_INCLUDED_


#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <nxt_unit.h>
#include <nxt_unit_request.h>

enum {
    NXT_FIELDS_OFFSET = offsetof(nxt_unit_request_t, fields)
};

int nxt_cgo_run(uintptr_t handler);

ssize_t nxt_cgo_response_write(nxt_unit_request_info_t *req,
    uintptr_t src, uint32_t len);

ssize_t nxt_cgo_request_read(nxt_unit_request_info_t *req,
    uintptr_t dst, uint32_t dst_len);

void nxt_cgo_warn(const char *msg, uint32_t msg_len);
void nxt_cgo_alert(const char *msg, uint32_t msg_len);

#endif /* _NXT_CGO_LIB_H_INCLUDED_ */
