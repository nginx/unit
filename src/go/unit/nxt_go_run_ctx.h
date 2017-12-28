
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_GO_RUN_CTX_H_INCLUDED_
#define _NXT_GO_RUN_CTX_H_INCLUDED_


#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_port_memory_int.h>

#ifndef _NXT_GO_PROCESS_T_DEFINED_
#define _NXT_GO_PROCESS_T_DEFINED_
typedef struct nxt_go_process_s nxt_go_process_t;
#endif

typedef struct nxt_go_msg_s nxt_go_msg_t;

struct nxt_go_msg_s {
    off_t                start_offset;

    nxt_port_msg_t       *port_msg;
    size_t               raw_size;
    size_t               data_size;

    nxt_port_mmap_msg_t  *mmap_msg;
    nxt_port_mmap_msg_t  *end;

    nxt_port_mmap_tracking_msg_t  *tracking;

    nxt_go_msg_t         *next;
};


typedef struct {
    nxt_go_msg_t         msg;

    nxt_go_process_t     *process;
    nxt_port_mmap_msg_t  *wmmap_msg;
    nxt_bool_t           cancelled;

    uint32_t             nrbuf;
    nxt_buf_t            rbuf;

    uint32_t             nwbuf;
    nxt_buf_t            wbuf;
    nxt_port_msg_t       wport_msg;
    char                 wmmap_msg_buf[ sizeof(nxt_port_mmap_msg_t) * 8 ];

    nxt_app_request_t    request;
    uintptr_t            go_request;

    nxt_go_msg_t         *msg_last;

    nxt_port_msg_t       port_msg[];
} nxt_go_run_ctx_t;


void nxt_go_ctx_release_msg(nxt_go_run_ctx_t *ctx, nxt_go_msg_t *msg);

nxt_int_t nxt_go_ctx_init(nxt_go_run_ctx_t *ctx, nxt_port_msg_t *port_msg,
    size_t payload_size);

nxt_int_t nxt_go_ctx_flush(nxt_go_run_ctx_t *ctx, int last);

nxt_int_t nxt_go_ctx_write(nxt_go_run_ctx_t *ctx, void *data, size_t len);

nxt_int_t nxt_go_ctx_read_size(nxt_go_run_ctx_t *ctx, size_t *size);

nxt_int_t nxt_go_ctx_read_str(nxt_go_run_ctx_t *ctx, nxt_str_t *str);

size_t nxt_go_ctx_read_raw(nxt_go_run_ctx_t *ctx, void *dst, size_t size);


#endif /* _NXT_GO_RUN_CTX_H_INCLUDED_ */
