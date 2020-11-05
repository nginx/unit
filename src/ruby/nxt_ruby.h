
/*
 * Copyright (C) Alexander Borisov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_RUBY_H_INCLUDED_
#define _NXT_RUBY_H_INCLUDED_


#include <ruby.h>
#include <ruby/io.h>
#include <ruby/encoding.h>
#include <ruby/version.h>

#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_runtime.h>
#include <nxt_application.h>
#include <nxt_unit_typedefs.h>


typedef struct {
    VALUE                    env;
    VALUE                    io_input;
    VALUE                    io_error;
    VALUE                    thread;
    nxt_unit_ctx_t           *ctx;
    nxt_unit_request_info_t  *req;
} nxt_ruby_ctx_t;


VALUE nxt_ruby_stream_io_input_init(void);
VALUE nxt_ruby_stream_io_error_init(void);

#endif /* _NXT_RUBY_H_INCLUDED_ */
