
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


typedef struct {
    nxt_task_t      *task;
    nxt_app_rmsg_t  *rmsg;
    nxt_app_wmsg_t  *wmsg;

    size_t          body_preread_size;
} nxt_ruby_run_ctx_t;


VALUE nxt_ruby_stream_io_input_init(void);
VALUE nxt_ruby_stream_io_error_init(void);

#endif /* _NXT_RUBY_H_INCLUDED_ */
