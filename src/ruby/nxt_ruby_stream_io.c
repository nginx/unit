
/*
 * Copyright (C) Alexander Borisov
 * Copyright (C) NGINX, Inc.
 */

#include <ruby/nxt_ruby.h>
#include <nxt_unit.h>


static VALUE nxt_ruby_stream_io_new(VALUE class, VALUE wrap);
static VALUE nxt_ruby_stream_io_initialize(int argc, VALUE *argv, VALUE self);
static VALUE nxt_ruby_stream_io_gets(VALUE obj, VALUE args);
static VALUE nxt_ruby_stream_io_each(VALUE obj, VALUE args);
static VALUE nxt_ruby_stream_io_read(VALUE obj, VALUE args);
static VALUE nxt_ruby_stream_io_rewind(VALUE obj, VALUE args);
static VALUE nxt_ruby_stream_io_puts(VALUE obj, VALUE args);
static VALUE nxt_ruby_stream_io_write(VALUE obj, VALUE args);
nxt_inline long nxt_ruby_stream_io_s_write(nxt_ruby_run_ctx_t *run_ctx,
    VALUE val);
static VALUE nxt_ruby_stream_io_flush(VALUE obj, VALUE args);


VALUE
nxt_ruby_stream_io_input_init(void)
{
    VALUE  stream_io;

    stream_io = rb_define_class("NGINX_Unit_Stream_IO_Read", rb_cData);

    rb_gc_register_address(&stream_io);

    rb_define_singleton_method(stream_io, "new", nxt_ruby_stream_io_new, 1);
    rb_define_method(stream_io, "initialize",
                     nxt_ruby_stream_io_initialize, -1);
    rb_define_method(stream_io, "gets", nxt_ruby_stream_io_gets, 0);
    rb_define_method(stream_io, "each", nxt_ruby_stream_io_each, 0);
    rb_define_method(stream_io, "read", nxt_ruby_stream_io_read, -2);
    rb_define_method(stream_io, "rewind", nxt_ruby_stream_io_rewind, 0);

    return stream_io;
}


VALUE
nxt_ruby_stream_io_error_init(void)
{
    VALUE  stream_io;

    stream_io = rb_define_class("NGINX_Unit_Stream_IO_Error", rb_cData);

    rb_gc_register_address(&stream_io);

    rb_define_singleton_method(stream_io, "new", nxt_ruby_stream_io_new, 1);
    rb_define_method(stream_io, "initialize",
                     nxt_ruby_stream_io_initialize, -1);
    rb_define_method(stream_io, "puts", nxt_ruby_stream_io_puts, -2);
    rb_define_method(stream_io, "write", nxt_ruby_stream_io_write, -2);
    rb_define_method(stream_io, "flush", nxt_ruby_stream_io_flush, 0);

    return stream_io;
}


static VALUE
nxt_ruby_stream_io_new(VALUE class, VALUE wrap)
{
    VALUE               self;
    nxt_ruby_run_ctx_t  *run_ctx;

    Data_Get_Struct(wrap, nxt_ruby_run_ctx_t, run_ctx);
    self = Data_Wrap_Struct(class, 0, 0, run_ctx);

    rb_obj_call_init(self, 0, NULL);

    return self;
}


static VALUE
nxt_ruby_stream_io_initialize(int argc, VALUE *argv, VALUE self)
{
    return self;
}


static VALUE
nxt_ruby_stream_io_gets(VALUE obj, VALUE args)
{
    VALUE                    buf;
    char                     *p;
    size_t                   size, b_size;
    nxt_unit_buf_t           *b;
    nxt_ruby_run_ctx_t       *run_ctx;
    nxt_unit_request_info_t  *req;

    Data_Get_Struct(obj, nxt_ruby_run_ctx_t, run_ctx);

    req = run_ctx->req;

    if (req->content_length == 0) {
        return Qnil;
    }

    size = 0;

    for (b = req->content_buf; b; b = nxt_unit_buf_next(b)) {
        b_size = b->end - b->free;
        p = memchr(b->free, '\n', b_size);

        if (p != NULL) {
            p++;
            size += p - b->free;
            break;
        }

        size += b_size;
    }

    buf = rb_str_buf_new(size);

    if (buf == Qnil) {
        return Qnil;
    }

    size = nxt_unit_request_read(req, RSTRING_PTR(buf), size);

    rb_str_set_len(buf, size);

    return buf;
}


static VALUE
nxt_ruby_stream_io_each(VALUE obj, VALUE args)
{
    VALUE  chunk;

    if (rb_block_given_p() == 0) {
        rb_raise(rb_eArgError, "Expected block on rack.input 'each' method");
    }

    for ( ;; ) {
        chunk = nxt_ruby_stream_io_gets(obj, Qnil);

        if (chunk == Qnil) {
            return Qnil;
        }

        rb_yield(chunk);
    }

    return Qnil;
}


static VALUE
nxt_ruby_stream_io_read(VALUE obj, VALUE args)
{
    VALUE                buf;
    long                 copy_size, u_size;
    nxt_ruby_run_ctx_t  *run_ctx;

    Data_Get_Struct(obj, nxt_ruby_run_ctx_t, run_ctx);

    copy_size = run_ctx->req->content_length;

    if (RARRAY_LEN(args) > 0 && TYPE(RARRAY_PTR(args)[0]) == T_FIXNUM) {
        u_size = NUM2LONG(RARRAY_PTR(args)[0]);

        if (u_size < 0 || copy_size == 0) {
            return Qnil;
        }

        if (copy_size > u_size) {
            copy_size = u_size;
        }
    }

    if (copy_size == 0) {
        return rb_str_new_cstr("");
    }

    buf = rb_str_buf_new(copy_size);

    if (nxt_slow_path(buf == Qnil)) {
        return Qnil;
    }

    copy_size = nxt_unit_request_read(run_ctx->req, RSTRING_PTR(buf),
                                      copy_size);

    if (RARRAY_LEN(args) > 1 && TYPE(RARRAY_PTR(args)[1]) == T_STRING) {

        rb_str_set_len(RARRAY_PTR(args)[1], 0);
        rb_str_cat(RARRAY_PTR(args)[1], RSTRING_PTR(buf), copy_size);
    }

    rb_str_set_len(buf, copy_size);

    return buf;
}


static VALUE
nxt_ruby_stream_io_rewind(VALUE obj, VALUE args)
{
    return Qnil;
}


static VALUE
nxt_ruby_stream_io_puts(VALUE obj, VALUE args)
{
    nxt_ruby_run_ctx_t  *run_ctx;

    if (RARRAY_LEN(args) != 1) {
        return Qnil;
    }

    Data_Get_Struct(obj, nxt_ruby_run_ctx_t, run_ctx);

    nxt_ruby_stream_io_s_write(run_ctx, RARRAY_PTR(args)[0]);

    return Qnil;
}


static VALUE
nxt_ruby_stream_io_write(VALUE obj, VALUE args)
{
    long                len;
    nxt_ruby_run_ctx_t  *run_ctx;

    if (RARRAY_LEN(args) != 1) {
        return Qnil;
    }

    Data_Get_Struct(obj, nxt_ruby_run_ctx_t, run_ctx);

    len = nxt_ruby_stream_io_s_write(run_ctx, RARRAY_PTR(args)[0]);

    return LONG2FIX(len);
}


nxt_inline long
nxt_ruby_stream_io_s_write(nxt_ruby_run_ctx_t *run_ctx, VALUE val)
{
    if (nxt_slow_path(val == Qnil)) {
        return 0;
    }

    if (TYPE(val) != T_STRING) {
        val = rb_funcall(val, rb_intern("to_s"), 0);

        if (TYPE(val) != T_STRING) {
            return 0;
        }
    }

    nxt_unit_req_error(run_ctx->req, "Ruby: %s", RSTRING_PTR(val));

    return RSTRING_LEN(val);
}


static VALUE
nxt_ruby_stream_io_flush(VALUE obj, VALUE args)
{
    return Qnil;
}
