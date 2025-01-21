
/*
 * Copyright (C) Alexander Borisov
 * Copyright (C) NGINX, Inc.
 */

#include <ruby/nxt_ruby.h>
#include <nxt_unit.h>


static VALUE nxt_ruby_stream_io_new(VALUE class, VALUE arg);
static VALUE nxt_ruby_stream_io_initialize(int argc, VALUE *argv, VALUE self);
static VALUE nxt_ruby_stream_io_gets(VALUE obj);
static VALUE nxt_ruby_stream_io_each(VALUE obj);
static VALUE nxt_ruby_stream_io_read(VALUE obj, VALUE args);
static VALUE nxt_ruby_stream_io_rewind(VALUE obj);
static VALUE nxt_ruby_stream_io_puts(VALUE obj, VALUE args);
static VALUE nxt_ruby_stream_io_write(VALUE obj, VALUE args);
nxt_inline long nxt_ruby_stream_io_s_write(nxt_ruby_ctx_t *rctx, VALUE val);
static VALUE nxt_ruby_stream_io_flush(VALUE obj);
static VALUE nxt_ruby_stream_io_close(VALUE obj);
nxt_inline size_t nxt_ruby_dt_dsize_rctx(const void *arg);


static const rb_data_type_t  nxt_rctx_dt = {
    .wrap_struct_name  = "rctx",
    .function  = {
        .dsize         = nxt_ruby_dt_dsize_rctx,
    },
};


nxt_inline size_t
nxt_ruby_dt_dsize_rctx(const void *arg)
{
    const nxt_ruby_ctx_t  *rctx = arg;

    return sizeof(*rctx);
}


VALUE
nxt_ruby_stream_io_input_init(void)
{
    VALUE  stream_io;

    stream_io = rb_define_class("NGINX_Unit_Stream_IO_Read", rb_cObject);

    rb_undef_alloc_func(stream_io);

    rb_gc_register_address(&stream_io);

    rb_define_singleton_method(stream_io, "new", nxt_ruby_stream_io_new, 1);
    rb_define_method(stream_io, "initialize",
                     nxt_ruby_stream_io_initialize, -1);
    rb_define_method(stream_io, "gets", nxt_ruby_stream_io_gets, 0);
    rb_define_method(stream_io, "each", nxt_ruby_stream_io_each, 0);
    rb_define_method(stream_io, "read", nxt_ruby_stream_io_read, -2);
    rb_define_method(stream_io, "rewind", nxt_ruby_stream_io_rewind, 0);
    rb_define_method(stream_io, "close", nxt_ruby_stream_io_close, 0);

    return stream_io;
}


VALUE
nxt_ruby_stream_io_error_init(void)
{
    VALUE  stream_io;

    stream_io = rb_define_class("NGINX_Unit_Stream_IO_Error", rb_cObject);

    rb_undef_alloc_func(stream_io);

    rb_gc_register_address(&stream_io);

    rb_define_singleton_method(stream_io, "new", nxt_ruby_stream_io_new, 1);
    rb_define_method(stream_io, "initialize",
                     nxt_ruby_stream_io_initialize, -1);
    rb_define_method(stream_io, "puts", nxt_ruby_stream_io_puts, -2);
    rb_define_method(stream_io, "write", nxt_ruby_stream_io_write, -2);
    rb_define_method(stream_io, "flush", nxt_ruby_stream_io_flush, 0);
    rb_define_method(stream_io, "close", nxt_ruby_stream_io_close, 0);

    return stream_io;
}


static VALUE
nxt_ruby_stream_io_new(VALUE class, VALUE arg)
{
    VALUE  self;

    self = TypedData_Wrap_Struct(class, &nxt_rctx_dt, (void *)(uintptr_t)arg);

    rb_obj_call_init(self, 0, NULL);

    return self;
}


static VALUE
nxt_ruby_stream_io_initialize(int argc, VALUE *argv, VALUE self)
{
    return self;
}


static VALUE
nxt_ruby_stream_io_gets(VALUE obj)
{
    VALUE                    buf;
    ssize_t                  res;
    nxt_ruby_ctx_t           *rctx;
    nxt_unit_request_info_t  *req;

    TypedData_Get_Struct(obj, nxt_ruby_ctx_t, &nxt_rctx_dt, rctx);
    req = rctx->req;

    if (req->content_length == 0) {
        return Qnil;
    }

    res = nxt_unit_request_readline_size(req, SSIZE_MAX);
    if (nxt_slow_path(res < 0)) {
        return Qnil;
    }

    buf = rb_str_buf_new(res);

    if (nxt_slow_path(buf == Qnil)) {
        return Qnil;
    }

    res = nxt_unit_request_read(req, RSTRING_PTR(buf), res);

    rb_str_set_len(buf, res);

    return buf;
}


static VALUE
nxt_ruby_stream_io_each(VALUE obj)
{
    VALUE  chunk;

    if (rb_block_given_p() == 0) {
        rb_raise(rb_eArgError, "Expected block on rack.input 'each' method");
    }

    for ( ;; ) {
        chunk = nxt_ruby_stream_io_gets(obj);

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
    VALUE           buf;
    long            copy_size, u_size;
    nxt_ruby_ctx_t  *rctx;

    TypedData_Get_Struct(obj, nxt_ruby_ctx_t, &nxt_rctx_dt, rctx);

    copy_size = rctx->req->content_length;

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

    copy_size = nxt_unit_request_read(rctx->req, RSTRING_PTR(buf), copy_size);

    if (RARRAY_LEN(args) > 1 && TYPE(RARRAY_PTR(args)[1]) == T_STRING) {

        rb_str_set_len(RARRAY_PTR(args)[1], 0);
        rb_str_cat(RARRAY_PTR(args)[1], RSTRING_PTR(buf), copy_size);
    }

    rb_str_set_len(buf, copy_size);

    return buf;
}


static VALUE
nxt_ruby_stream_io_rewind(VALUE obj)
{
    return Qnil;
}


static VALUE
nxt_ruby_stream_io_puts(VALUE obj, VALUE args)
{
    nxt_ruby_ctx_t  *rctx;

    if (RARRAY_LEN(args) != 1) {
        return Qnil;
    }

    TypedData_Get_Struct(obj, nxt_ruby_ctx_t, &nxt_rctx_dt, rctx);

    nxt_ruby_stream_io_s_write(rctx, RARRAY_PTR(args)[0]);

    return Qnil;
}


static VALUE
nxt_ruby_stream_io_write(VALUE obj, VALUE args)
{
    long            len;
    nxt_ruby_ctx_t  *rctx;

    if (RARRAY_LEN(args) != 1) {
        return Qnil;
    }

    TypedData_Get_Struct(obj, nxt_ruby_ctx_t, &nxt_rctx_dt, rctx);

    len = nxt_ruby_stream_io_s_write(rctx, RARRAY_PTR(args)[0]);

    return LONG2FIX(len);
}


nxt_inline long
nxt_ruby_stream_io_s_write(nxt_ruby_ctx_t *rctx, VALUE val)
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

    nxt_unit_req_error(rctx->req, "Ruby: %s", RSTRING_PTR(val));

    return RSTRING_LEN(val);
}


static VALUE
nxt_ruby_stream_io_flush(VALUE obj)
{
    return Qnil;
}


static VALUE
nxt_ruby_stream_io_close(VALUE obj)
{
    return Qnil;
}
