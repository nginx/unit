/*
 * Copyright (C) Alexander Borisov
 * Copyright (C) NGINX, Inc.
 */

#include <ruby/nxt_ruby.h>


#define NXT_RUBY_RACK_API_VERSION_MAJOR  1
#define NXT_RUBY_RACK_API_VERSION_MINOR  3

#define NXT_RUBY_STRINGIZE_HELPER(x)     #x
#define NXT_RUBY_STRINGIZE(x)            NXT_RUBY_STRINGIZE_HELPER(x)

#define NXT_RUBY_LIB_VERSION                                                   \
    NXT_RUBY_STRINGIZE(RUBY_API_VERSION_MAJOR)                                 \
    "." NXT_RUBY_STRINGIZE(RUBY_API_VERSION_MINOR)                             \
    "." NXT_RUBY_STRINGIZE(RUBY_API_VERSION_TEENY)


typedef struct {
    nxt_task_t  *task;
    nxt_str_t   *script;
    VALUE       builder;
} nxt_ruby_rack_init_t;


static nxt_int_t nxt_ruby_init(nxt_task_t *task, nxt_common_app_conf_t *conf);
static VALUE nxt_ruby_init_basic(VALUE arg);
static nxt_int_t nxt_ruby_init_io(nxt_task_t *task);
static VALUE nxt_ruby_rack_init(nxt_ruby_rack_init_t *rack_init);

static VALUE nxt_ruby_require_rubygems(VALUE arg);
static VALUE nxt_ruby_bundler_setup(VALUE arg);
static VALUE nxt_ruby_require_rack(VALUE arg);
static VALUE nxt_ruby_rack_parse_script(VALUE ctx);
static VALUE nxt_ruby_rack_env_create(VALUE arg);
static nxt_int_t nxt_ruby_run(nxt_task_t *task, nxt_app_rmsg_t *rmsg,
    nxt_app_wmsg_t *wmsg);

static VALUE nxt_ruby_rack_app_run(VALUE arg);
static nxt_int_t nxt_ruby_read_request(nxt_ruby_run_ctx_t *run_ctx,
    VALUE hash_env);
nxt_inline nxt_int_t nxt_ruby_read_add_env(nxt_task_t *task,
    nxt_app_rmsg_t *rmsg, VALUE hash_env, const char *name, nxt_str_t *str);
static nxt_int_t nxt_ruby_rack_result_status(VALUE result);
nxt_inline nxt_int_t nxt_ruby_write(nxt_task_t *task, nxt_app_wmsg_t *wmsg,
    const u_char *data, size_t len, nxt_bool_t flush, nxt_bool_t last);
static nxt_int_t nxt_ruby_rack_result_headers(VALUE result);
static int nxt_ruby_hash_foreach(VALUE r_key, VALUE r_value, VALUE arg);
static nxt_int_t nxt_ruby_head_send_part(const char *key, size_t key_size,
    const char *value, size_t value_size);
static nxt_int_t nxt_ruby_rack_result_body(VALUE result);
static nxt_int_t nxt_ruby_rack_result_body_file_write(VALUE filepath);
static VALUE nxt_ruby_rack_result_body_each(VALUE body);

static void nxt_ruby_exception_log(nxt_task_t *task, uint32_t level,
    const char *desc);

static void nxt_ruby_atexit(nxt_task_t *task);


static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};

static VALUE               nxt_ruby_rackup;
static VALUE               nxt_ruby_call;
static VALUE               nxt_ruby_env;
static VALUE               nxt_ruby_io_input;
static VALUE               nxt_ruby_io_error;
static nxt_ruby_run_ctx_t  nxt_ruby_run_ctx;

NXT_EXPORT nxt_application_module_t  nxt_app_module = {
    sizeof(compat),
    compat,
    nxt_string("ruby"),
    ruby_version,
    nxt_ruby_init,
    nxt_ruby_run,
    nxt_ruby_atexit,
};


static nxt_int_t
nxt_ruby_init(nxt_task_t *task, nxt_common_app_conf_t *conf)
{
    int                   state;
    VALUE                 dummy, res;
    nxt_ruby_rack_init_t  rack_init;

    ruby_init();
    Init_stack(&dummy);
    ruby_init_loadpath();
    ruby_script("NGINX_Unit");

    rack_init.task = task;
    rack_init.script = &conf->u.ruby.script;

    res = rb_protect(nxt_ruby_init_basic,
                     (VALUE) (uintptr_t) &rack_init, &state);
    if (nxt_slow_path(res == Qnil || state != 0)) {
        nxt_ruby_exception_log(task, NXT_LOG_ALERT,
                               "Failed to init basic variables");
        return NXT_ERROR;
    }

    nxt_ruby_rackup = nxt_ruby_rack_init(&rack_init);
    if (nxt_slow_path(nxt_ruby_rackup == Qnil)) {
        return NXT_ERROR;
    }

    nxt_ruby_call = rb_intern("call");
    if (nxt_slow_path(nxt_ruby_call == Qnil)) {
        nxt_alert(task, "Ruby: Unable to find rack entry point");

        return NXT_ERROR;
    }

    nxt_ruby_env = rb_protect(nxt_ruby_rack_env_create, Qnil, &state);
    if (nxt_slow_path(state != 0)) {
        nxt_ruby_exception_log(task, NXT_LOG_ALERT,
                               "Failed to create 'environ' variable");
        return NXT_ERROR;
    }

    rb_gc_register_address(&nxt_ruby_rackup);
    rb_gc_register_address(&nxt_ruby_call);
    rb_gc_register_address(&nxt_ruby_env);

    return NXT_OK;
}


static VALUE
nxt_ruby_init_basic(VALUE arg)
{
    int                   state;
    nxt_int_t             rc;
    nxt_ruby_rack_init_t  *rack_init;

    rack_init = (nxt_ruby_rack_init_t *) (uintptr_t) arg;

    state = rb_enc_find_index("encdb");
    if (nxt_slow_path(state == 0)) {
        nxt_alert(rack_init->task,
                  "Ruby: Failed to find encoding index 'encdb'");

        return Qnil;
    }

    rb_funcall(rb_cObject, rb_intern("require"), 1,
               rb_str_new2("enc/trans/transdb"));

    rc = nxt_ruby_init_io(rack_init->task);
    if (nxt_slow_path(rc != NXT_OK)) {
        return Qnil;
    }

    return arg;
}


static nxt_int_t
nxt_ruby_init_io(nxt_task_t *task)
{
    VALUE  rb, io_input, io_error;

    io_input = nxt_ruby_stream_io_input_init();
    rb = Data_Wrap_Struct(io_input, 0, 0, &nxt_ruby_run_ctx);

    nxt_ruby_io_input = rb_funcall(io_input, rb_intern("new"), 1, rb);
    if (nxt_slow_path(nxt_ruby_io_input == Qnil)) {
        nxt_alert(task, "Ruby: Failed to create environment 'rack.input' var");

        return NXT_ERROR;
    }

    io_error = nxt_ruby_stream_io_error_init();
    rb = Data_Wrap_Struct(io_error, 0, 0, &nxt_ruby_run_ctx);

    nxt_ruby_io_error = rb_funcall(io_error, rb_intern("new"), 1, rb);
    if (nxt_slow_path(nxt_ruby_io_error == Qnil)) {
        nxt_alert(task, "Ruby: Failed to create environment 'rack.error' var");

        return NXT_ERROR;
    }

    rb_gc_register_address(&nxt_ruby_io_input);
    rb_gc_register_address(&nxt_ruby_io_error);

    return NXT_OK;
}


static VALUE
nxt_ruby_rack_init(nxt_ruby_rack_init_t *rack_init)
{
    int    state;
    VALUE  rack, rackup, err;

    rb_protect(nxt_ruby_require_rubygems, Qnil, &state);
    if (nxt_slow_path(state != 0)) {
        nxt_ruby_exception_log(rack_init->task, NXT_LOG_ALERT,
                               "Failed to require 'rubygems' package");
        return Qnil;
    }

    rb_protect(nxt_ruby_bundler_setup, Qnil, &state);
    if (state != 0) {
        err = rb_errinfo();

        if (rb_obj_is_kind_of(err, rb_eLoadError) == Qfalse) {
            nxt_ruby_exception_log(rack_init->task, NXT_LOG_ALERT,
                                   "Failed to require 'bundler/setup' package");
            return Qnil;
        }

        rb_set_errinfo(Qnil);
    }

    rb_protect(nxt_ruby_require_rack, Qnil, &state);
    if (nxt_slow_path(state != 0)) {
        nxt_ruby_exception_log(rack_init->task, NXT_LOG_ALERT,
                               "Failed to require 'rack' package");
        return Qnil;
    }

    rack = rb_const_get(rb_cObject, rb_intern("Rack"));
    rack_init->builder = rb_const_get(rack, rb_intern("Builder"));

    rackup = rb_protect(nxt_ruby_rack_parse_script,
                        (VALUE) (uintptr_t) rack_init, &state);
    if (nxt_slow_path(TYPE(rackup) != T_ARRAY || state != 0)) {
        nxt_ruby_exception_log(rack_init->task, NXT_LOG_ALERT,
                               "Failed to parse rack script");
        return Qnil;
    }

    if (nxt_slow_path(RARRAY_LEN(rackup) < 1)) {
        nxt_alert(rack_init->task, "Ruby: Invalid rack config file");
        return Qnil;
    }

    return RARRAY_PTR(rackup)[0];
}


static VALUE
nxt_ruby_require_rubygems(VALUE arg)
{
    return rb_funcall(rb_cObject, rb_intern("require"), 1,
                      rb_str_new2("rubygems"));
}


static VALUE
nxt_ruby_bundler_setup(VALUE arg)
{
    return rb_funcall(rb_cObject, rb_intern("require"), 1,
                      rb_str_new2("bundler/setup"));
}


static VALUE
nxt_ruby_require_rack(VALUE arg)
{
    return rb_funcall(rb_cObject, rb_intern("require"), 1, rb_str_new2("rack"));
}


static VALUE
nxt_ruby_rack_parse_script(VALUE ctx)
{
    VALUE                 script, res;
    nxt_ruby_rack_init_t  *rack_init;

    rack_init = (nxt_ruby_rack_init_t *) (uintptr_t) ctx;

    script = rb_str_new((const char *) rack_init->script->start,
                        (long) rack_init->script->length);

    res = rb_funcall(rack_init->builder, rb_intern("parse_file"), 1, script);

    rb_str_free(script);

    return res;
}


static VALUE
nxt_ruby_rack_env_create(VALUE arg)
{
    VALUE  hash_env, version;

    hash_env = rb_hash_new();

    rb_hash_aset(hash_env, rb_str_new2("SERVER_SOFTWARE"),
                 rb_str_new((const char *) nxt_server.start,
                            (long) nxt_server.length));

    version = rb_ary_new();

    rb_ary_push(version, UINT2NUM(NXT_RUBY_RACK_API_VERSION_MAJOR));
    rb_ary_push(version, UINT2NUM(NXT_RUBY_RACK_API_VERSION_MINOR));

    rb_hash_aset(hash_env, rb_str_new2("rack.version"), version);
    rb_hash_aset(hash_env, rb_str_new2("rack.url_scheme"), rb_str_new2("http"));
    rb_hash_aset(hash_env, rb_str_new2("rack.input"), nxt_ruby_io_input);
    rb_hash_aset(hash_env, rb_str_new2("rack.errors"), nxt_ruby_io_error);
    rb_hash_aset(hash_env, rb_str_new2("rack.multithread"), Qfalse);
    rb_hash_aset(hash_env, rb_str_new2("rack.multiprocess"), Qtrue);
    rb_hash_aset(hash_env, rb_str_new2("rack.run_once"), Qfalse);
    rb_hash_aset(hash_env, rb_str_new2("rack.hijack?"), Qfalse);
    rb_hash_aset(hash_env, rb_str_new2("rack.hijack"), Qnil);
    rb_hash_aset(hash_env, rb_str_new2("rack.hijack_io"), Qnil);

    return hash_env;
}


static nxt_int_t
nxt_ruby_run(nxt_task_t *task, nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *wmsg)
{
    int    state;
    VALUE  res;

    nxt_ruby_run_ctx.task = task;
    nxt_ruby_run_ctx.rmsg = rmsg;
    nxt_ruby_run_ctx.wmsg = wmsg;

    res = rb_protect(nxt_ruby_rack_app_run, Qnil, &state);
    if (nxt_slow_path(state != 0)) {
        nxt_ruby_exception_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                               "Failed to run ruby script");
        return NXT_ERROR;
    }

    if (nxt_slow_path(res == Qnil)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static VALUE
nxt_ruby_rack_app_run(VALUE arg)
{
    VALUE      env, result;
    nxt_int_t  rc;

    env = rb_hash_dup(nxt_ruby_env);

    rc = nxt_ruby_read_request(&nxt_ruby_run_ctx, env);
    if (nxt_slow_path(rc != NXT_OK)) {
        nxt_alert(nxt_ruby_run_ctx.task,
                  "Ruby: Failed to process incoming request");

        goto fail;
    }

    result = rb_funcall(nxt_ruby_rackup, nxt_ruby_call, 1, env);
    if (nxt_slow_path(TYPE(result) != T_ARRAY)) {
        nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                "Ruby: Invalid response format from application");

        goto fail;
    }

    if (nxt_slow_path(RARRAY_LEN(result) != 3)) {
        nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                "Ruby: Invalid response format from application. "
                "Need 3 entries [Status, Headers, Body]");

        goto fail;
    }

    rc = nxt_ruby_rack_result_status(result);
    if (nxt_slow_path(rc != NXT_OK)) {
        goto fail;
    }

    rc = nxt_ruby_rack_result_headers(result);
    if (nxt_slow_path(rc != NXT_OK)) {
        goto fail;
    }

    rc = nxt_ruby_rack_result_body(result);
    if (nxt_slow_path(rc != NXT_OK)) {
        goto fail;
    }

    rc = nxt_app_msg_flush(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg, 1);
    if (nxt_slow_path(rc != NXT_OK)) {
        goto fail;
    }

    rb_hash_delete(env, rb_obj_id(env));

    return result;

fail:

    rb_hash_delete(env, rb_obj_id(env));

    return Qnil;
}


static nxt_int_t
nxt_ruby_read_request(nxt_ruby_run_ctx_t *run_ctx, VALUE hash_env)
{
    u_char          *colon;
    size_t          query_size;
    nxt_int_t       rc;
    nxt_str_t       str, value, path, target;
    nxt_str_t       host, server_name, server_port;
    nxt_task_t      *task;
    nxt_app_rmsg_t  *rmsg;

    static nxt_str_t  def_host = nxt_string("localhost");
    static nxt_str_t  def_port = nxt_string("80");

    task = run_ctx->task;
    rmsg = run_ctx->rmsg;

    rc = nxt_ruby_read_add_env(task, rmsg, hash_env, "REQUEST_METHOD", &str);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_ruby_read_add_env(task, rmsg, hash_env, "REQUEST_URI", &target);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_app_msg_read_str(task, rmsg, &path);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_app_msg_read_size(task, rmsg, &query_size);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    if (path.start == NULL || path.length == 0) {
        path = target;
    }

    rb_hash_aset(hash_env, rb_str_new2("PATH_INFO"),
                 rb_str_new((const char *) path.start, (long) path.length));

    if (query_size > 0) {
        query_size--;

        if (nxt_slow_path(target.length < query_size)) {
            return NXT_ERROR;
        }

        str.start  = &target.start[query_size];
        str.length = target.length - query_size;

        rb_hash_aset(hash_env, rb_str_new2("QUERY_STRING"),
                     rb_str_new((const char *) str.start, (long) str.length));
    }

    rc = nxt_ruby_read_add_env(task, rmsg, hash_env, "SERVER_PROTOCOL", &str);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_ruby_read_add_env(task, rmsg, hash_env, "REMOTE_ADDR", &str);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_ruby_read_add_env(task, rmsg, hash_env, "SERVER_ADDR", &str);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_app_msg_read_str(task, rmsg, &host);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    if (host.length == 0) {
        host = def_host;
    }

    colon = nxt_memchr(host.start, ':', host.length);
    server_name = host;

    if (colon != NULL) {
        server_name.length = colon - host.start;

        server_port.start = colon + 1;
        server_port.length = host.length - server_name.length - 1;

    } else {
        server_port = def_port;
    }

    rb_hash_aset(hash_env, rb_str_new2("SERVER_NAME"),
                 rb_str_new((const char *) server_name.start,
                            (long) server_name.length));

    rb_hash_aset(hash_env, rb_str_new2("SERVER_PORT"),
                 rb_str_new((const char *) server_port.start,
                            (long) server_port.length));

    rc = nxt_ruby_read_add_env(task, rmsg, hash_env, "CONTENT_TYPE", &str);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_ruby_read_add_env(task, rmsg, hash_env, "CONTENT_LENGTH", &str);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    for ( ;; ) {
        rc = nxt_app_msg_read_str(task, rmsg, &str);
        if (nxt_slow_path(rc != NXT_OK)) {
            return NXT_ERROR;
        }

        if (nxt_slow_path(str.length == 0)) {
            break;
        }

        rc = nxt_app_msg_read_str(task, rmsg, &value);
        if (nxt_slow_path(rc != NXT_OK)) {
            return NXT_ERROR;
        }

        rb_hash_aset(hash_env,
                     rb_str_new((char *) str.start, (long) str.length),
                     rb_str_new((const char *) value.start,
                                (long) value.length));
    }

    rc = nxt_app_msg_read_size(task, rmsg, &run_ctx->body_preread_size);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_inline nxt_int_t
nxt_ruby_read_add_env(nxt_task_t *task, nxt_app_rmsg_t *rmsg, VALUE hash_env,
    const char *name, nxt_str_t *str)
{
    nxt_int_t  rc;

    rc = nxt_app_msg_read_str(task, rmsg, str);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    if (str->start == NULL) {
        rb_hash_aset(hash_env, rb_str_new2(name), Qnil);
        return NXT_OK;
    }

    rb_hash_aset(hash_env, rb_str_new2(name),
                 rb_str_new((const char *) str->start, (long) str->length));

    return NXT_OK;
}


static nxt_int_t
nxt_ruby_rack_result_status(VALUE result)
{
    VALUE      status;
    u_char     *p;
    size_t     len;
    nxt_int_t  rc;
    u_char     buf[3];

    status = rb_ary_entry(result, 0);

    if (TYPE(status) == T_FIXNUM) {
        nxt_sprintf(buf, buf + 3, "%03d", FIX2INT(status));

        p = buf;
        len = 3;

    } else if (TYPE(status) == T_STRING) {
        p = (u_char *) RSTRING_PTR(status);
        len = RSTRING_LEN(status);

    } else {
        nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                "Ruby: Invalid response 'status' format from application");

        return NXT_ERROR;
    }

    rc = nxt_ruby_write(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg,
                        (u_char *) "Status: ", nxt_length("Status: "), 0, 0);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_ruby_write(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg,
                        p, len, 0, 0);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_ruby_write(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg,
                        (u_char *) "\r\n", nxt_length("\r\n"), 0, 0);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_inline nxt_int_t
nxt_ruby_write(nxt_task_t *task, nxt_app_wmsg_t *wmsg,
    const u_char *data, size_t len, nxt_bool_t flush, nxt_bool_t last)
{
    nxt_int_t  rc;

    rc = nxt_app_msg_write_raw(task, wmsg, data, len);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    if (flush || last) {
        rc = nxt_app_msg_flush(task, wmsg, last);
    }

    return rc;
}


static nxt_int_t
nxt_ruby_rack_result_headers(VALUE result)
{
    VALUE      headers;
    nxt_int_t  rc;

    headers = rb_ary_entry(result, 1);
    if (nxt_slow_path(TYPE(headers) != T_HASH)) {
        nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                "Ruby: Invalid response 'headers' format from application");

        return NXT_ERROR;
    }

    rc = NXT_OK;

    rb_hash_foreach(headers, nxt_ruby_hash_foreach, (VALUE) (uintptr_t) &rc);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_ruby_write(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg,
                        (u_char *) "\r\n", nxt_length("\r\n"), 0, 0);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static int
nxt_ruby_hash_foreach(VALUE r_key, VALUE r_value, VALUE arg)
{
    nxt_int_t   rc, *rc_p;
    const char  *value, *value_end, *pos;

    rc_p = (nxt_int_t *) (uintptr_t) arg;

    if (nxt_slow_path(TYPE(r_key) != T_STRING)) {
        nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                "Ruby: Wrong header entry 'key' from application");

        goto fail;
    }

    if (nxt_slow_path(TYPE(r_value) != T_STRING)) {
        nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                "Ruby: Wrong header entry 'value' from application");

        goto fail;
    }

    value = RSTRING_PTR(r_value);
    value_end = value + RSTRING_LEN(r_value);

    pos = value;

    for ( ;; ) {
        pos = strchr(pos, '\n');

        if (pos == NULL) {
            break;
        }

        rc = nxt_ruby_head_send_part(RSTRING_PTR(r_key), RSTRING_LEN(r_key),
                                     value, pos - value);
        if (nxt_slow_path(rc != NXT_OK)) {
            goto fail;
        }

        pos++;
        value = pos;
    }

    if (value <= value_end) {
        rc = nxt_ruby_head_send_part(RSTRING_PTR(r_key), RSTRING_LEN(r_key),
                                     value, value_end - value);
        if (nxt_slow_path(rc != NXT_OK)) {
            goto fail;
        }
    }

    *rc_p = NXT_OK;

    return ST_CONTINUE;

fail:

    *rc_p = NXT_ERROR;

    return ST_STOP;
}


static nxt_int_t
nxt_ruby_head_send_part(const char *key, size_t key_size,
    const char *value, size_t value_size)
{
    nxt_int_t  rc;

    rc = nxt_app_msg_write_raw(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg,
                               (u_char *) key, key_size);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    rc = nxt_app_msg_write_raw(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg,
                               (u_char *) ": ", nxt_length(": "));
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    rc = nxt_app_msg_write_raw(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg,
                               (u_char *) value, value_size);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    return nxt_app_msg_write_raw(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg,
                                 (u_char *) "\r\n", nxt_length("\r\n"));
}


static nxt_int_t
nxt_ruby_rack_result_body(VALUE result)
{
    VALUE      fn, body;
    nxt_int_t  rc;

    body = rb_ary_entry(result, 2);

    if (rb_respond_to(body, rb_intern("to_path"))) {

        fn = rb_funcall(body, rb_intern("to_path"), 0);
        if (nxt_slow_path(TYPE(fn) != T_STRING)) {
            nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                    "Ruby: Failed to get 'body' file path from application");

            return NXT_ERROR;
        }

        rc = nxt_ruby_rack_result_body_file_write(fn);
        if (nxt_slow_path(rc != NXT_OK)) {
            return NXT_ERROR;
        }

    } else if (rb_respond_to(body, rb_intern("each"))) {
        rb_iterate(rb_each, body, nxt_ruby_rack_result_body_each, 0);

    } else {
        nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                "Ruby: Invalid response 'body' format from application");

        return NXT_ERROR;
    }

    if (rb_respond_to(body, rb_intern("close"))) {
        rb_funcall(body, rb_intern("close"), 0);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_ruby_rack_result_body_file_write(VALUE filepath)
{
    size_t           len;
    ssize_t          n;
    nxt_off_t        rest;
    nxt_int_t        rc;
    nxt_file_t       file;
    nxt_file_info_t  finfo;
    u_char           buf[8192];

    nxt_memzero(&file, sizeof(nxt_file_t));

    file.name = (nxt_file_name_t *) RSTRING_PTR(filepath);

    rc = nxt_file_open(nxt_ruby_run_ctx.task, &file, NXT_FILE_RDONLY,
                       NXT_FILE_OPEN, 0);
    if (nxt_slow_path(rc != NXT_OK)) {
        nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                "Ruby: Failed to open 'body' file: %s",
                (const char *) file.name);

        return NXT_ERROR;
    }

    rc = nxt_file_info(&file, &finfo);
    if (nxt_slow_path(rc != NXT_OK)) {
        nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                "Ruby: Failed to get 'body' file information: %s",
                (const char *) file.name);

        goto fail;
    }

    rest = nxt_file_size(&finfo);

    while (rest != 0) {
        len = nxt_min(rest, (nxt_off_t) sizeof(buf));

        n = nxt_file_read(&file, buf, len, nxt_file_size(&finfo) - rest);
        if (nxt_slow_path(n != (ssize_t) len)) {
            nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                    "Ruby: Failed to read 'body' file");

            goto fail;
        }

        rest -= len;

        rc = nxt_app_msg_write_raw(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg,
                                   buf, len);
        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                    "Ruby: Failed to write 'body' from application");

            goto fail;
        }
    }

    nxt_file_close(nxt_ruby_run_ctx.task, &file);

    return NXT_OK;

fail:

    nxt_file_close(nxt_ruby_run_ctx.task, &file);

    return NXT_ERROR;
}


static VALUE
nxt_ruby_rack_result_body_each(VALUE body)
{
    nxt_int_t  rc;

    if (TYPE(body) != T_STRING) {
        return Qnil;
    }

    rc = nxt_app_msg_write_raw(nxt_ruby_run_ctx.task, nxt_ruby_run_ctx.wmsg,
                               (u_char *) RSTRING_PTR(body), RSTRING_LEN(body));
    if (nxt_slow_path(rc != NXT_OK)) {
        nxt_log(nxt_ruby_run_ctx.task, NXT_LOG_ERR,
                "Ruby: Failed to write 'body' from application");
    }

    return Qnil;
}


static void
nxt_ruby_exception_log(nxt_task_t *task, uint32_t level, const char *desc)
{
    int    i;
    VALUE  err, ary, eclass, msg;

    nxt_log(task, level, "Ruby: %s", desc);

    err = rb_errinfo();
    ary = rb_funcall(err, rb_intern("backtrace"), 0);

    if (RARRAY_LEN(ary) == 0) {
        return;
    }

    eclass = rb_class_name(rb_class_of(err));
    msg = rb_funcall(err, rb_intern("message"), 0);

    nxt_log(task, level, "Ruby: %s: %s (%s)",
            RSTRING_PTR(RARRAY_PTR(ary)[0]),
            RSTRING_PTR(msg), RSTRING_PTR(eclass));

    for (i = 1; i < RARRAY_LEN(ary); i++) {
        nxt_log(task, level, "from %s", RSTRING_PTR(RARRAY_PTR(ary)[i]));
    }
}


static void
nxt_ruby_atexit(nxt_task_t *task)
{
    rb_gc_unregister_address(&nxt_ruby_io_input);
    rb_gc_unregister_address(&nxt_ruby_io_error);

    rb_gc_unregister_address(&nxt_ruby_rackup);
    rb_gc_unregister_address(&nxt_ruby_call);
    rb_gc_unregister_address(&nxt_ruby_env);

    ruby_cleanup(0);
}
