/*
 * Copyright (C) Alexander Borisov
 * Copyright (C) NGINX, Inc.
 */

#include <ruby/nxt_ruby.h>

#include <nxt_unit.h>
#include <nxt_unit_request.h>

#include <ruby/thread.h>

#include NXT_RUBY_MOUNTS_H

#include <locale.h>


#define NXT_RUBY_RACK_API_VERSION_MAJOR  1
#define NXT_RUBY_RACK_API_VERSION_MINOR  3


typedef struct {
    nxt_task_t      *task;
    nxt_str_t       *script;
    nxt_ruby_ctx_t  *rctx;
} nxt_ruby_rack_init_t;


static nxt_int_t nxt_ruby_start(nxt_task_t *task,
    nxt_process_data_t *data);
static VALUE nxt_ruby_init_basic(VALUE arg);

static VALUE nxt_ruby_hook_procs_load(VALUE path);
static VALUE nxt_ruby_hook_register(VALUE arg);
static VALUE nxt_ruby_hook_call(VALUE name);

static VALUE nxt_ruby_rack_init(nxt_ruby_rack_init_t *rack_init);

static VALUE nxt_ruby_require_rubygems(VALUE arg);
static VALUE nxt_ruby_bundler_setup(VALUE arg);
static VALUE nxt_ruby_require_rack(VALUE arg);
static VALUE nxt_ruby_rack_parse_script(VALUE ctx);
static VALUE nxt_ruby_rack_env_create(VALUE arg);
static int nxt_ruby_init_io(nxt_ruby_ctx_t *rctx);
static void nxt_ruby_request_handler(nxt_unit_request_info_t *req);
static void *nxt_ruby_request_handler_gvl(void *req);
static int nxt_ruby_ready_handler(nxt_unit_ctx_t *ctx);
static void *nxt_ruby_thread_create_gvl(void *rctx);
static VALUE nxt_ruby_thread_func(VALUE arg);
static void *nxt_ruby_unit_run(void *ctx);
static void nxt_ruby_ubf(void *ctx);
static int nxt_ruby_init_threads(nxt_ruby_app_conf_t *c);
static void nxt_ruby_join_threads(nxt_unit_ctx_t *ctx,
    nxt_ruby_app_conf_t *c);

static VALUE nxt_ruby_rack_app_run(VALUE arg);
static int nxt_ruby_read_request(nxt_unit_request_info_t *req, VALUE hash_env);
nxt_inline void nxt_ruby_add_sptr(VALUE hash_env, VALUE name,
    nxt_unit_sptr_t *sptr, uint32_t len);
static nxt_int_t nxt_ruby_rack_result_status(nxt_unit_request_info_t *req,
    VALUE result);
static int nxt_ruby_rack_result_headers(nxt_unit_request_info_t *req,
    VALUE result, nxt_int_t status);
static int nxt_ruby_hash_info(VALUE r_key, VALUE r_value, VALUE arg);
static int nxt_ruby_hash_add(VALUE r_key, VALUE r_value, VALUE arg);
static int nxt_ruby_rack_result_body(nxt_unit_request_info_t *req,
    VALUE result);
static int nxt_ruby_rack_result_body_file_write(nxt_unit_request_info_t *req,
    VALUE filepath);
static void *nxt_ruby_response_write_cb(void *read_info);
static VALUE nxt_ruby_rack_result_body_each(VALUE body, VALUE arg,
    int argc, const VALUE *argv, VALUE blockarg);
static void *nxt_ruby_response_write(void *body);

static void nxt_ruby_exception_log(nxt_unit_request_info_t *req,
    uint32_t level, const char *desc);

static void nxt_ruby_ctx_done(nxt_ruby_ctx_t *rctx);
static void nxt_ruby_atexit(void);


static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};

static VALUE  nxt_ruby_hook_procs;
static VALUE  nxt_ruby_rackup;
static VALUE  nxt_ruby_call;

static uint32_t        nxt_ruby_threads;
static nxt_ruby_ctx_t  *nxt_ruby_ctxs;

NXT_EXPORT nxt_app_module_t  nxt_app_module = {
    sizeof(compat),
    compat,
    nxt_string("ruby"),
    ruby_version,
    nxt_ruby_mounts,
    nxt_nitems(nxt_ruby_mounts),
    NULL,
    nxt_ruby_start,
};

typedef struct {
    nxt_str_t  string;
    VALUE      *v;
} nxt_ruby_string_t;

static VALUE  nxt_rb_80_str;
static VALUE  nxt_rb_content_length_str;
static VALUE  nxt_rb_content_type_str;
static VALUE  nxt_rb_http_str;
static VALUE  nxt_rb_https_str;
static VALUE  nxt_rb_path_info_str;
static VALUE  nxt_rb_query_string_str;
static VALUE  nxt_rb_rack_url_scheme_str;
static VALUE  nxt_rb_remote_addr_str;
static VALUE  nxt_rb_request_method_str;
static VALUE  nxt_rb_request_uri_str;
static VALUE  nxt_rb_server_addr_str;
static VALUE  nxt_rb_server_name_str;
static VALUE  nxt_rb_server_port_str;
static VALUE  nxt_rb_server_protocol_str;
static VALUE  nxt_rb_on_worker_boot;
static VALUE  nxt_rb_on_worker_shutdown;
static VALUE  nxt_rb_on_thread_boot;
static VALUE  nxt_rb_on_thread_shutdown;

static nxt_ruby_string_t nxt_rb_strings[] = {
    { nxt_string("80"), &nxt_rb_80_str },
    { nxt_string("CONTENT_LENGTH"), &nxt_rb_content_length_str },
    { nxt_string("CONTENT_TYPE"), &nxt_rb_content_type_str },
    { nxt_string("http"), &nxt_rb_http_str },
    { nxt_string("https"), &nxt_rb_https_str },
    { nxt_string("PATH_INFO"), &nxt_rb_path_info_str },
    { nxt_string("QUERY_STRING"), &nxt_rb_query_string_str },
    { nxt_string("rack.url_scheme"), &nxt_rb_rack_url_scheme_str },
    { nxt_string("REMOTE_ADDR"), &nxt_rb_remote_addr_str },
    { nxt_string("REQUEST_METHOD"), &nxt_rb_request_method_str },
    { nxt_string("REQUEST_URI"), &nxt_rb_request_uri_str },
    { nxt_string("SERVER_ADDR"), &nxt_rb_server_addr_str },
    { nxt_string("SERVER_NAME"), &nxt_rb_server_name_str },
    { nxt_string("SERVER_PORT"), &nxt_rb_server_port_str },
    { nxt_string("SERVER_PROTOCOL"), &nxt_rb_server_protocol_str },
    { nxt_string("on_worker_boot"), &nxt_rb_on_worker_boot },
    { nxt_string("on_worker_shutdown"), &nxt_rb_on_worker_shutdown },
    { nxt_string("on_thread_boot"), &nxt_rb_on_thread_boot },
    { nxt_string("on_thread_shutdown"), &nxt_rb_on_thread_shutdown },
    { nxt_null_string, NULL },
};


static int
nxt_ruby_init_strings(void)
{
    VALUE              v;
    nxt_ruby_string_t  *pstr;

    pstr = nxt_rb_strings;

    while (pstr->string.start != NULL) {
        v = rb_str_new_static((char *) pstr->string.start, pstr->string.length);

        if (nxt_slow_path(v == Qnil)) {
            nxt_unit_alert(NULL, "Ruby: failed to create const string '%.*s'",
                           (int) pstr->string.length,
                           (char *) pstr->string.start);

            return NXT_UNIT_ERROR;
        }

        *pstr->v = v;

        rb_gc_register_address(pstr->v);

        pstr++;
    }

    return NXT_UNIT_OK;
}


static void
nxt_ruby_done_strings(void)
{
    nxt_ruby_string_t  *pstr;

    pstr = nxt_rb_strings;

    while (pstr->string.start != NULL) {
        rb_gc_unregister_address(pstr->v);

        *pstr->v = Qnil;

        pstr++;
    }
}


static VALUE
nxt_ruby_hook_procs_load(VALUE path)
{
    VALUE  module, file, file_obj;

    module = rb_define_module("Unit");

    nxt_ruby_hook_procs = rb_hash_new();

    rb_gc_register_address(&nxt_ruby_hook_procs);

    rb_define_module_function(module, "on_worker_boot",
                              &nxt_ruby_hook_register, 0);
    rb_define_module_function(module, "on_worker_shutdown",
                              &nxt_ruby_hook_register, 0);
    rb_define_module_function(module, "on_thread_boot",
                              &nxt_ruby_hook_register, 0);
    rb_define_module_function(module, "on_thread_shutdown",
                              &nxt_ruby_hook_register, 0);

    file = rb_const_get(rb_cObject, rb_intern("File"));
    file_obj = rb_funcall(file, rb_intern("read"), 1, path);

    return rb_funcall(module, rb_intern("module_eval"), 3, file_obj, path,
                      INT2NUM(1));
}


static VALUE
nxt_ruby_hook_register(VALUE arg)
{
    VALUE  kernel, callee, callee_str;

    rb_need_block();

    kernel = rb_const_get(rb_cObject, rb_intern("Kernel"));
    callee = rb_funcall(kernel, rb_intern("__callee__"), 0);
    callee_str = rb_funcall(callee, rb_intern("to_s"), 0);

    rb_hash_aset(nxt_ruby_hook_procs, callee_str, rb_block_proc());

    return Qnil;
}


static VALUE
nxt_ruby_hook_call(VALUE name)
{
    VALUE  proc;

    proc = rb_hash_lookup(nxt_ruby_hook_procs, name);
    if (proc == Qnil) {
        return Qnil;
    }

    return rb_funcall(proc, rb_intern("call"), 0);
}


static nxt_int_t
nxt_ruby_start(nxt_task_t *task, nxt_process_data_t *data)
{
    int                    state, rc;
    VALUE                  res, path;
    nxt_ruby_ctx_t         ruby_ctx;
    nxt_unit_ctx_t         *unit_ctx;
    nxt_unit_init_t        ruby_unit_init;
    nxt_ruby_app_conf_t    *c;
    nxt_ruby_rack_init_t   rack_init;
    nxt_common_app_conf_t  *conf;

    static char  *argv[2] = { (char *) "NGINX_Unit", (char *) "-e0" };

    signal(SIGINT, SIG_IGN);

    conf = data->app;
    c = &conf->u.ruby;

    nxt_ruby_threads = c->threads;

    setlocale(LC_CTYPE, "");

    RUBY_INIT_STACK
    ruby_init();
    ruby_options(2, argv);
    ruby_script("NGINX_Unit");

    ruby_ctx.env = Qnil;
    ruby_ctx.io_input = Qnil;
    ruby_ctx.io_error = Qnil;
    ruby_ctx.thread = Qnil;
    ruby_ctx.ctx = NULL;
    ruby_ctx.req = NULL;

    rack_init.task = task;
    rack_init.script = &c->script;
    rack_init.rctx = &ruby_ctx;

    nxt_ruby_init_strings();

    res = rb_protect(nxt_ruby_init_basic,
                     (VALUE) (uintptr_t) &rack_init, &state);
    if (nxt_slow_path(res == Qnil || state != 0)) {
        nxt_ruby_exception_log(NULL, NXT_LOG_ALERT,
                               "Failed to init basic variables");
        return NXT_ERROR;
    }

    nxt_ruby_call = Qnil;
    nxt_ruby_hook_procs = Qnil;

    if (c->hooks.start != NULL) {
        path = rb_str_new((const char *) c->hooks.start,
                          (long) c->hooks.length);

        rb_protect(nxt_ruby_hook_procs_load, path, &state);
        rb_str_free(path);
        if (nxt_slow_path(state != 0)) {
            nxt_ruby_exception_log(NULL, NXT_LOG_ALERT,
                                   "Failed to setup hooks");
            return NXT_ERROR;
        }
    }

    if (nxt_ruby_hook_procs != Qnil) {
        rb_protect(nxt_ruby_hook_call, nxt_rb_on_worker_boot, &state);
        if (nxt_slow_path(state != 0)) {
            nxt_ruby_exception_log(NULL, NXT_LOG_ERR,
                                   "Failed to call on_worker_boot()");
            return NXT_ERROR;
        }
    }

    nxt_ruby_rackup = nxt_ruby_rack_init(&rack_init);
    if (nxt_slow_path(nxt_ruby_rackup == Qnil)) {
        return NXT_ERROR;
    }

    rb_gc_register_address(&nxt_ruby_rackup);

    nxt_ruby_call = rb_intern("call");
    if (nxt_slow_path(nxt_ruby_call == Qnil)) {
        nxt_alert(task, "Ruby: Unable to find rack entry point");

        goto fail;
    }

    rb_gc_register_address(&nxt_ruby_call);

    ruby_ctx.env = rb_protect(nxt_ruby_rack_env_create,
                              (VALUE) (uintptr_t) &ruby_ctx, &state);
    if (nxt_slow_path(ruby_ctx.env == Qnil || state != 0)) {
        nxt_ruby_exception_log(NULL, NXT_LOG_ALERT,
                               "Failed to create 'environ' variable");
        goto fail;
    }

    rc = nxt_ruby_init_threads(c);
    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        goto fail;
    }

    nxt_unit_default_init(task, &ruby_unit_init, conf);

    ruby_unit_init.callbacks.request_handler = nxt_ruby_request_handler;
    ruby_unit_init.callbacks.ready_handler = nxt_ruby_ready_handler;
    ruby_unit_init.data = c;
    ruby_unit_init.ctx_data = &ruby_ctx;

    unit_ctx = nxt_unit_init(&ruby_unit_init);
    if (nxt_slow_path(unit_ctx == NULL)) {
        goto fail;
    }

    if (nxt_ruby_hook_procs != Qnil) {
        rb_protect(nxt_ruby_hook_call, nxt_rb_on_thread_boot, &state);
        if (nxt_slow_path(state != 0)) {
            nxt_ruby_exception_log(NULL, NXT_LOG_ERR,
                                   "Failed to call on_thread_boot()");
        }
    }

    rc = (intptr_t) rb_thread_call_without_gvl2(nxt_ruby_unit_run, unit_ctx,
                                                nxt_ruby_ubf, unit_ctx);

    if (nxt_ruby_hook_procs != Qnil) {
        rb_protect(nxt_ruby_hook_call, nxt_rb_on_thread_shutdown, &state);
        if (nxt_slow_path(state != 0)) {
            nxt_ruby_exception_log(NULL, NXT_LOG_ERR,
                                   "Failed to call on_thread_shutdown()");
        }
    }

    nxt_ruby_join_threads(unit_ctx, c);

    if (nxt_ruby_hook_procs != Qnil) {
        rb_protect(nxt_ruby_hook_call, nxt_rb_on_worker_shutdown, &state);
        if (nxt_slow_path(state != 0)) {
            nxt_ruby_exception_log(NULL, NXT_LOG_ERR,
                                   "Failed to call on_worker_shutdown()");
        }
    }

    nxt_unit_done(unit_ctx);

    nxt_ruby_ctx_done(&ruby_ctx);

    nxt_ruby_atexit();

    exit(rc);

    return NXT_OK;

fail:

    nxt_ruby_join_threads(NULL, c);

    nxt_ruby_ctx_done(&ruby_ctx);

    nxt_ruby_atexit();

    return NXT_ERROR;
}


static VALUE
nxt_ruby_init_basic(VALUE arg)
{
    int                   state;
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

    return arg;
}


static VALUE
nxt_ruby_rack_init(nxt_ruby_rack_init_t *rack_init)
{
    int    state;
    VALUE  rackup, err;

    rb_protect(nxt_ruby_require_rubygems, Qnil, &state);
    if (nxt_slow_path(state != 0)) {
        nxt_ruby_exception_log(NULL, NXT_LOG_ALERT,
                               "Failed to require 'rubygems' package");
        return Qnil;
    }

    rb_protect(nxt_ruby_bundler_setup, Qnil, &state);
    if (state != 0) {
        err = rb_errinfo();

        if (rb_obj_is_kind_of(err, rb_eLoadError) == Qfalse) {
            nxt_ruby_exception_log(NULL, NXT_LOG_ALERT,
                                   "Failed to require 'bundler/setup' package");
            return Qnil;
        }

        rb_set_errinfo(Qnil);
    }

    rb_protect(nxt_ruby_require_rack, Qnil, &state);
    if (nxt_slow_path(state != 0)) {
        nxt_ruby_exception_log(NULL, NXT_LOG_ALERT,
                               "Failed to require 'rack' package");
        return Qnil;
    }

    rackup = rb_protect(nxt_ruby_rack_parse_script,
                        (VALUE) (uintptr_t) rack_init, &state);

    if (nxt_slow_path(state != 0)) {
        nxt_ruby_exception_log(NULL, NXT_LOG_ALERT,
                               "Failed to parse rack script");
        return Qnil;
    }

    if (TYPE(rackup) != T_ARRAY) {
        return rackup;
    }

    if (nxt_slow_path(RARRAY_LEN(rackup) < 1)) {
        nxt_ruby_exception_log(NULL, NXT_LOG_ALERT, "Invalid rack config file");
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
    VALUE                 script, res, rack, builder;
    nxt_ruby_rack_init_t  *rack_init;

    rack_init = (nxt_ruby_rack_init_t *) (uintptr_t) ctx;

    rack = rb_const_get(rb_cObject, rb_intern("Rack"));
    builder = rb_const_get(rack, rb_intern("Builder"));

    script = rb_str_new((const char *) rack_init->script->start,
                        (long) rack_init->script->length);

    res = rb_funcall(builder, rb_intern("parse_file"), 1, script);

    rb_str_free(script);

    return res;
}


static VALUE
nxt_ruby_rack_env_create(VALUE arg)
{
    int             rc;
    VALUE           hash_env, version;
    nxt_ruby_ctx_t  *rctx;

    rctx = (nxt_ruby_ctx_t *) (uintptr_t) arg;

    rc = nxt_ruby_init_io(rctx);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return Qnil;
    }

    hash_env = rb_hash_new();

    rb_hash_aset(hash_env, rb_str_new2("SERVER_SOFTWARE"),
                 rb_str_new((const char *) nxt_server.start,
                            (long) nxt_server.length));

    version = rb_ary_new();

    rb_ary_push(version, UINT2NUM(NXT_RUBY_RACK_API_VERSION_MAJOR));
    rb_ary_push(version, UINT2NUM(NXT_RUBY_RACK_API_VERSION_MINOR));

    rb_hash_aset(hash_env, rb_str_new2("SCRIPT_NAME"), rb_str_new("", 0));
    rb_hash_aset(hash_env, rb_str_new2("rack.version"), version);
    rb_hash_aset(hash_env, rb_str_new2("rack.input"), rctx->io_input);
    rb_hash_aset(hash_env, rb_str_new2("rack.errors"), rctx->io_error);
    rb_hash_aset(hash_env, rb_str_new2("rack.multithread"),
                 nxt_ruby_threads > 1 ? Qtrue : Qfalse);
    rb_hash_aset(hash_env, rb_str_new2("rack.multiprocess"), Qtrue);
    rb_hash_aset(hash_env, rb_str_new2("rack.run_once"), Qfalse);
    rb_hash_aset(hash_env, rb_str_new2("rack.hijack?"), Qfalse);
    rb_hash_aset(hash_env, rb_str_new2("rack.hijack"), Qnil);
    rb_hash_aset(hash_env, rb_str_new2("rack.hijack_io"), Qnil);

    rctx->env = hash_env;

    rb_gc_register_address(&rctx->env);

    return hash_env;
}


static int
nxt_ruby_init_io(nxt_ruby_ctx_t *rctx)
{
    VALUE  io_input, io_error;

    io_input = nxt_ruby_stream_io_input_init();

    rctx->io_input = rb_funcall(io_input, rb_intern("new"), 1,
                                   (VALUE) (uintptr_t) rctx);
    if (nxt_slow_path(rctx->io_input == Qnil)) {
        nxt_unit_alert(NULL,
                       "Ruby: Failed to create environment 'rack.input' var");

        return NXT_UNIT_ERROR;
    }

    rb_gc_register_address(&rctx->io_input);

    io_error = nxt_ruby_stream_io_error_init();

    rctx->io_error = rb_funcall(io_error, rb_intern("new"), 1,
                                   (VALUE) (uintptr_t) rctx);
    if (nxt_slow_path(rctx->io_error == Qnil)) {
        nxt_unit_alert(NULL,
                       "Ruby: Failed to create environment 'rack.error' var");

        return NXT_UNIT_ERROR;
    }

    rb_gc_register_address(&rctx->io_error);

    return NXT_UNIT_OK;
}


static void
nxt_ruby_request_handler(nxt_unit_request_info_t *req)
{
    (void) rb_thread_call_with_gvl(nxt_ruby_request_handler_gvl, req);
}


static void *
nxt_ruby_request_handler_gvl(void *data)
{
    int                      state;
    VALUE                    res;
    nxt_ruby_ctx_t           *rctx;
    nxt_unit_request_info_t  *req;

    req = data;

    rctx = req->ctx->data;
    rctx->req = req;

    res = rb_protect(nxt_ruby_rack_app_run, (VALUE) (uintptr_t) req, &state);
    if (nxt_slow_path(res == Qnil || state != 0)) {
        nxt_ruby_exception_log(req, NXT_LOG_ERR,
                               "Failed to run ruby script");

        nxt_unit_request_done(req, NXT_UNIT_ERROR);

    } else {
        nxt_unit_request_done(req, NXT_UNIT_OK);
    }

    rctx->req = NULL;

    return NULL;
}


static VALUE
nxt_ruby_rack_app_run(VALUE arg)
{
    int                      rc;
    VALUE                    env, result;
    nxt_int_t                status;
    nxt_ruby_ctx_t           *rctx;
    nxt_unit_request_info_t  *req;

    req = (nxt_unit_request_info_t *) arg;

    rctx = req->ctx->data;

    env = rb_hash_dup(rctx->env);

    rc = nxt_ruby_read_request(req, env);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_req_alert(req,
                           "Ruby: Failed to process incoming request");

        goto fail;
    }

    result = rb_funcall(nxt_ruby_rackup, nxt_ruby_call, 1, env);
    if (nxt_slow_path(TYPE(result) != T_ARRAY)) {
        nxt_unit_req_error(req,
                           "Ruby: Invalid response format from application");

        goto fail;
    }

    if (nxt_slow_path(RARRAY_LEN(result) != 3)) {
        nxt_unit_req_error(req,
                           "Ruby: Invalid response format from application. "
                           "Need 3 entries [Status, Headers, Body]");

        goto fail;
    }

    status = nxt_ruby_rack_result_status(req, result);
    if (nxt_slow_path(status < 0)) {
        nxt_unit_req_error(req,
                           "Ruby: Invalid response status from application.");

        goto fail;
    }

    rc = nxt_ruby_rack_result_headers(req, result, status);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    rc = nxt_ruby_rack_result_body(req, result);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    rb_hash_delete(env, rb_obj_id(env));

    return result;

fail:

    rb_hash_delete(env, rb_obj_id(env));

    return Qnil;
}


static int
nxt_ruby_read_request(nxt_unit_request_info_t *req, VALUE hash_env)
{
    VALUE               name;
    uint32_t            i;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    r = req->request;

    nxt_ruby_add_sptr(hash_env, nxt_rb_request_method_str, &r->method,
                      r->method_length);
    nxt_ruby_add_sptr(hash_env, nxt_rb_request_uri_str, &r->target,
                      r->target_length);
    nxt_ruby_add_sptr(hash_env, nxt_rb_path_info_str, &r->path, r->path_length);
    nxt_ruby_add_sptr(hash_env, nxt_rb_query_string_str, &r->query,
                      r->query_length);
    nxt_ruby_add_sptr(hash_env, nxt_rb_server_protocol_str, &r->version,
                      r->version_length);
    nxt_ruby_add_sptr(hash_env, nxt_rb_remote_addr_str, &r->remote,
                      r->remote_length);
    nxt_ruby_add_sptr(hash_env, nxt_rb_server_addr_str, &r->local_addr,
                      r->local_addr_length);
    nxt_ruby_add_sptr(hash_env, nxt_rb_server_name_str, &r->server_name,
                      r->server_name_length);

    rb_hash_aset(hash_env, nxt_rb_server_port_str, nxt_rb_80_str);

    rb_hash_aset(hash_env, nxt_rb_rack_url_scheme_str,
                 r->tls ? nxt_rb_https_str : nxt_rb_http_str);

    for (i = 0; i < r->fields_count; i++) {
        f = r->fields + i;

        name = rb_str_new(nxt_unit_sptr_get(&f->name), f->name_length);

        nxt_ruby_add_sptr(hash_env, name, &f->value, f->value_length);
    }

    if (r->content_length_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_length_field;

        nxt_ruby_add_sptr(hash_env, nxt_rb_content_length_str,
                          &f->value, f->value_length);
    }

    if (r->content_type_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_type_field;

        nxt_ruby_add_sptr(hash_env, nxt_rb_content_type_str,
                          &f->value, f->value_length);
    }

    return NXT_UNIT_OK;
}


nxt_inline void
nxt_ruby_add_sptr(VALUE hash_env, VALUE name,
    nxt_unit_sptr_t *sptr, uint32_t len)
{
    char  *str;

    str = nxt_unit_sptr_get(sptr);

    rb_hash_aset(hash_env, name, rb_str_new(str, len));
}


static nxt_int_t
nxt_ruby_rack_result_status(nxt_unit_request_info_t *req, VALUE result)
{
    VALUE   status;

    status = rb_ary_entry(result, 0);

    if (TYPE(status) == T_FIXNUM) {
        return FIX2INT(status);
    }

    if (TYPE(status) == T_STRING) {
        return nxt_int_parse((u_char *) RSTRING_PTR(status),
                             RSTRING_LEN(status));
    }

    nxt_unit_req_error(req, "Ruby: Invalid response 'status' "
                       "format from application");

    return -2;
}


typedef struct {
    int                      rc;
    uint32_t                 fields;
    uint32_t                 size;
    nxt_unit_request_info_t  *req;
} nxt_ruby_headers_info_t;


static int
nxt_ruby_rack_result_headers(nxt_unit_request_info_t *req, VALUE result,
    nxt_int_t status)
{
    int                      rc;
    VALUE                    headers;
    nxt_ruby_headers_info_t  headers_info;

    headers = rb_ary_entry(result, 1);
    if (nxt_slow_path(TYPE(headers) != T_HASH)) {
        nxt_unit_req_error(req,
                           "Ruby: Invalid response 'headers' format from "
                           "application");

        return NXT_UNIT_ERROR;
    }

    rc = NXT_UNIT_OK;

    headers_info.rc = NXT_UNIT_OK;
    headers_info.fields = 0;
    headers_info.size = 0;
    headers_info.req = req;

    rb_hash_foreach(headers, nxt_ruby_hash_info,
                    (VALUE) (uintptr_t) &headers_info);
    if (nxt_slow_path(headers_info.rc != NXT_UNIT_OK)) {
        return headers_info.rc;
    }

    rc = nxt_unit_response_init(req, status,
                                headers_info.fields, headers_info.size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return rc;
    }

    rb_hash_foreach(headers, nxt_ruby_hash_add,
                    (VALUE) (uintptr_t) &headers_info);

    return rc;
}


static int
nxt_ruby_hash_info(VALUE r_key, VALUE r_value, VALUE arg)
{
    const char               *value, *value_end, *pos;
    nxt_ruby_headers_info_t  *headers_info;

    headers_info = (void *) (uintptr_t) arg;

    if (nxt_slow_path(TYPE(r_key) != T_STRING)) {
        nxt_unit_req_error(headers_info->req,
                           "Ruby: Wrong header entry 'key' from application");

        goto fail;
    }

    if (nxt_slow_path(TYPE(r_value) != T_STRING && TYPE(r_value) != T_ARRAY)) {
        nxt_unit_req_error(headers_info->req,
                           "Ruby: Wrong header entry 'value' from application");

        goto fail;
    }

    if (TYPE(r_value) == T_ARRAY) {
        int     i;
        int     arr_len = RARRAY_LEN(r_value);
        VALUE   item;
        size_t  len = 0;

        for (i = 0; i < arr_len; i++) {
            item = rb_ary_entry(r_value, i);
            if (TYPE(item) != T_STRING) {
                nxt_unit_req_error(headers_info->req,
                                   "Ruby: Wrong header entry in 'value' array "
                                   "from application");
                goto fail;
            }

            len += RSTRING_LEN(item) + 2;   /* +2 for '; ' */
        }

        if (arr_len > 0) {
            len -= 2;
        }

        headers_info->fields++;
        headers_info->size += RSTRING_LEN(r_key) + len;

        return ST_CONTINUE;
    }

    value = RSTRING_PTR(r_value);
    value_end = value + RSTRING_LEN(r_value);

    pos = value;

    for ( ;; ) {
        pos = strchr(pos, '\n');

        if (pos == NULL) {
            break;
        }

        headers_info->fields++;
        headers_info->size += RSTRING_LEN(r_key) + (pos - value);

        pos++;
        value = pos;
    }

    if (value <= value_end) {
        headers_info->fields++;
        headers_info->size += RSTRING_LEN(r_key) + (value_end - value);
    }

    return ST_CONTINUE;

fail:

    headers_info->rc = NXT_UNIT_ERROR;

    return ST_STOP;
}


static int
nxt_ruby_hash_add(VALUE r_key, VALUE r_value, VALUE arg)
{
    int                      *rc;
    uint32_t                 key_len;
    const char               *value, *value_end, *pos;
    nxt_ruby_headers_info_t  *headers_info;

    headers_info = (void *) (uintptr_t) arg;
    rc = &headers_info->rc;

    key_len = RSTRING_LEN(r_key);

    if (TYPE(r_value) == T_ARRAY) {
        int     i;
        int     arr_len = RARRAY_LEN(r_value);
        char    *field, *p;
        VALUE   item;
        size_t  len = 0;

        for (i = 0; i < arr_len; i++) {
            item = rb_ary_entry(r_value, i);

            len += RSTRING_LEN(item) + 2;   /* +2 for '; ' */
        }

        field = nxt_unit_malloc(NULL, len);
        if (field == NULL) {
            goto fail;
        }

        p = field;

        for (i = 0; i < arr_len; i++) {
            item = rb_ary_entry(r_value, i);

            p = nxt_cpymem(p, RSTRING_PTR(item), RSTRING_LEN(item));
            p = nxt_cpymem(p, "; ", 2);
        }

        if (arr_len > 0) {
            len -= 2;
        }

        *rc = nxt_unit_response_add_field(headers_info->req,
                                          RSTRING_PTR(r_key), key_len,
                                          field, len);
        nxt_unit_free(NULL, field);

        if (nxt_slow_path(*rc != NXT_UNIT_OK)) {
            goto fail;
        }

        return ST_CONTINUE;
    }

    value = RSTRING_PTR(r_value);
    value_end = value + RSTRING_LEN(r_value);

    pos = value;

    for ( ;; ) {
        pos = strchr(pos, '\n');

        if (pos == NULL) {
            break;
        }

        *rc = nxt_unit_response_add_field(headers_info->req,
                                          RSTRING_PTR(r_key), key_len,
                                          value, pos - value);
        if (nxt_slow_path(*rc != NXT_UNIT_OK)) {
            goto fail;
        }

        pos++;
        value = pos;
    }

    if (value <= value_end) {
        *rc = nxt_unit_response_add_field(headers_info->req,
                                          RSTRING_PTR(r_key), key_len,
                                          value, value_end - value);
        if (nxt_slow_path(*rc != NXT_UNIT_OK)) {
            goto fail;
        }
    }

    return ST_CONTINUE;

fail:

    *rc = NXT_UNIT_ERROR;

    return ST_STOP;
}


static int
nxt_ruby_rack_result_body(nxt_unit_request_info_t *req, VALUE result)
{
    int    rc;
    VALUE  fn, body;

    body = rb_ary_entry(result, 2);

    if (rb_respond_to(body, rb_intern("to_path"))) {

        fn = rb_funcall(body, rb_intern("to_path"), 0);
        if (nxt_slow_path(TYPE(fn) != T_STRING)) {
            nxt_unit_req_error(req,
                               "Ruby: Failed to get 'body' file path from "
                               "application");

            return NXT_UNIT_ERROR;
        }

        rc = nxt_ruby_rack_result_body_file_write(req, fn);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return rc;
        }

    } else if (rb_respond_to(body, rb_intern("each"))) {
        rb_block_call(body, rb_intern("each"), 0, 0,
                      nxt_ruby_rack_result_body_each, (VALUE) (uintptr_t) req);

    } else {
        nxt_unit_req_error(req,
                           "Ruby: Invalid response 'body' format "
                           "from application");

        return NXT_UNIT_ERROR;
    }

    if (rb_respond_to(body, rb_intern("close"))) {
        rb_funcall(body, rb_intern("close"), 0);
    }

    return NXT_UNIT_OK;
}


typedef struct {
    int    fd;
    off_t  pos;
    off_t  rest;
} nxt_ruby_rack_file_t;


static ssize_t
nxt_ruby_rack_file_read(nxt_unit_read_info_t *read_info, void *dst, size_t size)
{
    ssize_t               res;
    nxt_ruby_rack_file_t  *file;

    file = read_info->data;

    size = nxt_min(size, (size_t) file->rest);

    res = pread(file->fd, dst, size, file->pos);

    if (res >= 0) {
        file->pos += res;
        file->rest -= res;

        if (size > (size_t) res) {
            file->rest = 0;
        }
    }

    read_info->eof = file->rest == 0;

    return res;
}


typedef struct {
    nxt_unit_read_info_t     read_info;
    nxt_unit_request_info_t  *req;
} nxt_ruby_read_info_t;


static int
nxt_ruby_rack_result_body_file_write(nxt_unit_request_info_t *req,
    VALUE filepath)
{
    int                   fd, rc;
    struct stat           finfo;
    nxt_ruby_rack_file_t  ruby_file;
    nxt_ruby_read_info_t  ri;

    fd = open(RSTRING_PTR(filepath), O_RDONLY, 0);
    if (nxt_slow_path(fd == -1)) {
        nxt_unit_req_error(req,
                           "Ruby: Failed to open content file \"%s\": %s (%d)",
                           RSTRING_PTR(filepath), strerror(errno), errno);

        return NXT_UNIT_ERROR;
    }

    rc = fstat(fd, &finfo);
    if (nxt_slow_path(rc == -1)) {
        nxt_unit_req_error(req,
                           "Ruby: Content file fstat(\"%s\") failed: %s (%d)",
                           RSTRING_PTR(filepath), strerror(errno), errno);

        close(fd);

        return NXT_UNIT_ERROR;
    }

    ruby_file.fd = fd;
    ruby_file.pos = 0;
    ruby_file.rest = finfo.st_size;

    ri.read_info.read = nxt_ruby_rack_file_read;
    ri.read_info.eof = ruby_file.rest == 0;
    ri.read_info.buf_size = ruby_file.rest;
    ri.read_info.data = &ruby_file;
    ri.req = req;

    rc = (intptr_t) rb_thread_call_without_gvl(nxt_ruby_response_write_cb,
                                               &ri,
                                               nxt_ruby_ubf,
                                               req->ctx);

    close(fd);

    return rc;
}


static void *
nxt_ruby_response_write_cb(void *data)
{
    int                   rc;
    nxt_ruby_read_info_t  *ri;

    ri = data;

    rc = nxt_unit_response_write_cb(ri->req, &ri->read_info);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_req_error(ri->req, "Ruby: Failed to write content file.");
    }

    return (void *) (intptr_t) rc;
}


typedef struct {
    VALUE                    body;
    nxt_unit_request_info_t  *req;
} nxt_ruby_write_info_t;


static VALUE
nxt_ruby_rack_result_body_each(VALUE body, VALUE arg, int argc,
    const VALUE *argv, VALUE blockarg)
{
    nxt_ruby_write_info_t  wi;

    if (TYPE(body) != T_STRING) {
        return Qnil;
    }

    wi.body = body;
    wi.req = (void *) (uintptr_t) arg;

    (void) rb_thread_call_without_gvl(nxt_ruby_response_write,
                                      (void *) (uintptr_t) &wi,
                                      nxt_ruby_ubf, wi.req->ctx);

    return Qnil;
}


static void *
nxt_ruby_response_write(void *data)
{
    int                    rc;
    nxt_ruby_write_info_t  *wi;

    wi = data;

    rc = nxt_unit_response_write(wi->req, RSTRING_PTR(wi->body),
                                 RSTRING_LEN(wi->body));
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_req_error(wi->req,
                           "Ruby: Failed to write 'body' from application");
    }

    return (void *) (intptr_t) rc;
}


static void
nxt_ruby_exception_log(nxt_unit_request_info_t *req, uint32_t level,
    const char *desc)
{
    int    i;
    VALUE  err, ary, eclass, msg;

    nxt_unit_req_log(req, level, "Ruby: %s", desc);

    err = rb_errinfo();
    if (nxt_slow_path(err == Qnil)) {
        return;
    }

    eclass = rb_class_name(rb_class_of(err));

    msg = rb_funcall(err, rb_intern("message"), 0);
    ary = rb_funcall(err, rb_intern("backtrace"), 0);

    if (RARRAY_LEN(ary) == 0) {
        nxt_unit_req_log(req, level, "Ruby: %s (%s)", RSTRING_PTR(msg),
                         RSTRING_PTR(eclass));

        return;
    }

    nxt_unit_req_log(req, level, "Ruby: %s: %s (%s)",
                     RSTRING_PTR(RARRAY_PTR(ary)[0]),
                     RSTRING_PTR(msg), RSTRING_PTR(eclass));

    for (i = 1; i < RARRAY_LEN(ary); i++) {
        nxt_unit_req_log(req, level, "from %s",
                         RSTRING_PTR(RARRAY_PTR(ary)[i]));
    }
}


static void
nxt_ruby_ctx_done(nxt_ruby_ctx_t *rctx)
{
    if (rctx->io_input != Qnil) {
        rb_gc_unregister_address(&rctx->io_input);
    }

    if (rctx->io_error != Qnil) {
        rb_gc_unregister_address(&rctx->io_error);
    }

    if (rctx->env != Qnil) {
        rb_gc_unregister_address(&rctx->env);
    }
}


static void
nxt_ruby_atexit(void)
{
    if (nxt_ruby_rackup != Qnil) {
        rb_gc_unregister_address(&nxt_ruby_rackup);
    }

    if (nxt_ruby_call != Qnil) {
        rb_gc_unregister_address(&nxt_ruby_call);
    }

    if (nxt_ruby_hook_procs != Qnil) {
        rb_gc_unregister_address(&nxt_ruby_hook_procs);
    }

    nxt_ruby_done_strings();

    ruby_cleanup(0);
}


static int
nxt_ruby_ready_handler(nxt_unit_ctx_t *ctx)
{
    VALUE                res;
    uint32_t             i;
    nxt_ruby_ctx_t       *rctx;
    nxt_ruby_app_conf_t  *c;

    c = ctx->unit->data;

    if (c->threads <= 1) {
        return NXT_UNIT_OK;
    }

    for (i = 0; i < c->threads - 1; i++) {
        rctx = &nxt_ruby_ctxs[i];

        rctx->ctx = ctx;

        res = (VALUE) rb_thread_call_with_gvl(nxt_ruby_thread_create_gvl, rctx);

        if (nxt_fast_path(res != Qnil)) {
            nxt_unit_debug(ctx, "thread #%d created", (int) (i + 1));

            rctx->thread = res;

        } else {
            nxt_unit_alert(ctx, "thread #%d create failed", (int) (i + 1));

            return NXT_UNIT_ERROR;
        }
    }

    return NXT_UNIT_OK;
}


static void *
nxt_ruby_thread_create_gvl(void *rctx)
{
    VALUE  res;

    res = rb_thread_create(RUBY_METHOD_FUNC(nxt_ruby_thread_func), rctx);

    return (void *) (uintptr_t) res;
}


static VALUE
nxt_ruby_thread_func(VALUE arg)
{
    int             state;
    nxt_unit_ctx_t  *ctx;
    nxt_ruby_ctx_t  *rctx;

    rctx = (nxt_ruby_ctx_t *) (uintptr_t) arg;

    nxt_unit_debug(rctx->ctx, "worker thread start");

    ctx = nxt_unit_ctx_alloc(rctx->ctx, rctx);
    if (nxt_slow_path(ctx == NULL)) {
        goto fail;
    }

    if (nxt_ruby_hook_procs != Qnil) {
        rb_protect(nxt_ruby_hook_call, nxt_rb_on_thread_boot, &state);
        if (nxt_slow_path(state != 0)) {
            nxt_ruby_exception_log(NULL, NXT_LOG_ERR,
                                   "Failed to call on_thread_boot()");
        }
    }

    (void) rb_thread_call_without_gvl(nxt_ruby_unit_run, ctx,
                                      nxt_ruby_ubf, ctx);

    if (nxt_ruby_hook_procs != Qnil) {
        rb_protect(nxt_ruby_hook_call, nxt_rb_on_thread_shutdown, &state);
        if (nxt_slow_path(state != 0)) {
            nxt_ruby_exception_log(NULL, NXT_LOG_ERR,
                                   "Failed to call on_thread_shutdown()");
        }
    }

    nxt_unit_done(ctx);

fail:

    nxt_unit_debug(NULL, "worker thread end");

    return Qnil;
}


static void *
nxt_ruby_unit_run(void *ctx)
{
    return (void *) (intptr_t) nxt_unit_run(ctx);
}


static void
nxt_ruby_ubf(void *ctx)
{
    nxt_unit_warn(ctx, "Ruby: UBF");
}


static int
nxt_ruby_init_threads(nxt_ruby_app_conf_t *c)
{
    int             state;
    uint32_t        i;
    nxt_ruby_ctx_t  *rctx;

    if (c->threads <= 1) {
        return NXT_UNIT_OK;
    }

    nxt_ruby_ctxs = nxt_unit_malloc(NULL, sizeof(nxt_ruby_ctx_t)
                                          * (c->threads - 1));
    if (nxt_slow_path(nxt_ruby_ctxs == NULL)) {
        nxt_unit_alert(NULL, "Failed to allocate run contexts array");

        return NXT_UNIT_ERROR;
    }

    for (i = 0; i < c->threads - 1; i++) {
        rctx = &nxt_ruby_ctxs[i];

        rctx->env = Qnil;
        rctx->io_input = Qnil;
        rctx->io_error = Qnil;
        rctx->thread = Qnil;
    }

    for (i = 0; i < c->threads - 1; i++) {
        rctx = &nxt_ruby_ctxs[i];

        rctx->env = rb_protect(nxt_ruby_rack_env_create,
                               (VALUE) (uintptr_t) rctx, &state);
        if (nxt_slow_path(rctx->env == Qnil || state != 0)) {
            nxt_ruby_exception_log(NULL, NXT_LOG_ALERT,
                                   "Failed to create 'environ' variable");
            return NXT_UNIT_ERROR;
        }
    }

    return NXT_UNIT_OK;
}


static void
nxt_ruby_join_threads(nxt_unit_ctx_t *ctx, nxt_ruby_app_conf_t *c)
{
    uint32_t        i;
    nxt_ruby_ctx_t  *rctx;

    if (nxt_ruby_ctxs == NULL) {
        return;
    }

    for (i = 0; i < c->threads - 1; i++) {
        rctx = &nxt_ruby_ctxs[i];

        if (rctx->thread != Qnil) {
            rb_funcall(rctx->thread, rb_intern("join"), 0);

            nxt_unit_debug(ctx, "thread #%d joined", (int) (i + 1));

        } else {
            nxt_unit_debug(ctx, "thread #%d not started", (int) (i + 1));
        }
    }

    for (i = 0; i < c->threads - 1; i++) {
        nxt_ruby_ctx_done(&nxt_ruby_ctxs[i]);
    }

    nxt_unit_free(ctx, nxt_ruby_ctxs);
}
