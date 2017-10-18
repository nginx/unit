
/*
 * Copyright (C) Fedor Sakharov
 */

#include "ruby.h"
#include "ruby/version.h"

#include <nxt_main.h>
#include <nxt_application.h>

#include <string.h>

#define STRINGIFY(V)                        #V
#define RUBY_VERSION_TO_STR(MAJ, MIN, TEE)  STRINGIFY(MAJ) "." \
                                            STRINGIFY(MIN) "." \
                                            STRINGIFY(TEE)

#define RUBY_API_VERSION_STR RUBY_VERSION_TO_STR(RUBY_API_VERSION_MAJOR, \
                                                 RUBY_API_VERSION_MINOR, \
                                                 RUBY_API_VERSION_TEENY)

static nxt_int_t nxt_ruby_init(nxt_task_t *task, nxt_common_app_conf_t *conf);
static nxt_int_t nxt_ruby_run(nxt_task_t *task,
                    nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *wmsg);

extern nxt_int_t nxt_ruby_rack_init(nxt_thread_t *thr, nxt_runtime_t *rt);

typedef struct {
    nxt_task_t          *task;
    nxt_app_rmsg_t      *rmsg;
    nxt_app_request_t   r;
    nxt_str_t           script;
    nxt_app_wmsg_t      *wmsg;
    nxt_mp_t            *mem_pool;
} nxt_ruby_run_ctx_t;

typedef struct nxt_ruby_ctx {
    VALUE               call;
    VALUE               dispatcher;
    VALUE               script;

    VALUE               rack;
    VALUE               rackup;
    nxt_ruby_run_ctx_t  *current_run_ctx;
} nxt_ruby_ctx_t;


static nxt_ruby_ctx_t   ruby_context;

static uint32_t  compat[] = {
    NXT_VERNUM,
};

NXT_EXPORT nxt_application_module_t  nxt_app_module = {
    sizeof(compat),
    compat,
    nxt_string("ruby"),
    nxt_string(RUBY_API_VERSION_STR),
    nxt_ruby_init,
    nxt_ruby_run
};

static VALUE
require_rubygems(VALUE obj1)
{
    return rb_funcall(rb_cObject, rb_intern("require"), 1, rb_str_new2("rubygems"));
}

static VALUE
require_rack(VALUE obj1)
{
    return rb_funcall(rb_cObject, rb_intern("require"), 1, rb_str_new2("rack"));
}

static VALUE
call_dispatch(VALUE env)
{
    return rb_funcall(ruby_context.dispatcher, ruby_context.call, 1, env);
}

struct parse_file_data {
    VALUE       rack;
    VALUE       scr;
};

static VALUE
call_rackup(VALUE data)
{

    struct parse_file_data *datastr = (struct parse_file_data*)data;
    return rb_funcall(rb_const_get(datastr->rack, rb_intern("Builder")),
            rb_intern("parse_file"), 1, datastr->scr);
}

static void
nxt_ruby_print_error(nxt_log_t *log)
{
    VALUE err = rb_errinfo();
    VALUE msg = rb_funcall(err, rb_intern("message"), 0, 0);

    nxt_log_alert(log, "Ruby error: %s", RSTRING_PTR(msg));
}

static VALUE
nxt_ruby_load_func(VALUE obj1)
{
    int state;

    rb_load_protect(obj1, 0, &state);

    return obj1;
}

static VALUE
nxt_ruby_script_path(nxt_common_app_conf_t *conf, int *error)
{
    VALUE ret = 0;
    nxt_ruby_app_conf_t     *c;

    c = &conf->u.ruby;

    if (c->index.length == 0) {
        *error = NXT_ERROR;

        return ret;
    }

    char *script_cstr = strndup((char*)c->index.start,
            c->index.length);

    char *root_cstr = strndup((char*)c->root.start,
            c->root.length);

    printf("%s %s %u %u\n", root_cstr, script_cstr,
            (unsigned)strlen(root_cstr), (unsigned)strlen(script_cstr));

    char *full_path = malloc(sizeof(char) * (strlen(root_cstr) + strlen(script_cstr)));

    full_path[0] = 0;
    strcat(full_path, root_cstr);
    strcat(full_path, script_cstr);

    printf("Full path %s\n", full_path);

    full_path[strlen(root_cstr) + strlen(script_cstr)] = '\0';

    free(script_cstr);
    free(root_cstr);

    ret = rb_str_new_cstr(full_path);
    free(full_path);

    *error = 0;

    return ret;
}

static nxt_int_t
nxt_ruby_init(nxt_task_t *task, nxt_common_app_conf_t *conf)
{
    int error;
    VALUE dummy, result;
    struct parse_file_data pfd;

    ruby_init();
    Init_stack(&dummy);
    ruby_init_loadpath();
    ruby_script("nginext");

    rb_protect(require_rubygems, 0, &error);

    if (error) {
        nxt_ruby_print_error(task->log);

        return NXT_ERROR;
    }

    rb_protect(require_rack, 0, &error);

    if (error) {
        nxt_ruby_print_error(task->log);

        return NXT_ERROR;
    }

    ruby_context.script = nxt_ruby_script_path(conf, &error);

    if (error) {
        nxt_log_alert(task->log, "Failed to load ruby script");
        return NXT_ERROR;
    }

    result = rb_protect(nxt_ruby_load_func, ruby_context.script, &error);
    (void)result;

    if (error) {
        nxt_ruby_print_error(task->log);

        return NXT_ERROR;
    }

    ruby_context.call = rb_intern("my_call");

    if (!ruby_context.call) {
        nxt_ruby_print_error(task->log);

        return NXT_ERROR;
    } else {
        nxt_log_debug(task->log, "Found rack script entry point");
    }

    VALUE rack = rb_const_get(rb_cObject, rb_intern("Rack"));
    VALUE scr = ruby_context.script;

    pfd.rack = rack;
    pfd.scr = scr;

    ruby_context.rackup = rb_protect(call_rackup, (VALUE)&pfd, &error);

    if (error) {
        nxt_ruby_print_error(task->log);
        return NXT_ERROR;
    }

    if (TYPE(ruby_context.rackup) != T_ARRAY) {
        nxt_log_alert(task->log, "Failed to parse file\n");

        return NXT_ERROR;
    }

    if (RARRAY_LEN(ruby_context.rackup) < 1) {
        nxt_log_alert(task->log, "Invalid rack config file\n");

        return NXT_ERROR;
    }

    ruby_context.dispatcher = RARRAY_PTR(ruby_context.rackup)[0];

    if (ruby_context.dispatcher == Qnil) {
        nxt_log_alert(task->log, "Failed to alloc dispatcher\n");

        return NXT_ERROR;
    }

    nxt_log(task, NXT_LOG_INFO, "Ruby " RUBY_API_VERSION_STR " init completed");

    return NXT_OK;
}

nxt_inline nxt_int_t
nxt_ruby_write(nxt_ruby_run_ctx_t *ctx, const u_char *data, size_t len,
        nxt_bool_t flush, nxt_bool_t last)
{
    nxt_int_t   rc;

    rc = nxt_app_msg_write_raw(ctx->task, ctx->wmsg, data, len);

    if (flush || last) {
        rc = nxt_app_msg_flush(ctx->task, ctx->wmsg, last);
    }

    return rc;
}

static VALUE
append_header(VALUE obj, VALUE headers)
{
    static const u_char cr_lf[] = "\r\n";
    static const u_char colon[] = ": ";
    VALUE hkey, hval;

    /* Ruby RTTI */
    if (TYPE(obj) == T_ARRAY) {
        if (RARRAY_LEN(obj) >= 2) {
            hkey = rb_obj_as_string(RARRAY_PTR(obj)[0]);
            hval = rb_obj_as_string(RARRAY_PTR(obj)[1]);
        } else {
            goto clear;
        }
    }
    else if (TYPE(obj) == T_STRING) {
        hkey = obj;
        hval = rb_hash_lookup(headers, obj);
    } else {
        goto clear;
    }

    if (TYPE(hkey) != T_STRING || TYPE(hval) != T_STRING) {
        goto clear;
    }

    char *header_key = RSTRING_PTR(hkey);
    size_t header_key_len = RSTRING_LEN(hkey);

    char *header_value = RSTRING_PTR(hval);
    size_t header_value_len = RSTRING_LEN(hval);

    nxt_ruby_write(ruby_context.current_run_ctx,
            (u_char*)header_key, header_key_len, 0, 0);
    nxt_ruby_write(ruby_context.current_run_ctx,
            colon, sizeof(colon) - 1, 0, 0);
    nxt_ruby_write(ruby_context.current_run_ctx,
            (u_char*)header_value, header_value_len, 0, 0);
    nxt_ruby_write(ruby_context.current_run_ctx,
            cr_lf, sizeof(cr_lf) - 1, 0, 0);

clear:

    return Qnil;
}

static VALUE
iterate_headers(VALUE headers)
{
    return rb_iterate(rb_each, headers, append_header, headers);
}

static VALUE
append_body(VALUE obj)
{
    if (TYPE(obj) == T_STRING) {
        nxt_ruby_write(ruby_context.current_run_ctx,
                (u_char*)RSTRING_PTR(obj), RSTRING_LEN(obj), 0, 0);
    }

    return Qnil;
}

static VALUE
iterate_body(VALUE body)
{
    return rb_iterate(rb_each, body, append_body, 0);
}

static nxt_int_t
nxt_ruby_read_resp(nxt_task_t *task, VALUE resp, nxt_ruby_run_ctx_t *ctx)
{
    int                     error;
    VALUE                   status, headers, body;
    u_char                  *str_status;

    static const u_char http_11[] = "HTTP/1.1 ";
    static const u_char cr_lf[] = "\r\n";

    static const u_char default_response[]
        = "HTTP/1.1 200 OK\r\n"
          "Server: nginext/0.1\r\n"
          "Content-Type: text/html; charset=UTF-8\r\n"
          "Connection: close\r\n"
          "\r\n";

    ruby_context.current_run_ctx = ctx;

    if (RARRAY_LEN(resp) != 3) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                "Invalid RACK response size: %ld",
                RARRAY_LEN(resp));

        goto error;
    }

    status = rb_obj_as_string(RARRAY_PTR(resp)[0]);
    str_status = (u_char*)RSTRING_PTR(status);

    nxt_ruby_write(ctx, http_11, sizeof(http_11) - 1, 0, 0);

    nxt_ruby_write(ctx, str_status, strlen((char*)str_status), 0, 0);
    nxt_ruby_write(ctx, cr_lf, sizeof(cr_lf) - 1, 0, 0);

    headers = RARRAY_PTR(resp)[1];

    if (rb_respond_to(headers, rb_intern("each"))) {
        rb_protect(iterate_headers, headers, &error);

        if (error) {
            nxt_log_error(NXT_LOG_INFO, task->log,
                    "Failed to iterate through headers");
        }
    }

    body = RARRAY_PTR(resp)[2];

    if (rb_respond_to(body, rb_intern("each"))) {
        rb_protect(iterate_body, body, &error);

        if (error) {
            nxt_log_error(NXT_LOG_INFO, task->log,
                    "Failed to iterate through body");
        }
    }

    nxt_ruby_write(ctx, cr_lf, sizeof(cr_lf) - 1, 0, 1);

    return NXT_OK;

error:

    nxt_ruby_write(ctx, default_response, sizeof(default_response) - 1, 0, 1);

    return NXT_ERROR;
}

static nxt_int_t
nxt_ruby_run(nxt_task_t *task,
        nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *wmsg)
{
    int error;
    size_t                      s;
    VALUE                       env, retval, rvb;
    nxt_ruby_run_ctx_t          run_ctx, *ctx;
    nxt_app_request_header_t    *h;

    nxt_memzero(&run_ctx, sizeof(run_ctx));

    run_ctx.task = task;
    run_ctx.rmsg = rmsg;
    run_ctx.wmsg = wmsg;

    run_ctx.mem_pool = nxt_mp_create(1024, 128, 256, 32);

    ctx = &run_ctx;

    h = &ctx->r.header;

    nxt_app_msg_read_str(task, rmsg, &h->method);
    nxt_app_msg_read_str(task, rmsg, &h->path);
    //h->path_no_query = h->path;

    nxt_app_msg_read_size(task, rmsg, &s);

    nxt_app_msg_read_str(task, rmsg, &h->version);

    nxt_app_msg_read_str(task, rmsg, &h->cookie);
    nxt_app_msg_read_str(task, rmsg, &h->content_type);
    nxt_app_msg_read_str(task, rmsg, &h->content_length);

    env = rb_hash_new();

    rb_hash_aset(env, rb_str_new2("REQUEST_METHOD"),
            rb_str_new((char*)h->method.start, h->method.length));
    rb_hash_aset(env, rb_str_new2("SCRIPT_NAME"),
            rb_str_new2("nginext"));
    rb_hash_aset(env, rb_str_new2("QUERY_STRING"),
            rb_str_new2((char*)h->path.start));
    rb_hash_aset(env, rb_str_new2("SERVER_NAME"),
            rb_str_new2("testhost"));
    rb_hash_aset(env, rb_str_new2("SERVER_PORT"),
            rb_str_new2("80"));

    rvb = rb_ary_new();
    rb_ary_store(rvb, 0, INT2NUM(1));
    rb_ary_store(rvb, 1, INT2NUM(1));

    rb_hash_aset(env, rb_str_new2("rack.version"), rvb);
    rb_hash_aset(env, rb_str_new2("rack.url_scheme"),
            rb_str_new2("http"));
    rb_hash_aset(env, rb_str_new2("rack.multithread"), Qfalse);
    rb_hash_aset(env, rb_str_new2("rack.run_once"), Qfalse);

    retval = rb_protect(call_dispatch, env, &error);

    if (error) {
        goto fail;
    }

    if (TYPE(retval) == T_ARRAY) {
        if (RARRAY_LEN(retval) != 3) {
            goto fail;
        }
    }

    nxt_ruby_read_resp(task, retval, ctx);

    nxt_mp_destroy(run_ctx.mem_pool);

    return NXT_OK;

fail:

    nxt_mp_destroy(run_ctx.mem_pool);

    return NXT_ERROR;
}
