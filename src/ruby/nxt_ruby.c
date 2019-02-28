/*
 * Copyright (C) Alexander Borisov
 * Copyright (C) NGINX, Inc.
 */

#include <ruby/nxt_ruby.h>

#include <nxt_unit.h>
#include <nxt_unit_request.h>


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
static void nxt_ruby_request_handler(nxt_unit_request_info_t *req);

static VALUE nxt_ruby_rack_app_run(VALUE arg);
static int nxt_ruby_read_request(VALUE hash_env);
nxt_inline void nxt_ruby_add_sptr(VALUE hash_env,
    const char *name, uint32_t name_len, nxt_unit_sptr_t *sptr, uint32_t len);
nxt_inline void nxt_ruby_add_str(VALUE hash_env,
    const char *name, uint32_t name_len, const char *str, uint32_t len);
static nxt_int_t nxt_ruby_rack_result_status(VALUE result);
static int nxt_ruby_rack_result_headers(VALUE result, nxt_int_t status);
static int nxt_ruby_hash_info(VALUE r_key, VALUE r_value, VALUE arg);
static int nxt_ruby_hash_add(VALUE r_key, VALUE r_value, VALUE arg);
static int nxt_ruby_rack_result_body(VALUE result);
static int nxt_ruby_rack_result_body_file_write(VALUE filepath);
static VALUE nxt_ruby_rack_result_body_each(VALUE body);

static void nxt_ruby_exception_log(nxt_task_t *task, uint32_t level,
    const char *desc);

static void nxt_ruby_atexit(void);


static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};

static VALUE               nxt_ruby_rackup;
static VALUE               nxt_ruby_call;
static VALUE               nxt_ruby_env;
static VALUE               nxt_ruby_io_input;
static VALUE               nxt_ruby_io_error;
static nxt_ruby_run_ctx_t  nxt_ruby_run_ctx;

NXT_EXPORT nxt_app_module_t  nxt_app_module = {
    sizeof(compat),
    compat,
    nxt_string("ruby"),
    ruby_version,
    NULL,
    nxt_ruby_init,
};


static nxt_int_t
nxt_ruby_init(nxt_task_t *task, nxt_common_app_conf_t *conf)
{
    int                   state, rc;
    VALUE                 dummy, res;
    nxt_unit_ctx_t        *unit_ctx;
    nxt_unit_init_t       ruby_unit_init;
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

    nxt_unit_default_init(task, &ruby_unit_init);

    ruby_unit_init.callbacks.request_handler = nxt_ruby_request_handler;

    unit_ctx = nxt_unit_init(&ruby_unit_init);
    if (nxt_slow_path(unit_ctx == NULL)) {
        return NXT_ERROR;
    }

    nxt_ruby_run_ctx.unit_ctx = unit_ctx;

    rc = nxt_unit_run(unit_ctx);

    nxt_ruby_atexit();

    nxt_ruby_run_ctx.unit_ctx = NULL;

    nxt_unit_done(unit_ctx);

    exit(rc);

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


static void
nxt_ruby_request_handler(nxt_unit_request_info_t *req)
{
    int    state;
    VALUE  res;

    nxt_ruby_run_ctx.req = req;

    res = rb_protect(nxt_ruby_rack_app_run, Qnil, &state);
    if (nxt_slow_path(res == Qnil || state != 0)) {
        nxt_ruby_exception_log(NULL, NXT_LOG_ERR,
                               "Failed to run ruby script");
    }
}


static VALUE
nxt_ruby_rack_app_run(VALUE arg)
{
    int        rc;
    VALUE      env, result;
    nxt_int_t  status;

    env = rb_hash_dup(nxt_ruby_env);

    rc = nxt_ruby_read_request(env);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_req_alert(nxt_ruby_run_ctx.req,
                           "Ruby: Failed to process incoming request");

        goto fail;
    }

    result = rb_funcall(nxt_ruby_rackup, nxt_ruby_call, 1, env);
    if (nxt_slow_path(TYPE(result) != T_ARRAY)) {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
                           "Ruby: Invalid response format from application");

        goto fail;
    }

    if (nxt_slow_path(RARRAY_LEN(result) != 3)) {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
                           "Ruby: Invalid response format from application. "
                           "Need 3 entries [Status, Headers, Body]");

        goto fail;
    }

    status = nxt_ruby_rack_result_status(result);
    if (nxt_slow_path(status < 0)) {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
                           "Ruby: Invalid response status from application.");

        goto fail;
    }

    rc = nxt_ruby_rack_result_headers(result, status);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    rc = nxt_ruby_rack_result_body(result);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    nxt_unit_request_done(nxt_ruby_run_ctx.req, rc);
    nxt_ruby_run_ctx.req = NULL;

    rb_hash_delete(env, rb_obj_id(env));

    return result;

fail:

    nxt_unit_request_done(nxt_ruby_run_ctx.req, NXT_UNIT_ERROR);
    nxt_ruby_run_ctx.req = NULL;

    rb_hash_delete(env, rb_obj_id(env));

    return Qnil;
}


static int
nxt_ruby_read_request(VALUE hash_env)
{
    uint32_t            i;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    r = nxt_ruby_run_ctx.req->request;

#define NL(S) (S), sizeof(S)-1

    nxt_ruby_add_sptr(hash_env, NL("REQUEST_METHOD"), &r->method,
                      r->method_length);
    nxt_ruby_add_sptr(hash_env, NL("REQUEST_URI"), &r->target,
                      r->target_length);
    nxt_ruby_add_sptr(hash_env, NL("PATH_INFO"), &r->path, r->path_length);
    if (r->query.offset) {
        nxt_ruby_add_sptr(hash_env, NL("QUERY_STRING"), &r->query,
                          r->query_length);
    }
    nxt_ruby_add_sptr(hash_env, NL("SERVER_PROTOCOL"), &r->version,
                      r->version_length);
    nxt_ruby_add_sptr(hash_env, NL("REMOTE_ADDR"), &r->remote,
                      r->remote_length);
    nxt_ruby_add_sptr(hash_env, NL("SERVER_ADDR"), &r->local, r->local_length);

    nxt_ruby_add_sptr(hash_env, NL("SERVER_NAME"), &r->server_name,
                      r->server_name_length);
    nxt_ruby_add_str(hash_env, NL("SERVER_PORT"), "80", 2);

    for (i = 0; i < r->fields_count; i++) {
        f = r->fields + i;

        nxt_ruby_add_sptr(hash_env, nxt_unit_sptr_get(&f->name), f->name_length,
                          &f->value, f->value_length);
    }

    if (r->content_length_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_length_field;

        nxt_ruby_add_sptr(hash_env, NL("CONTENT_LENGTH"),
                          &f->value, f->value_length);
    }

    if (r->content_type_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_type_field;

        nxt_ruby_add_sptr(hash_env, NL("CONTENT_TYPE"),
                          &f->value, f->value_length);
    }

#undef NL

    return NXT_UNIT_OK;
}


nxt_inline void
nxt_ruby_add_sptr(VALUE hash_env,
    const char *name, uint32_t name_len, nxt_unit_sptr_t *sptr, uint32_t len)
{
    char  *str;

    str = nxt_unit_sptr_get(sptr);

    rb_hash_aset(hash_env, rb_str_new(name, name_len), rb_str_new(str, len));
}


nxt_inline void
nxt_ruby_add_str(VALUE hash_env,
    const char *name, uint32_t name_len, const char *str, uint32_t len)
{
    rb_hash_aset(hash_env, rb_str_new(name, name_len), rb_str_new(str, len));
}


static nxt_int_t
nxt_ruby_rack_result_status(VALUE result)
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

    nxt_unit_req_error(nxt_ruby_run_ctx.req, "Ruby: Invalid response 'status' "
                       "format from application");

    return -2;
}


typedef struct {
    int       rc;
    uint32_t  fields;
    uint32_t  size;
} nxt_ruby_headers_info_t;


static int
nxt_ruby_rack_result_headers(VALUE result, nxt_int_t status)
{
    int                      rc;
    VALUE                    headers;
    nxt_ruby_headers_info_t  headers_info;

    headers = rb_ary_entry(result, 1);
    if (nxt_slow_path(TYPE(headers) != T_HASH)) {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
                           "Ruby: Invalid response 'headers' format from "
                           "application");

        return NXT_UNIT_ERROR;
    }

    rc = NXT_UNIT_OK;

    headers_info.rc = NXT_UNIT_OK;
    headers_info.fields = 0;
    headers_info.size = 0;

    rb_hash_foreach(headers, nxt_ruby_hash_info,
                    (VALUE) (uintptr_t) &headers_info);
    if (nxt_slow_path(headers_info.rc != NXT_UNIT_OK)) {
        return headers_info.rc;
    }

    rc = nxt_unit_response_init(nxt_ruby_run_ctx.req, status,
                                headers_info.fields, headers_info.size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return rc;
    }

    rb_hash_foreach(headers, nxt_ruby_hash_add, (VALUE) (uintptr_t) &rc);

    return rc;
}


static int
nxt_ruby_hash_info(VALUE r_key, VALUE r_value, VALUE arg)
{
    const char               *value, *value_end, *pos;
    nxt_ruby_headers_info_t  *headers_info;

    headers_info = (void *) (uintptr_t) arg;

    if (nxt_slow_path(TYPE(r_key) != T_STRING)) {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
                           "Ruby: Wrong header entry 'key' from application");

        goto fail;
    }

    if (nxt_slow_path(TYPE(r_value) != T_STRING)) {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
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
    int         *rc;
    uint32_t    key_len;
    const char  *value, *value_end, *pos;

    rc = (int *) (uintptr_t) arg;

    value = RSTRING_PTR(r_value);
    value_end = value + RSTRING_LEN(r_value);

    key_len = RSTRING_LEN(r_key);

    pos = value;

    for ( ;; ) {
        pos = strchr(pos, '\n');

        if (pos == NULL) {
            break;
        }

        *rc = nxt_unit_response_add_field(nxt_ruby_run_ctx.req,
                                          RSTRING_PTR(r_key), key_len,
                                          value, pos - value);
        if (nxt_slow_path(*rc != NXT_UNIT_OK)) {
            goto fail;
        }

        pos++;
        value = pos;
    }

    if (value <= value_end) {
        *rc = nxt_unit_response_add_field(nxt_ruby_run_ctx.req,
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
nxt_ruby_rack_result_body(VALUE result)
{
    int    rc;
    VALUE  fn, body;

    body = rb_ary_entry(result, 2);

    if (rb_respond_to(body, rb_intern("to_path"))) {

        fn = rb_funcall(body, rb_intern("to_path"), 0);
        if (nxt_slow_path(TYPE(fn) != T_STRING)) {
            nxt_unit_req_error(nxt_ruby_run_ctx.req,
                               "Ruby: Failed to get 'body' file path from "
                               "application");

            return NXT_UNIT_ERROR;
        }

        rc = nxt_ruby_rack_result_body_file_write(fn);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return rc;
        }

    } else if (rb_respond_to(body, rb_intern("each"))) {
        rb_iterate(rb_each, body, nxt_ruby_rack_result_body_each, 0);

    } else {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
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


static int
nxt_ruby_rack_result_body_file_write(VALUE filepath)
{
    int                   fd, rc;
    struct stat           finfo;
    nxt_ruby_rack_file_t  ruby_file;
    nxt_unit_read_info_t  read_info;

    fd = open(RSTRING_PTR(filepath), O_RDONLY, 0);
    if (nxt_slow_path(fd == -1)) {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
                           "Ruby: Failed to open content file \"%s\": %s (%d)",
                           RSTRING_PTR(filepath), strerror(errno), errno);

        return NXT_UNIT_ERROR;
    }

    rc = fstat(fd, &finfo);
    if (nxt_slow_path(rc == -1)) {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
                           "Ruby: Content file fstat(\"%s\") failed: %s (%d)",
                           RSTRING_PTR(filepath), strerror(errno), errno);

        close(fd);

        return NXT_UNIT_ERROR;
    }

    ruby_file.fd = fd;
    ruby_file.pos = 0;
    ruby_file.rest = finfo.st_size;

    read_info.read = nxt_ruby_rack_file_read;
    read_info.eof = ruby_file.rest == 0;
    read_info.buf_size = ruby_file.rest;
    read_info.data = &ruby_file;

    rc = nxt_unit_response_write_cb(nxt_ruby_run_ctx.req, &read_info);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
                           "Ruby: Failed to write content file.");
    }

    close(fd);

    return rc;
}


static VALUE
nxt_ruby_rack_result_body_each(VALUE body)
{
    int  rc;

    if (TYPE(body) != T_STRING) {
        return Qnil;
    }

    rc = nxt_unit_response_write(nxt_ruby_run_ctx.req, RSTRING_PTR(body),
                                 RSTRING_LEN(body));
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_req_error(nxt_ruby_run_ctx.req,
                           "Ruby: Failed to write 'body' from application");
    }

    return Qnil;
}


static void
nxt_ruby_exception_log(nxt_task_t *task, uint32_t level, const char *desc)
{
    int    i;
    VALUE  err, ary, eclass, msg;

    if (task != NULL) {
        nxt_log(task, level, "Ruby: %s", desc);

    } else {
        nxt_unit_log(nxt_ruby_run_ctx.unit_ctx, level, "Ruby: %s", desc);
    }

    err = rb_errinfo();
    if (nxt_slow_path(err == Qnil)) {
        return;
    }

    ary = rb_funcall(err, rb_intern("backtrace"), 0);
    if (nxt_slow_path(RARRAY_LEN(ary) == 0)) {
        return;
    }

    eclass = rb_class_name(rb_class_of(err));
    msg = rb_funcall(err, rb_intern("message"), 0);

    if (task != NULL) {
        nxt_log(task, level, "Ruby: %s: %s (%s)",
                RSTRING_PTR(RARRAY_PTR(ary)[0]),
                RSTRING_PTR(msg), RSTRING_PTR(eclass));

    } else {
        nxt_unit_log(nxt_ruby_run_ctx.unit_ctx, level, "Ruby: %s: %s (%s)",
                     RSTRING_PTR(RARRAY_PTR(ary)[0]),
                     RSTRING_PTR(msg), RSTRING_PTR(eclass));
    }

    for (i = 1; i < RARRAY_LEN(ary); i++) {
        if (task != NULL) {
            nxt_log(task, level, "from %s", RSTRING_PTR(RARRAY_PTR(ary)[i]));

        } else {
            nxt_unit_log(nxt_ruby_run_ctx.unit_ctx, level, "from %s",
                         RSTRING_PTR(RARRAY_PTR(ary)[i]));
        }
    }
}


static void
nxt_ruby_atexit(void)
{
    rb_gc_unregister_address(&nxt_ruby_io_input);
    rb_gc_unregister_address(&nxt_ruby_io_error);

    rb_gc_unregister_address(&nxt_ruby_rackup);
    rb_gc_unregister_address(&nxt_ruby_call);
    rb_gc_unregister_address(&nxt_ruby_env);

    ruby_cleanup(0);
}
