
/*
 * Copyright (C) Max Romanov
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include "php.h"
#include "SAPI.h"
#include "php_main.h"
#include "php_variables.h"

#include <nxt_main.h>
#include <nxt_router.h>


static nxt_int_t nxt_php_init(nxt_task_t *task, nxt_common_app_conf_t *conf);

static nxt_int_t nxt_php_run(nxt_task_t *task,
                      nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *wmsg);

#if PHP_MAJOR_VERSION >= 7
#   define NXT_PHP7 1
#   if PHP_MINOR_VERSION >= 1
#       define NXT_HAVE_PHP_LOG_MESSAGE_WITH_SYSLOG_TYPE 1
#   else
#       define NXT_HAVE_PHP_INTERRUPTS 1
#   endif
#   define NXT_HAVE_PHP_IGNORE_CWD 1
#else
#   define NXT_HAVE_PHP_INTERRUPTS 1
#   if PHP_MINOR_VERSION >= 4
#       define NXT_HAVE_PHP_IGNORE_CWD 1
#   endif
#endif

static int nxt_php_startup(sapi_module_struct *sapi_module);
static void nxt_php_set_options(nxt_task_t *task, nxt_conf_value_t *options,
    int type);
static nxt_int_t nxt_php_alter_option(nxt_str_t *name, nxt_str_t *value,
    int type);
static int nxt_php_send_headers(sapi_headers_struct *sapi_headers);
static char *nxt_php_read_cookies(void);
static void nxt_php_register_variables(zval *track_vars_array);
#ifdef NXT_HAVE_PHP_LOG_MESSAGE_WITH_SYSLOG_TYPE
static void nxt_php_log_message(char *message, int syslog_type_int);
#else
static void nxt_php_log_message(char *message);
#endif

#ifdef NXT_PHP7
static size_t nxt_php_unbuffered_write(const char *str,
    size_t str_length TSRMLS_DC);
static size_t nxt_php_read_post(char *buffer, size_t count_bytes TSRMLS_DC);
#else
static int nxt_php_unbuffered_write(const char *str, uint str_length TSRMLS_DC);
static int nxt_php_read_post(char *buffer, uint count_bytes TSRMLS_DC);
#endif

static void nxt_php_flush(void *server_context);


static sapi_module_struct  nxt_php_sapi_module =
{
    (char *) "cli-server",
    (char *) "unit",

    nxt_php_startup,             /* startup */
    php_module_shutdown_wrapper, /* shutdown */

    NULL,                        /* activate */
    NULL,                        /* deactivate */

    nxt_php_unbuffered_write,    /* unbuffered write */
    nxt_php_flush,               /* flush */
    NULL,                        /* get uid */
    NULL,                        /* getenv */

    php_error,                   /* error handler */

    NULL,                        /* header handler */
    nxt_php_send_headers,        /* send headers handler */
    NULL,                        /* send header handler */

    nxt_php_read_post,           /* read POST data */
    nxt_php_read_cookies,        /* read Cookies */

    nxt_php_register_variables,  /* register server variables */
    nxt_php_log_message,         /* log message */
    NULL,                        /* get request time */
    NULL,                        /* terminate process */

    NULL,                        /* php_ini_path_override */
#ifdef NXT_HAVE_PHP_INTERRUPTS
    NULL,                        /* block_interruptions */
    NULL,                        /* unblock_interruptions */
#endif
    NULL,                        /* default_post_reader */
    NULL,                        /* treat_data */
    NULL,                        /* executable_location */

    0,                           /* php_ini_ignore */
#ifdef NXT_HAVE_PHP_IGNORE_CWD
    1,                           /* php_ini_ignore_cwd */
#endif
    NULL,                        /* get_fd */

    NULL,                        /* force_http_10 */

    NULL,                        /* get_target_uid */
    NULL,                        /* get_target_gid */

    NULL,                        /* input_filter */

    NULL,                        /* ini_defaults */
    0,                           /* phpinfo_as_text */

    NULL,                        /* ini_entries */
    NULL,                        /* additional_functions */
    NULL                         /* input_filter_init */
};

typedef struct {
    nxt_task_t           *task;
    nxt_app_rmsg_t       *rmsg;
    nxt_app_request_t    r;
    nxt_str_t            script;
    nxt_app_wmsg_t       *wmsg;

    size_t               body_preread_size;
} nxt_php_run_ctx_t;

nxt_inline nxt_int_t nxt_php_write(nxt_php_run_ctx_t *ctx,
                      const u_char *data, size_t len,
                      nxt_bool_t flush, nxt_bool_t last);


static nxt_str_t nxt_php_path;
static nxt_str_t nxt_php_root;
static nxt_str_t nxt_php_script;
static nxt_str_t nxt_php_index = nxt_string("index.php");


static void
nxt_php_str_trim_trail(nxt_str_t *str, u_char t)
{
    while (str->length > 0 && str->start[str->length - 1] == t) {
        str->length--;
    }

    str->start[str->length] = '\0';
}


static void
nxt_php_str_trim_lead(nxt_str_t *str, u_char t)
{
    while (str->length > 0 && str->start[0] == t) {
        str->length--;
        str->start++;
    }
}

static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};


NXT_EXPORT nxt_application_module_t  nxt_app_module = {
    sizeof(compat),
    compat,
    nxt_string("php"),
    PHP_VERSION,
    nxt_php_init,
    nxt_php_run,
    NULL,
};


static nxt_task_t  *nxt_php_task;


nxt_inline u_char *
nxt_realpath(const void *c)
{
    return (u_char *) realpath(c, NULL);
}


static nxt_int_t
nxt_php_init(nxt_task_t *task, nxt_common_app_conf_t *conf)
{
    u_char              *p;
    nxt_str_t           rpath, ini_path;
    nxt_str_t           *root, *path, *script, *index;
    nxt_conf_value_t    *value;
    nxt_php_app_conf_t  *c;

    static nxt_str_t  file_str = nxt_string("file");
    static nxt_str_t  user_str = nxt_string("user");
    static nxt_str_t  admin_str = nxt_string("admin");

    nxt_php_task = task;

    c = &conf->u.php;

    if (c->root == NULL) {
        nxt_alert(task, "php root is empty");
        return NXT_ERROR;
    }

    root = &nxt_php_root;
    path = &nxt_php_path;
    script = &nxt_php_script;
    index = &nxt_php_index;

    root->start = nxt_realpath(c->root);
    if (nxt_slow_path(root->start == NULL)) {
        nxt_alert(task, "root realpath(%s) failed %E", c->root, nxt_errno);
        return NXT_ERROR;
    }

    root->length = nxt_strlen(root->start);

    nxt_php_str_trim_trail(root, '/');

    if (c->script.length > 0) {
        nxt_php_str_trim_lead(&c->script, '/');

        path->length = root->length + 1 + c->script.length;
        path->start = nxt_malloc(path->length + 1);
        if (nxt_slow_path(path->start == NULL)) {
            return NXT_ERROR;
        }

        p = nxt_cpymem(path->start, root->start, root->length);
        *p++ = '/';

        p = nxt_cpymem(p, c->script.start, c->script.length);
        *p = '\0';

        rpath.start = nxt_realpath(path->start);
        if (nxt_slow_path(rpath.start == NULL)) {
            nxt_alert(task, "script realpath(%V) failed %E", path, nxt_errno);
            return NXT_ERROR;
        }

        rpath.length = nxt_strlen(rpath.start);

        if (!nxt_str_start(&rpath, root->start, root->length)) {
            nxt_alert(task, "script is not under php root");
            return NXT_ERROR;
        }

        nxt_free(path->start);

        *path = rpath;

        script->length = c->script.length + 1;
        script->start = nxt_malloc(script->length);
        if (nxt_slow_path(script->start == NULL)) {
            return NXT_ERROR;
        }

        script->start[0] = '/';
        nxt_memcpy(script->start + 1, c->script.start, c->script.length);

        nxt_log_error(NXT_LOG_INFO, task->log,
                      "(ABS_MODE) php script \"%V\" root: \"%V\"",
                      script, root);

    } else {
        nxt_log_error(NXT_LOG_INFO, task->log,
                      "(non ABS_MODE) php root: \"%V\"", root);
    }

    if (c->index.length > 0) {
        index->length = c->index.length;
        index->start = nxt_malloc(index->length);
        if (nxt_slow_path(index->start == NULL)) {
            return NXT_ERROR;
        }

        nxt_memcpy(index->start, c->index.start, c->index.length);
    }

    sapi_startup(&nxt_php_sapi_module);

    if (c->options != NULL) {
        value = nxt_conf_get_object_member(c->options, &file_str, NULL);

        if (value != NULL) {
            nxt_conf_get_string(value, &ini_path);

            p = nxt_malloc(ini_path.length + 1);
            if (nxt_slow_path(p == NULL)) {
                return NXT_ERROR;
            }

            nxt_php_sapi_module.php_ini_path_override = (char *) p;

            p = nxt_cpymem(p, ini_path.start, ini_path.length);
            *p = '\0';
        }
    }

    nxt_php_startup(&nxt_php_sapi_module);

    if (c->options != NULL) {
        value = nxt_conf_get_object_member(c->options, &admin_str, NULL);
        nxt_php_set_options(task, value, ZEND_INI_SYSTEM);

        value = nxt_conf_get_object_member(c->options, &user_str, NULL);
        nxt_php_set_options(task, value, ZEND_INI_USER);
    }

    return NXT_OK;
}


static void
nxt_php_set_options(nxt_task_t *task, nxt_conf_value_t *options, int type)
{
    uint32_t          next;
    nxt_str_t         name, value;
    nxt_conf_value_t  *value_obj;

    if (options != NULL) {
        next = 0;

        for ( ;; ) {
            value_obj = nxt_conf_next_object_member(options, &name, &next);
            if (value_obj == NULL) {
                break;
            }

            nxt_conf_get_string(value_obj, &value);

            if (nxt_php_alter_option(&name, &value, type) != NXT_OK) {
                nxt_log(task, NXT_LOG_ERR,
                        "setting PHP option \"%V: %V\" failed", &name, &value);
            }
        }
    }
}


#if (NXT_PHP7)

static nxt_int_t
nxt_php_alter_option(nxt_str_t *name, nxt_str_t *value, int type)
{
    zend_string     *zs;
    zend_ini_entry  *ini_entry;

    ini_entry = zend_hash_str_find_ptr(EG(ini_directives),
                                       (char *) name->start, name->length);

    if (ini_entry == NULL) {
        return NXT_ERROR;
    }

    /* PHP exits on memory allocation errors. */
    zs = zend_string_init((char *) value->start, value->length, 1);

    if (ini_entry->on_modify
        && ini_entry->on_modify(ini_entry, zs, ini_entry->mh_arg1,
                                ini_entry->mh_arg2, ini_entry->mh_arg3,
                                ZEND_INI_STAGE_ACTIVATE)
           != SUCCESS)
    {
        zend_string_release(zs);
        return NXT_ERROR;
    }

    ini_entry->value = zs;
    ini_entry->modifiable = type;

    return NXT_OK;
}

#else  /* PHP 5. */

static nxt_int_t
nxt_php_alter_option(nxt_str_t *name, nxt_str_t *value, int type)
{
    char            *cstr;
    zend_ini_entry  *ini_entry;
    char            buf[256];

    if (nxt_slow_path(name->length >= sizeof(buf))) {
        return NXT_ERROR;
    }

    nxt_memcpy(buf, name->start, name->length);
    buf[name->length] = '\0';

    if (zend_hash_find(EG(ini_directives), buf, name->length + 1,
                       (void **) &ini_entry)
        == FAILURE)
    {
        return NXT_ERROR;
    }

    cstr = nxt_malloc(value->length + 1);
    if (nxt_slow_path(cstr == NULL)) {
        return NXT_ERROR;
    }

    nxt_memcpy(cstr, value->start, value->length);
    cstr[value->length] = '\0';

    if (ini_entry->on_modify
        && ini_entry->on_modify(ini_entry, cstr, value->length,
                                ini_entry->mh_arg1, ini_entry->mh_arg2,
                                ini_entry->mh_arg3, ZEND_INI_STAGE_ACTIVATE)
           != SUCCESS)
    {
        nxt_free(cstr);
        return NXT_ERROR;
    }

    ini_entry->value = cstr;
    ini_entry->value_length = value->length;
    ini_entry->modifiable = type;

    return NXT_OK;
}

#endif


static nxt_int_t
nxt_php_read_request(nxt_task_t *task, nxt_app_rmsg_t *rmsg,
    nxt_php_run_ctx_t *ctx)
{
    u_char                    *p;
    size_t                    s;
    nxt_int_t                 rc;
    nxt_str_t                 script_name;
    nxt_app_request_header_t  *h;

    h = &ctx->r.header;

#define RC(S)                                                                 \
    do {                                                                      \
        rc = (S);                                                             \
        if (nxt_slow_path(rc != NXT_OK)) {                                    \
            goto fail;                                                        \
        }                                                                     \
    } while(0)

#define NXT_READ(dst)                                                         \
    RC(nxt_app_msg_read_str(task, rmsg, (dst)))

    NXT_READ(&h->method);
    NXT_READ(&h->target);
    NXT_READ(&h->path);

    RC(nxt_app_msg_read_size(task, rmsg, &s));
    if (s > 0) {
        s--;
        h->query.start = h->target.start + s;
        h->query.length = h->target.length - s;

        if (h->path.start == NULL) {
            h->path.start = h->target.start;
            h->path.length = s - 1;
        }
    }

    if (h->path.start == NULL) {
        h->path = h->target;
    }

    if (nxt_php_path.start == NULL) {
        if (h->path.start[h->path.length - 1] == '/') {
            script_name = nxt_php_index;

        } else {
            script_name.length = 0;
            script_name.start = NULL;
        }

        ctx->script.length = nxt_php_root.length + h->path.length
                             + script_name.length;
        p = ctx->script.start = nxt_malloc(ctx->script.length + 1);
        if (nxt_slow_path(p == NULL)) {
            return NXT_ERROR;
        }

        p = nxt_cpymem(p, nxt_php_root.start, nxt_php_root.length);
        p = nxt_cpymem(p, h->path.start, h->path.length);

        if (script_name.length > 0) {
            p = nxt_cpymem(p, script_name.start, script_name.length);
        }

        *p = '\0';

    } else {
        ctx->script = nxt_php_path;
    }

    NXT_READ(&h->version);

    NXT_READ(&ctx->r.remote);
    NXT_READ(&ctx->r.local);

    NXT_READ(&h->host);
    NXT_READ(&h->cookie);
    NXT_READ(&h->content_type);
    NXT_READ(&h->content_length);

    RC(nxt_app_msg_read_size(task, rmsg, &s));
    h->parsed_content_length = s;

    RC(nxt_app_msg_read_size(task, ctx->rmsg, &ctx->body_preread_size));

#undef NXT_READ
#undef RC

    /* Further headers read moved to nxt_php_register_variables. */
    return NXT_OK;

fail:

    return rc;
}


static nxt_int_t
nxt_php_run(nxt_task_t *task,
    nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *wmsg)
{
    nxt_int_t                 rc;
    zend_file_handle          file_handle;
    nxt_php_run_ctx_t         run_ctx;
    nxt_app_request_header_t  *h;

    nxt_memzero(&run_ctx, sizeof(run_ctx));

    run_ctx.task = task;
    run_ctx.rmsg = rmsg;
    run_ctx.wmsg = wmsg;

    h = &run_ctx.r.header;

    rc = nxt_php_read_request(task, rmsg, &run_ctx);

    if (nxt_slow_path(rc != NXT_OK)) {
        goto fail;
    }

    SG(server_context) = &run_ctx;
    SG(request_info).request_uri = (char *) h->target.start;
    SG(request_info).request_method = (char *) h->method.start;

    SG(request_info).proto_num = 1001;

    SG(request_info).query_string = (char *) h->query.start;
    SG(request_info).content_length = h->parsed_content_length;

    if (h->content_type.start != NULL) {
        SG(request_info).content_type = (char *) h->content_type.start;
    }

    SG(sapi_headers).http_response_code = 200;

    SG(request_info).path_translated = NULL;

    file_handle.type = ZEND_HANDLE_FILENAME;
    file_handle.filename = (char *) run_ctx.script.start;
    file_handle.free_filename = 0;
    file_handle.opened_path = NULL;

    nxt_debug(task, "handle.filename = '%s'", run_ctx.script.start);

    if (nxt_php_path.start != NULL) {
        nxt_debug(task, "run script %V in absolute mode", &nxt_php_path);

    } else {
        nxt_debug(task, "run script %V", &run_ctx.script);
    }

    if (nxt_slow_path(php_request_startup() == FAILURE)) {
        nxt_debug(task, "php_request_startup() failed");
        rc = NXT_ERROR;
        goto fail;
    }

    php_execute_script(&file_handle TSRMLS_CC);
    php_request_shutdown(NULL);

    nxt_app_msg_flush(task, wmsg, 1);

    rc = NXT_OK;

fail:

    if (run_ctx.script.start != nxt_php_path.start) {
        nxt_free(run_ctx.script.start);
    }

    return rc;
}


nxt_inline nxt_int_t
nxt_php_write(nxt_php_run_ctx_t *ctx, const u_char *data, size_t len,
    nxt_bool_t flush, nxt_bool_t last)
{
    nxt_int_t  rc;

    if (len > 0) {
        rc = nxt_app_msg_write_raw(ctx->task, ctx->wmsg, data, len);

    } else {
        rc = NXT_OK;
    }

    if (flush || last) {
        rc = nxt_app_msg_flush(ctx->task, ctx->wmsg, last);
    }

    return rc;
}


static int
nxt_php_startup(sapi_module_struct *sapi_module)
{
   return php_module_startup(sapi_module, NULL, 0);
}


#ifdef NXT_PHP7
static size_t
nxt_php_unbuffered_write(const char *str, size_t str_length TSRMLS_DC)
#else
static int
nxt_php_unbuffered_write(const char *str, uint str_length TSRMLS_DC)
#endif
{
    nxt_int_t          rc;
    nxt_php_run_ctx_t  *ctx;

    ctx = SG(server_context);

    rc = nxt_php_write(ctx, (u_char *) str, str_length, 1, 0);

    if (nxt_fast_path(rc == NXT_OK)) {
        return str_length;
    }

    // TODO handle NXT_AGAIN
    php_handle_aborted_connection();
    return 0;
}


static void
nxt_php_flush(void *server_context)
{
    nxt_php_run_ctx_t  *ctx;

    ctx = server_context;

    (void) nxt_app_msg_flush(ctx->task, ctx->wmsg, 0);
}


static int
nxt_php_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC)
{
    size_t               len;
    u_char               *status, buf[64];
    nxt_int_t            rc;
    nxt_php_run_ctx_t    *ctx;
    sapi_header_struct   *h;
    zend_llist_position  zpos;

    static const u_char default_repsonse[]
        = "Status: 200\r\n"
          "\r\n";

    static const u_char status_200[] = "Status: 200";
    static const u_char cr_lf[] = "\r\n";

    ctx = SG(server_context);

#define RC(S)                                                                 \
    do {                                                                      \
        rc = (S);                                                             \
        if (nxt_slow_path(rc != NXT_OK)) {                                    \
            goto fail;                                                        \
        }                                                                     \
    } while(0)

    if (SG(request_info).no_headers == 1) {
        RC(nxt_php_write(ctx, default_repsonse, nxt_length(default_repsonse),
                         1, 0));
        return SAPI_HEADER_SENT_SUCCESSFULLY;
    }

    if (SG(sapi_headers).http_status_line) {
        status = (u_char *) SG(sapi_headers).http_status_line;
        len = nxt_strlen(status);

        if (len < 12) {
            goto fail;
        }

        RC(nxt_php_write(ctx, status_200, sizeof(status_200) - 4, 0, 0));
        RC(nxt_php_write(ctx, status + 9, 3, 0, 0));

    } else if (SG(sapi_headers).http_response_code) {
        status = nxt_sprintf(buf, buf + sizeof(buf), "%03d",
                        SG(sapi_headers).http_response_code);
        len = status - buf;

        RC(nxt_php_write(ctx, status_200, sizeof(status_200) - 4, 0, 0));
        RC(nxt_php_write(ctx, buf, len, 0, 0));

    } else {
        RC(nxt_php_write(ctx, status_200, nxt_length(status_200), 0, 0));
    }

    RC(nxt_php_write(ctx, cr_lf, nxt_length(cr_lf), 0, 0));

    h = zend_llist_get_first_ex(&sapi_headers->headers, &zpos);

    while (h) {
        RC(nxt_php_write(ctx, (u_char *) h->header, h->header_len, 0, 0));
        RC(nxt_php_write(ctx, cr_lf, nxt_length(cr_lf), 0, 0));

        h = zend_llist_get_next_ex(&sapi_headers->headers, &zpos);
    }

    RC(nxt_php_write(ctx, cr_lf, nxt_length(cr_lf), 1, 0));

#undef RC

    return SAPI_HEADER_SENT_SUCCESSFULLY;

fail:

    // TODO handle NXT_AGAIN
    return SAPI_HEADER_SEND_FAILED;
}


#ifdef NXT_PHP7
static size_t
nxt_php_read_post(char *buffer, size_t count_bytes TSRMLS_DC)
#else
static int
nxt_php_read_post(char *buffer, uint count_bytes TSRMLS_DC)
#endif
{
    size_t                    size, rest;
    nxt_php_run_ctx_t         *ctx;
    nxt_app_request_header_t  *h;

    ctx = SG(server_context);
    h = &ctx->r.header;

    rest = (size_t) h->parsed_content_length - SG(read_post_bytes);

    nxt_debug(ctx->task, "nxt_php_read_post %O", rest);

    if (rest == 0) {
        return 0;
    }

    rest = nxt_min(ctx->body_preread_size, (size_t) count_bytes);
    size = nxt_app_msg_read_raw(ctx->task, ctx->rmsg, buffer, rest);

    ctx->body_preread_size -= size;

    return size;
}


static char *
nxt_php_read_cookies(TSRMLS_D)
{
    nxt_php_run_ctx_t  *ctx;

    ctx = SG(server_context);

    nxt_debug(ctx->task, "nxt_php_read_cookies");

    return (char *) ctx->r.header.cookie.start;
}


static void
nxt_php_register_variables(zval *track_vars_array TSRMLS_DC)
{
    u_char                    *colon;
    size_t                    rest, size;
    nxt_str_t                 n, v;
    nxt_int_t                 rc;
    nxt_str_t                 host, server_name, server_port;
    nxt_buf_t                 *b, buf;
    nxt_task_t                *task;
    nxt_app_rmsg_t            *rmsg, rmsg_tmp;
    nxt_php_run_ctx_t         *ctx;
    nxt_app_request_header_t  *h;

    static nxt_str_t def_host = nxt_string("localhost");
    static nxt_str_t def_port = nxt_string("80");

    ctx = SG(server_context);

    h = &ctx->r.header;
    task = ctx->task;

    nxt_debug(task, "php register variables");

#define NXT_PHP_SET(n, v)                                                     \
    nxt_debug(task, "php: register %s='%V'", n, &v);                          \
    php_register_variable_safe((char *) (n), (char *) (v).start,              \
                               (v).length, track_vars_array TSRMLS_CC)        \

    NXT_PHP_SET("SERVER_SOFTWARE", nxt_server);

    NXT_PHP_SET("SERVER_PROTOCOL", h->version);

/*
 * 'SCRIPT_NAME'
 * Contains the current script's path. This is useful for pages which need to
 * point to themselves. The __FILE__ constant contains the full path and
 * filename of the current (i.e. included) file.
 */

/*
 * 'SCRIPT_FILENAME'
 * The absolute pathname of the currently executing script.
 */

/*
 * 'DOCUMENT_ROOT'
 * The document root directory under which the current script is executing,
 * as defined in the server's configuration file.
 */

    if (nxt_php_script.start != NULL) {
    // ABS_MODE
/*
 * 'PHP_SELF'
 * The filename of the currently executing script, relative to the document
 * root. For instance, $_SERVER['PHP_SELF'] in a script at the address
 * http://example.com/foo/bar.php would be /foo/bar.php. The __FILE__ constant
 * contains the full path and filename of the current (i.e. included) file.
 * If PHP is running as a command-line processor this variable contains the
 * script name since PHP 4.3.0. Previously it was not available.
 */
        NXT_PHP_SET("PHP_SELF", nxt_php_script);
        NXT_PHP_SET("SCRIPT_NAME", nxt_php_script);

    } else {
        NXT_PHP_SET("PHP_SELF", h->path);
        NXT_PHP_SET("SCRIPT_NAME", h->path);
    }

    NXT_PHP_SET("SCRIPT_FILENAME", ctx->script);
    NXT_PHP_SET("DOCUMENT_ROOT", nxt_php_root);

    NXT_PHP_SET("REQUEST_METHOD", h->method);
    NXT_PHP_SET("REQUEST_URI", h->target);

    if (h->query.start != NULL) {
        NXT_PHP_SET("QUERY_STRING", h->query);
    }

    if (h->content_type.start != NULL) {
        NXT_PHP_SET("CONTENT_TYPE", h->content_type);
    }

    if (h->content_length.start != NULL) {
        NXT_PHP_SET("CONTENT_LENGTH", h->content_length);
    }

    host = h->host;
    if (host.length == 0) {
        host = def_host;
    }

    server_name = host;
    colon = nxt_memchr(host.start, ':', host.length);

    if (colon != NULL) {
        server_name.length = colon - host.start;

        server_port.start = colon + 1;
        server_port.length = host.length - server_name.length - 1;

    } else {
        server_port = def_port;
    }

    NXT_PHP_SET("SERVER_NAME", server_name);
    NXT_PHP_SET("SERVER_PORT", server_port);

    NXT_PHP_SET("REMOTE_ADDR", ctx->r.remote);
    NXT_PHP_SET("SERVER_ADDR", ctx->r.local);

    rmsg = ctx->rmsg;
    rest = ctx->body_preread_size;

    if (rest != 0) {
        /* Skipping request body. */

        b = rmsg->buf;

        do {
            if (nxt_slow_path(b == NULL)) {
                return;
            }

            size = nxt_buf_mem_used_size(&b->mem);

            if (rest < size) {
                nxt_memcpy(&buf, b, NXT_BUF_MEM_SIZE);
                buf.mem.pos += rest;
                b = &buf;
                break;
            }

            rest -= size;
            b = b->next;

        } while (rest != 0);

        rmsg_tmp = *rmsg;
        rmsg_tmp.buf = b;
        rmsg = &rmsg_tmp;
    }

    while (nxt_app_msg_read_str(task, rmsg, &n) == NXT_OK) {
        if (nxt_slow_path(n.length == 0)) {
            break;
        }

        rc = nxt_app_msg_read_str(task, rmsg, &v);
        if (nxt_slow_path(rc != NXT_OK)) {
            break;
        }

        NXT_PHP_SET(n.start, v);
    }

#undef NXT_PHP_SET
}


#ifdef NXT_HAVE_PHP_LOG_MESSAGE_WITH_SYSLOG_TYPE
static void
nxt_php_log_message(char *message, int syslog_type_int)
#else
static void
nxt_php_log_message(char *message)
#endif
{
    nxt_log(nxt_php_task, NXT_LOG_NOTICE, "php message: %s", message);
}
