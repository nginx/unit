
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
#include <nxt_application.h>


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
static int nxt_php_send_headers(sapi_headers_struct *sapi_headers);
static char *nxt_php_read_cookies(void);
static void nxt_php_register_variables(zval *track_vars_array);
static void nxt_php_log_message(char *message
#ifdef NXT_HAVE_PHP_LOG_MESSAGE_WITH_SYSLOG_TYPE
                                , int syslog_type_int
#endif
);

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
    0,                           /* php_ini_ignore_cwd */
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
    nxt_mp_t             *mem_pool;

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
nxt_php_strdup(nxt_str_t *dst, nxt_str_t *src)
{
    dst->start = malloc(src->length + 1);
    nxt_memcpy(dst->start, src->start, src->length);
    dst->start[src->length] = '\0';

    dst->length = src->length;
}

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
    nxt_string(PHP_VERSION),
    nxt_php_init,
    nxt_php_run,
};


static nxt_int_t
nxt_php_init(nxt_task_t *task, nxt_common_app_conf_t *conf)
{
    nxt_str_t           *root, *path, *script, *index;
    nxt_php_app_conf_t  *c;

    c = &conf->u.php;

    if (c->root.length == 0) {
        nxt_log_emerg(task->log, "php root is empty");
        return NXT_ERROR;
    }

    root = &nxt_php_root;
    path = &nxt_php_path;
    script = &nxt_php_script;
    index = &nxt_php_index;

    nxt_php_strdup(root, &c->root);

    nxt_php_str_trim_trail(root, '/');

    if (c->script.length > 0) {
        nxt_php_str_trim_lead(&c->script, '/');

        path->length = root->length + c->script.length + 1;
        path->start = malloc(path->length + 1);

        nxt_memcpy(path->start, root->start, root->length);
        path->start[root->length] = '/';

        nxt_memcpy(path->start + root->length + 1,
                   c->script.start, c->script.length);

        path->start[path->length] = '\0';


        script->length = c->script.length + 1;
        script->start = malloc(script->length + 1);
        script->start[0] = '/';
        nxt_memcpy(script->start + 1, c->script.start, c->script.length);
        script->start[script->length] = '\0';

        nxt_log_error(NXT_LOG_INFO, task->log,
                      "(ABS_MODE) php script \"%V\" root: \"%V\"",
                      script, root);

    } else {
        nxt_log_error(NXT_LOG_INFO, task->log,
                      "(non ABS_MODE) php root: \"%V\"", root);
    }

    if (c->index.length > 0) {
        nxt_php_strdup(index, &c->index);
    }

    sapi_startup(&nxt_php_sapi_module);
    nxt_php_startup(&nxt_php_sapi_module);

    return NXT_OK;
}


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
        }

        ctx->script.length = nxt_php_root.length + h->path.length +
                             script_name.length;
        ctx->script.start = nxt_mp_nget(ctx->mem_pool,
            ctx->script.length + 1);

        p = ctx->script.start;

        nxt_memcpy(p, nxt_php_root.start, nxt_php_root.length);
        p += nxt_php_root.length;

        nxt_memcpy(p, h->path.start, h->path.length);
        p += h->path.length;

        if (script_name.length > 0) {
            nxt_memcpy(p, script_name.start, script_name.length);
            p += script_name.length;
        }

        p[0] = '\0';

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

    if (nxt_php_root.length == 0) {
        return NXT_ERROR;
    }

    nxt_memzero(&run_ctx, sizeof(run_ctx));

    run_ctx.task = task;
    run_ctx.rmsg = rmsg;
    run_ctx.wmsg = wmsg;

    run_ctx.mem_pool = nxt_mp_create(1024, 128, 256, 32);

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
        goto fail;
    }

    php_execute_script(&file_handle TSRMLS_CC);
    php_request_shutdown(NULL);

    nxt_app_msg_flush(task, wmsg, 1);

    nxt_mp_destroy(run_ctx.mem_pool);

    return NXT_OK;

fail:

    nxt_mp_destroy(run_ctx.mem_pool);

    return NXT_ERROR;
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
        = "HTTP/1.1 200 OK\r\n"
          "Server: unit/" NXT_VERSION "\r\n"
          "Content-Type: text/html; charset=UTF-8\r\n"
          "Connection: close\r\n"
          "\r\n";

    static const u_char default_headers[]
        = "Server: unit/" NXT_VERSION "\r\n"
          "Connection: close\r\n";

    static const u_char http_11[] = "HTTP/1.1 ";
    static const u_char cr_lf[] = "\r\n";
    static const u_char _200_ok[] = "200 OK";

    ctx = SG(server_context);

#define RC(S)                                                                 \
    do {                                                                      \
        rc = (S);                                                             \
        if (nxt_slow_path(rc != NXT_OK)) {                                    \
            goto fail;                                                        \
        }                                                                     \
    } while(0)

    if (SG(request_info).no_headers == 1) {
        RC(nxt_php_write(ctx, default_repsonse, sizeof(default_repsonse) - 1,
                      1, 0));
        return SAPI_HEADER_SENT_SUCCESSFULLY;
    }

    if (SG(sapi_headers).http_status_line) {
        status = (u_char *) SG(sapi_headers).http_status_line;
        len = nxt_strlen(status);

        RC(nxt_php_write(ctx, status, len, 0, 0));

    } else if (SG(sapi_headers).http_response_code) {
        status = nxt_sprintf(buf, buf + sizeof(buf), "%03d",
                        SG(sapi_headers).http_response_code);
        len = status - buf;

        RC(nxt_php_write(ctx, http_11, sizeof(http_11) - 1, 0, 0));
        RC(nxt_php_write(ctx, buf, len, 0, 0));

    } else {
        RC(nxt_php_write(ctx, http_11, sizeof(http_11) - 1, 0, 0));
        RC(nxt_php_write(ctx, _200_ok, sizeof(_200_ok) - 1, 0, 0));
    }

    RC(nxt_php_write(ctx, cr_lf, sizeof(cr_lf) - 1, 0, 0));
    RC(nxt_php_write(ctx, default_headers, sizeof(default_headers) - 1, 0, 0));

    h = zend_llist_get_first_ex(&sapi_headers->headers, &zpos);

    while (h) {
        RC(nxt_php_write(ctx, (u_char *) h->header, h->header_len, 0, 0));
        RC(nxt_php_write(ctx, cr_lf, sizeof(cr_lf) - 1, 0, 0));

        h = zend_llist_get_next_ex(&sapi_headers->headers, &zpos);
    }

    RC(nxt_php_write(ctx, cr_lf, sizeof(cr_lf) - 1, 1, 0));

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
    nxt_str_t                 n, v;
    nxt_int_t                 rc;
    nxt_str_t                 host, server_name, server_port;
    nxt_task_t                *task;
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

    while (nxt_app_msg_read_str(task, ctx->rmsg, &n) == NXT_OK) {
        if (nxt_slow_path(n.length == 0)) {
            break;
        }

        rc = nxt_app_msg_read_str(task, ctx->rmsg, &v);
        if (nxt_slow_path(rc != NXT_OK)) {
            break;
        }

        NXT_PHP_SET(n.start, v);
    }

#undef NXT_PHP_SET
}


static void
nxt_php_log_message(char *message
#ifdef NXT_HAVE_PHP_LOG_MESSAGE_WITH_SYSLOG_TYPE
                                , int syslog_type_int
#endif
)
{
    return;
}
