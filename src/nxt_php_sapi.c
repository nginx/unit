
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


static nxt_int_t nxt_php_init(nxt_task_t *task);

static nxt_int_t nxt_php_prepare_msg(nxt_task_t *task,
                      nxt_app_request_t *r, nxt_app_wmsg_t *wmsg);

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

extern nxt_int_t nxt_php_sapi_init(nxt_thread_t *thr, nxt_runtime_t *rt);


static sapi_module_struct  nxt_php_sapi_module =
{
    (char *) "cli-server",
    (char *) "nginext",

    nxt_php_startup,             /* startup */
    php_module_shutdown_wrapper, /* shutdown */

    NULL,                        /* activate */
    NULL,                        /* deactivate */

    nxt_php_unbuffered_write,    /* unbuffered write */
    NULL,                        /* flush */
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
} nxt_php_run_ctx_t;

nxt_inline nxt_int_t nxt_php_write(nxt_php_run_ctx_t *ctx,
                      const u_char *data, size_t len,
                      nxt_bool_t flush, nxt_bool_t last);


static nxt_str_t nxt_php_path;
static nxt_str_t nxt_php_root;
static nxt_str_t nxt_php_script;
static nxt_str_t nxt_php_index_name = nxt_string("index.php");


nxt_application_module_t  nxt_php_module = {
    nxt_php_init,
    nxt_php_prepare_msg,
    nxt_php_run
};


nxt_int_t
nxt_php_sapi_init(nxt_thread_t *thr, nxt_runtime_t *rt)
{
    char        **argv;
    u_char      *p;
    nxt_uint_t  i;

    argv = nxt_process_argv;

    while (*argv != NULL) {
        p = (u_char *) *argv++;

        if (nxt_strcmp(p, "--php") == 0) {
            if (*argv == NULL) {
                nxt_log_error(NXT_LOG_ERR, thr->log,
                              "no argument for option \"--php\"");
                return NXT_ERROR;
            }

            p = (u_char *) *argv;

            nxt_php_root.start = p;
            nxt_php_path.start = p;

            i = 0;

            for ( /* void */ ; p[i] != '\0'; i++) {
                if (p[i] == '/') {
                    nxt_php_script.start = &p[i];
                    nxt_php_root.length = i;
                }
            }

            nxt_php_path.length = i;
            nxt_php_script.length = i - nxt_php_root.length;

            nxt_log_error(NXT_LOG_INFO, thr->log,
                          "(ABS_MODE) php script \"%V\" root: \"%V\"",
                          &nxt_php_script, &nxt_php_root);

            sapi_startup(&nxt_php_sapi_module);
            nxt_php_startup(&nxt_php_sapi_module);

            nxt_app = &nxt_php_module;

            return NXT_OK;
        }

        if (nxt_strcmp(p, "--php-root") == 0) {
            if (*argv == NULL) {
                nxt_log_error(NXT_LOG_ERR, thr->log,
                              "no argument for option \"--php\"");
                return NXT_ERROR;
            }

            p = (u_char *) *argv;

            nxt_php_root.start = p;
            nxt_php_root.length = nxt_strlen(p);

            nxt_log_error(NXT_LOG_INFO, thr->log,
                          "(non ABS_MODE) php root: \"%V\"",
                          &nxt_php_root);

            sapi_startup(&nxt_php_sapi_module);
            nxt_php_startup(&nxt_php_sapi_module);

            nxt_app = &nxt_php_module;

            return NXT_OK;
        }
    }

    nxt_log_error(NXT_LOG_ERR, thr->log, "no option \"--php\" specified");

    return NXT_ERROR;
}


static nxt_int_t
nxt_php_init(nxt_task_t *task)
{
    return NXT_OK;
}


static nxt_int_t
nxt_php_read_request(nxt_task_t *task, nxt_app_rmsg_t *rmsg,
    nxt_php_run_ctx_t *ctx)
{
    u_char                    *p;
    size_t                    s;
    nxt_str_t                 script_name;
    nxt_app_request_header_t  *h;

    h = &ctx->r.header;

    nxt_app_msg_read_str(task, rmsg, &h->method);
    nxt_app_msg_read_str(task, rmsg, &h->path);
    h->path_no_query = h->path;

    nxt_app_msg_read_size(task, rmsg, &s);
    if (s > 0) {
        s--;
        h->query.start = h->path.start + s;
        h->query.length = h->path.length - s;

        if (s > 0) {
            h->path_no_query.length = s - 1;
        }
    }

    if (nxt_php_path.start == NULL) {
        if (h->path_no_query.start[h->path_no_query.length - 1] == '/') {
            script_name = nxt_php_index_name;
        } else {
            script_name.length = 0;
        }

        ctx->script.length = nxt_php_root.length + h->path_no_query.length +
                             script_name.length;
        ctx->script.start = nxt_mp_nget(ctx->mem_pool,
            ctx->script.length + 1);

        p = ctx->script.start;

        nxt_memcpy(p, nxt_php_root.start, nxt_php_root.length);
        p += nxt_php_root.length;

        nxt_memcpy(p, h->path_no_query.start, h->path_no_query.length);
        p += h->path_no_query.length;

        if (script_name.length > 0) {
            nxt_memcpy(p, script_name.start, script_name.length);
            p += script_name.length;
        }

        p[0] = '\0';
    } else {
        ctx->script = nxt_php_path;
    }

    nxt_app_msg_read_str(task, rmsg, &h->version);

    nxt_app_msg_read_str(task, rmsg, &h->cookie);
    nxt_app_msg_read_str(task, rmsg, &h->content_type);
    nxt_app_msg_read_str(task, rmsg, &h->content_length);

    nxt_app_msg_read_size(task, rmsg, &s);
    h->parsed_content_length = s;

    nxt_app_msg_read_str(task, rmsg, &ctx->r.body.preread);

    /* Further headers read moved to nxt_php_register_variables. */
    return NXT_OK;
}


static nxt_int_t
nxt_php_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg)
{
    nxt_int_t                 rc;
    nxt_http_field_t          *field;
    nxt_app_request_header_t  *h;

    static const nxt_str_t prefix = nxt_string("HTTP_");
    static const nxt_str_t eof = nxt_null_string;

    h = &r->header;

#define RC(S)                                                                 \
    do {                                                                      \
        rc = (S);                                                             \
        if (nxt_slow_path(rc != NXT_OK)) {                                    \
            goto fail;                                                        \
        }                                                                     \
    } while(0)

#define NXT_WRITE(N)                                                          \
    RC(nxt_app_msg_write_str(task, wmsg, N))

    /* TODO error handle, async mmap buffer assignment */

    NXT_WRITE(&h->method);
    NXT_WRITE(&h->path);

    if (h->query.start != NULL) {
        RC(nxt_app_msg_write_size(task, wmsg,
                                  h->query.start - h->path.start + 1));
    } else {
        RC(nxt_app_msg_write_size(task, wmsg, 0));
    }

    NXT_WRITE(&h->version);

    // PHP_SELF
    // SCRIPT_NAME
    // SCRIPT_FILENAME
    // DOCUMENT_ROOT

    NXT_WRITE(&h->cookie);
    NXT_WRITE(&h->content_type);
    NXT_WRITE(&h->content_length);

    RC(nxt_app_msg_write_size(task, wmsg, h->parsed_content_length));

    NXT_WRITE(&r->body.preread);

    nxt_list_each(field, h->fields) {
        RC(nxt_app_msg_write_prefixed_upcase(task, wmsg,
                                             &prefix, &field->name));
        NXT_WRITE(&field->value);

    } nxt_list_loop;

    /* end-of-headers mark */
    NXT_WRITE(&eof);

#undef NXT_WRITE
#undef RC

    return NXT_OK;

fail:

    return NXT_ERROR;
}


static nxt_int_t
nxt_php_run(nxt_task_t *task,
    nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *wmsg)
{
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

    nxt_php_read_request(task, rmsg, &run_ctx);

    SG(server_context) = &run_ctx;
    SG(request_info).request_uri = (char *) h->path.start;
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

    if (nxt_php_path.start != NULL) {
        nxt_debug(task, "run script %V in absolute mode", &nxt_php_path);
    } else {
        nxt_debug(task, "run script %V", &run_ctx.script);
    }

    if (nxt_slow_path(php_request_startup() == FAILURE)) {
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

    rc = nxt_app_msg_write_raw(ctx->task, ctx->wmsg, data, len);

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
    nxt_php_run_ctx_t  *ctx;

    ctx = SG(server_context);

    nxt_php_write(ctx, (u_char *) str, str_length, 1, 0);

    return str_length;
}


static int
nxt_php_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC)
{
    size_t               len;
    sapi_header_struct   *h;
    zend_llist_position  zpos;
    u_char               *status, buf[4096];
    nxt_php_run_ctx_t    *ctx;

    static const u_char default_repsonse[]
        = "HTTP/1.1 200 OK\r\n"
          "Server: nginext/0.1\r\n"
          "Content-Type: text/html; charset=UTF-8\r\n"
          "Connection: close\r\n"
          "\r\n";

    static const u_char default_headers[]
        = "Server: nginext/0.1\r\n"
          "Connection: close\r\n";

    static const u_char http_11[] = "HTTP/1.1 ";
    static const u_char cr_lf[] = "\r\n";
    static const u_char _200_ok[] = "200 OK";

    ctx = SG(server_context);

    if (SG(request_info).no_headers == 1) {
        nxt_php_write(ctx, default_repsonse, sizeof(default_repsonse) - 1,
                      1, 0);
        return SAPI_HEADER_SENT_SUCCESSFULLY;
    }

    nxt_php_write(ctx, http_11, sizeof(http_11) - 1, 0, 0);

    if (SG(sapi_headers).http_status_line) {
        status = (u_char *) SG(sapi_headers).http_status_line + 9;
        len = nxt_strlen(status);

        nxt_php_write(ctx, status, len, 0, 0);

    } else if (SG(sapi_headers).http_response_code) {
        status = nxt_sprintf(buf, buf + sizeof(buf), "%03d",
                        SG(sapi_headers).http_response_code);
        len = status - buf;

        nxt_php_write(ctx, buf, len, 0, 0);

    } else {
        nxt_php_write(ctx, _200_ok, sizeof(_200_ok) - 1, 0, 0);
    }

    nxt_php_write(ctx, cr_lf, sizeof(cr_lf) - 1, 0, 0);

    nxt_php_write(ctx, default_headers, sizeof(default_headers) - 1, 0, 0);

    h = zend_llist_get_first_ex(&sapi_headers->headers, &zpos);

    while (h) {
        nxt_php_write(ctx, (u_char *) h->header, h->header_len, 0, 0);
        nxt_php_write(ctx, cr_lf, sizeof(cr_lf) - 1, 0, 0);

        h = zend_llist_get_next_ex(&sapi_headers->headers, &zpos);
    }

    nxt_php_write(ctx, cr_lf, sizeof(cr_lf) - 1, 1, 0);

    return SAPI_HEADER_SENT_SUCCESSFULLY;
}


#ifdef NXT_PHP7
static size_t
nxt_php_read_post(char *buffer, size_t count_bytes TSRMLS_DC)
#else
static int
nxt_php_read_post(char *buffer, uint count_bytes TSRMLS_DC)
#endif
{
    off_t              rest;
    size_t             size;
/*
    ssize_t            n;
    nxt_err_t          err;
    nxt_php_ctx_t      *ctx;
    nxt_app_request_t  *r;
*/
    nxt_php_run_ctx_t         *ctx;
    nxt_app_request_body_t    *b;
    nxt_app_request_header_t  *h;

    ctx = SG(server_context);
    h = &ctx->r.header;
    b = &ctx->r.body;

    rest = h->parsed_content_length - SG(read_post_bytes);

    nxt_debug(ctx->task, "nxt_php_read_post %O", rest);

    if (rest == 0) {
        return 0;
    }

    size = 0;
#ifdef NXT_PHP7
    count_bytes = (size_t) nxt_min(rest, (off_t) count_bytes);
#else
    count_bytes = (uint) nxt_min(rest, (off_t) count_bytes);
#endif

    if (b->preread.length != 0) {
        size = nxt_min(b->preread.length, count_bytes);

        nxt_memcpy(buffer, b->preread.start, size);

        b->preread.length -= size;
        b->preread.start += size;

        if (size == count_bytes) {
            return size;
        }
    }

#if 0
    nxt_debug(ctx->task, "recv %z", (size_t) count_bytes - size);

    n = recv(r->event_conn->socket.fd, buffer + size, count_bytes - size, 0);

    if (nxt_slow_path(n <= 0)) {
        err = (n == 0) ? 0 : nxt_socket_errno;

        nxt_log_error(NXT_LOG_ERR, r->log, "recv(%d, %uz) failed %E",
                      r->event_conn->socket.fd, (size_t) count_bytes - size,
                      err);

        return size;
    }

    return size + n;
#endif
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
    nxt_str_t                 n, v;
    nxt_int_t                 rc;
    nxt_task_t                *task;
    nxt_php_run_ctx_t         *ctx;
    nxt_app_request_header_t  *h;

    ctx = SG(server_context);

    h = &ctx->r.header;
    task = ctx->task;

    nxt_debug(task, "php register variables");

    php_register_variable_safe((char *) "SERVER_PROTOCOL",
                          (char *) h->version.start,
                          h->version.length, track_vars_array TSRMLS_CC);

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
        php_register_variable_safe((char *) "PHP_SELF",
                                   (char *) nxt_php_script.start,
                                   nxt_php_script.length,
                                   track_vars_array TSRMLS_CC);

        php_register_variable_safe((char *) "SCRIPT_NAME",
                                   (char *) nxt_php_script.start,
                                   nxt_php_script.length,
                                   track_vars_array TSRMLS_CC);
    } else {
        php_register_variable_safe((char *) "PHP_SELF",
                                   (char *) h->path.start,
                                   h->path.length, track_vars_array TSRMLS_CC);

        php_register_variable_safe((char *) "SCRIPT_NAME",
                                   (char *) h->path.start,
                                   h->path.length, track_vars_array TSRMLS_CC);
    }

    php_register_variable_safe((char *) "SCRIPT_FILENAME",
                               (char *) ctx->script.start,
                               ctx->script.length,
                               track_vars_array TSRMLS_CC);

    php_register_variable_safe((char *) "DOCUMENT_ROOT",
                               (char *) nxt_php_root.start,
                               nxt_php_root.length,
                               track_vars_array TSRMLS_CC);

    php_register_variable_safe((char *) "REQUEST_METHOD",
                          (char *) h->method.start,
                          h->method.length, track_vars_array TSRMLS_CC);

    php_register_variable_safe((char *) "REQUEST_URI",
                          (char *) h->path.start,
                          h->path.length, track_vars_array TSRMLS_CC);

    if (h->query.start != NULL) {
        php_register_variable_safe((char *) "QUERY_STRING",
                          (char *) h->query.start,
                          h->query.length, track_vars_array TSRMLS_CC);
    }

    if (h->content_type.start != NULL) {
        php_register_variable_safe((char *) "CONTENT_TYPE",
                          (char *) h->content_type.start,
                          h->content_type.length, track_vars_array TSRMLS_CC);
    }

    if (h->content_length.start != NULL) {
        php_register_variable_safe((char *) "CONTENT_LENGTH",
                          (char *) h->content_length.start,
                          h->content_length.length,
                          track_vars_array TSRMLS_CC);
    }

    while (nxt_app_msg_read_str(task, ctx->rmsg, &n) == NXT_OK) {
        if (nxt_slow_path(n.length == 0)) {
            break;
        }

        rc = nxt_app_msg_read_str(task, ctx->rmsg, &v);
        if (nxt_slow_path(rc != NXT_OK)) {
            break;
        }

        php_register_variable_safe((char *) n.start,
                          (char *) v.start, v.length,
                          track_vars_array TSRMLS_CC);
    }
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
