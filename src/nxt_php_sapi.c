
/*
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include "php.h"
#include "SAPI.h"
#include "php_main.h"
#include "php_variables.h"

#include <nxt_main.h>
#include <nxt_application.h>


typedef struct {
    size_t     max_name;

    nxt_str_t  *cookie;
    nxt_str_t  *content_type;
    nxt_str_t  *content_length;

    nxt_str_t  script;
    nxt_str_t  query;

    size_t     script_name_len;

    off_t      content_length_n;
} nxt_php_ctx_t;


nxt_int_t nxt_php_init(nxt_thread_t *thr);
nxt_int_t nxt_php_request_init(nxt_app_request_t *r);
nxt_int_t nxt_php_request_header(nxt_app_request_t *r,
    nxt_app_header_field_t *field);
nxt_int_t nxt_php_handler(nxt_app_request_t *r);


nxt_int_t nxt_python_init();


static nxt_int_t nxt_php_opts(nxt_log_t *log);


static int nxt_php_startup(sapi_module_struct *sapi_module);
static int nxt_php_send_headers(sapi_headers_struct *sapi_headers);
static char *nxt_php_read_cookies(void);
static void nxt_php_register_variables(zval *track_vars_array);
static void nxt_php_log_message(char *message);

#define NXT_PHP7 1

#ifdef NXT_PHP7
static size_t nxt_php_unbuffered_write(const char *str,
    size_t str_length TSRMLS_DC);
static size_t nxt_php_read_post(char *buffer, size_t count_bytes TSRMLS_DC);
#else
static int nxt_php_unbuffered_write(const char *str, uint str_length TSRMLS_DC);
static int nxt_php_read_post(char *buffer, uint count_bytes TSRMLS_DC);
#endif


static sapi_module_struct  nxt_php_sapi_module =
{
    (char *) "cli-server",
    (char *) "nginman",

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

    NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, 0, 0, NULL, NULL, NULL,
    NULL, NULL, NULL, 0, NULL, NULL, NULL
};


static nxt_str_t nxt_php_path;
static nxt_str_t nxt_php_root;
static nxt_str_t nxt_php_script;


nxt_int_t
nxt_php_init(nxt_thread_t *thr)
{
    if (nxt_php_opts(thr->log)) {
        return NXT_ERROR;
    }

    sapi_startup(&nxt_php_sapi_module);
    nxt_php_startup(&nxt_php_sapi_module);

    return NXT_OK;
}


static nxt_int_t
nxt_php_opts(nxt_log_t *log)
{
    char        **argv;
    u_char      *p;
    nxt_uint_t  i;

    argv = nxt_process_argv;

    while (*argv != NULL) {
        p = (u_char *) *argv++;

        if (nxt_strcmp(p, "--php") == 0) {
            if (*argv == NULL) {
                nxt_log_error(NXT_LOG_ERR, log,
                              "no argument for option \"--php\"");
                return NXT_ERROR;
            }

            p = (u_char *) *argv;

            nxt_php_root.data = p;
            nxt_php_path.data = p;

            i = 0;

            for ( /* void */ ; p[i] != '\0'; i++) {
                if (p[i] == '/') {
                    nxt_php_script.data = &p[i];
                    nxt_php_root.len = i;
                }
            }

            nxt_php_path.len = i;
            nxt_php_script.len = i - nxt_php_root.len;

            nxt_log_error(NXT_LOG_INFO, log, "php script \"%V\" root: \"%V\"",
                          &nxt_php_script, &nxt_php_root);

            return NXT_OK;
        }
    }

    nxt_log_error(NXT_LOG_ERR, log, "no option \"--php\" specified");

    return NXT_ERROR;
}


nxt_int_t
nxt_php_request_init(nxt_app_request_t *r)
{
    nxt_php_ctx_t  *ctx;

    ctx = nxt_mem_zalloc(r->mem_pool, sizeof(nxt_php_ctx_t));
    if (nxt_slow_path(ctx == NULL)) {
        return NXT_ERROR;
    }

    r->ctx = ctx;

    return NXT_OK;
}



nxt_int_t
nxt_php_request_header(nxt_app_request_t *r, nxt_app_header_field_t *field)
{
    nxt_php_ctx_t  *ctx;

    static const u_char cookie[6] = "Cookie";
    static const u_char content_length[14] = "Content-Length";
    static const u_char content_type[12] = "Content-Type";

    ctx = r->ctx;

    ctx->max_name = nxt_max(ctx->max_name, field->name.len);

    if (field->name.len == sizeof(cookie)
        && nxt_memcasecmp(field->name.data, cookie, sizeof(cookie)) == 0)
    {
        ctx->cookie = &field->value;

    } else if (field->name.len == sizeof(content_length)
               && nxt_memcasecmp(field->name.data, content_length,
                                 sizeof(content_length)) == 0)
    {
        ctx->content_length = &field->value;
        ctx->content_length_n = nxt_off_t_parse(field->value.data,
                                                field->value.len);

    } else if (field->name.len == sizeof(content_type)
               && nxt_memcasecmp(field->name.data, content_type,
                                 sizeof(content_type)) == 0)
    {
        ctx->content_type = &field->value;
        field->value.data[field->value.len] = '\0';
    }

    return NXT_OK;
}


#define ABS_MODE 1


#if !ABS_MODE
static const u_char root[] = "/home/vbart/Development/tests/php/wordpress";
#endif


nxt_int_t
nxt_php_handler(nxt_app_request_t *r)
{
    u_char            *query;
#if !ABS_MODE
    u_char            *p;
#endif
    nxt_php_ctx_t     *ctx;
    zend_file_handle  file_handle;

#if ABS_MODE
    if (nxt_php_path.len == 0) {
        return NXT_ERROR;
    }
#endif

    r->header.path.data[r->header.path.len] = '\0';
    r->header.method.data[r->header.method.len] = '\0';

    ctx = r->ctx;

    query = nxt_memchr(r->header.path.data, '?', r->header.path.len);

    if (query != NULL) {
        ctx->script_name_len = query - r->header.path.data;

        ctx->query.data = query + 1;
        ctx->query.len = r->header.path.data + r->header.path.len
                         - ctx->query.data;

    } else {
        ctx->script_name_len = r->header.path.len;
    }

#if !ABS_MODE
    ctx->script.len = sizeof(root) - 1 + ctx->script_name_len;
    ctx->script.data = nxt_mem_nalloc(r->mem_pool, ctx->script.len + 1);

    if (nxt_slow_path(ctx->script.data == NULL)) {
        return NXT_ERROR;
    }

    p = nxt_cpymem(ctx->script.data, root, sizeof(root) - 1);
    p = nxt_cpymem(p, r->header.path.data, ctx->script_name_len);
    *p = '\0';
#endif

    SG(server_context) = r;
    SG(request_info).request_uri = (char *) r->header.path.data;
    SG(request_info).request_method = (char *) r->header.method.data;

    SG(request_info).proto_num = 1001;

    SG(request_info).query_string = (char *) ctx->query.data;
    SG(request_info).content_length = ctx->content_length_n;

    if (ctx->content_type != NULL) {
        SG(request_info).content_type = (char *) ctx->content_type->data;
    }

    SG(sapi_headers).http_response_code = 200;

    SG(request_info).path_translated = NULL;

    file_handle.type = ZEND_HANDLE_FILENAME;
#if ABS_MODE
    file_handle.filename = (char *) nxt_php_path.data;
#else
    file_handle.filename = (char *) ctx->script.data;
#endif
    file_handle.free_filename = 0;
    file_handle.opened_path = NULL;

#if ABS_MODE
    nxt_log_debug(r->log, "run script %V in absolute mode", &nxt_php_path);
#else
    nxt_log_debug(r->log, "run script %V", &ctx->script);
#endif

    if (nxt_slow_path(php_request_startup() == FAILURE)) {
        return NXT_ERROR;
    }

    php_execute_script(&file_handle TSRMLS_CC);
    php_request_shutdown(NULL);

    return NXT_OK;
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
    nxt_app_request_t  *r;

    r = SG(server_context);

    nxt_app_write(r, (u_char *) str, str_length);

    return str_length;
}


static int
nxt_php_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC)
{
    size_t               len;
    nxt_app_request_t    *r;
    sapi_header_struct   *h;
    zend_llist_position  zpos;
    u_char               *p, *status, buf[4096];

    static const u_char default_repsonse[]
        = "HTTP/1.1 200 OK\r\n"
          "Server: nginman/0.1\r\n"
          "Content-Type: text/html; charset=UTF-8\r\n"
          "Connection: close\r\n"
          "\r\n";

    static const u_char default_headers[]
        = "Server: nginman/0.1\r\n"
          "Connection: close\r\n";

    r = SG(server_context);

    if (SG(request_info).no_headers == 1) {
        nxt_app_write(r, default_repsonse, sizeof(default_repsonse) - 1);
        return SAPI_HEADER_SENT_SUCCESSFULLY;
    }

    if (SG(sapi_headers).http_status_line) {
        status = (u_char *) SG(sapi_headers).http_status_line + 9;
        len = nxt_strlen(status);

        p = nxt_cpymem(buf, "HTTP/1.1 ", sizeof("HTTP/1.1 ") - 1);
        p = nxt_cpymem(p, status, len);
        *p++ = '\r'; *p++ = '\n';

    } else if (SG(sapi_headers).http_response_code) {
        p = nxt_cpymem(buf, "HTTP/1.1 ", sizeof("HTTP/1.1 ") - 1);
        p = nxt_sprintf(p, buf + sizeof(buf), "%03d",
                        SG(sapi_headers).http_response_code);
        *p++ = '\r'; *p++ = '\n';

    } else {
        p = nxt_cpymem(buf, "HTTP/1.1 200 OK\r\n",
                       sizeof("HTTP/1.1 200 OK\r\n") - 1);
    }

    p = nxt_cpymem(p, default_headers, sizeof(default_headers) - 1);

    h = zend_llist_get_first_ex(&sapi_headers->headers, &zpos);

    while (h) {
        p = nxt_cpymem(p, h->header, h->header_len);
        *p++ = '\r'; *p++ = '\n';

        h = zend_llist_get_next_ex(&sapi_headers->headers, &zpos);
    }

    *p++ = '\r'; *p++ = '\n';

    nxt_app_write(r, buf, p - buf);

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
    ssize_t            n;
    nxt_err_t          err;
    nxt_php_ctx_t      *ctx;
    nxt_app_request_t  *r;

    r = SG(server_context);
    ctx = r->ctx;

    rest = ctx->content_length_n - SG(read_post_bytes);

    nxt_log_debug(r->log, "nxt_php_read_post %O", rest);

    if (rest == 0) {
        return 0;
    }

    size = 0;
#ifdef NXT_PHP7
    count_bytes = (size_t) nxt_min(rest, (off_t) count_bytes);
#else
    count_bytes = (uint) nxt_min(rest, (off_t) count_bytes);
#endif

    if (r->body_preread.len != 0) {
        size = nxt_min(r->body_preread.len, count_bytes);

        nxt_memcpy(buffer, r->body_preread.data, size);

        r->body_preread.len -= size;
        r->body_preread.data += size;

        if (size == count_bytes) {
            return size;
        }
    }

    nxt_log_debug(r->log, "recv %z", (size_t) count_bytes - size);

    n = recv(r->event_conn->socket.fd, buffer + size, count_bytes - size, 0);

    if (nxt_slow_path(n <= 0)) {
        err = (n == 0) ? 0 : nxt_socket_errno;

        nxt_log_error(NXT_LOG_ERR, r->log, "recv(%d, %uz) failed %E",
                      r->event_conn->socket.fd, (size_t) count_bytes - size,
                      err);

        return size;
    }

    return size + n;
}


static char *
nxt_php_read_cookies(TSRMLS_D)
{
    u_char             *p;
    nxt_php_ctx_t      *ctx;
    nxt_app_request_t  *r;

    r = SG(server_context);
    ctx = r->ctx;

    if (ctx->cookie == NULL) {
        return NULL;
    }

    p = ctx->cookie->data;
    p[ctx->cookie->len] = '\0';

    return (char *) p;
}


static void
nxt_php_register_variables(zval *track_vars_array TSRMLS_DC)
{
    u_char                  *var, *p, ch;
    nxt_uint_t              i, n;
    nxt_php_ctx_t           *ctx;
    nxt_app_request_t       *r;
    nxt_app_header_field_t  *fld;

    static const u_char prefix[5] = "HTTP_";

    r = SG(server_context);
    ctx = r->ctx;

    nxt_log_debug(r->log, "php register variables");

    php_register_variable_safe((char *) "PHP_SELF",
                               (char *) r->header.path.data,
                               ctx->script_name_len, track_vars_array TSRMLS_CC);

    php_register_variable_safe((char *) "SERVER_PROTOCOL",
                               (char *) r->header.version.data,
                               r->header.version.len, track_vars_array TSRMLS_CC);

#if ABS_MODE
    php_register_variable_safe((char *) "SCRIPT_NAME",
                               (char *) nxt_php_script.data,
                               nxt_php_script.len, track_vars_array TSRMLS_CC);

    php_register_variable_safe((char *) "SCRIPT_FILENAME",
                               (char *) nxt_php_path.data,
                               nxt_php_path.len, track_vars_array TSRMLS_CC);

    php_register_variable_safe((char *) "DOCUMENT_ROOT",
                               (char *) nxt_php_root.data,
                               nxt_php_root.len, track_vars_array TSRMLS_CC);
#else
    php_register_variable_safe((char *) "SCRIPT_NAME",
                               (char *) r->header.path.data,
                               ctx->script_name_len, track_vars_array TSRMLS_CC);

    php_register_variable_safe((char *) "SCRIPT_FILENAME",
                               (char *) ctx->script.data, ctx->script.len,
                               track_vars_array TSRMLS_CC);

    php_register_variable_safe((char *) "DOCUMENT_ROOT", (char *) root,
                               sizeof(root) - 1, track_vars_array TSRMLS_CC);
#endif

    php_register_variable_safe((char *) "REQUEST_METHOD",
                               (char *) r->header.method.data,
                               r->header.method.len, track_vars_array TSRMLS_CC);

    php_register_variable_safe((char *) "REQUEST_URI",
                               (char *) r->header.path.data,
                               r->header.path.len, track_vars_array TSRMLS_CC);

    if (ctx->query.data != NULL) {
        php_register_variable_safe((char *) "QUERY_STRING",
                                   (char *) ctx->query.data,
                                   ctx->query.len, track_vars_array TSRMLS_CC);
    }

    if (ctx->content_type != NULL) {
        php_register_variable_safe((char *) "CONTENT_TYPE",
                                   (char *) ctx->content_type->data,
                                   ctx->content_type->len, track_vars_array TSRMLS_CC);
    }

    if (ctx->content_length != NULL) {
        php_register_variable_safe((char *) "CONTENT_LENGTH",
                                   (char *) ctx->content_length->data,
                                   ctx->content_length->len, track_vars_array TSRMLS_CC);
    }

    var = nxt_mem_nalloc(r->mem_pool, sizeof(prefix) + ctx->max_name + 1);

    if (nxt_slow_path(var == NULL)) {
        return;
    }

    nxt_memcpy(var, prefix, sizeof(prefix));

    for (i = 0; i < r->header.fields_num; i++) {
        fld = &r->header.fields[i];
        p = var + sizeof(prefix);

        for (n = 0; n < fld->name.len; n++, p++) {

            ch = fld->name.data[n];

            if (ch >= 'a' && ch <= 'z') {
                *p = ch & ~0x20;
                continue;
            }

            if (ch == '-') {
                *p = '_';
                continue;
            }

            *p = ch;
        }

        *p = '\0';

        php_register_variable_safe((char *) var, (char *) fld->value.data,
                                   fld->value.len, track_vars_array TSRMLS_CC);
    }

    return;
}


static void
nxt_php_log_message(char *message TSRMLS_DC)
{
    return;
}
