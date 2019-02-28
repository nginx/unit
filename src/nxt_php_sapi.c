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
#include <nxt_unit.h>
#include <nxt_unit_request.h>


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


typedef struct nxt_php_run_ctx_s  nxt_php_run_ctx_t;

#ifdef NXT_PHP7
typedef int (*nxt_php_disable_t)(char *p, size_t size);
#else
typedef int (*nxt_php_disable_t)(char *p, uint TSRMLS_DC);
#endif


static nxt_int_t nxt_php_init(nxt_task_t *task, nxt_common_app_conf_t *conf);

static void nxt_php_str_trim_trail(nxt_str_t *str, u_char t);
static void nxt_php_str_trim_lead(nxt_str_t *str, u_char t);
nxt_inline u_char *nxt_realpath(const void *c);

static void nxt_php_request_handler(nxt_unit_request_info_t *req);

static int nxt_php_startup(sapi_module_struct *sapi_module);
static void nxt_php_set_options(nxt_task_t *task, nxt_conf_value_t *options,
    int type);
static nxt_int_t nxt_php_alter_option(nxt_str_t *name, nxt_str_t *value,
    int type);
static void nxt_php_disable(nxt_task_t *task, const char *type,
    nxt_str_t *value, char **ptr, nxt_php_disable_t disable);
static int nxt_php_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC);
static char *nxt_php_read_cookies(TSRMLS_D);
static void nxt_php_set_sptr(nxt_unit_request_info_t *req, const char *name,
    nxt_unit_sptr_t *v, uint32_t len, zval *track_vars_array TSRMLS_DC);
nxt_inline void nxt_php_set_str(nxt_unit_request_info_t *req, const char *name,
    nxt_str_t *s, zval *track_vars_array TSRMLS_DC);
static void nxt_php_set_cstr(nxt_unit_request_info_t *req, const char *name,
    const char *str, uint32_t len, zval *track_vars_array TSRMLS_DC);
static void nxt_php_register_variables(zval *track_vars_array TSRMLS_DC);
#ifdef NXT_HAVE_PHP_LOG_MESSAGE_WITH_SYSLOG_TYPE
static void nxt_php_log_message(char *message, int syslog_type_int);
#else
static void nxt_php_log_message(char *message TSRMLS_DC);
#endif

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
    (char *) "unit",

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


struct nxt_php_run_ctx_s {
    char                       *cookie;
    nxt_str_t                  script;
    nxt_unit_request_info_t    *req;
};


static nxt_str_t nxt_php_path;
static nxt_str_t nxt_php_root;
static nxt_str_t nxt_php_script;
static nxt_str_t nxt_php_index = nxt_string("index.php");


static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};


NXT_EXPORT nxt_app_module_t  nxt_app_module = {
    sizeof(compat),
    compat,
    nxt_string("php"),
    PHP_VERSION,
    NULL,
    nxt_php_init,
};


static nxt_task_t  *nxt_php_task;
#ifdef ZTS
static void        ***tsrm_ls;
#endif


static nxt_int_t
nxt_php_init(nxt_task_t *task, nxt_common_app_conf_t *conf)
{
    u_char              *p;
    nxt_str_t           rpath, ini_path;
    nxt_str_t           *root, *path, *script, *index;
    nxt_port_t          *my_port, *main_port;
    nxt_runtime_t       *rt;
    nxt_unit_ctx_t      *unit_ctx;
    nxt_unit_init_t     php_init;
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

#ifdef ZTS
    tsrm_startup(1, 1, 0, NULL);
    tsrm_ls = ts_resource(0);
#endif

#if defined(NXT_PHP7) && defined(ZEND_SIGNALS)

#if (NXT_ZEND_SIGNAL_STARTUP)
    zend_signal_startup();
#elif defined(ZTS)
#error PHP is built with thread safety and broken signals.
#endif

#endif

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

    nxt_memzero(&php_init, sizeof(nxt_unit_init_t));

    rt = task->thread->runtime;

    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    if (nxt_slow_path(main_port == NULL)) {
        return NXT_ERROR;
    }

    my_port = nxt_runtime_port_find(rt, nxt_pid, 0);
    if (nxt_slow_path(my_port == NULL)) {
        return NXT_ERROR;
    }

    php_init.callbacks.request_handler = nxt_php_request_handler;
    php_init.ready_port.id.pid = main_port->pid;
    php_init.ready_port.id.id = main_port->id;
    php_init.ready_port.out_fd = main_port->pair[1];

    nxt_fd_blocking(task, main_port->pair[1]);

    php_init.ready_stream = my_port->process->init->stream;

    php_init.read_port.id.pid = my_port->pid;
    php_init.read_port.id.id = my_port->id;
    php_init.read_port.in_fd = my_port->pair[0];

    nxt_fd_blocking(task, my_port->pair[0]);

    php_init.log_fd = 2;

    unit_ctx = nxt_unit_init(&php_init);
    if (nxt_slow_path(unit_ctx == NULL)) {
        return NXT_ERROR;
    }

    nxt_unit_run(unit_ctx);

    nxt_unit_done(unit_ctx);

    exit(0);

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
                continue;
            }

            if (nxt_str_eq(&name, "disable_functions", 17)) {
                nxt_php_disable(task, "function", &value,
                                &PG(disable_functions),
                                zend_disable_function);
                continue;
            }

            if (nxt_str_eq(&name, "disable_classes", 15)) {
                nxt_php_disable(task, "class", &value,
                                &PG(disable_classes),
                                zend_disable_class);
                continue;
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
                                ini_entry->mh_arg3, ZEND_INI_STAGE_ACTIVATE
                                TSRMLS_CC)
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


static void
nxt_php_disable(nxt_task_t *task, const char *type, nxt_str_t *value,
    char **ptr, nxt_php_disable_t disable)
{
    char  c, *p, *start;

    p = nxt_malloc(value->length + 1);
    if (nxt_slow_path(p == NULL)) {
        return;
    }

    /*
     * PHP frees this memory on module shutdown.
     * See core_globals_dtor() for details.
     */
    *ptr = p;

    nxt_memcpy(p, value->start, value->length);
    p[value->length] = '\0';

    start = p;

    do {
        c = *p;

        if (c == ' ' || c == ',' || c == '\0') {

            if (p != start) {
                *p = '\0';

#ifdef NXT_PHP7
                if (disable(start, p - start)
#else
                if (disable(start, p - start TSRMLS_CC)
#endif
                    != SUCCESS)
                {
                    nxt_log(task, NXT_LOG_ERR,
                            "PHP: failed to disable \"%s\": no such %s",
                            start, type);
                }
            }

            start = p + 1;
        }

        p++;

    } while (c != '\0');
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


nxt_inline u_char *
nxt_realpath(const void *c)
{
    return (u_char *) realpath(c, NULL);
}


static void
nxt_php_request_handler(nxt_unit_request_info_t *req)
{
    int                 rc;
    u_char              *p;
    nxt_str_t           path, script_name;
    nxt_unit_field_t    *f;
    zend_file_handle    file_handle;
    nxt_php_run_ctx_t   run_ctx, *ctx;
    nxt_unit_request_t  *r;

    nxt_memzero(&run_ctx, sizeof(run_ctx));

    ctx = &run_ctx;
    ctx->req = req;

    r = req->request;

    path.length = r->path_length;
    path.start = nxt_unit_sptr_get(&r->path);

    if (nxt_php_path.start == NULL) {
        if (path.start[path.length - 1] == '/') {
            script_name = nxt_php_index;

        } else {
            script_name.length = 0;
            script_name.start = NULL;
        }

        ctx->script.length = nxt_php_root.length + path.length
                             + script_name.length;
        p = ctx->script.start = nxt_malloc(ctx->script.length + 1);
        if (nxt_slow_path(p == NULL)) {
            nxt_unit_request_done(req, NXT_UNIT_ERROR);

            return;
        }

        p = nxt_cpymem(p, nxt_php_root.start, nxt_php_root.length);
        p = nxt_cpymem(p, path.start, path.length);

        if (script_name.length > 0) {
            p = nxt_cpymem(p, script_name.start, script_name.length);
        }

        *p = '\0';

    } else {
        ctx->script = nxt_php_path;
    }

    SG(server_context) = ctx;
    SG(request_info).request_uri = nxt_unit_sptr_get(&r->target);
    SG(request_info).request_method = nxt_unit_sptr_get(&r->method);

    SG(request_info).proto_num = 1001;

    SG(request_info).query_string = r->query.offset
                                    ? nxt_unit_sptr_get(&r->query) : NULL;
    SG(request_info).content_length = r->content_length;

    if (r->content_type_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_type_field;

        SG(request_info).content_type = nxt_unit_sptr_get(&f->value);
    }

    if (r->cookie_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->cookie_field;

        ctx->cookie = nxt_unit_sptr_get(&f->value);
    }

    SG(sapi_headers).http_response_code = 200;

    SG(request_info).path_translated = NULL;

    file_handle.type = ZEND_HANDLE_FILENAME;
    file_handle.filename = (char *) ctx->script.start;
    file_handle.free_filename = 0;
    file_handle.opened_path = NULL;

    nxt_unit_req_debug(req, "handle.filename = '%s'", ctx->script.start);

    if (nxt_php_path.start != NULL) {
        nxt_unit_req_debug(req, "run script %.*s in absolute mode",
                           (int) nxt_php_path.length,
                           (char *) nxt_php_path.start);

    } else {
        nxt_unit_req_debug(req, "run script %.*s", (int) ctx->script.length,
                           (char *) ctx->script.start);
    }

#if (NXT_PHP7)
    if (nxt_slow_path(php_request_startup() == FAILURE)) {
#else
    if (nxt_slow_path(php_request_startup(TSRMLS_C) == FAILURE)) {
#endif
        nxt_unit_req_debug(req, "php_request_startup() failed");
        rc = NXT_UNIT_ERROR;

        goto fail;
    }

    rc = NXT_UNIT_OK;

    php_execute_script(&file_handle TSRMLS_CC);
    php_request_shutdown(NULL);

fail:

    nxt_unit_request_done(req, rc);

    if (ctx->script.start != nxt_php_path.start) {
        nxt_free(ctx->script.start);
    }
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
    int                rc;
    nxt_php_run_ctx_t  *ctx;

    ctx = SG(server_context);

    rc = nxt_unit_response_write(ctx->req, str, str_length);
    if (nxt_fast_path(rc == NXT_UNIT_OK)) {
        return str_length;
    }

    php_handle_aborted_connection();
    return 0;
}


static int
nxt_php_send_headers(sapi_headers_struct *sapi_headers TSRMLS_DC)
{
    int                      rc, fields_count;
    char                     *colon, *status_line, *value;
    uint16_t                 status;
    uint32_t                 resp_size;
    nxt_php_run_ctx_t        *ctx;
    sapi_header_struct       *h;
    zend_llist_position      zpos;
    nxt_unit_request_info_t  *req;

    ctx = SG(server_context);
    req = ctx->req;

    nxt_unit_req_debug(req, "nxt_php_send_headers");

    if (SG(request_info).no_headers == 1) {
        rc = nxt_unit_response_init(req, 200, 0, 0);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return SAPI_HEADER_SEND_FAILED;
        }

        return SAPI_HEADER_SENT_SUCCESSFULLY;
    }

    resp_size = 0;
    fields_count = zend_llist_count(&sapi_headers->headers);

    for (h = zend_llist_get_first_ex(&sapi_headers->headers, &zpos);
         h;
         h = zend_llist_get_next_ex(&sapi_headers->headers, &zpos))
    {
        resp_size += h->header_len;
    }

    if (SG(sapi_headers).http_status_line) {
        status_line = SG(sapi_headers).http_status_line;

        status = nxt_int_parse((u_char *) status_line + 9, 3);

    } else if (SG(sapi_headers).http_response_code) {
        status = SG(sapi_headers).http_response_code;

    } else {
        status = 200;
    }

    rc = nxt_unit_response_init(req, status, fields_count, resp_size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return SAPI_HEADER_SEND_FAILED;
    }

    for (h = zend_llist_get_first_ex(&sapi_headers->headers, &zpos);
         h;
         h = zend_llist_get_next_ex(&sapi_headers->headers, &zpos))
    {
        nxt_unit_req_debug(req, "header: %.*s", (int) h->header_len, h->header);

        colon = memchr(h->header, ':', h->header_len);
        if (nxt_slow_path(colon == NULL)) {
            nxt_unit_req_warn(req, "colon not found in header '%.*s'",
                              (int) h->header_len, h->header);
            continue;
        }

        value = colon + 1;
        while(isspace(*value)) {
            value++;
        }

        nxt_unit_response_add_field(req, h->header, colon - h->header,
                                    value,
                                    h->header_len - (value - h->header));
    }

    rc = nxt_unit_response_send(req);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_unit_req_debug(req, "failed to send response");

        return SAPI_HEADER_SEND_FAILED;
    }

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
    nxt_php_run_ctx_t  *ctx;

    ctx = SG(server_context);

    nxt_unit_req_debug(ctx->req, "nxt_php_read_post %d", (int) count_bytes);

    return nxt_unit_request_read(ctx->req, buffer, count_bytes);
}


static char *
nxt_php_read_cookies(TSRMLS_D)
{
    nxt_php_run_ctx_t  *ctx;

    ctx = SG(server_context);

    nxt_unit_req_debug(ctx->req, "nxt_php_read_cookies");

    return ctx->cookie;
}


static void
nxt_php_register_variables(zval *track_vars_array TSRMLS_DC)
{
    const char               *name;
    nxt_unit_field_t         *f, *f_end;
    nxt_php_run_ctx_t        *ctx;
    nxt_unit_request_t       *r;
    nxt_unit_request_info_t  *req;

    ctx = SG(server_context);

    req = ctx->req;
    r = req->request;

    nxt_unit_req_debug(req, "nxt_php_register_variables");

    php_register_variable_safe((char *) "SERVER_SOFTWARE",
                               (char *) nxt_server.start,
                               nxt_server.length, track_vars_array TSRMLS_CC);

    nxt_php_set_sptr(req, "SERVER_PROTOCOL", &r->version, r->version_length,
                     track_vars_array TSRMLS_CC);

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
        nxt_php_set_str(req, "PHP_SELF", &nxt_php_script,
                        track_vars_array TSRMLS_CC);
        nxt_php_set_str(req, "SCRIPT_NAME", &nxt_php_script,
                        track_vars_array TSRMLS_CC);

    } else {
        nxt_php_set_sptr(req, "PHP_SELF", &r->path, r->path_length,
                         track_vars_array TSRMLS_CC);
        nxt_php_set_sptr(req, "SCRIPT_NAME", &r->path, r->path_length,
                         track_vars_array TSRMLS_CC);
    }

    nxt_php_set_str(req, "SCRIPT_FILENAME", &ctx->script,
                    track_vars_array TSRMLS_CC);
    nxt_php_set_str(req, "DOCUMENT_ROOT", &nxt_php_root,
                    track_vars_array TSRMLS_CC);

    nxt_php_set_sptr(req, "REQUEST_METHOD", &r->method, r->method_length,
                     track_vars_array TSRMLS_CC);
    nxt_php_set_sptr(req, "REQUEST_URI", &r->target, r->target_length,
                     track_vars_array TSRMLS_CC);
    if (r->query.offset) {
        nxt_php_set_sptr(req, "QUERY_STRING", &r->query, r->query_length,
                         track_vars_array TSRMLS_CC);
    }

    nxt_php_set_sptr(req, "REMOTE_ADDR", &r->remote, r->remote_length,
                     track_vars_array TSRMLS_CC);
    nxt_php_set_sptr(req, "SERVER_ADDR", &r->local, r->local_length,
                     track_vars_array TSRMLS_CC);

    nxt_php_set_sptr(req, "SERVER_NAME", &r->server_name, r->server_name_length,
                     track_vars_array TSRMLS_CC);
    nxt_php_set_cstr(req, "SERVER_PORT", "80", 2, track_vars_array TSRMLS_CC);

    f_end = r->fields + r->fields_count;
    for (f = r->fields; f < f_end; f++) {
        name = nxt_unit_sptr_get(&f->name);

        nxt_php_set_sptr(req, name, &f->value, f->value_length,
                         track_vars_array TSRMLS_CC);
    }

    if (r->content_length_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_length_field;

        nxt_php_set_sptr(req, "CONTENT_LENGTH", &f->value, f->value_length,
                         track_vars_array TSRMLS_CC);
    }

    if (r->content_type_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_type_field;

        nxt_php_set_sptr(req, "CONTENT_TYPE", &f->value, f->value_length,
                         track_vars_array TSRMLS_CC);
    }
}


static void
nxt_php_set_sptr(nxt_unit_request_info_t *req, const char *name,
    nxt_unit_sptr_t *v, uint32_t len, zval *track_vars_array TSRMLS_DC)
{
    char  *str;

    str = nxt_unit_sptr_get(v);

    nxt_unit_req_debug(req, "php: register %s='%.*s'", name, (int) len, str);

    php_register_variable_safe((char *) name, str, len,
                               track_vars_array TSRMLS_CC);
}


nxt_inline void
nxt_php_set_str(nxt_unit_request_info_t *req, const char *name,
    nxt_str_t *s, zval *track_vars_array TSRMLS_DC)
{
    nxt_php_set_cstr(req, name, (char *) s->start, s->length,
                     track_vars_array TSRMLS_CC);
}


static void
nxt_php_set_cstr(nxt_unit_request_info_t *req, const char *name,
    const char *cstr, uint32_t len, zval *track_vars_array TSRMLS_DC)
{
    if (nxt_slow_path(cstr == NULL)) {
        return;
    }

    nxt_unit_req_debug(req, "php: register %s='%.*s'", name, (int) len, cstr);

    php_register_variable_safe((char *) name, (char *) cstr, len,
                               track_vars_array TSRMLS_CC);
}


#ifdef NXT_HAVE_PHP_LOG_MESSAGE_WITH_SYSLOG_TYPE
static void
nxt_php_log_message(char *message, int syslog_type_int)
#else
static void
nxt_php_log_message(char *message TSRMLS_DC)
#endif
{
    nxt_log(nxt_php_task, NXT_LOG_NOTICE, "php message: %s", message);
}
