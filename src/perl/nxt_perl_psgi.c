
/*
 * Copyright (C) Alexander Borisov
 * Copyright (C) NGINX, Inc.
 */

#include <perl/nxt_perl_psgi_layer.h>

#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_runtime.h>
#include <nxt_application.h>
#include <nxt_file.h>


typedef struct {
    PerlInterpreter  *my_perl;

    nxt_task_t       *task;
    nxt_app_rmsg_t   *rmsg;
    nxt_app_wmsg_t   *wmsg;

    size_t           body_preread_size;
} nxt_perl_psgi_input_t;


nxt_inline nxt_int_t nxt_perl_psgi_write(nxt_task_t *task, nxt_app_wmsg_t *wmsg,
    const u_char *data, size_t len,
    nxt_bool_t flush, nxt_bool_t last);

nxt_inline nxt_int_t nxt_perl_psgi_http_write_status_str(nxt_task_t *task,
    nxt_app_wmsg_t *wmsg, nxt_str_t *http_status);

static long nxt_perl_psgi_io_input_read(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length);
static long nxt_perl_psgi_io_input_write(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const void *vbuf, size_t length);
static long nxt_perl_psgi_io_input_flush(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg);

static long nxt_perl_psgi_io_error_read(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length);
static long nxt_perl_psgi_io_error_write(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const void *vbuf, size_t length);
static long nxt_perl_psgi_io_error_flush(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg);

/*
static void nxt_perl_psgi_xs_core_global_changes(PerlInterpreter *my_perl,
    const char *core, const char *sub, XSUBADDR_t sub_addr);
*/

static void nxt_perl_psgi_xs_init(pTHX);

static SV *nxt_perl_psgi_call_var_application(PerlInterpreter *my_perl,
    SV *env, nxt_task_t *task);

/* For currect load XS modules */
EXTERN_C void boot_DynaLoader(pTHX_ CV *cv);

static nxt_int_t nxt_perl_psgi_io_input_init(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg);
static nxt_int_t nxt_perl_psgi_io_error_init(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg);

static PerlInterpreter *nxt_perl_psgi_interpreter_init(nxt_task_t *task,
    char *script);

nxt_inline nxt_int_t nxt_perl_psgi_env_append_str(PerlInterpreter *my_perl,
    HV *hash_env, const char *name, nxt_str_t *str);
nxt_inline nxt_int_t nxt_perl_psgi_env_append(PerlInterpreter *my_perl,
    HV *hash_env, const char *name, void *value);

static SV *nxt_perl_psgi_env_create(PerlInterpreter *my_perl, nxt_task_t *task,
    nxt_app_rmsg_t *rmsg, size_t *body_preread_size);

nxt_inline nxt_int_t nxt_perl_psgi_read_add_env(PerlInterpreter *my_perl,
    nxt_task_t *task, nxt_app_rmsg_t *rmsg, HV *hash_env,
    const char *name, nxt_str_t *str);

static u_char *nxt_perl_psgi_module_create(nxt_task_t *task,
    const char *script);

static nxt_str_t nxt_perl_psgi_result_status(PerlInterpreter *my_perl,
    SV *result);
static nxt_int_t nxt_perl_psgi_result_head(PerlInterpreter *my_perl,
    SV *sv_head, nxt_task_t *task, nxt_app_wmsg_t *wmsg);
static nxt_int_t nxt_perl_psgi_result_body(PerlInterpreter *my_perl,
    SV *result, nxt_task_t *task, nxt_app_wmsg_t *wmsg);
static nxt_int_t nxt_perl_psgi_result_body_ref(PerlInterpreter *my_perl,
    SV *sv_body, nxt_task_t *task, nxt_app_wmsg_t *wmsg);
static nxt_int_t nxt_perl_psgi_result_array(PerlInterpreter *my_perl,
    SV *result, nxt_task_t *task, nxt_app_wmsg_t *wmsg);

static nxt_int_t nxt_perl_psgi_init(nxt_task_t *task,
    nxt_common_app_conf_t *conf);
static nxt_int_t nxt_perl_psgi_run(nxt_task_t *task,
    nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *wmsg);
static void nxt_perl_psgi_atexit(nxt_task_t *task);

typedef SV *(*nxt_perl_psgi_callback_f)(PerlInterpreter *my_perl,
    SV *env, nxt_task_t *task);

static SV                      *nxt_perl_psgi_app;
static PerlInterpreter         *nxt_perl_psgi;
static nxt_perl_psgi_io_arg_t  nxt_perl_psgi_arg_input, nxt_perl_psgi_arg_error;

static uint32_t  nxt_perl_psgi_compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};

NXT_EXPORT nxt_application_module_t  nxt_app_module = {
    sizeof(nxt_perl_psgi_compat),
    nxt_perl_psgi_compat,
    nxt_string("perl"),
    PERL_VERSION_STRING,
    nxt_perl_psgi_init,
    nxt_perl_psgi_run,
    nxt_perl_psgi_atexit,
};


nxt_inline nxt_int_t
nxt_perl_psgi_write(nxt_task_t *task, nxt_app_wmsg_t *wmsg,
    const u_char *data, size_t len,
    nxt_bool_t flush, nxt_bool_t last)
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


nxt_inline nxt_int_t
nxt_perl_psgi_http_write_status_str(nxt_task_t *task, nxt_app_wmsg_t *wmsg,
    nxt_str_t *http_status)
{
    nxt_int_t  rc;

    rc = NXT_OK;

#define RC_WRT(DATA, DATALEN, FLUSH)                       \
    do {                                                   \
        rc = nxt_perl_psgi_write(task, wmsg, DATA,         \
                    DATALEN, FLUSH, 0);                    \
        if (nxt_slow_path(rc != NXT_OK))                   \
            return rc;                                     \
                                                           \
    } while (0)

    RC_WRT((const u_char *) "Status: ", nxt_length("Status: "), 0);
    RC_WRT(http_status->start, http_status->length, 0);
    RC_WRT((u_char *) "\r\n", nxt_length("\r\n"), 0);

#undef RC_WRT

    return rc;
}


static long
nxt_perl_psgi_io_input_read(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length)
{
    size_t                 copy_size;
    nxt_perl_psgi_input_t  *input;

    input = (nxt_perl_psgi_input_t *) arg->ctx;

    if (input->body_preread_size == 0) {
        return 0;
    }

    copy_size = nxt_min(length, input->body_preread_size);
    copy_size = nxt_app_msg_read_raw(input->task, input->rmsg,
                                     vbuf, copy_size);

    input->body_preread_size -= copy_size;

    return copy_size;
}


static long
nxt_perl_psgi_io_input_write(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const void *vbuf, size_t length)
{
    return 0;
}


static long
nxt_perl_psgi_io_input_flush(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg)
{
    return 0;
}


static long
nxt_perl_psgi_io_error_read(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length)
{
    return 0;
}


static long
nxt_perl_psgi_io_error_write(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const void *vbuf, size_t length)
{
    nxt_perl_psgi_input_t *input;

    input = (nxt_perl_psgi_input_t *) arg->ctx;
    nxt_log_error(NXT_LOG_ERR, input->task->log, "Perl: %s", vbuf);

    return (long) length;
}


static long
nxt_perl_psgi_io_error_flush(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg)
{
    return 0;
}


/* In the future it will be necessary to change some Perl functions. */
/*
static void
nxt_perl_psgi_xs_core_global_changes(PerlInterpreter *my_perl,
    const char *core, const char *sub, XSUBADDR_t sub_addr)
{
    GV  *gv;

    gv = gv_fetchpv(core, TRUE, SVt_PVCV);

#ifdef MUTABLE_CV
    GvCV_set(gv, MUTABLE_CV(SvREFCNT_inc(get_cv(sub, TRUE))));
#else
    GvCV_set(gv, (CV *) (SvREFCNT_inc(get_cv(sub, TRUE))));
#endif
    GvIMPORTED_CV_on(gv);

    newXS(sub, sub_addr, __FILE__);
}
*/


XS(XS_NGINX__Unit__PSGI_exit);
XS(XS_NGINX__Unit__PSGI_exit)
{
    I32 ax = POPMARK;
    Perl_croak(aTHX_ (char *) NULL);
    XSRETURN_EMPTY;
}


static void
nxt_perl_psgi_xs_init(pTHX)
{
/*
    nxt_perl_psgi_xs_core_global_changes(my_perl, "CORE::GLOBAL::exit",
                                         "NGINX::Unit::PSGI::exit",
                                         XS_NGINX__Unit__PSGI_exit);
*/
    nxt_perl_psgi_layer_stream_init(aTHX);

    /* DynaLoader for Perl modules who use XS */
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);
}


static SV *
nxt_perl_psgi_call_var_application(PerlInterpreter *my_perl,
    SV *env, nxt_task_t *task)
{
    SV  *result;

    dSP;

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);
    XPUSHs(env);
    PUTBACK;

    call_sv(nxt_perl_psgi_app, G_EVAL|G_SCALAR);

    SPAGAIN;

    if (SvTRUE(ERRSV)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: Failed to run Perl Application: \n%s",
                      SvPV_nolen(ERRSV));
    }

    result = POPs;
    SvREFCNT_inc(result);

    PUTBACK;
    FREETMPS;
    LEAVE;

    return result;
}


static u_char *
nxt_perl_psgi_module_create(nxt_task_t *task, const char *script)
{
    u_char  *buf, *p;
    size_t  length;

    static nxt_str_t  prefix = nxt_string(
        "package NGINX::Unit::Sandbox;"
        "{my $app = do \""
    );

    static nxt_str_t  suffix = nxt_string_zero(
        "\";"
        "unless ($app) {"
        "    if($@ || $1) {die $@ || $1}"
        "    else {die \"File not found or compilation error.\"}"
        "} "
        "return $app}"
    );

    length = strlen(script);

    buf = nxt_malloc(prefix.length + length + suffix.length);

    if (nxt_slow_path(buf == NULL)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: Failed to allocate memory "
                      "for Perl script file %s", script);
        return NULL;
    }

    p = nxt_cpymem(buf, prefix.start, prefix.length);
    p = nxt_cpymem(p, script, length);
    nxt_memcpy(p, suffix.start, suffix.length);

    return buf;
}


static nxt_int_t
nxt_perl_psgi_io_input_init(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg)
{
    SV      *io;
    PerlIO  *fp;

    fp = nxt_perl_psgi_layer_stream_fp_create(aTHX_ arg, "r");

    if (nxt_slow_path(fp == NULL)) {
        return NXT_ERROR;
    }

    io = nxt_perl_psgi_layer_stream_io_create(aTHX_ fp);

    if (nxt_slow_path(io == NULL)) {
        nxt_perl_psgi_layer_stream_fp_destroy(aTHX_ fp);
        return NXT_ERROR;
    }

    arg->io = io;
    arg->fp = fp;
    arg->flush = nxt_perl_psgi_io_input_flush;
    arg->read = nxt_perl_psgi_io_input_read;
    arg->write = nxt_perl_psgi_io_input_write;

    return NXT_OK;
}


static nxt_int_t
nxt_perl_psgi_io_error_init(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg)
{
    SV      *io;
    PerlIO  *fp;

    fp = nxt_perl_psgi_layer_stream_fp_create(aTHX_ arg, "w");

    if (nxt_slow_path(fp == NULL)) {
        return NXT_ERROR;
    }

    io = nxt_perl_psgi_layer_stream_io_create(aTHX_ fp);

    if (nxt_slow_path(io == NULL)) {
        nxt_perl_psgi_layer_stream_fp_destroy(aTHX_ fp);
        return NXT_ERROR;
    }

    arg->io = io;
    arg->fp = fp;
    arg->flush = nxt_perl_psgi_io_error_flush;
    arg->read = nxt_perl_psgi_io_error_read;
    arg->write = nxt_perl_psgi_io_error_write;

    return NXT_OK;
}


static PerlInterpreter *
nxt_perl_psgi_interpreter_init(nxt_task_t *task, char *script)
{
    int              status, pargc;
    char             **pargv, **penv;
    u_char           *run_module;
    PerlInterpreter  *my_perl;

    static char  argv[] = "\0""-e\0""0";
    static char  *embedding[] = { &argv[0], &argv[1], &argv[4] };

    pargc = 0;
    pargv = NULL;
    penv = NULL;

    PERL_SYS_INIT3(&pargc, &pargv, &penv);

    my_perl = perl_alloc();

    if (nxt_slow_path(my_perl == NULL)) {
        nxt_alert(task, "PSGI: Failed to allocate memory for Perl interpreter");
        return NULL;
    }

    run_module = NULL;

    perl_construct(my_perl);
    PERL_SET_CONTEXT(my_perl);

    status = perl_parse(my_perl, nxt_perl_psgi_xs_init, 3, embedding, NULL);

    if (nxt_slow_path(status != 0)) {
        nxt_alert(task, "PSGI: Failed to parse Perl Script");
        goto fail;
    }

    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    PL_origalen = 1;

    status = perl_run(my_perl);

    if (nxt_slow_path(status != 0)) {
        nxt_alert(task, "PSGI: Failed to run Perl");
        goto fail;
    }

    sv_setsv(get_sv("0", 0), newSVpv(script, 0));

    run_module = nxt_perl_psgi_module_create(task, script);

    if (nxt_slow_path(run_module == NULL)) {
        goto fail;
    }

    status = nxt_perl_psgi_io_input_init(my_perl, &nxt_perl_psgi_arg_input);

    if (nxt_slow_path(status != NXT_OK)) {
        nxt_alert(task, "PSGI: Failed to init io.psgi.input");
        goto fail;
    }

    status = nxt_perl_psgi_io_error_init(my_perl, &nxt_perl_psgi_arg_error);

    if (nxt_slow_path(status != NXT_OK)) {
        nxt_alert(task, "PSGI: Failed to init io.psgi.errors");
        goto fail;
    }

    nxt_perl_psgi_app = eval_pv((const char *) run_module, FALSE);

    if (SvTRUE(ERRSV)) {
        nxt_alert(task, "PSGI: Failed to parse script: %s\n%s",
                  script, SvPV_nolen(ERRSV));
        goto fail;
    }

    nxt_free(run_module);

    return my_perl;

fail:

    if (run_module != NULL) {
        nxt_free(run_module);
    }

    perl_destruct(my_perl);
    perl_free(my_perl);
    PERL_SYS_TERM();

    return NULL;
}


nxt_inline nxt_int_t
nxt_perl_psgi_env_append_str(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, nxt_str_t *str)
{
    SV  **ha;

    ha = hv_store(hash_env, name, (I32) strlen(name),
                  newSVpv((const char *) str->start, (STRLEN) str->length), 0);

    if (nxt_slow_path(ha == NULL)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_inline nxt_int_t
nxt_perl_psgi_env_append(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, void *value)
{
    SV  **ha;

    ha = hv_store(hash_env, name, (I32) strlen(name), value, 0);

    if (nxt_slow_path(ha == NULL)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_inline nxt_int_t
nxt_perl_psgi_read_add_env(PerlInterpreter *my_perl, nxt_task_t *task,
    nxt_app_rmsg_t *rmsg, HV *hash_env,
    const char *name, nxt_str_t *str)
{
    nxt_int_t  rc;

    rc = nxt_app_msg_read_str(task, rmsg, str);

    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    if (str->start == NULL) {
        return NXT_OK;
    }

    return nxt_perl_psgi_env_append_str(my_perl, hash_env, name, str);
}


static SV *
nxt_perl_psgi_env_create(PerlInterpreter *my_perl, nxt_task_t *task,
    nxt_app_rmsg_t *rmsg, size_t *body_preread_size)
{
    HV         *hash_env;
    AV         *array_version;
    u_char     *colon;
    size_t     query_size;
    nxt_int_t  rc;
    nxt_str_t  str, value, path, target;
    nxt_str_t  host, server_name, server_port;

    static nxt_str_t  def_host = nxt_string("localhost");
    static nxt_str_t  def_port = nxt_string("80");

    hash_env = newHV();

    if (nxt_slow_path(hash_env == NULL)) {
        return NULL;
    }

#define RC(FNS)                                                  \
    do {                                                         \
        if (nxt_slow_path((FNS) != NXT_OK))                      \
            goto fail;                                           \
    } while (0)

#define GET_STR(ATTR)                                            \
    RC(nxt_perl_psgi_read_add_env(my_perl, task, rmsg,           \
        hash_env, ATTR, &str))

    RC(nxt_perl_psgi_env_append_str(my_perl, hash_env,
                                    "SERVER_SOFTWARE", &nxt_server));

    GET_STR("REQUEST_METHOD");
    GET_STR("REQUEST_URI");

    target = str;

    RC(nxt_app_msg_read_str(task, rmsg, &path));
    RC(nxt_app_msg_read_size(task, rmsg, &query_size));

    if (path.start == NULL || path.length == 0) {
        path = target;
    }

    RC(nxt_perl_psgi_env_append_str(my_perl, hash_env, "PATH_INFO",
                                    &path));

    array_version = newAV();

    if (nxt_slow_path(array_version == NULL)) {
        goto fail;
    }

    av_push(array_version, newSViv(1));
    av_push(array_version, newSViv(1));

    RC(nxt_perl_psgi_env_append(my_perl, hash_env, "psgi.version",
                                newRV_noinc((SV *) array_version)));
    RC(nxt_perl_psgi_env_append(my_perl, hash_env, "psgi.url_scheme",
                                newSVpv("http", 4)));
    RC(nxt_perl_psgi_env_append(my_perl, hash_env, "psgi.input",
                                SvREFCNT_inc(nxt_perl_psgi_arg_input.io)));
    RC(nxt_perl_psgi_env_append(my_perl, hash_env, "psgi.errors",
                                SvREFCNT_inc(nxt_perl_psgi_arg_error.io)));
    RC(nxt_perl_psgi_env_append(my_perl, hash_env, "psgi.multithread",
                                &PL_sv_no));
    RC(nxt_perl_psgi_env_append(my_perl, hash_env, "psgi.multiprocess",
                                &PL_sv_yes));
    RC(nxt_perl_psgi_env_append(my_perl, hash_env, "psgi.run_once",
                                &PL_sv_no));
    RC(nxt_perl_psgi_env_append(my_perl, hash_env, "psgi.nonblocking",
                                &PL_sv_no));
    RC(nxt_perl_psgi_env_append(my_perl, hash_env, "psgi.streaming",
                                &PL_sv_no));

    if (query_size > 0) {
        query_size--;

        if (nxt_slow_path(target.length < query_size)) {
            goto fail;
        }

        str.start = &target.start[query_size];
        str.length = target.length - query_size;

        RC(nxt_perl_psgi_env_append_str(my_perl, hash_env,
                                        "QUERY_STRING", &str));
    }

    GET_STR("SERVER_PROTOCOL");
    GET_STR("REMOTE_ADDR");
    GET_STR("SERVER_ADDR");

    RC(nxt_app_msg_read_str(task, rmsg, &host));

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

    RC(nxt_perl_psgi_env_append_str(my_perl, hash_env,
                                    "SERVER_NAME", &server_name));
    RC(nxt_perl_psgi_env_append_str(my_perl, hash_env,
                                    "SERVER_PORT", &server_port));

    GET_STR("CONTENT_TYPE");
    GET_STR("CONTENT_LENGTH");

    for ( ;; ) {
        rc = nxt_app_msg_read_str(task, rmsg, &str);

        if (nxt_slow_path(rc != NXT_OK)) {
            goto fail;
        }

        if (nxt_slow_path(str.length == 0)) {
            break;
        }

        rc = nxt_app_msg_read_str(task, rmsg, &value);

        if (nxt_slow_path(rc != NXT_OK)) {
            break;
        }

        RC(nxt_perl_psgi_env_append_str(my_perl, hash_env,
                                        (char *) str.start, &value));
    }

    RC(nxt_app_msg_read_size(task, rmsg, body_preread_size));

#undef GET_STR
#undef RC

    return newRV_noinc((SV *) hash_env);

fail:

    SvREFCNT_dec(hash_env);

    return NULL;
}


static nxt_str_t
nxt_perl_psgi_result_status(PerlInterpreter *my_perl, SV *result)
{
    SV         **sv_status;
    AV         *array;
    nxt_str_t  status;

    array = (AV *) SvRV(result);
    sv_status = av_fetch(array, 0, 0);

    status.start = (u_char *) SvPV(*sv_status, status.length);

    return status;
}


static nxt_int_t
nxt_perl_psgi_result_head(PerlInterpreter *my_perl, SV *sv_head,
    nxt_task_t *task, nxt_app_wmsg_t *wmsg)
{
    AV         *array_head;
    SV         **entry;
    long       i, array_len;
    nxt_int_t  rc;
    nxt_str_t  body;

    if (nxt_slow_path(SvROK(sv_head) == 0
                      || SvTYPE(SvRV(sv_head)) != SVt_PVAV))
    {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: An unsupported format was received from "
                      "Perl Application for head part");

        return NXT_ERROR;
    }

    array_head = (AV *) SvRV(sv_head);
    array_len = av_len(array_head);

    if (array_len < 1) {
        return NXT_OK;
    }

    if (nxt_slow_path((array_len % 2) == 0)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: Bad format for head from "
                      "Perl Application");

        return NXT_ERROR;
    }

    for (i = 0; i <= array_len; i++) {
        entry = av_fetch(array_head, i, 0);

        if (nxt_fast_path(entry == NULL)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "PSGI: Failed to get head entry from "
                          "Perl Application");

            return NXT_ERROR;
        }

        body.start = (u_char *) SvPV(*entry, body.length);

        rc = nxt_app_msg_write_raw(task, wmsg,
                                   (u_char *) body.start, body.length);

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "PSGI: Failed to write head "
                          "from Perl Application");
            return rc;
        }

        if ((i % 2) == 0) {
            rc = nxt_app_msg_write_raw(task, wmsg,
                                       (u_char *) ": ", nxt_length(": "));
        } else {
            rc = nxt_app_msg_write_raw(task, wmsg,
                                       (u_char *) "\r\n", nxt_length("\r\n"));
        }

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "PSGI: Failed to write head from "
                          "Perl Application");
            return rc;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_perl_psgi_result_body(PerlInterpreter *my_perl, SV *sv_body,
    nxt_task_t *task, nxt_app_wmsg_t *wmsg)
{
    SV         **entry;
    AV         *body_array;
    long       i;
    nxt_int_t  rc;
    nxt_str_t  body;

    if (nxt_slow_path(SvROK(sv_body) == 0
                      || SvTYPE(SvRV(sv_body)) != SVt_PVAV))
    {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: An unsupported format was received from "
                      "Perl Application for a body part");

        return NXT_ERROR;
    }

    body_array = (AV *) SvRV(sv_body);

    for (i = 0; i <= av_len(body_array); i++) {

        entry = av_fetch(body_array, i, 0);

        if (nxt_fast_path(entry == NULL)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "PSGI: Failed to get body entry from "
                          "Perl Application");
            return NXT_ERROR;
        }

        body.start = (u_char *) SvPV(*entry, body.length);

        if (body.length == 0) {
            continue;
        }

        rc = nxt_app_msg_write_raw(task, wmsg,
                                   (u_char *) body.start, body.length);

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "PSGI: Failed to write 'body' from "
                          "Perl Application");
            return rc;
        }

        rc = nxt_app_msg_flush(task, wmsg, 0);

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "PSGI: Failed to flush data for a 'body' "
                          "part from Perl Application");
            return rc;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_perl_psgi_result_body_ref(PerlInterpreter *my_perl, SV *sv_body,
    nxt_task_t *task, nxt_app_wmsg_t *wmsg)
{
    IO         *io;
    PerlIO     *fp;
    SSize_t    n;
    nxt_int_t  rc;
    u_char     vbuf[8192];

    io = GvIO(SvRV(sv_body));

    if (io == NULL) {
        return NXT_OK;
    }

    fp = IoIFP(io);

    for ( ;; ) {
        n = PerlIO_read(fp, vbuf, 8192);

        if (n < 1) {
            break;
        }

        rc = nxt_app_msg_write_raw(task, wmsg,
                                   (u_char *) vbuf, (size_t) n);

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "PSGI: Failed to write 'body' from "
                          "Perl Application");

            return rc;
        }

        rc = nxt_app_msg_flush(task, wmsg, 0);

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "PSGI: Failed to flush data for a body "
                          "part from Perl Application");

            return rc;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_perl_psgi_result_array(PerlInterpreter *my_perl, SV *result,
    nxt_task_t *task, nxt_app_wmsg_t *wmsg)
{
    AV         *array;
    SV         **sv_temp;
    long       array_len;
    nxt_int_t  rc;
    nxt_str_t  http_status;

    array = (AV *) SvRV(result);
    array_len = av_len(array);

    if (nxt_slow_path(array_len < 0)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: Invalid result format from Perl Application");

        return NXT_ERROR;
    }

    http_status = nxt_perl_psgi_result_status(nxt_perl_psgi, result);

    if (nxt_slow_path(http_status.start == NULL || http_status.length == 0)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: An unexpected status was received "
                      "from Perl Application");

        return NXT_ERROR;
    }

    rc = nxt_perl_psgi_http_write_status_str(task, wmsg, &http_status);

    if (nxt_slow_path(rc != NXT_OK)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: Failed to write HTTP Status");

        return rc;
    }

    if (array_len < 1) {
        rc = nxt_app_msg_write_raw(task, wmsg,
                                   (u_char *) "\r\n", nxt_length("\r\n"));

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "PSGI: Failed to write HTTP Headers");

            return rc;
        }

        return NXT_OK;
    }

    sv_temp = av_fetch(array, 1, 0);

    if (nxt_slow_path(sv_temp == NULL)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: Failed to get head from Perl ARRAY variable");

        return NXT_ERROR;
    }

    rc = nxt_perl_psgi_result_head(nxt_perl_psgi, *sv_temp, task, wmsg);

    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    rc = nxt_app_msg_write_raw(task, wmsg,
                               (u_char *) "\r\n", nxt_length("\r\n"));

    if (nxt_slow_path(rc != NXT_OK)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: Failed to write HTTP Headers");

        return rc;
    }

    if (nxt_fast_path(array_len < 2)) {
        return NXT_OK;
    }

    sv_temp = av_fetch(array, 2, 0);

    if (nxt_slow_path(sv_temp == NULL || SvROK(*sv_temp) == FALSE)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: Failed to get body from Perl ARRAY variable");

        return NXT_ERROR;
    }

    if (SvTYPE(SvRV(*sv_temp)) == SVt_PVAV) {
        rc = nxt_perl_psgi_result_body(nxt_perl_psgi, *sv_temp, task, wmsg);

    } else {
        rc = nxt_perl_psgi_result_body_ref(nxt_perl_psgi, *sv_temp,
                                           task, wmsg);
    }

    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_perl_psgi_init(nxt_task_t *task, nxt_common_app_conf_t *conf)
{
    PerlInterpreter  *my_perl;

    my_perl = nxt_perl_psgi_interpreter_init(task, conf->u.perl.script);

    if (nxt_slow_path(my_perl == NULL)) {
        return NXT_ERROR;
    }

    nxt_perl_psgi = my_perl;

    return NXT_OK;
}


static nxt_int_t
nxt_perl_psgi_run(nxt_task_t *task, nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *wmsg)
{
    SV                     *env, *result;
    size_t                 body_preread_size;
    nxt_int_t              rc;
    nxt_perl_psgi_input_t  input;

    dTHXa(nxt_perl_psgi);

    /*
     * Create environ variable for perl sub "application".
     *  > sub application {
     *  >     my ($environ) = @_;
     */
    env = nxt_perl_psgi_env_create(nxt_perl_psgi, task, rmsg,
                                   &body_preread_size);

    if (nxt_slow_path(env == NULL)) {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: Failed to create 'env' for Perl Application");

        return NXT_ERROR;
    }

    input.my_perl = nxt_perl_psgi;
    input.task = task;
    input.rmsg = rmsg;
    input.wmsg = wmsg;
    input.body_preread_size = body_preread_size;

    nxt_perl_psgi_arg_input.ctx = &input;
    nxt_perl_psgi_arg_error.ctx = &input;

    /* Call perl sub and get result as SV*. */
    result = nxt_perl_psgi_call_var_application(nxt_perl_psgi, env, task);

    /*
     * We expect ARRAY ref like a
     * ['200', ['Content-Type' => "text/plain"], ["body"]]
     */
    if (nxt_slow_path(SvOK(result) == 0 || SvROK(result) == 0
                      || SvTYPE(SvRV(result)) != SVt_PVAV))
    {
        nxt_log_error(NXT_LOG_ERR, task->log,
                      "PSGI: An unexpected response was received from "
                      "Perl Application");
        goto fail;
    }

    rc = nxt_perl_psgi_result_array(nxt_perl_psgi, result, task, wmsg);

    if (nxt_slow_path(rc != NXT_OK)) {
        goto fail;
    }

    rc = nxt_app_msg_flush(task, wmsg, 1);

    if (nxt_slow_path(rc != NXT_OK)) {
        goto fail;
    }

    SvREFCNT_dec(result);
    SvREFCNT_dec(env);

    return NXT_OK;

fail:

    SvREFCNT_dec(result);
    SvREFCNT_dec(env);

    return NXT_ERROR;
}


static void
nxt_perl_psgi_atexit(nxt_task_t *task)
{
    dTHXa(nxt_perl_psgi);

    nxt_perl_psgi_layer_stream_io_destroy(aTHX_ nxt_perl_psgi_arg_input.io);
    nxt_perl_psgi_layer_stream_fp_destroy(aTHX_ nxt_perl_psgi_arg_input.fp);

    nxt_perl_psgi_layer_stream_io_destroy(aTHX_ nxt_perl_psgi_arg_error.io);
    nxt_perl_psgi_layer_stream_fp_destroy(aTHX_ nxt_perl_psgi_arg_error.fp);

    perl_destruct(nxt_perl_psgi);
    perl_free(nxt_perl_psgi);
    PERL_SYS_TERM();
}
