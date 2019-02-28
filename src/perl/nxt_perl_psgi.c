
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
#include <nxt_unit.h>
#include <nxt_unit_request.h>
#include <nxt_unit_response.h>


typedef struct {
    PerlInterpreter          *my_perl;
    nxt_unit_request_info_t  *req;
} nxt_perl_psgi_input_t;


typedef struct {
    PerlInterpreter          *my_perl;
    SV                       *app;
} nxt_perl_psgi_module_t;


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
    SV *env, SV *app, nxt_unit_request_info_t *req);
static SV *nxt_perl_psgi_call_method(PerlInterpreter *my_perl, SV *obj,
    const char *method, nxt_unit_request_info_t *req);

/* For currect load XS modules */
EXTERN_C void boot_DynaLoader(pTHX_ CV *cv);

static nxt_int_t nxt_perl_psgi_io_input_init(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg);
static nxt_int_t nxt_perl_psgi_io_error_init(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg);

static PerlInterpreter *nxt_perl_psgi_interpreter_init(nxt_task_t *task,
    char *script, SV **app);

static SV *nxt_perl_psgi_env_create(PerlInterpreter *my_perl,
    nxt_unit_request_info_t *req, nxt_perl_psgi_input_t *input);
nxt_inline int nxt_perl_psgi_add_sptr(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, uint32_t name_len, nxt_unit_sptr_t *sptr, uint32_t len);
nxt_inline int nxt_perl_psgi_add_str(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, uint32_t name_len, const char *str, uint32_t len);
nxt_inline int nxt_perl_psgi_add_value(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, uint32_t name_len, void *value);


static u_char *nxt_perl_psgi_module_create(nxt_task_t *task,
    const char *script);

static nxt_int_t nxt_perl_psgi_result_status(PerlInterpreter *my_perl,
    SV *result);
static int nxt_perl_psgi_result_head(PerlInterpreter *my_perl,
    SV *sv_head, nxt_unit_request_info_t *req, uint16_t status);
static int nxt_perl_psgi_result_body(PerlInterpreter *my_perl,
    SV *result, nxt_unit_request_info_t *req);
static int nxt_perl_psgi_result_body_ref(PerlInterpreter *my_perl,
    SV *sv_body, nxt_unit_request_info_t *req);
static int nxt_perl_psgi_result_body_fh(PerlInterpreter *my_perl, SV *sv_body,
    nxt_unit_request_info_t *req);
static ssize_t nxt_perl_psgi_io_read(nxt_unit_read_info_t *read_info, void *dst,
    size_t size);
static int nxt_perl_psgi_result_array(PerlInterpreter *my_perl,
    SV *result, nxt_unit_request_info_t *req);

static nxt_int_t nxt_perl_psgi_init(nxt_task_t *task,
    nxt_common_app_conf_t *conf);
static void nxt_perl_psgi_request_handler(nxt_unit_request_info_t *req);
static void nxt_perl_psgi_atexit(void);

typedef SV *(*nxt_perl_psgi_callback_f)(PerlInterpreter *my_perl,
    SV *env, nxt_task_t *task);

static PerlInterpreter         *nxt_perl_psgi;
static nxt_perl_psgi_io_arg_t  nxt_perl_psgi_arg_input, nxt_perl_psgi_arg_error;

static uint32_t  nxt_perl_psgi_compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};

NXT_EXPORT nxt_app_module_t  nxt_app_module = {
    sizeof(nxt_perl_psgi_compat),
    nxt_perl_psgi_compat,
    nxt_string("perl"),
    PERL_VERSION_STRING,
    NULL,
    nxt_perl_psgi_init,
};


static long
nxt_perl_psgi_io_input_read(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length)
{
    nxt_perl_psgi_input_t  *input;

    input = (nxt_perl_psgi_input_t *) arg->ctx;

    return nxt_unit_request_read(input->req, vbuf, length);
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
    nxt_unit_req_error(input->req, "Perl: %s", vbuf);

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
    SV *env, SV *app, nxt_unit_request_info_t *req)
{
    SV  *result;

    dSP;

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);
    XPUSHs(env);
    PUTBACK;

    call_sv(app, G_EVAL|G_SCALAR);

    SPAGAIN;

    if (SvTRUE(ERRSV)) {
        nxt_unit_req_error(req, "PSGI: Failed to run Perl Application: \n%s",
                           SvPV_nolen(ERRSV));
    }

    result = POPs;
    SvREFCNT_inc(result);

    PUTBACK;
    FREETMPS;
    LEAVE;

    return result;
}


static SV *
nxt_perl_psgi_call_method(PerlInterpreter *my_perl, SV *obj, const char *method,
    nxt_unit_request_info_t *req)
{
    SV  *result;

    dSP;

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);
    XPUSHs(obj);
    PUTBACK;

    call_method(method, G_EVAL|G_SCALAR);

    SPAGAIN;

    if (SvTRUE(ERRSV)) {
        nxt_unit_req_error(req, "PSGI: Failed to call method '%s':\n%s",
                           method, SvPV_nolen(ERRSV));
        result = NULL;

    } else {
        result = SvREFCNT_inc(POPs);
    }

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
nxt_perl_psgi_interpreter_init(nxt_task_t *task, char *script, SV **app)
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

    *app = eval_pv((const char *) run_module, FALSE);

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


static SV *
nxt_perl_psgi_env_create(PerlInterpreter *my_perl,
    nxt_unit_request_info_t *req, nxt_perl_psgi_input_t *input)
{
    HV                  *hash_env;
    AV                  *array_version;
    uint32_t            i;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    hash_env = newHV();
    if (nxt_slow_path(hash_env == NULL)) {
        return NULL;
    }

#define RC(FNS)                                                               \
    do {                                                                      \
        if (nxt_slow_path((FNS) != NXT_UNIT_OK))                              \
            goto fail;                                                        \
     } while (0)

#define NL(S) (S), sizeof(S)-1

    r = req->request;

    RC(nxt_perl_psgi_add_str(my_perl, hash_env, NL("SERVER_SOFTWARE"),
                             (char *) nxt_server.start, nxt_server.length));

    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("REQUEST_METHOD"),
                              &r->method, r->method_length));
    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("REQUEST_URI"),
                              &r->target, r->target_length));
    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("PATH_INFO"),
                              &r->path, r->path_length));

    array_version = newAV();

    if (nxt_slow_path(array_version == NULL)) {
        goto fail;
    }

    av_push(array_version, newSViv(1));
    av_push(array_version, newSViv(1));

    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.version"),
                                newRV_noinc((SV *) array_version)));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.url_scheme"),
                                newSVpv("http", 4)));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.input"),
                                SvREFCNT_inc(nxt_perl_psgi_arg_input.io)));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.errors"),
                                SvREFCNT_inc(nxt_perl_psgi_arg_error.io)));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.multithread"),
                                &PL_sv_no));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.multiprocess"),
                                &PL_sv_yes));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.run_once"),
                                &PL_sv_no));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.nonblocking"),
                                &PL_sv_no));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.streaming"),
                                &PL_sv_no));

    if (r->query.offset) {
        RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("QUERY_STRING"),
                                  &r->query, r->query_length));
    }
    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("SERVER_PROTOCOL"),
                              &r->version, r->version_length));
    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("REMOTE_ADDR"),
                              &r->remote, r->remote_length));
    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("SERVER_ADDR"),
                              &r->local, r->local_length));

    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("SERVER_NAME"),
                              &r->server_name, r->server_name_length));
    RC(nxt_perl_psgi_add_str(my_perl, hash_env, NL("SERVER_PORT"), "80", 2));

    for (i = 0; i < r->fields_count; i++) {
        f = r->fields + i;

        RC(nxt_perl_psgi_add_sptr(my_perl, hash_env,
                                  nxt_unit_sptr_get(&f->name), f->name_length,
                                  &f->value, f->value_length));
    }

    if (r->content_length_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_length_field;

        RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("CONTENT_LENGTH"),
                                  &f->value, f->value_length));
    }

    if (r->content_type_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_type_field;

        RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("CONTENT_TYPE"),
                                  &f->value, f->value_length));
    }

#undef NL
#undef RC

    return newRV_noinc((SV *) hash_env);

fail:

    SvREFCNT_dec(hash_env);

    return NULL;
}


nxt_inline int
nxt_perl_psgi_add_sptr(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, uint32_t name_len, nxt_unit_sptr_t *sptr, uint32_t len)
{
    return nxt_perl_psgi_add_str(my_perl, hash_env, name, name_len,
                                 nxt_unit_sptr_get(sptr), len);
}


nxt_inline int
nxt_perl_psgi_add_str(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, uint32_t name_len, const char *str, uint32_t len)
{
    SV  **ha;

    ha = hv_store(hash_env, name, (I32) name_len,
                  newSVpv(str, (STRLEN) len), 0);
    if (nxt_slow_path(ha == NULL)) {
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


nxt_inline int
nxt_perl_psgi_add_value(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, uint32_t name_len, void *value)
{
    SV  **ha;

    ha = hv_store(hash_env, name, (I32) name_len, value, 0);
    if (nxt_slow_path(ha == NULL)) {
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static nxt_int_t
nxt_perl_psgi_result_status(PerlInterpreter *my_perl, SV *result)
{
    SV         **sv_status;
    AV         *array;
    u_char     *space;
    nxt_str_t  status;

    array = (AV *) SvRV(result);
    sv_status = av_fetch(array, 0, 0);

    status.start = (u_char *) SvPV(*sv_status, status.length);

    space = nxt_memchr(status.start, ' ', status.length);
    if (space != NULL) {
        status.length = space - status.start;
    }

    return nxt_int_parse(status.start, status.length);
}


static int
nxt_perl_psgi_result_head(PerlInterpreter *my_perl, SV *sv_head,
    nxt_unit_request_info_t *req, uint16_t status)
{
    AV         *array_head;
    SV         **entry;
    int        rc;
    long       i, array_len;
    char       *name, *value;
    STRLEN     name_len, value_len;
    uint32_t   fields, size;

    if (nxt_slow_path(SvROK(sv_head) == 0
                      || SvTYPE(SvRV(sv_head)) != SVt_PVAV))
    {
        nxt_unit_req_error(req,
                           "PSGI: An unsupported format was received from "
                           "Perl Application for head part");

        return NXT_UNIT_ERROR;
    }

    array_head = (AV *) SvRV(sv_head);
    array_len = av_len(array_head);

    if (array_len < 1) {
        return nxt_unit_response_init(req, status, 0, 0);
    }

    if (nxt_slow_path((array_len % 2) == 0)) {
        nxt_unit_req_error(req, "PSGI: Bad format for head from "
                           "Perl Application");

        return NXT_UNIT_ERROR;
    }

    fields = 0;
    size = 0;

    for (i = 0; i <= array_len; i++) {
        entry = av_fetch(array_head, i, 0);

        if (nxt_fast_path(entry == NULL)) {
            nxt_unit_req_error(req, "PSGI: Failed to get head entry from "
                               "Perl Application");

            return NXT_UNIT_ERROR;
        }

        value = SvPV(*entry, value_len);
        size += value_len;

        if ((i % 2) == 0) {
            fields++;
        }
    }

    rc = nxt_unit_response_init(req, status, fields, size);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        return rc;
    }

    for (i = 0; i <= array_len; i += 2) {
        entry = av_fetch(array_head, i, 0);
        name = SvPV(*entry, name_len);

        entry = av_fetch(array_head, i + 1, 0);
        value = SvPV(*entry, value_len);

        rc = nxt_unit_response_add_field(req, name, name_len, value, value_len);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return rc;
        }
    }

    return NXT_UNIT_OK;
}


static int
nxt_perl_psgi_result_body(PerlInterpreter *my_perl, SV *sv_body,
    nxt_unit_request_info_t *req)
{
    SV         **entry;
    AV         *body_array;
    int        rc;
    long       i;
    nxt_str_t  body;

    if (nxt_slow_path(SvROK(sv_body) == 0
                      || SvTYPE(SvRV(sv_body)) != SVt_PVAV))
    {
        nxt_unit_req_error(req, "PSGI: An unsupported format was received from "
                           "Perl Application for a body part");

        return NXT_UNIT_ERROR;
    }

    body_array = (AV *) SvRV(sv_body);

    for (i = 0; i <= av_len(body_array); i++) {

        entry = av_fetch(body_array, i, 0);

        if (nxt_fast_path(entry == NULL)) {
            nxt_unit_req_error(req, "PSGI: Failed to get body entry from "
                               "Perl Application");

            return NXT_UNIT_ERROR;
        }

        body.start = (u_char *) SvPV(*entry, body.length);

        if (body.length == 0) {
            continue;
        }

        rc = nxt_unit_response_write(req, body.start, body.length);

        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            nxt_unit_req_error(req, "PSGI: Failed to write content from "
                               "Perl Application");
            return rc;
        }
    }

    return NXT_UNIT_OK;
}


static int
nxt_perl_psgi_result_body_ref(PerlInterpreter *my_perl, SV *sv_body,
    nxt_unit_request_info_t *req)
{
    SV          *data, *old_rs, *old_perl_rs;
    int         rc;
    size_t      len;
    const char  *body;

    /*
     * Servers should set the $/ special variable to the buffer size
     * when reading content from $body using the getline method.
     * This is done by setting $/ with a reference to an integer ($/ = \8192).
     */

    old_rs = PL_rs;
    old_perl_rs = get_sv("/", GV_ADD);

    PL_rs = sv_2mortal(newRV_noinc(newSViv(nxt_unit_buf_min())));

    sv_setsv(old_perl_rs, PL_rs);

    rc = NXT_UNIT_OK;

    for ( ;; ) {
        data = nxt_perl_psgi_call_method(my_perl, sv_body, "getline", req);
        if (nxt_slow_path(data == NULL)) {
            rc = NXT_UNIT_ERROR;
            break;
        }

        body = SvPV(data, len);

        if (len == 0) {
            SvREFCNT_dec(data);

            data = nxt_perl_psgi_call_method(my_perl, sv_body, "close", req);
            if (nxt_fast_path(data != NULL)) {
                SvREFCNT_dec(data);
            }

            break;
        }

        rc = nxt_unit_response_write(req, body, len);

        SvREFCNT_dec(data);

        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            nxt_unit_req_error(req, "PSGI: Failed to write content from "
                               "Perl Application");
            break;
        }
    };

    PL_rs =  old_rs;
    sv_setsv(get_sv("/", GV_ADD), old_perl_rs);

    return rc;
}


typedef struct {
    PerlInterpreter  *my_perl;
    PerlIO           *fp;
} nxt_perl_psgi_io_ctx_t;


static int
nxt_perl_psgi_result_body_fh(PerlInterpreter *my_perl, SV *sv_body,
    nxt_unit_request_info_t *req)
{
    IO                      *io;
    nxt_unit_read_info_t    read_info;
    nxt_perl_psgi_io_ctx_t  io_ctx;

    io = GvIO(SvRV(sv_body));

    if (io == NULL) {
        return NXT_UNIT_OK;
    }

    io_ctx.my_perl = my_perl;
    io_ctx.fp = IoIFP(io);

    read_info.read = nxt_perl_psgi_io_read;
    read_info.eof = PerlIO_eof(io_ctx.fp);
    read_info.buf_size = 8192;
    read_info.data = &io_ctx;

    return nxt_unit_response_write_cb(req, &read_info);
}


static ssize_t
nxt_perl_psgi_io_read(nxt_unit_read_info_t *read_info, void *dst, size_t size)
{
    ssize_t                 res;
    nxt_perl_psgi_io_ctx_t  *ctx;

    ctx = read_info->data;

    dTHXa(ctx->my_perl);

    res = PerlIO_read(ctx->fp, dst, size);

    read_info->eof = PerlIO_eof(ctx->fp);

    return res;
}


static int
nxt_perl_psgi_result_array(PerlInterpreter *my_perl, SV *result,
    nxt_unit_request_info_t *req)
{
    AV         *array;
    SV         **sv_temp;
    int        rc;
    long       array_len;
    nxt_int_t  status;

    array = (AV *) SvRV(result);
    array_len = av_len(array);

    if (nxt_slow_path(array_len < 0)) {
        nxt_unit_req_error(req,
                           "PSGI: Invalid result format from Perl Application");

        return NXT_UNIT_ERROR;
    }

    status = nxt_perl_psgi_result_status(my_perl, result);

    if (nxt_slow_path(status < 0)) {
        nxt_unit_req_error(req,
                           "PSGI: An unexpected status was received "
                           "from Perl Application");

        return NXT_UNIT_ERROR;
    }

    if (array_len >= 1) {
        sv_temp = av_fetch(array, 1, 0);

        if (nxt_slow_path(sv_temp == NULL)) {
            nxt_unit_req_error(req, "PSGI: Failed to get head from "
                               "Perl ARRAY variable");

            return NXT_UNIT_ERROR;
        }

        rc = nxt_perl_psgi_result_head(my_perl, *sv_temp, req, status);
        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return rc;
        }

    } else {
        return nxt_unit_response_init(req, status, 0, 0);
    }

    if (nxt_fast_path(array_len < 2)) {
        return NXT_UNIT_OK;
    }

    sv_temp = av_fetch(array, 2, 0);

    if (nxt_slow_path(sv_temp == NULL || SvROK(*sv_temp) == FALSE)) {
        nxt_unit_req_error(req,
                           "PSGI: Failed to get body from "
                           "Perl ARRAY variable");

        return NXT_UNIT_ERROR;
    }

    if (SvTYPE(SvRV(*sv_temp)) == SVt_PVAV) {
        return nxt_perl_psgi_result_body(my_perl, *sv_temp, req);
    }

    if (SvTYPE(SvRV(*sv_temp)) == SVt_PVGV) {
        return nxt_perl_psgi_result_body_fh(my_perl, *sv_temp, req);
    }

    return nxt_perl_psgi_result_body_ref(my_perl, *sv_temp, req);
}


static nxt_int_t
nxt_perl_psgi_init(nxt_task_t *task, nxt_common_app_conf_t *conf)
{
    int                     rc;
    nxt_unit_ctx_t          *unit_ctx;
    nxt_unit_init_t         perl_init;
    PerlInterpreter         *my_perl;
    nxt_perl_psgi_module_t  module;

    my_perl = nxt_perl_psgi_interpreter_init(task, conf->u.perl.script,
                                             &module.app);

    if (nxt_slow_path(my_perl == NULL)) {
        return NXT_ERROR;
    }

    module.my_perl = my_perl;
    nxt_perl_psgi = my_perl;

    nxt_unit_default_init(task, &perl_init);

    perl_init.callbacks.request_handler = nxt_perl_psgi_request_handler;
    perl_init.data = &module;

    unit_ctx = nxt_unit_init(&perl_init);
    if (nxt_slow_path(unit_ctx == NULL)) {
        return NXT_ERROR;
    }

    rc = nxt_unit_run(unit_ctx);

    nxt_unit_done(unit_ctx);

    nxt_perl_psgi_atexit();

    exit(rc);

    return NXT_OK;
}


static void
nxt_perl_psgi_request_handler(nxt_unit_request_info_t *req)
{
    SV                      *env, *result;
    nxt_int_t               rc;
    PerlInterpreter         *my_perl;
    nxt_perl_psgi_input_t   input;
    nxt_perl_psgi_module_t  *module;

    module = req->unit->data;
    my_perl = module->my_perl;

    input.my_perl = my_perl;
    input.req = req;

    /*
     * Create environ variable for perl sub "application".
     *  > sub application {
     *  >     my ($environ) = @_;
     */
    env = nxt_perl_psgi_env_create(my_perl, req, &input);
    if (nxt_slow_path(env == NULL)) {
        nxt_unit_req_error(req,
                           "PSGI: Failed to create 'env' for Perl Application");
        nxt_unit_request_done(req, NXT_UNIT_ERROR);

        return;
    }

    nxt_perl_psgi_arg_input.ctx = &input;
    nxt_perl_psgi_arg_error.ctx = &input;

    /* Call perl sub and get result as SV*. */
    result = nxt_perl_psgi_call_var_application(my_perl, env, module->app, req);

    /*
     * We expect ARRAY ref like a
     * ['200', ['Content-Type' => "text/plain"], ["body"]]
     */
    if (nxt_slow_path(SvOK(result) == 0 || SvROK(result) == 0
                      || SvTYPE(SvRV(result)) != SVt_PVAV))
    {
        nxt_unit_req_error(req, "PSGI: An unexpected response was received "
                           "from Perl Application");

        rc = NXT_UNIT_ERROR;

    } else {
        rc = nxt_perl_psgi_result_array(my_perl, result, req);
    }

    nxt_unit_request_done(req, rc);

    SvREFCNT_dec(result);
    SvREFCNT_dec(env);
}


static void
nxt_perl_psgi_atexit(void)
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
