
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
    nxt_perl_psgi_io_arg_t   arg_input;
    nxt_perl_psgi_io_arg_t   arg_error;
    SV                       *app;
    CV                       *cb;
    nxt_unit_request_info_t  *req;
    pthread_t                thread;
    nxt_unit_ctx_t           *ctx;
} nxt_perl_psgi_ctx_t;


static SSize_t nxt_perl_psgi_io_input_read(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length);
static SSize_t nxt_perl_psgi_io_input_write(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const void *vbuf, size_t length);

static SSize_t nxt_perl_psgi_io_error_read(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length);
static SSize_t nxt_perl_psgi_io_error_write(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const void *vbuf, size_t length);

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

static int nxt_perl_psgi_io_init(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const char *mode, void *req);

static int nxt_perl_psgi_ctx_init(const char *script,
    nxt_perl_psgi_ctx_t *pctx);

static SV *nxt_perl_psgi_env_create(PerlInterpreter *my_perl,
    nxt_unit_request_info_t *req);
nxt_inline int nxt_perl_psgi_add_sptr(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, uint32_t name_len, nxt_unit_sptr_t *sptr, uint32_t len);
nxt_inline int nxt_perl_psgi_add_str(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, uint32_t name_len, const char *str, uint32_t len);
nxt_inline int nxt_perl_psgi_add_value(PerlInterpreter *my_perl, HV *hash_env,
    const char *name, uint32_t name_len, void *value);


static char *nxt_perl_psgi_module_create(const char *script);

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
static void nxt_perl_psgi_result_cb(PerlInterpreter *my_perl, SV *result,
    nxt_unit_request_info_t *req);

static nxt_int_t nxt_perl_psgi_start(nxt_task_t *task,
    nxt_process_data_t *data);
static void nxt_perl_psgi_request_handler(nxt_unit_request_info_t *req);
static int nxt_perl_psgi_ready_handler(nxt_unit_ctx_t *ctx);
static void *nxt_perl_psgi_thread_func(void *main_ctx);
static int nxt_perl_psgi_init_threads(nxt_perl_app_conf_t *c);
static void nxt_perl_psgi_join_threads(nxt_unit_ctx_t *ctx,
    nxt_perl_app_conf_t *c);
static void nxt_perl_psgi_ctx_free(nxt_perl_psgi_ctx_t *pctx);

static CV                   *nxt_perl_psgi_write;
static CV                   *nxt_perl_psgi_close;
static CV                   *nxt_perl_psgi_cb;
static pthread_attr_t       *nxt_perl_psgi_thread_attr;
static nxt_perl_psgi_ctx_t  *nxt_perl_psgi_ctxs;

static uint32_t  nxt_perl_psgi_compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};

NXT_EXPORT nxt_app_module_t  nxt_app_module = {
    sizeof(nxt_perl_psgi_compat),
    nxt_perl_psgi_compat,
    nxt_string("perl"),
    PERL_VERSION_STRING,
    NULL,
    0,
    NULL,
    nxt_perl_psgi_start,
};

const nxt_perl_psgi_io_tab_t nxt_perl_psgi_io_tab_input = {
    .read = nxt_perl_psgi_io_input_read,
    .write = nxt_perl_psgi_io_input_write,
};

const nxt_perl_psgi_io_tab_t nxt_perl_psgi_io_tab_error = {
    .read = nxt_perl_psgi_io_error_read,
    .write = nxt_perl_psgi_io_error_write,
};


static SSize_t
nxt_perl_psgi_io_input_read(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length)
{
    return nxt_unit_request_read(arg->req, vbuf, length);
}


static SSize_t
nxt_perl_psgi_io_input_write(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const void *vbuf, size_t length)
{
    return 0;
}


static SSize_t
nxt_perl_psgi_io_error_read(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length)
{
    return 0;
}


static SSize_t
nxt_perl_psgi_io_error_write(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const void *vbuf, size_t length)
{
    nxt_unit_req_error(arg->req, "Perl: %s", (const char*) vbuf);

    return (SSize_t) length;
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


XS(XS_NGINX__Unit__Sandbox_write);
XS(XS_NGINX__Unit__Sandbox_write)
{
    int                  rc;
    char                 *body;
    size_t               len;
    nxt_perl_psgi_ctx_t  *pctx;

    dXSARGS;

    if (nxt_slow_path(items != 2)) {
        Perl_croak(aTHX_ "Wrong number of arguments. Need one string");

        XSRETURN_EMPTY;
    }

    body = SvPV(ST(1), len);

    pctx = CvXSUBANY(cv).any_ptr;

    rc = nxt_unit_response_write(pctx->req, body, len);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        Perl_croak(aTHX_ "Failed to write response body");

        XSRETURN_EMPTY;
    }

    XSRETURN_IV(len);
}


nxt_inline void
nxt_perl_psgi_cb_request_done(nxt_perl_psgi_ctx_t *pctx, int status)
{
    if (pctx->req != NULL) {
        nxt_unit_request_done(pctx->req, status);
        pctx->req = NULL;
    }
}


XS(XS_NGINX__Unit__Sandbox_close);
XS(XS_NGINX__Unit__Sandbox_close)
{
    I32  ax;

    ax = POPMARK;

    nxt_perl_psgi_cb_request_done(CvXSUBANY(cv).any_ptr, NXT_UNIT_OK);

    XSRETURN_NO;
}


XS(XS_NGINX__Unit__Sandbox_cb);
XS(XS_NGINX__Unit__Sandbox_cb)
{
    SV                   *obj;
    int                  rc;
    long                 array_len;
    nxt_perl_psgi_ctx_t  *pctx;

    dXSARGS;

    if (nxt_slow_path(items != 1)) {
        nxt_perl_psgi_cb_request_done(CvXSUBANY(cv).any_ptr, NXT_UNIT_ERROR);

        Perl_croak(aTHX_ "Wrong number of arguments");

        XSRETURN_EMPTY;
    }

    pctx = CvXSUBANY(cv).any_ptr;

    if (nxt_slow_path(SvOK(ST(0)) == 0 || SvROK(ST(0)) == 0
                      || SvTYPE(SvRV(ST(0))) != SVt_PVAV
                      || pctx->req == NULL))
    {
        nxt_perl_psgi_cb_request_done(CvXSUBANY(cv).any_ptr, NXT_UNIT_ERROR);

        Perl_croak(aTHX_ "PSGI: An unexpected response was received "
                   "from Perl Application");

        XSRETURN_EMPTY;
    }

    rc = nxt_perl_psgi_result_array(PERL_GET_CONTEXT, ST(0), pctx->req);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        nxt_perl_psgi_cb_request_done(CvXSUBANY(cv).any_ptr, NXT_UNIT_ERROR);

        Perl_croak(aTHX_ (char *) NULL);

        XSRETURN_EMPTY;
    }

    array_len = av_len((AV *) SvRV(ST(0)));

    if (array_len < 2) {
        obj = sv_bless(newRV_noinc((SV *) newHV()),
                       gv_stashpv("NGINX::Unit::Sandbox", GV_ADD));
        ST(0) = obj;

        XSRETURN(1);
    }

    nxt_perl_psgi_cb_request_done(CvXSUBANY(cv).any_ptr, NXT_UNIT_OK);

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

    nxt_perl_psgi_write = newXS("NGINX::Unit::Sandbox::write",
                                XS_NGINX__Unit__Sandbox_write, __FILE__);

    nxt_perl_psgi_close = newXS("NGINX::Unit::Sandbox::close",
                                XS_NGINX__Unit__Sandbox_close, __FILE__);

    nxt_perl_psgi_cb = newXS("NGINX::Unit::Sandbox::cb",
                             XS_NGINX__Unit__Sandbox_cb, __FILE__);
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


static char *
nxt_perl_psgi_module_create(const char *script)
{
    char    *buf, *p;
    size_t  length;

    static nxt_str_t  prefix = nxt_string(
        "package NGINX::Unit::Sandbox;"
        "sub new {"
        "   return bless {}, $_[0];"
        "}"
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

    buf = nxt_unit_malloc(NULL, prefix.length + length + suffix.length);
    if (nxt_slow_path(buf == NULL)) {
        nxt_unit_alert(NULL, "PSGI: Failed to allocate memory "
                       "for Perl script file %s", script);

        return NULL;
    }

    p = nxt_cpymem(buf, prefix.start, prefix.length);
    p = nxt_cpymem(p, script, length);
    nxt_memcpy(p, suffix.start, suffix.length);

    return buf;
}


static int
nxt_perl_psgi_io_init(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const char *mode, void *req)
{
    SV      *io;
    PerlIO  *fp;

    if (arg->io == NULL) {
        fp = nxt_perl_psgi_layer_stream_fp_create(aTHX_ arg->rv, mode);
        if (nxt_slow_path(fp == NULL)) {
            return NXT_UNIT_ERROR;
        }

        io = nxt_perl_psgi_layer_stream_io_create(aTHX_ fp);
        if (nxt_slow_path(io == NULL)) {
            nxt_perl_psgi_layer_stream_fp_destroy(aTHX_ fp);
            return NXT_UNIT_ERROR;
        }

        arg->io = io;
        arg->fp = fp;
    }

    arg->req = req;

    return NXT_UNIT_OK;
}


static void
nxt_perl_psgi_io_release(PerlInterpreter *my_perl, nxt_perl_psgi_io_arg_t *arg)
{
    if (arg->io != NULL) {
        SvREFCNT_dec(arg->io);
        arg->io = NULL;
    }
}


static int
nxt_perl_psgi_ctx_init(const char *script, nxt_perl_psgi_ctx_t *pctx)
{
    int              status, res;
    char             *run_module;
    PerlInterpreter  *my_perl;

    static char  argv[] = "\0""-e\0""0";
    static char  *embedding[] = { &argv[0], &argv[1], &argv[4] };

    my_perl = perl_alloc();

    if (nxt_slow_path(my_perl == NULL)) {
        nxt_unit_alert(NULL,
                       "PSGI: Failed to allocate memory for Perl interpreter");

        return NXT_UNIT_ERROR;
    }

    pctx->my_perl = my_perl;

    run_module = NULL;

    perl_construct(my_perl);
    PERL_SET_CONTEXT(my_perl);

    status = perl_parse(my_perl, nxt_perl_psgi_xs_init, 3, embedding, NULL);

    if (nxt_slow_path(status != 0)) {
        nxt_unit_alert(NULL, "PSGI: Failed to parse Perl Script");
        goto fail;
    }

    CvXSUBANY(nxt_perl_psgi_write).any_ptr = pctx;
    CvXSUBANY(nxt_perl_psgi_close).any_ptr = pctx;
    CvXSUBANY(nxt_perl_psgi_cb).any_ptr = pctx;

    pctx->cb = nxt_perl_psgi_cb;

    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
    PL_origalen = 1;

    status = perl_run(my_perl);

    if (nxt_slow_path(status != 0)) {
        nxt_unit_alert(NULL, "PSGI: Failed to run Perl");
        goto fail;
    }

    sv_setsv(get_sv("0", 0), newSVpv(script, 0));

    run_module = nxt_perl_psgi_module_create(script);
    if (nxt_slow_path(run_module == NULL)) {
        goto fail;
    }

    pctx->arg_input.rv = newSV_type(SVt_RV);
    sv_setptrref(pctx->arg_input.rv, &pctx->arg_input);
    SvSETMAGIC(pctx->arg_input.rv);

    pctx->arg_input.io_tab = &nxt_perl_psgi_io_tab_input;

    res = nxt_perl_psgi_io_init(my_perl, &pctx->arg_input, "r", NULL);
    if (nxt_slow_path(res != NXT_UNIT_OK)) {
        nxt_unit_alert(NULL, "PSGI: Failed to init io.psgi.input");
        goto fail;
    }

    pctx->arg_error.rv = newSV_type(SVt_RV);
    sv_setptrref(pctx->arg_error.rv, &pctx->arg_error);
    SvSETMAGIC(pctx->arg_error.rv);

    pctx->arg_error.io_tab = &nxt_perl_psgi_io_tab_error;

    res = nxt_perl_psgi_io_init(my_perl, &pctx->arg_error, "w", NULL);
    if (nxt_slow_path(res != NXT_UNIT_OK)) {
        nxt_unit_alert(NULL, "PSGI: Failed to init io.psgi.error");
        goto fail;
    }

    pctx->app = eval_pv(run_module, FALSE);

    if (SvTRUE(ERRSV)) {
        nxt_unit_alert(NULL, "PSGI: Failed to parse script: %s\n%s",
                       script, SvPV_nolen(ERRSV));
        goto fail;
    }

    nxt_unit_free(NULL, run_module);

    return NXT_UNIT_OK;

fail:

    nxt_perl_psgi_io_release(my_perl, &pctx->arg_input);
    nxt_perl_psgi_io_release(my_perl, &pctx->arg_error);

    if (run_module != NULL) {
        nxt_unit_free(NULL, run_module);
    }

    perl_destruct(my_perl);
    perl_free(my_perl);

    pctx->my_perl = NULL;

    return NXT_UNIT_ERROR;
}


static SV *
nxt_perl_psgi_env_create(PerlInterpreter *my_perl,
    nxt_unit_request_info_t *req)
{
    HV                   *hash_env;
    AV                   *array_version;
    uint32_t             i;
    nxt_unit_field_t     *f;
    nxt_unit_request_t   *r;
    nxt_perl_psgi_ctx_t  *pctx;

    pctx = req->ctx->data;

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
                               r->tls ? newSVpv("https", 5)
                                    : newSVpv("http", 4)));

    RC(nxt_perl_psgi_io_init(my_perl, &pctx->arg_input, "r", req));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.input"),
                               SvREFCNT_inc(pctx->arg_input.io)));

    RC(nxt_perl_psgi_io_init(my_perl, &pctx->arg_error, "w", req));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.errors"),
                               SvREFCNT_inc(pctx->arg_error.io)));

    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.multithread"),
                               nxt_perl_psgi_ctxs != NULL
                                   ? &PL_sv_yes : &PL_sv_no));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.multiprocess"),
                               &PL_sv_yes));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.run_once"),
                               &PL_sv_no));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.nonblocking"),
                               &PL_sv_no));
    RC(nxt_perl_psgi_add_value(my_perl, hash_env, NL("psgi.streaming"),
                               &PL_sv_yes));

    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("QUERY_STRING"),
                              &r->query, r->query_length));
    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("SERVER_PROTOCOL"),
                              &r->version, r->version_length));
    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("REMOTE_ADDR"),
                              &r->remote, r->remote_length));
    RC(nxt_perl_psgi_add_sptr(my_perl, hash_env, NL("SERVER_ADDR"),
                              &r->local_addr, r->local_addr_length));

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

    space = memchr(status.start, ' ', status.length);
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


static void
nxt_perl_psgi_result_cb(PerlInterpreter *my_perl, SV *result,
    nxt_unit_request_info_t *req)
{
    nxt_perl_psgi_ctx_t  *pctx;

    dSP;

    pctx = req->ctx->data;

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);
    XPUSHs(newRV_noinc((SV*) pctx->cb));
    PUTBACK;

    call_sv(result, G_EVAL|G_SCALAR);

    SPAGAIN;

    if (SvTRUE(ERRSV)) {
        nxt_unit_error(NULL, "PSGI: Failed to execute result callback: \n%s",
                       SvPV_nolen(ERRSV));

        nxt_perl_psgi_cb_request_done(pctx, NXT_UNIT_ERROR);
    }

    PUTBACK;
    FREETMPS;
    LEAVE;
}


static nxt_int_t
nxt_perl_psgi_start(nxt_task_t *task, nxt_process_data_t *data)
{
    int                    rc, pargc;
    char                   **pargv, **penv;
    nxt_unit_ctx_t         *unit_ctx;
    nxt_unit_init_t        perl_init;
    nxt_perl_psgi_ctx_t    pctx;
    nxt_perl_app_conf_t    *c;
    nxt_common_app_conf_t  *common_conf;

    common_conf = data->app;
    c = &common_conf->u.perl;

    pargc = 0;
    pargv = NULL;
    penv = NULL;

    PERL_SYS_INIT3(&pargc, &pargv, &penv);

    memset(&pctx, 0, sizeof(nxt_perl_psgi_ctx_t));

    rc = nxt_perl_psgi_ctx_init(c->script, &pctx);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    rc = nxt_perl_psgi_init_threads(c);

    PERL_SET_CONTEXT(pctx.my_perl);

    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    nxt_unit_default_init(task, &perl_init, common_conf);

    perl_init.callbacks.request_handler = nxt_perl_psgi_request_handler;
    perl_init.callbacks.ready_handler = nxt_perl_psgi_ready_handler;
    perl_init.data = c;
    perl_init.ctx_data = &pctx;

    unit_ctx = nxt_unit_init(&perl_init);
    if (nxt_slow_path(unit_ctx == NULL)) {
        goto fail;
    }

    rc = nxt_unit_run(unit_ctx);

    nxt_perl_psgi_join_threads(unit_ctx, c);

    nxt_unit_done(unit_ctx);

    nxt_perl_psgi_ctx_free(&pctx);

    PERL_SYS_TERM();

    exit(rc);

    return NXT_OK;

fail:

    nxt_perl_psgi_join_threads(NULL, c);

    nxt_perl_psgi_ctx_free(&pctx);

    PERL_SYS_TERM();

    return NXT_ERROR;
}


static void
nxt_perl_psgi_request_handler(nxt_unit_request_info_t *req)
{
    SV                   *env, *result;
    nxt_int_t            rc;
    PerlInterpreter      *my_perl;
    nxt_perl_psgi_ctx_t  *pctx;

    pctx = req->ctx->data;
    my_perl = pctx->my_perl;

    pctx->req = req;

    /*
     * Create environ variable for perl sub "application".
     *  > sub application {
     *  >     my ($environ) = @_;
     */
    env = nxt_perl_psgi_env_create(my_perl, req);
    if (nxt_slow_path(env == NULL)) {
        nxt_unit_req_error(req,
                           "PSGI: Failed to create 'env' for Perl Application");
        nxt_unit_request_done(req, NXT_UNIT_ERROR);
        pctx->req = NULL;

        return;
    }

    /* Call perl sub and get result as SV*. */
    result = nxt_perl_psgi_call_var_application(my_perl, env, pctx->app,
                                                req);

    if (nxt_fast_path(SvOK(result) != 0 && SvROK(result) != 0)) {

        if (SvTYPE(SvRV(result)) == SVt_PVAV) {
            rc = nxt_perl_psgi_result_array(my_perl, result, req);
            nxt_unit_request_done(req, rc);
            pctx->req = NULL;

            goto release;
        }

        if (SvTYPE(SvRV(result)) == SVt_PVCV) {
            nxt_perl_psgi_result_cb(my_perl, result, req);
            goto release;
        }
    }

    nxt_unit_req_error(req, "PSGI: An unexpected response was received "
                       "from Perl Application");

    nxt_unit_request_done(req, NXT_UNIT_ERROR);
    pctx->req = NULL;

release:

    SvREFCNT_dec(result);
    SvREFCNT_dec(env);
}


static int
nxt_perl_psgi_ready_handler(nxt_unit_ctx_t *ctx)
{
    int                  res;
    uint32_t             i;
    nxt_perl_app_conf_t  *c;
    nxt_perl_psgi_ctx_t  *pctx;

    c = ctx->unit->data;

    if (c->threads <= 1) {
        return NXT_UNIT_OK;
    }

    for (i = 0; i < c->threads - 1; i++) {
        pctx = &nxt_perl_psgi_ctxs[i];

        pctx->ctx = ctx;

        res = pthread_create(&pctx->thread, nxt_perl_psgi_thread_attr,
                             nxt_perl_psgi_thread_func, pctx);

        if (nxt_fast_path(res == 0)) {
            nxt_unit_debug(ctx, "thread #%d created", (int) (i + 1));

        } else {
            nxt_unit_alert(ctx, "thread #%d create failed: %s (%d)",
                           (int) (i + 1), strerror(res), res);

            return NXT_UNIT_ERROR;
        }
    }

    return NXT_UNIT_OK;
}


static void *
nxt_perl_psgi_thread_func(void *data)
{
    nxt_unit_ctx_t       *ctx;
    nxt_perl_psgi_ctx_t  *pctx;

    pctx = data;

    nxt_unit_debug(pctx->ctx, "worker thread start");

    ctx = nxt_unit_ctx_alloc(pctx->ctx, pctx);
    if (nxt_slow_path(ctx == NULL)) {
        return NULL;
    }

    pctx->ctx = ctx;

    PERL_SET_CONTEXT(pctx->my_perl);

    (void) nxt_unit_run(ctx);

    nxt_unit_done(ctx);

    nxt_unit_debug(NULL, "worker thread end");

    return NULL;
}


static int
nxt_perl_psgi_init_threads(nxt_perl_app_conf_t *c)
{
    int                    rc;
    uint32_t               i;
    static pthread_attr_t  attr;

    if (c->threads <= 1) {
        return NXT_UNIT_OK;
    }

    if (c->thread_stack_size > 0) {
        rc = pthread_attr_init(&attr);
        if (nxt_slow_path(rc != 0)) {
            nxt_unit_alert(NULL, "thread attr init failed: %s (%d)",
                           strerror(rc), rc);

            return NXT_UNIT_ERROR;
        }

        rc = pthread_attr_setstacksize(&attr, c->thread_stack_size);
        if (nxt_slow_path(rc != 0)) {
            nxt_unit_alert(NULL, "thread attr set stack size failed: %s (%d)",
                           strerror(rc), rc);

            return NXT_UNIT_ERROR;
        }

        nxt_perl_psgi_thread_attr = &attr;
    }

    nxt_perl_psgi_ctxs = nxt_unit_malloc(NULL, sizeof(nxt_perl_psgi_ctx_t)
                                               * (c->threads - 1));
    if (nxt_slow_path(nxt_perl_psgi_ctxs == NULL)) {
        return NXT_UNIT_ERROR;
    }

    memset(nxt_perl_psgi_ctxs, 0, sizeof(nxt_perl_psgi_ctx_t)
                                  * (c->threads - 1));

    for (i = 0; i < c->threads - 1; i++) {
        rc = nxt_perl_psgi_ctx_init(c->script, &nxt_perl_psgi_ctxs[i]);

        if (nxt_slow_path(rc != NXT_UNIT_OK)) {
            return NXT_UNIT_ERROR;
        }
    }

    return NXT_UNIT_OK;
}


static void
nxt_perl_psgi_join_threads(nxt_unit_ctx_t *ctx, nxt_perl_app_conf_t *c)
{
    int                  res;
    uint32_t             i;
    nxt_perl_psgi_ctx_t  *pctx;

    if (nxt_perl_psgi_ctxs == NULL) {
        return;
    }

    for (i = 0; i < c->threads - 1; i++) {
        pctx = &nxt_perl_psgi_ctxs[i];

        res = pthread_join(pctx->thread, NULL);

        if (nxt_fast_path(res == 0)) {
            nxt_unit_debug(ctx, "thread #%d joined", (int) (i + 1));

        } else {
            nxt_unit_alert(ctx, "thread #%d join failed: %s (%d)",
                           (int) (i + 1), strerror(res), res);
        }
    }

    for (i = 0; i < c->threads - 1; i++) {
        nxt_perl_psgi_ctx_free(&nxt_perl_psgi_ctxs[i]);
    }

    nxt_unit_free(NULL, nxt_perl_psgi_ctxs);
}


static void
nxt_perl_psgi_ctx_free(nxt_perl_psgi_ctx_t *pctx)
{
    PerlInterpreter  *my_perl;

    my_perl = pctx->my_perl;

    if (nxt_slow_path(my_perl == NULL)) {
        return;
    }

    PERL_SET_CONTEXT(my_perl);

    SvREFCNT_dec(pctx->arg_input.rv);
    SvREFCNT_dec(pctx->arg_error.rv);

    nxt_perl_psgi_io_release(my_perl, &pctx->arg_input);
    nxt_perl_psgi_io_release(my_perl, &pctx->arg_error);

    perl_destruct(my_perl);
    perl_free(my_perl);
}
