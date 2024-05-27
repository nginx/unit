
/*
 * Copyright (C) Alexander Borisov
 * Copyright (C) NGINX, Inc.
 */

#include <perl/nxt_perl_psgi_layer.h>


typedef struct {
    struct _PerlIO  base;

    SV              *var;
} nxt_perl_psgi_layer_stream_t;


static IV nxt_perl_psgi_layer_stream_pushed(pTHX_ PerlIO *f, const char *mode,
    SV *arg, PerlIO_funcs *tab);
static IV nxt_perl_psgi_layer_stream_popped(pTHX_ PerlIO *f);

static PerlIO *nxt_perl_psgi_layer_stream_open(pTHX_ PerlIO_funcs *self,
    PerlIO_list_t *layers, IV n,
    const char *mode, int fd, int imode, int perm,
    PerlIO *f, int narg, SV **args);

static IV nxt_perl_psgi_layer_stream_close(pTHX_ PerlIO *f);

static SSize_t nxt_perl_psgi_layer_stream_read(pTHX_ PerlIO *f,
    void *vbuf, Size_t count);
static SSize_t nxt_perl_psgi_layer_stream_write(pTHX_ PerlIO *f,
    const void *vbuf, Size_t count);

static IV nxt_perl_psgi_layer_stream_fileno(pTHX_ PerlIO *f);
static IV nxt_perl_psgi_layer_stream_seek(pTHX_ PerlIO *f,
    Off_t offset, int whence);
static Off_t nxt_perl_psgi_layer_stream_tell(pTHX_ PerlIO *f);
static IV nxt_perl_psgi_layer_stream_fill(pTHX_ PerlIO *f);
static IV nxt_perl_psgi_layer_stream_flush(pTHX_ PerlIO *f);

static SV *nxt_perl_psgi_layer_stream_arg(pTHX_ PerlIO *f,
    CLONE_PARAMS *param, int flags);

static PerlIO *nxt_perl_psgi_layer_stream_dup(pTHX_ PerlIO *f, PerlIO *o,
    CLONE_PARAMS *param, int flags);
static IV nxt_perl_psgi_layer_stream_eof(pTHX_ PerlIO *f);

static STDCHAR *nxt_perl_psgi_layer_stream_get_base(pTHX_ PerlIO *f);
static STDCHAR *nxt_perl_psgi_layer_stream_get_ptr(pTHX_ PerlIO *f);
static SSize_t nxt_perl_psgi_layer_stream_get_cnt(pTHX_ PerlIO *f);
static Size_t nxt_perl_psgi_layer_stream_buffersize(pTHX_ PerlIO *f);
static void nxt_perl_psgi_layer_stream_set_ptrcnt(pTHX_ PerlIO *f,
    STDCHAR *ptr, SSize_t cnt);


static PERLIO_FUNCS_DECL(PerlIO_NGINX_Unit) = {
    sizeof(PerlIO_funcs),
    "NGINX_Unit_PSGI_Layer_Stream",
    sizeof(nxt_perl_psgi_layer_stream_t),
    PERLIO_K_BUFFERED | PERLIO_K_RAW,
    nxt_perl_psgi_layer_stream_pushed,
    nxt_perl_psgi_layer_stream_popped,
    nxt_perl_psgi_layer_stream_open,
    PerlIOBase_binmode,
    nxt_perl_psgi_layer_stream_arg,
    nxt_perl_psgi_layer_stream_fileno,
    nxt_perl_psgi_layer_stream_dup,
    nxt_perl_psgi_layer_stream_read,
    NULL,
    nxt_perl_psgi_layer_stream_write,
    nxt_perl_psgi_layer_stream_seek,
    nxt_perl_psgi_layer_stream_tell,
    nxt_perl_psgi_layer_stream_close,
    nxt_perl_psgi_layer_stream_flush,
    nxt_perl_psgi_layer_stream_fill,
    nxt_perl_psgi_layer_stream_eof,
    PerlIOBase_error,
    PerlIOBase_clearerr,
    PerlIOBase_setlinebuf,
    nxt_perl_psgi_layer_stream_get_base,
    nxt_perl_psgi_layer_stream_buffersize,
    nxt_perl_psgi_layer_stream_get_ptr,
    nxt_perl_psgi_layer_stream_get_cnt,
    nxt_perl_psgi_layer_stream_set_ptrcnt,
};


static IV
nxt_perl_psgi_layer_stream_pushed(pTHX_ PerlIO *f, const char *mode, SV *arg,
    PerlIO_funcs *tab)
{
    nxt_perl_psgi_layer_stream_t  *unit_stream;

    unit_stream = PerlIOSelf(f, nxt_perl_psgi_layer_stream_t);

    if (arg != NULL && SvOK(arg)) {
        unit_stream->var = SvREFCNT_inc(arg);
    }

    return PerlIOBase_pushed(aTHX_ f, mode, Nullsv, tab);
}


static IV
nxt_perl_psgi_layer_stream_popped(pTHX_ PerlIO *f)
{
    nxt_perl_psgi_io_arg_t        *arg;
    nxt_perl_psgi_layer_stream_t  *unit_stream;

    unit_stream = PerlIOSelf(f, nxt_perl_psgi_layer_stream_t);

    if (unit_stream->var != NULL) {
        arg = (void *) (intptr_t) SvIV(SvRV(unit_stream->var));

        arg->io = NULL;
        arg->fp = NULL;

        SvREFCNT_dec(unit_stream->var);
        unit_stream->var = Nullsv;
    }

    return 0;
}


static PerlIO *
nxt_perl_psgi_layer_stream_open(pTHX_ PerlIO_funcs *self,
    PerlIO_list_t *layers, IV n,
    const char *mode, int fd, int imode, int perm,
    PerlIO *f, int narg, SV **args)
{
    SV  *arg;

    arg = (narg > 0) ? *args : PerlIOArg;

    PERL_UNUSED_ARG(fd);
    PERL_UNUSED_ARG(imode);
    PERL_UNUSED_ARG(perm);

    if (SvROK(arg) || SvPOK(arg)) {

        if (f == NULL) {
            f = PerlIO_allocate(aTHX);
        }

        f = PerlIO_push(aTHX_ f, self, mode, arg);

        if (f != NULL) {
            PerlIOBase(f)->flags |= PERLIO_F_OPEN;
        }

        return f;
    }

    return NULL;
}


static IV
nxt_perl_psgi_layer_stream_close(pTHX_ PerlIO *f)
{
    IV  code;

    code = PerlIOBase_close(aTHX_ f);
    PerlIOBase(f)->flags &= ~(PERLIO_F_RDBUF | PERLIO_F_WRBUF);

    return code;
}


static IV
nxt_perl_psgi_layer_stream_fileno(pTHX_ PerlIO *f)
{
    PERL_UNUSED_ARG(f);
    return -1;
}


static SSize_t
nxt_perl_psgi_layer_stream_read(pTHX_ PerlIO *f, void *vbuf, Size_t count)
{
    nxt_perl_psgi_io_arg_t        *arg;
    nxt_perl_psgi_layer_stream_t  *unit_stream;

    if (f == NULL) {
        return 0;
    }

    if ((PerlIOBase(f)->flags & PERLIO_F_CANREAD) == 0) {
        PerlIOBase(f)->flags |= PERLIO_F_ERROR;

        SETERRNO(EBADF, SS_IVCHAN);

        return 0;
    }

    unit_stream = PerlIOSelf(f, nxt_perl_psgi_layer_stream_t);
    arg = (void *) (intptr_t) SvIV(SvRV(unit_stream->var));

    return arg->io_tab->read(PERL_GET_CONTEXT, arg, vbuf, count);
}


static SSize_t
nxt_perl_psgi_layer_stream_write(pTHX_ PerlIO *f,
    const void *vbuf, Size_t count)
{
    nxt_perl_psgi_io_arg_t        *arg;
    nxt_perl_psgi_layer_stream_t  *unit_stream;

    if (PerlIOBase(f)->flags & PERLIO_F_CANWRITE) {
        unit_stream = PerlIOSelf(f, nxt_perl_psgi_layer_stream_t);
        arg = (void *) (intptr_t) SvIV(SvRV(unit_stream->var));

        return arg->io_tab->write(PERL_GET_CONTEXT, arg, vbuf, count);
    }

    return 0;
}


static IV
nxt_perl_psgi_layer_stream_seek(pTHX_ PerlIO *f, Off_t offset, int whence)
{
    PERL_UNUSED_ARG(f);
    return 0;
}


static Off_t
nxt_perl_psgi_layer_stream_tell(pTHX_ PerlIO *f)
{
    PERL_UNUSED_ARG(f);
    return 0;
}


static IV
nxt_perl_psgi_layer_stream_fill(pTHX_ PerlIO *f)
{
    PERL_UNUSED_ARG(f);
    return -1;
}


static IV
nxt_perl_psgi_layer_stream_flush(pTHX_ PerlIO *f)
{
    return 0;
}


static SV *
nxt_perl_psgi_layer_stream_arg(pTHX_ PerlIO * f,
    CLONE_PARAMS *param, int flags)
{
    SV                            *var;
    nxt_perl_psgi_layer_stream_t  *unit_stream;

    unit_stream = PerlIOSelf(f, nxt_perl_psgi_layer_stream_t);
    var = unit_stream->var;

    if (flags & PERLIO_DUP_CLONE) {
        var = PerlIO_sv_dup(aTHX_ var, param);

    } else if (flags & PERLIO_DUP_FD) {
        var = newSVsv(var);

    } else {
        var = SvREFCNT_inc(var);
    }

    return var;
}


static PerlIO *
nxt_perl_psgi_layer_stream_dup(pTHX_ PerlIO *f, PerlIO *o,
    CLONE_PARAMS *param, int flags)
{
    nxt_perl_psgi_layer_stream_t  *fs;

    f = PerlIOBase_dup(aTHX_ f, o, param, flags);

    if (f != NULL) {
        fs = PerlIOSelf(f, nxt_perl_psgi_layer_stream_t);
        fs->var = nxt_perl_psgi_layer_stream_arg(aTHX_ o, param, flags);
    }

    return f;
}


static IV
nxt_perl_psgi_layer_stream_eof(pTHX_ PerlIO *f)
{
    return 1;
}


static STDCHAR *
nxt_perl_psgi_layer_stream_get_base(pTHX_ PerlIO *f)
{
    return (STDCHAR *) NULL;
}


static STDCHAR *
nxt_perl_psgi_layer_stream_get_ptr(pTHX_ PerlIO *f)
{
    return (STDCHAR *) NULL;
}


static SSize_t
nxt_perl_psgi_layer_stream_get_cnt(pTHX_ PerlIO *f)
{
    return 0;
}


static Size_t
nxt_perl_psgi_layer_stream_buffersize(pTHX_ PerlIO *f)
{
    return 0;
}


static void
nxt_perl_psgi_layer_stream_set_ptrcnt(pTHX_ PerlIO *f,
    STDCHAR *ptr, SSize_t cnt)
{
    /* Need some code. */
}


void
nxt_perl_psgi_layer_stream_init(pTHX)
{
    PerlIO_define_layer(aTHX_ PERLIO_FUNCS_CAST(&PerlIO_NGINX_Unit));
}


PerlIO *
nxt_perl_psgi_layer_stream_fp_create(pTHX_ SV *arg_rv,
    const char *mode)
{
    return PerlIO_openn(aTHX_ "NGINX_Unit_PSGI_Layer_Stream",
                        mode, 0, 0, 0, NULL, 1, &arg_rv);
}


void
nxt_perl_psgi_layer_stream_fp_destroy(pTHX_ PerlIO *io)
{
    PerlIO_close(io);
}


SV *
nxt_perl_psgi_layer_stream_io_create(pTHX_ PerlIO *fp)
{
    SV  *rvio;
    IO  *thatio;

    thatio = newIO();

    if (thatio == NULL) {
        return NULL;
    }

    IoOFP(thatio) = fp;
    IoIFP(thatio) = fp;

    rvio = newRV_noinc((SV *) thatio);

    if (rvio == NULL) {
        SvREFCNT_dec(thatio);
        return NULL;
    }

    return rvio;
}
