
/*
 * Copyright (C) Alexander Borisov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PERL_PSGI_LAYER_H_INCLUDED_
#define _NXT_PERL_PSGI_LAYER_H_INCLUDED_


#include <EXTERN.h>
#include <XSUB.h>
#include <perl.h>
#include <perliol.h>


typedef struct nxt_perl_psgi_io_arg nxt_perl_psgi_io_arg_t;

typedef long (*nxt_perl_psgi_io_read_f)(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length);
typedef long (*nxt_perl_psgi_io_write_f)(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg, const void *vbuf, size_t length);
typedef long (*nxt_perl_psgi_io_arg_f)(PerlInterpreter *my_perl,
    nxt_perl_psgi_io_arg_t *arg);


struct nxt_perl_psgi_io_arg {
    SV                        *io;
    PerlIO                    *fp;

    nxt_perl_psgi_io_arg_f    flush;
    nxt_perl_psgi_io_read_f   read;
    nxt_perl_psgi_io_write_f  write;

    void                      *ctx;
};


void nxt_perl_psgi_layer_stream_init(pTHX);

PerlIO *nxt_perl_psgi_layer_stream_fp_create(pTHX_ nxt_perl_psgi_io_arg_t *arg,
    const char *mode);
void nxt_perl_psgi_layer_stream_fp_destroy(pTHX_ PerlIO *io);

SV *nxt_perl_psgi_layer_stream_io_create(pTHX_ PerlIO *fp);
void nxt_perl_psgi_layer_stream_io_destroy(pTHX_ SV *rvio);

#endif /* _NXT_PERL_PSGI_LAYER_H_INCLUDED_ */
