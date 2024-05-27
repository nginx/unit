
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


typedef struct nxt_perl_psgi_io_tab_s nxt_perl_psgi_io_tab_t;
typedef struct nxt_perl_psgi_io_arg_s nxt_perl_psgi_io_arg_t;


struct nxt_perl_psgi_io_tab_s {
    SSize_t (*read)(PerlInterpreter *my_perl,
        nxt_perl_psgi_io_arg_t *arg, void *vbuf, size_t length);
    SSize_t (*write)(PerlInterpreter *my_perl,
        nxt_perl_psgi_io_arg_t *arg, const void *vbuf, size_t length);
};


struct nxt_perl_psgi_io_arg_s {
    SV                            *rv;
    SV                            *io;
    PerlIO                        *fp;

    const nxt_perl_psgi_io_tab_t  *io_tab;

    void                          *req;
};


void nxt_perl_psgi_layer_stream_init(pTHX);

PerlIO *nxt_perl_psgi_layer_stream_fp_create(pTHX_ SV *arg_rv,
    const char *mode);
void nxt_perl_psgi_layer_stream_fp_destroy(pTHX_ PerlIO *io);

SV *nxt_perl_psgi_layer_stream_io_create(pTHX_ PerlIO *fp);

#endif /* _NXT_PERL_PSGI_LAYER_H_INCLUDED_ */
