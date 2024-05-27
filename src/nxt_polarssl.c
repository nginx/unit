
/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Igor Sysoev
 */

#include <nxt_main.h>
#include <polarssl/config.h>
#include <polarssl/ssl.h>
#include <polarssl/x509.h>
#include <polarssl/error.h>


typedef struct {
    ssl_context  ssl;
    x509_cert    certificate;
    rsa_context  key;
} nxt_polarssl_ctx_t;


static nxt_int_t nxt_polarssl_server_init(nxt_ssltls_conf_t *conf);
static void nxt_polarssl_conn_init(nxt_thread_t *thr, nxt_ssltls_conf_t *conf,
    nxt_event_conn_t *c);
static void nxt_polarssl_log_error(nxt_uint_t level, nxt_log_t *log, int err,
    const char *fmt, ...);


nxt_ssltls_lib_t  nxt_polarssl_lib = {
    nxt_polarssl_server_init,
    NULL,
};


static nxt_int_t
nxt_polarssl_server_init(nxt_ssltls_conf_t *conf)
{
    int                 n;
    nxt_thread_t        *thr;
    nxt_polarssl_ctx_t  *ctx;

    thr = nxt_thread();

    /* TODO: mem_pool */

    ctx = nxt_zalloc(sizeof(nxt_polarssl_ctx_t));
    if (ctx == NULL) {
        return NXT_ERROR;
    }

    n = ssl_init(&ctx->ssl);
    if (n != 0) {
        nxt_polarssl_log_error(NXT_LOG_ALERT, thr->log, n, "ssl_init() failed");
        return NXT_ERROR;
    }

    ssl_set_endpoint(&ctx->ssl, SSL_IS_SERVER );

    conf->ctx = ctx;
    conf->conn_init = nxt_polarssl_conn_init;

    n = x509parse_crtfile(&ctx->certificate, conf->certificate);
    if (n != 0) {
        nxt_polarssl_log_error(NXT_LOG_ALERT, thr->log, n,
                               "x509parse_crt(\"%V\") failed",
                               &conf->certificate);
        goto fail;
    }

    rsa_init(&ctx->key, RSA_PKCS_V15, 0);

    n = x509parse_keyfile(&ctx->key, conf->certificate_key, NULL);
    if (n != 0) {
        nxt_polarssl_log_error(NXT_LOG_ALERT, thr->log, n,
                               "x509parse_key(\"%V\") failed",
                               &conf->certificate_key);
        goto fail;
    }

    ssl_set_own_cert(&ctx->ssl, &ctx->certificate, &ctx->key);

    /* TODO: ciphers */

    /* TODO: ca_certificate */

    return NXT_OK;

fail:

    return NXT_ERROR;
}


static void
nxt_polarssl_conn_init(nxt_thread_t *thr, nxt_ssltls_conf_t *conf,
    nxt_event_conn_t *c)
{
}


static void
nxt_polarssl_log_error(nxt_uint_t level, nxt_log_t *log, int err,
    const char *fmt, ...)
{
    va_list  args;
    u_char   *p, *end, msg[NXT_MAX_ERROR_STR];

    end = msg + NXT_MAX_ERROR_STR;

    va_start(args, fmt);
    p = nxt_vsprintf(msg, end, fmt, args);
    va_end(args);

    p = nxt_sprintf(p, end, " (%d: ", err);

    error_strerror(err, (char *) msg, p - msg);

    nxt_log_error(level, log, "%*s)", p - msg, msg);
}
