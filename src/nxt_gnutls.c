
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <gnutls/gnutls.h>


typedef struct {
    gnutls_session_t                  session;

    uint8_t                           times;        /* 2 bits */
    uint8_t                           no_shutdown;  /* 1 bit */

    nxt_buf_mem_t                     buffer;
} nxt_gnutls_conn_t;


typedef struct {
    gnutls_priority_t                 ciphers;
    gnutls_certificate_credentials_t  certificate;
} nxt_gnutls_ctx_t;



#if (NXT_HAVE_GNUTLS_SET_TIME)
time_t nxt_gnutls_time(time_t *tp);
#endif
static nxt_int_t nxt_gnutls_server_init(nxt_ssltls_conf_t *conf);
static nxt_int_t nxt_gnutls_set_ciphers(nxt_ssltls_conf_t *conf);

static void nxt_gnutls_conn_init(nxt_thread_t *thr, nxt_ssltls_conf_t *conf,
    nxt_event_conn_t *c);
static void nxt_gnutls_session_cleanup(void *data);
static ssize_t nxt_gnutls_pull(gnutls_transport_ptr_t data, void *buf,
    size_t size);
static ssize_t nxt_gnutls_push(gnutls_transport_ptr_t data, const void *buf,
    size_t size);
#if (NXT_HAVE_GNUTLS_VEC_PUSH)
static ssize_t nxt_gnutls_vec_push(gnutls_transport_ptr_t data,
    const giovec_t *iov, int iovcnt);
#endif
static void nxt_gnutls_conn_handshake(nxt_thread_t *thr, void *obj, void *data);
static void nxt_gnutls_conn_io_read(nxt_thread_t *thr, void *obj, void *data);
static ssize_t nxt_gnutls_conn_io_write_chunk(nxt_thread_t *thr,
    nxt_event_conn_t *c, nxt_buf_t *b, size_t limit);
static ssize_t nxt_gnutls_conn_io_send(nxt_event_conn_t *c, void *buf,
    size_t size);
static void nxt_gnutls_conn_io_shutdown(nxt_thread_t *thr, void *obj,
    void *data);
static nxt_int_t nxt_gnutls_conn_test_error(nxt_thread_t *thr,
    nxt_event_conn_t *c, ssize_t err, nxt_work_handler_t handler);
static void nxt_cdecl nxt_gnutls_conn_log_error(nxt_event_conn_t *c,
    ssize_t err, const char *fmt, ...);
static nxt_uint_t nxt_gnutls_log_error_level(nxt_event_conn_t *c, ssize_t err);
static void nxt_cdecl nxt_gnutls_log_error(nxt_uint_t level, nxt_log_t *log,
    int err, const char *fmt, ...);


const nxt_ssltls_lib_t  nxt_gnutls_lib = {
    nxt_gnutls_server_init,
    NULL,
};


static nxt_event_conn_io_t  nxt_gnutls_event_conn_io = {
    NULL,
    NULL,

    nxt_gnutls_conn_io_read,
    NULL,
    NULL,

    nxt_event_conn_io_write,
    nxt_gnutls_conn_io_write_chunk,
    NULL,
    NULL,
    nxt_gnutls_conn_io_send,

    nxt_gnutls_conn_io_shutdown,
};


static nxt_int_t
nxt_gnutls_start(void)
{
    int                ret;
    static nxt_bool_t  started;

    if (nxt_fast_path(started)) {
        return NXT_OK;
    }

    started = 1;

    /* TODO: gnutls_global_deinit */

    ret = gnutls_global_init();
    if (ret != GNUTLS_E_SUCCESS) {
        nxt_gnutls_log_error(NXT_LOG_ALERT, nxt_thread_log(), ret,
                             "gnutls_global_init() failed");
        return NXT_ERROR;
    }

    nxt_thread_log_error(NXT_LOG_INFO, "GnuTLS version: %s",
                         gnutls_check_version(NULL));

#if (NXT_HAVE_GNUTLS_SET_TIME)
    gnutls_global_set_time_function(nxt_gnutls_time);
#endif

    return NXT_OK;
}


#if (NXT_HAVE_GNUTLS_SET_TIME)

/* GnuTLS 2.12.0 */

time_t
nxt_gnutls_time(time_t *tp)
{
    time_t        t;
    nxt_thread_t  *thr;

    thr = nxt_thread();
    nxt_log_debug(thr->log, "gnutls time");

    t = (time_t) nxt_thread_time(thr);

    if (tp != NULL) {
        *tp = t;
    }

    return t;
}

#endif


static nxt_int_t
nxt_gnutls_server_init(nxt_ssltls_conf_t *conf)
{
    int                ret;
    char               *certificate, *key, *ca_certificate;
    nxt_thread_t       *thr;
    nxt_gnutls_ctx_t   *ctx;

    if (nxt_slow_path(nxt_gnutls_start() != NXT_OK)) {
        return NXT_ERROR;
    }

    /* TODO: mem_pool, cleanup: gnutls_certificate_free_credentials,
             gnutls_priority_deinit */

    ctx = nxt_zalloc(sizeof(nxt_gnutls_ctx_t));
    if (ctx == NULL) {
        return NXT_ERROR;
    }

    conf->ctx = ctx;
    conf->conn_init = nxt_gnutls_conn_init;

    thr = nxt_thread();

    ret = gnutls_certificate_allocate_credentials(&ctx->certificate);
    if (ret != GNUTLS_E_SUCCESS) {
        nxt_gnutls_log_error(NXT_LOG_ALERT, thr->log, ret,
                "gnutls_certificate_allocate_credentials() failed");
        return NXT_ERROR;
    }

    certificate = conf->certificate;
    key = conf->certificate_key;

    ret = gnutls_certificate_set_x509_key_file(ctx->certificate, certificate,
                                               key, GNUTLS_X509_FMT_PEM);
    if (ret != GNUTLS_E_SUCCESS) {
        nxt_gnutls_log_error(NXT_LOG_ALERT, thr->log, ret,
                "gnutls_certificate_set_x509_key_file(\"%s\", \"%s\") failed",
                certificate, key);
        goto certificate_fail;
    }

    if (nxt_gnutls_set_ciphers(conf) != NXT_OK) {
        goto ciphers_fail;
    }

    if (conf->ca_certificate != NULL) {
        ca_certificate = conf->ca_certificate;

        ret = gnutls_certificate_set_x509_trust_file(ctx->certificate,
                                                     ca_certificate,
                                                     GNUTLS_X509_FMT_PEM);
        if (ret < 0) {
            nxt_gnutls_log_error(NXT_LOG_ALERT, thr->log, ret,
                "gnutls_certificate_set_x509_trust_file(\"%s\") failed",
                ca_certificate);
            goto ca_certificate_fail;
        }
    }

    return NXT_OK;

ca_certificate_fail:

    gnutls_priority_deinit(ctx->ciphers);

ciphers_fail:

certificate_fail:

    gnutls_certificate_free_credentials(ctx->certificate);

    return NXT_ERROR;
}


static nxt_int_t
nxt_gnutls_set_ciphers(nxt_ssltls_conf_t *conf)
{
    int                ret;
    const char         *ciphers;
    const char         *err;
    nxt_gnutls_ctx_t   *ctx;

    ciphers = (conf->ciphers != NULL) ? conf->ciphers : "NORMAL:!COMP-DEFLATE";
    ctx = conf->ctx;

    ret = gnutls_priority_init(&ctx->ciphers, ciphers, &err);

    switch (ret) {

    case GNUTLS_E_SUCCESS:
        return NXT_OK;

    case GNUTLS_E_INVALID_REQUEST:
        nxt_gnutls_log_error(NXT_LOG_ALERT, nxt_thread_log(), ret,
                             "gnutls_priority_init(\"%s\") failed at \"%s\"",
                             ciphers, err);
        return NXT_ERROR;

    default:
        nxt_gnutls_log_error(NXT_LOG_ALERT, nxt_thread_log(), ret,
                             "gnutls_priority_init() failed");
        return NXT_ERROR;
    }
}


static void
nxt_gnutls_conn_init(nxt_thread_t *thr, nxt_ssltls_conf_t *conf,
    nxt_event_conn_t *c)
{
    int                     ret;
    gnutls_session_t        sess;
    nxt_gnutls_ctx_t        *ctx;
    nxt_gnutls_conn_t       *ssltls;
    nxt_mem_pool_cleanup_t  *mpcl;

    nxt_log_debug(c->socket.log, "gnutls conn init");

    ssltls = nxt_mp_zget(c->mem_pool, sizeof(nxt_gnutls_conn_t));
    if (ssltls == NULL) {
        goto fail;
    }

    c->u.ssltls = ssltls;
    nxt_buf_mem_set_size(&ssltls->buffer, conf->buffer_size);

    mpcl = nxt_mem_pool_cleanup(c->mem_pool, 0);
    if (mpcl == NULL) {
        goto fail;
    }

    ret = gnutls_init(&ssltls->session, GNUTLS_SERVER);
    if (ret != GNUTLS_E_SUCCESS) {
        nxt_gnutls_log_error(NXT_LOG_ALERT, c->socket.log, ret,
                             "gnutls_init() failed");
        goto fail;
    }

    sess = ssltls->session;
    mpcl->handler = nxt_gnutls_session_cleanup;
    mpcl->data = ssltls;

    ctx = conf->ctx;

    ret = gnutls_priority_set(sess, ctx->ciphers);
    if (ret != GNUTLS_E_SUCCESS) {
        nxt_gnutls_log_error(NXT_LOG_ALERT, c->socket.log, ret,
                             "gnutls_priority_set() failed");
        goto fail;
    }

    /*
     * Disable TLS random padding of records in CBC ciphers,
     * which may be up to 255 bytes.
     */
    gnutls_record_disable_padding(sess);

    ret = gnutls_credentials_set(sess, GNUTLS_CRD_CERTIFICATE,
                                 ctx->certificate);
    if (ret != GNUTLS_E_SUCCESS) {
        nxt_gnutls_log_error(NXT_LOG_ALERT, c->socket.log, ret,
                             "gnutls_credentials_set() failed");
        goto fail;
    }

    if (conf->ca_certificate != NULL) {
        gnutls_certificate_server_set_request(sess, GNUTLS_CERT_REQUEST);
    }

    gnutls_transport_set_ptr(sess, (gnutls_transport_ptr_t) c);
    gnutls_transport_set_pull_function(sess, nxt_gnutls_pull);
    gnutls_transport_set_push_function(sess, nxt_gnutls_push);
#if (NXT_HAVE_GNUTLS_VEC_PUSH)
    gnutls_transport_set_vec_push_function(sess, nxt_gnutls_vec_push);
#endif

    c->io = &nxt_gnutls_event_conn_io;
    c->sendfile = NXT_CONN_SENDFILE_OFF;

    nxt_gnutls_conn_handshake(thr, c, c->socket.data);
    return;

fail:

    nxt_event_conn_io_handle(thr, c->read_work_queue,
                             c->read_state->error_handler, c, c->socket.data);
}


static void
nxt_gnutls_session_cleanup(void *data)
{
    nxt_gnutls_conn_t  *ssltls;

    ssltls = data;

    nxt_thread_log_debug("gnutls session cleanup");

    nxt_free(ssltls->buffer.start);

    gnutls_deinit(ssltls->session);
}


static ssize_t
nxt_gnutls_pull(gnutls_transport_ptr_t data, void *buf, size_t size)
{
    ssize_t           n;
    nxt_thread_t      *thr;
    nxt_event_conn_t  *c;

    c = data;
    thr = nxt_thread();

    n = thr->engine->event->io->recv(c, buf, size, 0);

    if (n == NXT_AGAIN) {
        nxt_set_errno(NXT_EAGAIN);
        return -1;
    }

    return n;
}


static ssize_t
nxt_gnutls_push(gnutls_transport_ptr_t data, const void *buf, size_t size)
{
    ssize_t           n;
    nxt_thread_t      *thr;
    nxt_event_conn_t  *c;

    c = data;
    thr = nxt_thread();

    n = thr->engine->event->io->send(c, (u_char *) buf, size);

    if (n == NXT_AGAIN) {
        nxt_set_errno(NXT_EAGAIN);
        return -1;
    }

    return n;
}


#if (NXT_HAVE_GNUTLS_VEC_PUSH)

/* GnuTLS 2.12.0 */

static ssize_t
nxt_gnutls_vec_push(gnutls_transport_ptr_t data, const giovec_t *iov,
    int iovcnt)
{
    ssize_t           n;
    nxt_thread_t      *thr;
    nxt_event_conn_t  *c;

    c = data;
    thr = nxt_thread();

    /*
     * This code assumes that giovec_t is the same as "struct iovec"
     * and nxt_iobuf_t.  It is not true for Windows.
     */
    n = thr->engine->event->io->writev(c, (nxt_iobuf_t *) iov, iovcnt);

    if (n == NXT_AGAIN) {
        nxt_set_errno(NXT_EAGAIN);
        return -1;
    }

    return n;
}

#endif


static void
nxt_gnutls_conn_handshake(nxt_thread_t *thr, void *obj, void *data)
{
    int                err;
    nxt_int_t          ret;
    nxt_event_conn_t   *c;
    nxt_gnutls_conn_t  *ssltls;

    c = obj;
    ssltls = c->u.ssltls;

    nxt_log_debug(thr->log, "gnutls conn handshake: %d", ssltls->times);

    /* "ssltls->times == 1" is suitable to run gnutls_handshake() in job. */

    err = gnutls_handshake(ssltls->session);

    nxt_thread_time_debug_update(thr);

    nxt_log_debug(thr->log, "gnutls_handshake(): %d", err);

    if (err == GNUTLS_E_SUCCESS) {
        nxt_gnutls_conn_io_read(thr, c, data);
        return;
    }

    ret = nxt_gnutls_conn_test_error(thr, c, err, nxt_gnutls_conn_handshake);

    if (ret == NXT_ERROR) {
        nxt_gnutls_conn_log_error(c, err, "gnutls_handshake() failed");

        nxt_event_conn_io_handle(thr, c->read_work_queue,
                                 c->read_state->error_handler, c, data);

    } else if (err == GNUTLS_E_AGAIN
               && ssltls->times < 2
               && gnutls_record_get_direction(ssltls->session) == 0)
    {
        ssltls->times++;
    }
}


static void
nxt_gnutls_conn_io_read(nxt_thread_t *thr, void *obj, void *data)
{
    ssize_t             n;
    nxt_buf_t           *b;
    nxt_int_t           ret;
    nxt_event_conn_t    *c;
    nxt_gnutls_conn_t   *ssltls;
    nxt_work_handler_t  handler;

    c = obj;

    nxt_log_debug(thr->log, "gnutls conn read");

    handler = c->read_state->ready_handler;
    b = c->read;

    /* b == NULL is used to test descriptor readiness. */

    if (b != NULL) {
        ssltls = c->u.ssltls;

        n = gnutls_record_recv(ssltls->session, b->mem.free,
                               b->mem.end - b->mem.free);

        nxt_log_debug(thr->log, "gnutls_record_recv(%d, %p, %uz): %z",
                      c->socket.fd, b->mem.free, b->mem.end - b->mem.free, n);

        if (n > 0) {
            /* c->socket.read_ready is kept. */
            b->mem.free += n;
            handler = c->read_state->ready_handler;

        } else if (n == 0) {
            handler = c->read_state->close_handler;

        } else {
            ret = nxt_gnutls_conn_test_error(thr, c, n,
                                             nxt_gnutls_conn_io_read);

            if (nxt_fast_path(ret != NXT_ERROR)) {
                return;
            }

            nxt_gnutls_conn_log_error(c, n,
                                      "gnutls_record_recv(%d, %p, %uz): failed",
                                      c->socket.fd, b->mem.free,
                                      b->mem.end - b->mem.free);

            handler = c->read_state->error_handler;
        }
    }

    nxt_event_conn_io_handle(thr, c->read_work_queue, handler, c, data);
}


static ssize_t
nxt_gnutls_conn_io_write_chunk(nxt_thread_t *thr, nxt_event_conn_t *c,
    nxt_buf_t *b, size_t limit)
{
    nxt_gnutls_conn_t  *ssltls;

    nxt_log_debug(thr->log, "gnutls conn write chunk");

    ssltls = c->u.ssltls;

    return nxt_sendbuf_copy_coalesce(c, &ssltls->buffer, b, limit);
}


static ssize_t
nxt_gnutls_conn_io_send(nxt_event_conn_t *c, void *buf, size_t size)
{
    ssize_t            n;
    nxt_int_t          ret;
    nxt_gnutls_conn_t  *ssltls;

    ssltls = c->u.ssltls;

    n = gnutls_record_send(ssltls->session, buf, size);

    nxt_log_debug(c->socket.log, "gnutls_record_send(%d, %p, %uz): %z",
                  c->socket.fd, buf, size, n);

    if (n > 0) {
        return n;
    }

    ret = nxt_gnutls_conn_test_error(nxt_thread(), c, n,
                                     nxt_event_conn_io_write);

    if (nxt_slow_path(ret == NXT_ERROR)) {
        nxt_gnutls_conn_log_error(c, n,
                                  "gnutls_record_send(%d, %p, %uz): failed",
                                  c->socket.fd, buf, size);
    }

    return ret;
}


static void
nxt_gnutls_conn_io_shutdown(nxt_thread_t *thr, void *obj, void *data)
{
    int                     err;
    nxt_int_t               ret;
    nxt_event_conn_t        *c;
    nxt_gnutls_conn_t       *ssltls;
    nxt_work_handler_t      handler;
    gnutls_close_request_t  how;

    c = obj;
    ssltls = c->u.ssltls;

    if (ssltls->session == NULL || ssltls->no_shutdown) {
        handler = c->write_state->close_handler;
        goto done;
    }

    nxt_log_debug(c->socket.log, "gnutls conn shutdown");

    if (c->socket.timedout || c->socket.error != 0) {
        how = GNUTLS_SHUT_WR;

    } else if (c->socket.closed) {
        how = GNUTLS_SHUT_RDWR;

    } else {
        how = GNUTLS_SHUT_RDWR;
    }

    err = gnutls_bye(ssltls->session, how);

    nxt_log_debug(c->socket.log, "gnutls_bye(%d, %d): %d",
                  c->socket.fd, how, err);

    if (err == GNUTLS_E_SUCCESS) {
        handler = c->write_state->close_handler;

    } else {
        ret = nxt_gnutls_conn_test_error(thr, c, err,
                                         nxt_gnutls_conn_io_shutdown);

        if (ret != NXT_ERROR) {  /* ret == NXT_AGAIN */
            c->socket.error_handler = c->read_state->error_handler;
            nxt_event_timer_add(thr->engine, &c->read_timer, 5000);
            return;
        }

        nxt_gnutls_conn_log_error(c, err, "gnutls_bye(%d) failed",
                                  c->socket.fd);

        handler = c->write_state->error_handler;
    }

done:

    nxt_event_conn_io_handle(thr, c->write_work_queue, handler, c, data);
}


static nxt_int_t
nxt_gnutls_conn_test_error(nxt_thread_t *thr, nxt_event_conn_t *c, ssize_t err,
    nxt_work_handler_t handler)
{
    int                ret;
    nxt_gnutls_conn_t  *ssltls;

    switch (err) {

    case GNUTLS_E_REHANDSHAKE:
    case GNUTLS_E_AGAIN:
        ssltls = c->u.ssltls;
        ret = gnutls_record_get_direction(ssltls->session);

        nxt_log_debug(thr->log, "gnutls_record_get_direction(): %d", ret);

        if (ret == 0) {
            /* A read direction. */

            nxt_event_fd_block_write(thr->engine, &c->socket);

            c->socket.read_ready = 0;
            c->socket.read_handler = handler;

            if (nxt_event_fd_is_disabled(c->socket.read)) {
                nxt_event_fd_enable_read(thr->engine, &c->socket);
            }

        } else {
            /* A write direction. */

            nxt_event_fd_block_read(thr->engine, &c->socket);

            c->socket.write_ready = 0;
            c->socket.write_handler = handler;

            if (nxt_event_fd_is_disabled(c->socket.write)) {
                nxt_event_fd_enable_write(thr->engine, &c->socket);
            }
        }

        return NXT_AGAIN;

    default:
        c->socket.error = 1000;  /* Nonexistent errno code. */
        return NXT_ERROR;
    }
}


static void
nxt_gnutls_conn_log_error(nxt_event_conn_t *c, ssize_t err,
    const char *fmt, ...)
{
    va_list      args;
    nxt_uint_t   level;
    u_char       *p, msg[NXT_MAX_ERROR_STR];

    level = nxt_gnutls_log_error_level(c, err);

    if (nxt_log_level_enough(c->socket.log, level)) {

        va_start(args, fmt);
        p = nxt_vsprintf(msg, msg + sizeof(msg), fmt, args);
        va_end(args);

        nxt_log_error(level, c->socket.log, "%*s (%d: %s)",
                      p - msg, msg, err, gnutls_strerror(err));
    }
}


static nxt_uint_t
nxt_gnutls_log_error_level(nxt_event_conn_t *c, ssize_t err)
{
    nxt_gnutls_conn_t  *ssltls;

    switch (err) {

    case GNUTLS_E_UNKNOWN_CIPHER_SUITE:                      /*  -21 */

        /* Disable gnutls_bye(), because it returns GNUTLS_E_INTERNAL_ERROR. */
        ssltls = c->u.ssltls;
        ssltls->no_shutdown = 1;

        /* Fall through. */

    case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:                  /*   -9 */
        c->socket.error = 1000;  /* Nonexistent errno code. */
        break;

    default:
        return NXT_LOG_ALERT;
    }

    return NXT_LOG_INFO;
}


static void
nxt_gnutls_log_error(nxt_uint_t level, nxt_log_t *log, int err,
    const char *fmt, ...)
{
    va_list  args;
    u_char   *p, msg[NXT_MAX_ERROR_STR];

    va_start(args, fmt);
    p = nxt_vsprintf(msg, msg + sizeof(msg), fmt, args);
    va_end(args);

    nxt_log_error(level, log, "%*s (%d: %s)",
                  p - msg, msg, err, gnutls_strerror(err));
}
