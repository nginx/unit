
/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Igor Sysoev
 */

#include <nxt_main.h>
#include <cyassl/ssl.h>
#include <cyassl/error-ssl.h>


typedef struct {
    CYASSL         *session;

    int            ssl_error;
    uint8_t        times;      /* 2 bits */

    nxt_buf_mem_t  buffer;
} nxt_cyassl_conn_t;


static nxt_int_t nxt_cyassl_server_init(nxt_ssltls_conf_t *conf);
static void nxt_cyassl_conn_init(nxt_thread_t *thr, nxt_ssltls_conf_t *conf,
    nxt_event_conn_t *c);
static void nxt_cyassl_session_cleanup(void *data);
static int nxt_cyassl_io_recv(CYASSL *ssl, char *buf, int size, void *data);
static int nxt_cyassl_io_send(CYASSL *ssl, char *buf, int size, void *data);
static void nxt_cyassl_conn_handshake(nxt_thread_t *thr, void *obj, void *data);
static void nxt_cyassl_conn_io_read(nxt_thread_t *thr, void *obj, void *data);
static void nxt_cyassl_conn_io_shutdown(nxt_thread_t *thr, void *obj,
    void *data);
static ssize_t nxt_cyassl_conn_io_write_chunk(nxt_thread_t *thr,
    nxt_event_conn_t *c, nxt_buf_t *b, size_t limit);
static ssize_t nxt_cyassl_conn_io_send(nxt_event_conn_t *c, void *buf,
    size_t size);
static nxt_int_t nxt_cyassl_conn_test_error(nxt_thread_t *thr,
    nxt_event_conn_t *c, int err, nxt_work_handler_t handler);
static void nxt_cdecl nxt_cyassl_conn_error(nxt_event_conn_t *c, nxt_err_t err,
    const char *fmt, ...);
static nxt_uint_t nxt_cyassl_log_error_level(nxt_event_conn_t *c, nxt_err_t err,
    int ssl_error);
static void nxt_cdecl nxt_cyassl_log_error(nxt_uint_t level, nxt_log_t *log,
    int ret, const char *fmt, ...);
static u_char *nxt_cyassl_copy_error(int err, u_char *p, u_char *end);


const nxt_ssltls_lib_t  nxt_cyassl_lib = {
    nxt_cyassl_server_init,
    NULL,
};


static nxt_event_conn_io_t  nxt_cyassl_event_conn_io = {
    NULL,
    NULL,

    nxt_cyassl_conn_io_read,
    NULL,
    NULL,

    nxt_event_conn_io_write,
    nxt_cyassl_conn_io_write_chunk,
    NULL,
    NULL,
    nxt_cyassl_conn_io_send,

    nxt_cyassl_conn_io_shutdown,
};


static nxt_int_t
nxt_cyassl_start(void)
{
    int                err;
    nxt_thread_t       *thr;
    static nxt_bool_t  started;

    if (nxt_fast_path(started)) {
        return NXT_OK;
    }

    started = 1;

    thr = nxt_thread();

    /* TODO: CyaSSL_Cleanup() */

    err = CyaSSL_Init();
    if (err != SSL_SUCCESS) {
        nxt_cyassl_log_error(NXT_LOG_ALERT, thr->log, err,
                             "CyaSSL_Init() failed");
        return NXT_ERROR;
    }

    nxt_thread_log_error(NXT_LOG_INFO, "CyaSSL version: %s",
                         LIBCYASSL_VERSION_STRING);

    /* CyaSSL_SetLoggingCb */
    /* CyaSSL_SetAllocators */

    return NXT_OK;
}


static nxt_int_t
nxt_cyassl_server_init(nxt_ssltls_conf_t *conf)
{
    int           err;
    char          *certificate, *key;
    CYASSL_CTX    *ctx;
    nxt_thread_t  *thr;

    thr = nxt_thread();

    if (nxt_slow_path(nxt_cyassl_start() != NXT_OK)) {
        return NXT_ERROR;
    }

    ctx = CyaSSL_CTX_new(CyaSSLv23_server_method());
    if (ctx == NULL) {
        nxt_cyassl_log_error(NXT_LOG_ALERT, thr->log, 0,
                             "CyaSSL_CTX_new() failed");
        return NXT_ERROR;
    }

    conf->ctx = ctx;
    conf->conn_init = nxt_cyassl_conn_init;

    certificate = conf->certificate;

    err = CyaSSL_CTX_use_certificate_file(ctx, certificate, SSL_FILETYPE_PEM);
    if (err != SSL_SUCCESS) {
        nxt_cyassl_log_error(NXT_LOG_ALERT, thr->log, err,
                             "CyaSSL_CTX_use_certificate_file(\"%s\") failed",
                             certificate);
        goto fail;
    }

    key = conf->certificate_key;

    err = CyaSSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
    if (err != SSL_SUCCESS) {
        nxt_cyassl_log_error(NXT_LOG_ALERT, thr->log, err,
                             "CyaSSL_CTX_use_PrivateKey_file(\"%s\") failed",
                             key);
        goto fail;
    }

    if (conf->ciphers != NULL) {
        err = CyaSSL_CTX_set_cipher_list(ctx, conf->ciphers);
        if (err != SSL_SUCCESS) {
            nxt_cyassl_log_error(NXT_LOG_ALERT, thr->log, err,
                                 "CyaSSL_CTX_set_cipher_list(\"%s\") failed",
                                 conf->ciphers);
            goto fail;
        }
    }

    /* TODO: ca_certificate */

    CyaSSL_SetIORecv(ctx, nxt_cyassl_io_recv);
    CyaSSL_SetIOSend(ctx, nxt_cyassl_io_send);

    return NXT_OK;

fail:

    CyaSSL_CTX_free(ctx);

    return NXT_ERROR;
}


static void
nxt_cyassl_conn_init(nxt_thread_t *thr, nxt_ssltls_conf_t *conf,
    nxt_event_conn_t *c)
{
    CYASSL                  *s;
    CYASSL_CTX              *ctx;
    nxt_cyassl_conn_t       *ssltls;
    nxt_mem_pool_cleanup_t  *mpcl;

    nxt_log_debug(c->socket.log, "cyassl conn init");

    ssltls = nxt_mp_zget(c->mem_pool, sizeof(nxt_cyassl_conn_t));
    if (ssltls == NULL) {
        goto fail;
    }

    c->u.ssltls = ssltls;
    nxt_buf_mem_set_size(&ssltls->buffer, conf->buffer_size);

    mpcl = nxt_mem_pool_cleanup(c->mem_pool, 0);
    if (mpcl == NULL) {
        goto fail;
    }

    ctx = conf->ctx;

    s = CyaSSL_new(ctx);
    if (s == NULL) {
        nxt_cyassl_log_error(NXT_LOG_ALERT, c->socket.log, 0,
                             "CyaSSL_new() failed");
        goto fail;
    }

    ssltls->session = s;
    mpcl->handler = nxt_cyassl_session_cleanup;
    mpcl->data = ssltls;

    CyaSSL_SetIOReadCtx(s, c);
    CyaSSL_SetIOWriteCtx(s, c);

    c->io = &nxt_cyassl_event_conn_io;
    c->sendfile = NXT_CONN_SENDFILE_OFF;

    nxt_cyassl_conn_handshake(thr, c, c->socket.data);
    return;

fail:

    nxt_event_conn_io_handle(thr, c->read_work_queue,
                             c->read_state->error_handler, c, c->socket.data);
}


static void
nxt_cyassl_session_cleanup(void *data)
{
    nxt_cyassl_conn_t  *ssltls;

    ssltls = data;

    nxt_thread_log_debug("cyassl session cleanup");

    nxt_free(ssltls->buffer.start);

    CyaSSL_free(ssltls->session);
}


static int
nxt_cyassl_io_recv(CYASSL *ssl, char *buf, int size, void *data)
{
    ssize_t           n;
    nxt_thread_t      *thr;
    nxt_event_conn_t  *c;

    c = data;
    thr = nxt_thread();

    n = thr->engine->event->io->recv(c, (u_char *) buf, size, 0);

    if (n > 0) {
        return n;
    }

    if (n == 0) {
        return CYASSL_CBIO_ERR_CONN_CLOSE;
    }

    if (n == NXT_AGAIN) {
        return CYASSL_CBIO_ERR_WANT_READ;
    }

    return CYASSL_CBIO_ERR_GENERAL;
}


static int
nxt_cyassl_io_send(CYASSL *ssl, char *buf, int size, void *data)
{
    ssize_t           n;
    nxt_thread_t      *thr;
    nxt_event_conn_t  *c;

    c = data;
    thr = nxt_thread();

    n = thr->engine->event->io->send(c, (u_char *) buf, size);

    if (n > 0) {
        return n;
    }

    if (n == NXT_AGAIN) {
        return CYASSL_CBIO_ERR_WANT_WRITE;
    }

    return CYASSL_CBIO_ERR_GENERAL;
}


static void
nxt_cyassl_conn_handshake(nxt_thread_t *thr, void *obj, void *data)
{
    int                ret;
    nxt_int_t          n;
    nxt_err_t          err;
    nxt_event_conn_t   *c;
    nxt_cyassl_conn_t  *ssltls;

    c = obj;
    ssltls = c->u.ssltls;

    nxt_log_debug(thr->log, "cyassl conn handshake: %d", ssltls->times);

    /* "ssltls->times == 1" is suitable to run CyaSSL_negotiate() in job. */

    ret = CyaSSL_negotiate(ssltls->session);

    err = (ret != 0) ? nxt_socket_errno : 0;

    nxt_thread_time_debug_update(thr);

    nxt_log_debug(thr->log, "CyaSSL_negotiate(%d): %d", c->socket.fd, ret);

    if (ret == 0) {
        nxt_cyassl_conn_io_read(thr, c, data);
        return;
    }

    n = nxt_cyassl_conn_test_error(thr, c, ret, nxt_cyassl_conn_handshake);

    if (n == NXT_ERROR) {
        nxt_cyassl_conn_error(c, err, "CyaSSL_negotiate(%d) failed",
                              c->socket.fd);

        nxt_event_conn_io_handle(thr, c->read_work_queue,
                                 c->read_state->error_handler, c, data);

    } else if (ssltls->ssl_error == SSL_ERROR_WANT_READ && ssltls->times < 2) {
        ssltls->times++;
    }
}


static void
nxt_cyassl_conn_io_read(nxt_thread_t *thr, void *obj, void *data)
{
    int                 ret;
    nxt_buf_t           *b;
    nxt_err_t           err;
    nxt_int_t           n;
    nxt_event_conn_t    *c;
    nxt_cyassl_conn_t   *ssltls;
    nxt_work_handler_t  handler;

    c = obj;

    nxt_log_debug(thr->log, "cyassl conn read");

    handler = c->read_state->ready_handler;
    b = c->read;

    /* b == NULL is used to test descriptor readiness. */

    if (b != NULL) {
        ssltls = c->u.ssltls;

        ret = CyaSSL_read(ssltls->session, b->mem.free,
                          b->mem.end - b->mem.free);

        err = (ret <= 0) ? nxt_socket_errno : 0;

        nxt_log_debug(thr->log, "CyaSSL_read(%d, %p, %uz): %d",
                      c->socket.fd, b->mem.free, b->mem.end - b->mem.free, ret);

        if (ret > 0) {
            /* c->socket.read_ready is kept. */
            b->mem.free += ret;
            handler = c->read_state->ready_handler;

        } else {
            n = nxt_cyassl_conn_test_error(thr, c, ret,
                                           nxt_cyassl_conn_io_read);

            if (nxt_fast_path(n != NXT_ERROR)) {
                return;
            }

            nxt_cyassl_conn_error(c, err, "CyaSSL_read(%d, %p, %uz) failed",
                                  c->socket.fd, b->mem.free,
                                  b->mem.end - b->mem.free);

            handler = c->read_state->error_handler;
        }
    }

    nxt_event_conn_io_handle(thr, c->read_work_queue, handler, c, data);
}


static ssize_t
nxt_cyassl_conn_io_write_chunk(nxt_thread_t *thr, nxt_event_conn_t *c,
    nxt_buf_t *b, size_t limit)
{
    nxt_cyassl_conn_t  *ssltls;

    nxt_log_debug(thr->log, "cyassl conn write chunk");

    ssltls = c->u.ssltls;

    return nxt_sendbuf_copy_coalesce(c, &ssltls->buffer, b, limit);
}


static ssize_t
nxt_cyassl_conn_io_send(nxt_event_conn_t *c, void *buf, size_t size)
{
    int                ret;
    nxt_err_t          err;
    nxt_int_t          n;
    nxt_cyassl_conn_t  *ssltls;

    nxt_log_debug(c->socket.log, "cyassl send");

    ssltls = c->u.ssltls;

    ret = CyaSSL_write(ssltls->session, buf, size);

    if (ret <= 0) {
        err = nxt_socket_errno;
        c->socket.error = err;

    } else {
        err = 0;
    }

    nxt_log_debug(c->socket.log, "CyaSSL_write(%d, %p, %uz): %d",
                  c->socket.fd, buf, size, ret);

    if (ret > 0) {
        return ret;
    }

    n = nxt_cyassl_conn_test_error(nxt_thread(), c, ret,
                                   nxt_event_conn_io_write);

    if (nxt_slow_path(n == NXT_ERROR)) {
        nxt_cyassl_conn_error(c, err, "CyaSSL_write(%d, %p, %uz) failed",
                              c->socket.fd, buf, size);
    }

    return n;
}


static void
nxt_cyassl_conn_io_shutdown(nxt_thread_t *thr, void *obj, void *data)
{
    int                ret;
    nxt_event_conn_t   *c;
    nxt_cyassl_conn_t  *ssltls;

    c = obj;

    nxt_log_debug(thr->log, "cyassl conn shutdown");

    ssltls = c->u.ssltls;

    ret = CyaSSL_shutdown(ssltls->session);

    nxt_log_debug(thr->log, "CyaSSL_shutdown(%d): %d", c->socket.fd, ret);

    if (nxt_slow_path(ret != SSL_SUCCESS)) {
        nxt_cyassl_conn_error(c, 0, "CyaSSL_shutdown(%d) failed", c->socket.fd);
    }

    nxt_event_conn_io_handle(thr, c->write_work_queue,
                             c->write_state->close_handler, c, data);
}


static nxt_int_t
nxt_cyassl_conn_test_error(nxt_thread_t *thr, nxt_event_conn_t *c, int ret,
    nxt_work_handler_t handler)
{
    nxt_work_queue_t   *wq;
    nxt_cyassl_conn_t  *ssltls;

    ssltls = c->u.ssltls;
    ssltls->ssl_error = CyaSSL_get_error(ssltls->session, ret);

    nxt_log_debug(thr->log, "CyaSSL_get_error(): %d", ssltls->ssl_error);

    switch (ssltls->ssl_error) {

    case SSL_ERROR_WANT_READ:
        nxt_event_fd_block_write(thr->engine, &c->socket);

        c->socket.read_ready = 0;
        c->socket.read_handler = handler;

        if (nxt_event_fd_is_disabled(c->socket.read)) {
            nxt_event_fd_enable_read(thr->engine, &c->socket);
        }

        return NXT_AGAIN;

    case SSL_ERROR_WANT_WRITE:
        nxt_event_fd_block_read(thr->engine, &c->socket);

        c->socket.write_ready = 0;
        c->socket.write_handler = handler;

        if (nxt_event_fd_is_disabled(c->socket.write)) {
            nxt_event_fd_enable_write(thr->engine, &c->socket);
        }

        return NXT_AGAIN;

    case SSL_ERROR_ZERO_RETURN:
        /* A "close notify" alert */

        if (c->read_state != NULL) {
            wq = c->read_work_queue;
            handler = c->read_state->close_handler;

        } else {
            wq = c->write_work_queue;
            handler = c->write_state->close_handler;
        }

        nxt_event_conn_io_handle(thr, wq, handler, c, c->socket.data);

        return 0;

    default:
        return NXT_ERROR;
    }
}


static void nxt_cdecl
nxt_cyassl_conn_error(nxt_event_conn_t *c, nxt_err_t err, const char *fmt, ...)
{
    u_char             *p, *end;
    va_list            args;
    nxt_uint_t         level;
    nxt_cyassl_conn_t  *ssltls;
    u_char             msg[NXT_MAX_ERROR_STR];

    ssltls = c->u.ssltls;

    level = nxt_cyassl_log_error_level(c, err, ssltls->ssl_error);

    if (nxt_log_level_enough(c->socket.log, level)) {

        end = msg + sizeof(msg);

        va_start(args, fmt);
        p = nxt_vsprintf(msg, end, fmt, args);
        va_end(args);

        if (err != 0) {
            p = nxt_sprintf(p, end, " %E", err);
        }

        p = nxt_cyassl_copy_error(ssltls->ssl_error, p, end);

        nxt_log_error(level, c->socket.log, "%*s", p - msg, msg);
    }
}


static nxt_uint_t
nxt_cyassl_log_error_level(nxt_event_conn_t *c, nxt_err_t err, int ssl_error)
{
    switch (ssl_error) {

    case SOCKET_ERROR_E:            /* -208 */
    case MATCH_SUITE_ERROR:         /* -261 */
        break;

    default:
        return NXT_LOG_ALERT;
    }

    return NXT_LOG_INFO;
}


static void nxt_cdecl
nxt_cyassl_log_error(nxt_uint_t level, nxt_log_t *log, int err,
    const char *fmt, ...)
{
    u_char   *p, *end;
    va_list  args;
    u_char   msg[NXT_MAX_ERROR_STR];

    if (nxt_log_level_enough(log, level)) {

        end = msg + sizeof(msg);

        va_start(args, fmt);
        p = nxt_vsprintf(msg, end, fmt, args);
        va_end(args);

        p = nxt_cyassl_copy_error(err, p, end);

        nxt_log_error(level, log, "%*s", p - msg, msg);
    }
}


static u_char *
nxt_cyassl_copy_error(int err, u_char *p, u_char *end)
{
    p = nxt_sprintf(p, end, " (SSL:%d ", err);

    CyaSSL_ERR_error_string_n(err, (char *) p, end - p);

    p += nxt_strlen(p);

    if (p < end) {
        *p++ = ')';
    }

    return p;
}
