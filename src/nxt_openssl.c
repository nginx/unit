
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>


typedef struct {
    SSL            *session;

    int            ssl_error;
    uint8_t        times;      /* 2 bits */

    nxt_buf_mem_t  buffer;
} nxt_openssl_conn_t;


static nxt_int_t nxt_openssl_server_init(nxt_ssltls_conf_t *conf);

static void nxt_openssl_conn_init(nxt_task_t *task, nxt_ssltls_conf_t *conf,
    nxt_conn_t *c);
static void nxt_openssl_session_cleanup(nxt_task_t *task, void *data);
static void nxt_openssl_conn_handshake(nxt_task_t *task, void *obj, void *data);
static void nxt_openssl_conn_io_read(nxt_task_t *task, void *obj, void *data);
static void nxt_openssl_conn_io_shutdown(nxt_task_t *task, void *obj,
    void *data);
static ssize_t nxt_openssl_conn_io_write_chunk(nxt_conn_t *c, nxt_buf_t *b,
    size_t limit);
static ssize_t nxt_openssl_conn_io_send(nxt_conn_t *c, void *buf, size_t size);
static nxt_int_t nxt_openssl_conn_test_error(nxt_task_t *task,
    nxt_conn_t *c, int ret, nxt_err_t sys_err, nxt_work_handler_t handler);
static void nxt_cdecl nxt_openssl_conn_error(nxt_conn_t *c, nxt_err_t err,
    const char *fmt, ...);
static nxt_uint_t nxt_openssl_log_error_level(nxt_conn_t *c, nxt_err_t err);
static void nxt_cdecl nxt_openssl_log_error(nxt_uint_t level, nxt_log_t *log,
    const char *fmt, ...);
static u_char *nxt_openssl_copy_error(u_char *p, u_char *end);


const nxt_ssltls_lib_t  nxt_openssl_lib = {
    nxt_openssl_server_init,
    NULL,
};


static nxt_conn_io_t  nxt_openssl_conn_io = {
    NULL,
    NULL,

    nxt_openssl_conn_io_read,
    NULL,
    NULL,

    nxt_conn_io_write,
    nxt_openssl_conn_io_write_chunk,
    NULL,
    NULL,
    nxt_openssl_conn_io_send,

    nxt_openssl_conn_io_shutdown,
};


static long  nxt_openssl_version;
static int   nxt_openssl_connection_index;


static nxt_int_t
nxt_openssl_start(nxt_thread_t *thr)
{
    int  index;

    if (nxt_fast_path(nxt_openssl_version != 0)) {
        return NXT_OK;
    }

    SSL_load_error_strings();

    OPENSSL_config(NULL);

    /*
     * SSL_library_init(3):
     *
     *   SSL_library_init() always returns "1",
     *   so it is safe to discard the return value.
     */
    (void) SSL_library_init();

    nxt_openssl_version = SSLeay();

    nxt_log_error(NXT_LOG_INFO, thr->log, "%s, %xl",
                  SSLeay_version(SSLEAY_VERSION), nxt_openssl_version);

#ifndef SSL_OP_NO_COMPRESSION
    {
        /*
         * Disable gzip compression in OpenSSL prior to 1.0.0
         * version, this saves about 522K per connection.
         */
        int                 n;
        STACK_OF(SSL_COMP)  *ssl_comp_methods;

        ssl_comp_methods = SSL_COMP_get_compression_methods();

        for (n = sk_SSL_COMP_num(ssl_comp_methods); n != 0; n--) {
            (void) sk_SSL_COMP_pop(ssl_comp_methods);
        }
    }
#endif

    index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);

    if (index == -1) {
        nxt_openssl_log_error(NXT_LOG_ALERT, thr->log,
                              "SSL_get_ex_new_index() failed");
        return NXT_ERROR;
    }

    nxt_openssl_connection_index = index;

    return NXT_OK;
}


static nxt_int_t
nxt_openssl_server_init(nxt_ssltls_conf_t *conf)
{
    SSL_CTX              *ctx;
    const char           *certificate, *key, *ciphers, *ca_certificate;
    nxt_thread_t         *thr;
    STACK_OF(X509_NAME)  *list;

    thr = nxt_thread();

    if (nxt_openssl_start(thr) != NXT_OK) {
        return NXT_ERROR;
    }

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        nxt_openssl_log_error(NXT_LOG_ALERT, thr->log, "SSL_CTX_new() failed");
        return NXT_ERROR;
    }

    conf->ctx = ctx;
    conf->conn_init = nxt_openssl_conn_init;

#ifdef SSL_OP_NO_COMPRESSION
    /*
     * Disable gzip compression in OpenSSL 1.0.0,
     * this saves about 522K per connection.
     */
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS

    if (nxt_openssl_version >= 10001078) {
        /*
         * Allow to release read and write buffers in OpenSSL 1.0.0,
         * this saves about 34K per idle connection.  It is not safe
         * before OpenSSL 1.0.1h (CVE-2010-5298).
         */
        SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    }

#endif

    certificate = conf->certificate;

    if (SSL_CTX_use_certificate_chain_file(ctx, certificate) == 0) {
        nxt_openssl_log_error(NXT_LOG_ALERT, thr->log,
                              "SSL_CTX_use_certificate_file(\"%s\") failed",
                              certificate);
        goto fail;
    }

    key = conf->certificate_key;

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) == 0) {
        nxt_openssl_log_error(NXT_LOG_ALERT, thr->log,
                              "SSL_CTX_use_PrivateKey_file(\"%s\") failed",
                              key);
        goto fail;
    }

    ciphers = (conf->ciphers != NULL) ? conf->ciphers : "HIGH:!aNULL:!MD5";

    if (SSL_CTX_set_cipher_list(ctx, ciphers) == 0) {
        nxt_openssl_log_error(NXT_LOG_ALERT, thr->log,
                              "SSL_CTX_set_cipher_list(\"%s\") failed",
                              ciphers);
        goto fail;
    }

    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    if (conf->ca_certificate != NULL) {

        /* TODO: verify callback */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

        /* TODO: verify depth */
        SSL_CTX_set_verify_depth(ctx, 1);

        ca_certificate = conf->ca_certificate;

        if (SSL_CTX_load_verify_locations(ctx, ca_certificate, NULL) == 0) {
            nxt_openssl_log_error(NXT_LOG_ALERT, thr->log,
                              "SSL_CTX_load_verify_locations(\"%s\") failed",
                              ca_certificate);
            goto fail;
        }

        list = SSL_load_client_CA_file(ca_certificate);

        if (list == NULL) {
            nxt_openssl_log_error(NXT_LOG_ALERT, thr->log,
                              "SSL_load_client_CA_file(\"%s\") failed",
                              ca_certificate);
            goto fail;
        }

        /*
         * SSL_load_client_CA_file() in OpenSSL prior to 0.9.7h and
         * 0.9.8 versions always leaves an error in the error queue.
         */
        ERR_clear_error();

        SSL_CTX_set_client_CA_list(ctx, list);
    }

    return NXT_OK;

fail:

    SSL_CTX_free(ctx);

    return NXT_ERROR;
}


static void
nxt_openssl_conn_init(nxt_task_t *task, nxt_ssltls_conf_t *conf, nxt_conn_t *c)
{
    int                     ret;
    SSL                     *s;
    SSL_CTX                 *ctx;
    nxt_openssl_conn_t      *ssltls;
    nxt_mem_pool_cleanup_t  *mpcl;

    nxt_log_debug(c->socket.log, "openssl conn init");

    ssltls = nxt_mp_zget(c->mem_pool, sizeof(nxt_openssl_conn_t));
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

    s = SSL_new(ctx);
    if (s == NULL) {
        nxt_openssl_log_error(NXT_LOG_ALERT, c->socket.log,
                              "SSL_new() failed");
        goto fail;
    }

    ssltls->session = s;
    mpcl->handler = nxt_openssl_session_cleanup;
    mpcl->data = ssltls;

    ret = SSL_set_fd(s, c->socket.fd);

    if (ret == 0) {
        nxt_openssl_log_error(NXT_LOG_ALERT, c->socket.log,
                              "SSL_set_fd(%d) failed", c->socket.fd);
        goto fail;
    }

    SSL_set_accept_state(s);

    if (SSL_set_ex_data(s, nxt_openssl_connection_index, c) == 0) {
        nxt_openssl_log_error(NXT_LOG_ALERT, c->socket.log,
                              "SSL_set_ex_data() failed");
        goto fail;
    }

    c->io = &nxt_openssl_conn_io;
    c->sendfile = NXT_CONN_SENDFILE_OFF;

    nxt_openssl_conn_handshake(task, c, c->socket.data);
    return;

fail:

    nxt_work_queue_add(c->read_work_queue, c->read_state->error_handler,
                       task, c, c->socket.data);
}


static void
nxt_openssl_session_cleanup(nxt_task_t *task, void *data)
{
    nxt_openssl_conn_t  *ssltls;

    ssltls = data;

    nxt_debug(task, "openssl session cleanup");

    nxt_free(ssltls->buffer.start);

    SSL_free(ssltls->session);
}


static void
nxt_openssl_conn_handshake(nxt_task_t *task, void *obj, void *data)
{
    int                 ret;
    nxt_int_t           n;
    nxt_err_t           err;
    nxt_conn_t          *c;
    nxt_openssl_conn_t  *ssltls;

    c = obj;
    ssltls = c->u.ssltls;

    nxt_debug(task, "openssl conn handshake: %d", ssltls->times);

    /* "ssltls->times == 1" is suitable to run SSL_do_handshake() in job. */

    ret = SSL_do_handshake(ssltls->session);

    err = (ret <= 0) ? nxt_socket_errno : 0;

    nxt_thread_time_debug_update(task->thread);

    nxt_debug(task, "SSL_do_handshake(%d): %d err:%d", c->socket.fd, ret, err);

    if (ret > 0) {
        /* ret == 1, the handshake was successfully completed. */
        nxt_openssl_conn_io_read(task, c, data);
        return;
    }

    n = nxt_openssl_conn_test_error(task, c, ret, err,
                                    nxt_openssl_conn_handshake);

    if (n == NXT_ERROR) {
        nxt_openssl_conn_error(c, err, "SSL_do_handshake(%d) failed",
                               c->socket.fd);

        nxt_work_queue_add(c->read_work_queue, c->read_state->error_handler,
                           task, c, data);

    } else if (ssltls->ssl_error == SSL_ERROR_WANT_READ && ssltls->times < 2) {
        ssltls->times++;
    }
}


static void
nxt_openssl_conn_io_read(nxt_task_t *task, void *obj, void *data)
{
    int                 ret;
    nxt_buf_t           *b;
    nxt_int_t           n;
    nxt_err_t           err;
    nxt_conn_t          *c;
    nxt_work_handler_t  handler;
    nxt_openssl_conn_t  *ssltls;

    c = obj;

    nxt_debug(task, "openssl conn read");

    handler = c->read_state->ready_handler;
    b = c->read;

    /* b == NULL is used to test descriptor readiness. */

    if (b != NULL) {
        ssltls = c->u.ssltls;

        ret = SSL_read(ssltls->session, b->mem.free, b->mem.end - b->mem.free);

        err = (ret <= 0) ? nxt_socket_errno : 0;

        nxt_debug(task, "SSL_read(%d, %p, %uz): %d err:%d",
                  c->socket.fd, b->mem.free, b->mem.end - b->mem.free,
                  ret, err);

        if (ret > 0) {
            /* c->socket.read_ready is kept. */
            b->mem.free += ret;
            handler = c->read_state->ready_handler;

        } else {
            n = nxt_openssl_conn_test_error(task, c, ret, err,
                                            nxt_openssl_conn_io_read);

            if (nxt_fast_path(n != NXT_ERROR)) {
                return;
            }

            nxt_openssl_conn_error(c, err, "SSL_read(%d, %p, %uz) failed",
                                   c->socket.fd, b->mem.free,
                                   b->mem.end - b->mem.free);

            handler = c->read_state->error_handler;
        }
    }

    nxt_work_queue_add(c->read_work_queue, handler, task, c, data);
}


static ssize_t
nxt_openssl_conn_io_write_chunk(nxt_conn_t *c, nxt_buf_t *b, size_t limit)
{
    nxt_openssl_conn_t  *ssltls;

    nxt_debug(c->socket.task, "openssl conn write chunk");

    ssltls = c->u.ssltls;

    return nxt_sendbuf_copy_coalesce(c, &ssltls->buffer, b, limit);
}


static ssize_t
nxt_openssl_conn_io_send(nxt_conn_t *c, void *buf, size_t size)
{
    int                 ret;
    nxt_err_t           err;
    nxt_int_t           n;
    nxt_openssl_conn_t  *ssltls;

    ssltls = c->u.ssltls;

    ret = SSL_write(ssltls->session, buf, size);

    if (ret <= 0) {
        err = nxt_socket_errno;
        c->socket.error = err;

    } else {
        err = 0;
    }

    nxt_log_debug(c->socket.log, "SSL_write(%d, %p, %uz): %d err:%d",
                  c->socket.fd, buf, size, ret, err);

    if (ret > 0) {
        return ret;
    }

    n = nxt_openssl_conn_test_error(c->socket.task, c, ret, err,
                                    nxt_conn_io_write);

    if (n == NXT_ERROR) {
        nxt_openssl_conn_error(c, err, "SSL_write(%d, %p, %uz) failed",
                               c->socket.fd, buf, size);
    }

    return n;
}


static void
nxt_openssl_conn_io_shutdown(nxt_task_t *task, void *obj, void *data)
{
    int                 ret, mode;
    SSL                 *s;
    nxt_err_t           err;
    nxt_int_t           n;
    nxt_bool_t          quiet, once;
    nxt_conn_t          *c;
    nxt_work_handler_t  handler;
    nxt_openssl_conn_t  *ssltls;

    c = obj;

    nxt_debug(task, "openssl conn shutdown");

    ssltls = c->u.ssltls;
    s = ssltls->session;

    if (s == NULL) {
        handler = c->write_state->close_handler;
        goto done;
    }

    mode = SSL_get_shutdown(s);

    if (c->socket.timedout || c->socket.error != 0) {
        quiet = 1;

    } else if (c->socket.closed && !(mode & SSL_RECEIVED_SHUTDOWN)) {
        quiet = 1;

    } else {
        quiet = 0;
    }

    SSL_set_quiet_shutdown(s, quiet);

    once = 1;

    for ( ;; ) {
        SSL_set_shutdown(s, mode);

        ret = SSL_shutdown(s);

        err = (ret <= 0) ? nxt_socket_errno : 0;

        nxt_debug(task, "SSL_shutdown(%d, %d, %b): %d err:%d",
                  c->socket.fd, mode, quiet, ret, err);

        if (ret > 0) {
            /* ret == 1, the shutdown was successfully completed. */
            handler = c->write_state->close_handler;
            goto done;
        }

        if (ret == 0) {
            /*
             * If SSL_shutdown() returns 0 then it should be called
             * again.  The second SSL_shutdown() call should returns
             * -1/SSL_ERROR_WANT_READ or -1/SSL_ERROR_WANT_WRITE.
             * OpenSSL prior to 0.9.8m version however never returns
             * -1 at all.  Fortunately, OpenSSL internals preserve
             * correct status available via SSL_get_error(-1).
             */
            if (once) {
                mode = SSL_get_shutdown(s);
                once = 0;
                continue;
            }

            ret = -1;
        }

        /* ret == -1 */

        break;
    }

    n = nxt_openssl_conn_test_error(task, c, ret, err,
                                    nxt_openssl_conn_io_shutdown);

    if (nxt_fast_path(n == 0)) {
        return;
    }

    if (n != NXT_ERROR) {  /* n == NXT_AGAIN */
        c->socket.error_handler = c->read_state->error_handler;
        nxt_timer_add(task->thread->engine, &c->read_timer, 5000);
        return;
    }

    nxt_openssl_conn_error(c, err, "SSL_shutdown(%d) failed", c->socket.fd);

    handler = c->write_state->error_handler;

done:

    nxt_work_queue_add(c->write_work_queue, handler, task, c, data);
}


static nxt_int_t
nxt_openssl_conn_test_error(nxt_task_t *task, nxt_conn_t *c, int ret,
    nxt_err_t sys_err, nxt_work_handler_t handler)
{
    u_long              lib_err;
    nxt_work_queue_t    *wq;
    nxt_openssl_conn_t  *ssltls;

    ssltls = c->u.ssltls;

    ssltls->ssl_error = SSL_get_error(ssltls->session, ret);

    nxt_log_debug(c->socket.log, "SSL_get_error(): %d", ssltls->ssl_error);

    switch (ssltls->ssl_error) {

    case SSL_ERROR_WANT_READ:
        nxt_fd_event_block_write(task->thread->engine, &c->socket);

        c->socket.read_ready = 0;
        c->socket.read_handler = handler;

        if (nxt_fd_event_is_disabled(c->socket.read)) {
            nxt_fd_event_enable_read(task->thread->engine, &c->socket);
        }

        return NXT_AGAIN;

    case SSL_ERROR_WANT_WRITE:
        nxt_fd_event_block_read(task->thread->engine, &c->socket);

        c->socket.write_ready = 0;
        c->socket.write_handler = handler;

        if (nxt_fd_event_is_disabled(c->socket.write)) {
            nxt_fd_event_enable_write(task->thread->engine, &c->socket);
        }

        return NXT_AGAIN;

    case SSL_ERROR_SYSCALL:

        lib_err = ERR_peek_error();

        nxt_debug(task, "ERR_peek_error(): %l", lib_err);

        if (sys_err != 0 || lib_err != 0) {
            return NXT_ERROR;
        }

        /* A connection was just closed. */
        c->socket.closed = 1;

        /* Fall through. */

    case SSL_ERROR_ZERO_RETURN:
        /* A "close notify" alert. */

        if (c->read_state != NULL) {
            wq = c->read_work_queue;
            handler = c->read_state->close_handler;

        } else {
            wq = c->write_work_queue;
            handler = c->write_state->close_handler;
        }

        nxt_work_queue_add(wq, handler, task, c, c->socket.data);

        return 0;

    default: /* SSL_ERROR_SSL, etc. */
        c->socket.error = 1000;  /* Nonexistent errno code. */
        return NXT_ERROR;
    }
}


static void nxt_cdecl
nxt_openssl_conn_error(nxt_conn_t *c, nxt_err_t err, const char *fmt, ...)
{
    u_char      *p, *end;
    va_list     args;
    nxt_uint_t  level;
    u_char      msg[NXT_MAX_ERROR_STR];

    c->socket.error = err;
    level = nxt_openssl_log_error_level(c, err);

    if (nxt_log_level_enough(c->socket.log, level)) {

        end = msg + sizeof(msg);

        va_start(args, fmt);
        p = nxt_vsprintf(msg, end, fmt, args);
        va_end(args);

        if (err != 0) {
            p = nxt_sprintf(p, end, " %E", err);
        }

        p = nxt_openssl_copy_error(p, end);

        nxt_log_error(level, c->socket.log, "%*s", p - msg, msg);

    } else {
        ERR_clear_error();
    }
}


static nxt_uint_t
nxt_openssl_log_error_level(nxt_conn_t *c, nxt_err_t err)
{
    switch (ERR_GET_REASON(ERR_peek_error())) {

    case 0:
        return nxt_socket_error_level(err);

    case SSL_R_BAD_CHANGE_CIPHER_SPEC:                    /*  103 */
    case SSL_R_BLOCK_CIPHER_PAD_IS_WRONG:                 /*  129 */
    case SSL_R_DIGEST_CHECK_FAILED:                       /*  149 */
    case SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST:             /*  151 */
    case SSL_R_EXCESSIVE_MESSAGE_SIZE:                    /*  152 */
    case SSL_R_LENGTH_MISMATCH:                           /*  159 */
    case SSL_R_NO_CIPHERS_PASSED:                         /*  182 */
    case SSL_R_NO_CIPHERS_SPECIFIED:                      /*  183 */
    case SSL_R_NO_COMPRESSION_SPECIFIED:                  /*  187 */
    case SSL_R_NO_SHARED_CIPHER:                          /*  193 */
    case SSL_R_RECORD_LENGTH_MISMATCH:                    /*  213 */
#ifdef SSL_R_PARSE_TLSEXT
    case SSL_R_PARSE_TLSEXT:                              /*  227 */
#endif
    case SSL_R_UNEXPECTED_MESSAGE:                        /*  244 */
    case SSL_R_UNEXPECTED_RECORD:                         /*  245 */
    case SSL_R_UNKNOWN_ALERT_TYPE:                        /*  246 */
    case SSL_R_UNKNOWN_PROTOCOL:                          /*  252 */
    case SSL_R_WRONG_VERSION_NUMBER:                      /*  267 */
    case SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC:       /*  281 */
#ifdef SSL_R_RENEGOTIATE_EXT_TOO_LONG
    case SSL_R_RENEGOTIATE_EXT_TOO_LONG:                  /*  335 */
    case SSL_R_RENEGOTIATION_ENCODING_ERR:                /*  336 */
    case SSL_R_RENEGOTIATION_MISMATCH:                    /*  337 */
#endif
#ifdef SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED
    case SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED:      /*  338 */
#endif
#ifdef SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING
    case SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING:          /*  345 */
#endif
    case 1000:/* SSL_R_SSLV3_ALERT_CLOSE_NOTIFY */
    case SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE:            /* 1010 */
    case SSL_R_SSLV3_ALERT_BAD_RECORD_MAC:                /* 1020 */
    case SSL_R_TLSV1_ALERT_DECRYPTION_FAILED:             /* 1021 */
    case SSL_R_TLSV1_ALERT_RECORD_OVERFLOW:               /* 1022 */
    case SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE:         /* 1030 */
    case SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE:             /* 1040 */
    case SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER:             /* 1047 */
        break;

    case SSL_R_SSLV3_ALERT_NO_CERTIFICATE:                /* 1041 */
    case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:               /* 1042 */
    case SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE:       /* 1043 */
    case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED:           /* 1044 */
    case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:           /* 1045 */
    case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:           /* 1046 */
    case SSL_R_TLSV1_ALERT_UNKNOWN_CA:                    /* 1048 */
    case SSL_R_TLSV1_ALERT_ACCESS_DENIED:                 /* 1049 */
    case SSL_R_TLSV1_ALERT_DECODE_ERROR:                  /* 1050 */
    case SSL_R_TLSV1_ALERT_DECRYPT_ERROR:                 /* 1051 */
    case SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION:            /* 1060 */
    case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:              /* 1070 */
    case SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY:         /* 1071 */
    case SSL_R_TLSV1_ALERT_INTERNAL_ERROR:                /* 1080 */
    case SSL_R_TLSV1_ALERT_USER_CANCELLED:                /* 1090 */
    case SSL_R_TLSV1_ALERT_NO_RENEGOTIATION:              /* 1100 */
        return NXT_LOG_ERR;

    default:
        return NXT_LOG_ALERT;
    }

    return NXT_LOG_INFO;
}


static void nxt_cdecl
nxt_openssl_log_error(nxt_uint_t level, nxt_log_t *log, const char *fmt, ...)
{
    u_char   *p, *end;
    va_list  args;
    u_char   msg[NXT_MAX_ERROR_STR];

    end = msg + sizeof(msg);

    va_start(args, fmt);
    p = nxt_vsprintf(msg, end, fmt, args);
    va_end(args);

    p = nxt_openssl_copy_error(p, end);

    nxt_log_error(level, log, "%*s", p - msg, msg);
}


static u_char *
nxt_openssl_copy_error(u_char *p, u_char *end)
{
    int         flags;
    u_long      err;
    nxt_bool_t  clear;
    const char  *data, *delimiter;

    err = ERR_peek_error();
    if (err == 0) {
        return p;
    }

    /* Log the most relevant error message ... */
    data = ERR_reason_error_string(err);

    p = nxt_sprintf(p, end, " (%d: %s) (OpenSSL: ", ERR_GET_REASON(err), data);

    /*
     * ... followed by all queued cumbersome OpenSSL
     * error messages and drain the error queue.
     */
    delimiter = "";
    clear = 0;

    for ( ;; ) {
        err = ERR_get_error_line_data(NULL, NULL, &data, &flags);
        if (err == 0) {
            break;
        }

        p = nxt_sprintf(p, end, "%s", delimiter);

        ERR_error_string_n(err, (char *) p, end - p);

        while (p < end && *p != '\0') {
            p++;
        }

        if ((flags & ERR_TXT_STRING) != 0) {
            p = nxt_sprintf(p, end, ":%s", data);
        }

        clear |= ((flags & ERR_TXT_MALLOCED) != 0);

        delimiter = "; ";
    }

    /* Deallocate additional data. */

    if (clear) {
        ERR_clear_error();
    }

    if (p < end) {
        *p++ = ')';
    }

    return p;
}
