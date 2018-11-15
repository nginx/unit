
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
    nxt_conn_t     *conn;

    int            ssl_error;
    uint8_t        times;      /* 2 bits */
    uint8_t        handshake;  /* 1 bit  */

    nxt_buf_mem_t  buffer;
} nxt_openssl_conn_t;


typedef enum {
    NXT_OPENSSL_HANDSHAKE = 0,
    NXT_OPENSSL_READ,
    NXT_OPENSSL_WRITE,
    NXT_OPENSSL_SHUTDOWN,
} nxt_openssl_io_t;


static nxt_int_t nxt_openssl_library_init(nxt_task_t *task);
static void nxt_openssl_library_free(nxt_task_t *task);
#if OPENSSL_VERSION_NUMBER < 0x10100004L
static nxt_int_t nxt_openssl_locks_init(void);
static void nxt_openssl_lock(int mode, int type, const char *file, int line);
static unsigned long nxt_openssl_thread_id(void);
static void nxt_openssl_locks_free(void);
#endif
static nxt_int_t nxt_openssl_server_init(nxt_task_t *task,
    nxt_tls_conf_t *conf);
static nxt_int_t nxt_openssl_chain_file(SSL_CTX *ctx, nxt_fd_t fd);
static void nxt_openssl_server_free(nxt_task_t *task, nxt_tls_conf_t *conf);
static void nxt_openssl_conn_init(nxt_task_t *task, nxt_tls_conf_t *conf,
    nxt_conn_t *c);
static void nxt_openssl_conn_handshake(nxt_task_t *task, void *obj, void *data);
static ssize_t nxt_openssl_conn_io_recvbuf(nxt_conn_t *c, nxt_buf_t *b);
static ssize_t nxt_openssl_conn_io_sendbuf(nxt_task_t *task, nxt_sendbuf_t *sb);
static ssize_t nxt_openssl_conn_io_send(nxt_task_t *task, nxt_sendbuf_t *sb,
    void *buf, size_t size);
static void nxt_openssl_conn_io_shutdown(nxt_task_t *task, void *obj,
    void *data);
static nxt_int_t nxt_openssl_conn_test_error(nxt_task_t *task, nxt_conn_t *c,
    int ret, nxt_err_t sys_err, nxt_openssl_io_t io);
static void nxt_cdecl nxt_openssl_conn_error(nxt_task_t *task,
    nxt_err_t err, const char *fmt, ...);
static nxt_uint_t nxt_openssl_log_error_level(nxt_err_t err);


const nxt_tls_lib_t  nxt_openssl_lib = {
    .library_init = nxt_openssl_library_init,
    .library_free = nxt_openssl_library_free,

    .server_init = nxt_openssl_server_init,
    .server_free = nxt_openssl_server_free,
};


static nxt_conn_io_t  nxt_openssl_conn_io = {
    .read = nxt_conn_io_read,
    .recvbuf = nxt_openssl_conn_io_recvbuf,

    .write = nxt_conn_io_write,
    .sendbuf = nxt_openssl_conn_io_sendbuf,

    .shutdown = nxt_openssl_conn_io_shutdown,
};


static long  nxt_openssl_version;
static int   nxt_openssl_connection_index;


static nxt_int_t
nxt_openssl_library_init(nxt_task_t *task)
{
    int  index;

    if (nxt_fast_path(nxt_openssl_version != 0)) {
        return NXT_OK;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10100003L

    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);

#else
    {
        nxt_int_t  ret;

        SSL_load_error_strings();

        OPENSSL_config(NULL);

        /*
         * SSL_library_init(3):
         *
         *   SSL_library_init() always returns "1",
         *   so it is safe to discard the return value.
         */
        (void) SSL_library_init();

        ret = nxt_openssl_locks_init();
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }
    }

#endif

    nxt_openssl_version = SSLeay();

    nxt_log(task, NXT_LOG_INFO, "%s, %xl",
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
        nxt_openssl_log_error(task, NXT_LOG_ALERT,
                              "SSL_get_ex_new_index() failed");
        return NXT_ERROR;
    }

    nxt_openssl_connection_index = index;

    return NXT_OK;
}


#if OPENSSL_VERSION_NUMBER >= 0x10100003L

static void
nxt_openssl_library_free(nxt_task_t *task)
{
}

#else

static nxt_thread_mutex_t  *nxt_openssl_locks;

static nxt_int_t
nxt_openssl_locks_init(void)
{
    int        i, n;
    nxt_int_t  ret;

    n = CRYPTO_num_locks();

    nxt_openssl_locks = OPENSSL_malloc(n * sizeof(nxt_thread_mutex_t));
    if (nxt_slow_path(nxt_openssl_locks == NULL)) {
        return NXT_ERROR;
    }

    for (i = 0; i < n; i++) {
        ret = nxt_thread_mutex_create(&nxt_openssl_locks[i]);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }
    }

    CRYPTO_set_locking_callback(nxt_openssl_lock);

    CRYPTO_set_id_callback(nxt_openssl_thread_id);

    return NXT_OK;
}


static void
nxt_openssl_lock(int mode, int type, const char *file, int line)
{
    nxt_thread_mutex_t  *lock;

    lock = &nxt_openssl_locks[type];

    if ((mode & CRYPTO_LOCK) != 0) {
        (void) nxt_thread_mutex_lock(lock);

    } else {
        (void) nxt_thread_mutex_unlock(lock);
    }
}


static u_long
nxt_openssl_thread_id(void)
{
    return (u_long) nxt_thread_handle();
}


static void
nxt_openssl_library_free(nxt_task_t *task)
{
    nxt_openssl_locks_free();
}


static void
nxt_openssl_locks_free(void)
{
    int  i, n;

    n = CRYPTO_num_locks();

    CRYPTO_set_locking_callback(NULL);

    for (i = 0; i < n; i++) {
        nxt_thread_mutex_destroy(&nxt_openssl_locks[i]);
    }

    OPENSSL_free(nxt_openssl_locks);
}

#endif


static nxt_int_t
nxt_openssl_server_init(nxt_task_t *task, nxt_tls_conf_t *conf)
{
    SSL_CTX              *ctx;
    nxt_fd_t             fd;
    const char           *ciphers, *ca_certificate;
    STACK_OF(X509_NAME)  *list;

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        nxt_openssl_log_error(task, NXT_LOG_ALERT, "SSL_CTX_new() failed");
        return NXT_ERROR;
    }

    conf->ctx = ctx;
    conf->conn_init = nxt_openssl_conn_init;

#ifdef SSL_OP_NO_RENEGOTIATION
    /* Renegration is not currently supported. */
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
#endif

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

    fd = conf->chain_file;

    if (nxt_openssl_chain_file(ctx, fd) != NXT_OK) {
        nxt_openssl_log_error(task, NXT_LOG_ALERT,
                              "nxt_openssl_chain_file() failed");
        goto fail;
    }
/*
    key = conf->certificate_key;

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) == 0) {
        nxt_openssl_log_error(task, NXT_LOG_ALERT,
                              "SSL_CTX_use_PrivateKey_file(\"%s\") failed",
                              key);
        goto fail;
    }
*/
    ciphers = (conf->ciphers != NULL) ? conf->ciphers : "HIGH:!aNULL:!MD5";

    if (SSL_CTX_set_cipher_list(ctx, ciphers) == 0) {
        nxt_openssl_log_error(task, NXT_LOG_ALERT,
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
            nxt_openssl_log_error(task, NXT_LOG_ALERT,
                              "SSL_CTX_load_verify_locations(\"%s\") failed",
                              ca_certificate);
            goto fail;
        }

        list = SSL_load_client_CA_file(ca_certificate);

        if (list == NULL) {
            nxt_openssl_log_error(task, NXT_LOG_ALERT,
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


static nxt_int_t
nxt_openssl_chain_file(SSL_CTX *ctx, nxt_fd_t fd)
{
    BIO            *bio;
    X509           *cert, *ca;
    long           reason;
    EVP_PKEY       *key;
    nxt_int_t      ret;

    bio = BIO_new(BIO_s_fd());
    if (bio == NULL) {
        return NXT_ERROR;
    }

    BIO_set_fd(bio, fd, BIO_CLOSE);

    ret = NXT_ERROR;

    cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (cert == NULL) {
        goto end;
    }

    if (SSL_CTX_use_certificate(ctx, cert) != 1) {
        goto end;
    }

    for ( ;; ) {
        ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);

        if (ca == NULL) {
            reason = ERR_GET_REASON(ERR_peek_last_error());
            if (reason != PEM_R_NO_START_LINE) {
                goto end;
            }

            ERR_clear_error();
            break;
        }

        /*
         * Note that ca isn't freed if it was successfully added to the chain,
         * while the main certificate needs a X509_free() call, since
         * its reference count is increased by SSL_CTX_use_certificate().
         */
#ifdef SSL_CTX_add0_chain_cert
        if (SSL_CTX_add0_chain_cert(ctx, ca) != 1) {
#else
        if (SSL_CTX_add_extra_chain_cert(ctx, ca) != 1) {
#endif
            X509_free(ca);
            goto end;
        }
    }

    if (BIO_reset(bio) != 0) {
        goto end;
    }

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (key == NULL) {
        goto end;
    }

    if (SSL_CTX_use_PrivateKey(ctx, key) == 1) {
        ret = NXT_OK;
    }

    EVP_PKEY_free(key);

end:

    X509_free(cert);
    BIO_free(bio);

    return ret;
}


static void
nxt_openssl_server_free(nxt_task_t *task, nxt_tls_conf_t *conf)
{
    SSL_CTX_free(conf->ctx);
}


static void
nxt_openssl_conn_init(nxt_task_t *task, nxt_tls_conf_t *conf, nxt_conn_t *c)
{
    int                 ret;
    SSL                 *s;
    SSL_CTX             *ctx;
    nxt_openssl_conn_t  *tls;

    nxt_log_debug(c->socket.log, "openssl conn init");

    tls = nxt_mp_zget(c->mem_pool, sizeof(nxt_openssl_conn_t));
    if (tls == NULL) {
        goto fail;
    }

    c->u.tls = tls;
    nxt_buf_mem_set_size(&tls->buffer, conf->buffer_size);

    ctx = conf->ctx;

    s = SSL_new(ctx);
    if (s == NULL) {
        nxt_openssl_log_error(task, NXT_LOG_ALERT, "SSL_new() failed");
        goto fail;
    }

    tls->session = s;
    tls->conn = c;

    ret = SSL_set_fd(s, c->socket.fd);

    if (ret == 0) {
        nxt_openssl_log_error(task, NXT_LOG_ALERT, "SSL_set_fd(%d) failed",
                              c->socket.fd);
        goto fail;
    }

    SSL_set_accept_state(s);

    if (SSL_set_ex_data(s, nxt_openssl_connection_index, c) == 0) {
        nxt_openssl_log_error(task, NXT_LOG_ALERT, "SSL_set_ex_data() failed");
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


nxt_inline void
nxt_openssl_conn_free(nxt_task_t *task, nxt_conn_t *c)
{
    nxt_openssl_conn_t  *tls;

    nxt_debug(task, "openssl conn free");

    tls = c->u.tls;

    if (tls != NULL) {
        c->u.tls = NULL;
        nxt_free(tls->buffer.start);
        SSL_free(tls->session);
    }
}


static void
nxt_openssl_conn_handshake(nxt_task_t *task, void *obj, void *data)
{
    int                     ret;
    nxt_int_t               n;
    nxt_err_t               err;
    nxt_conn_t              *c;
    nxt_work_queue_t        *wq;
    nxt_work_handler_t      handler;
    nxt_openssl_conn_t      *tls;
    const nxt_conn_state_t  *state;

    c = obj;

    nxt_debug(task, "openssl conn handshake fd:%d", c->socket.fd);

    if (c->socket.error != 0) {
        return;
    }

    tls = c->u.tls;

    if (tls == NULL) {
        return;
    }

    nxt_debug(task, "openssl conn handshake: %d times", tls->times);

    /* "tls->times == 1" is suitable to run SSL_do_handshake() in job. */

    ret = SSL_do_handshake(tls->session);

    err = (ret <= 0) ? nxt_socket_errno : 0;

    nxt_thread_time_debug_update(task->thread);

    nxt_debug(task, "SSL_do_handshake(%d): %d err:%d", c->socket.fd, ret, err);

    state = (c->read_state != NULL) ? c->read_state : c->write_state;

    if (ret > 0) {
        /* ret == 1, the handshake was successfully completed. */
        tls->handshake = 1;

        if (c->read_state != NULL) {
            if (state->io_read_handler != NULL || c->read != NULL) {
                nxt_conn_read(task->thread->engine, c);
                return;
            }

        } else {
            if (c->write != NULL) {
                nxt_conn_write(task->thread->engine, c);
                return;
            }
        }

        handler = state->ready_handler;

    } else {
        c->socket.read_handler = nxt_openssl_conn_handshake;
        c->socket.write_handler = nxt_openssl_conn_handshake;

        n = nxt_openssl_conn_test_error(task, c, ret, err,
                                        NXT_OPENSSL_HANDSHAKE);
        switch (n) {

        case NXT_AGAIN:
            if (tls->ssl_error == SSL_ERROR_WANT_READ && tls->times < 2) {
                tls->times++;
            }

            return;

        case 0:
            handler = state->close_handler;
            break;

        default:
        case NXT_ERROR:
            c->socket.error = err;
            nxt_openssl_conn_error(task, err, "SSL_do_handshake(%d) failed",
                                   c->socket.fd);

            handler = state->error_handler;
            break;
        }
    }

    wq = (c->read_state != NULL) ? c->read_work_queue : c->write_work_queue;

    nxt_work_queue_add(wq, handler, task, c, data);
}


static ssize_t
nxt_openssl_conn_io_recvbuf(nxt_conn_t *c, nxt_buf_t *b)
{
    int                 ret;
    size_t              size;
    nxt_int_t           n;
    nxt_err_t           err;
    nxt_openssl_conn_t  *tls;

    tls = c->u.tls;
    size = b->mem.end - b->mem.free;

    ret = SSL_read(tls->session, b->mem.free, size);

    err = (ret <= 0) ? nxt_socket_errno : 0;

    nxt_debug(c->socket.task, "SSL_read(%d, %p, %uz): %d err:%d",
              c->socket.fd, b->mem.free, size, ret, err);

    if (ret > 0) {
        if ((size_t) ret < size) {
            c->socket.read_ready = 0;
        }

        return ret;
    }

    n = nxt_openssl_conn_test_error(c->socket.task, c, ret, err,
                                    NXT_OPENSSL_READ);
    if (n == NXT_ERROR) {
        c->socket.error = err;
        nxt_openssl_conn_error(c->socket.task, err,
                               "SSL_read(%d, %p, %uz) failed",
                               c->socket.fd, b->mem.free, size);
    }

    return n;
}


static ssize_t
nxt_openssl_conn_io_sendbuf(nxt_task_t *task, nxt_sendbuf_t *sb)
{
    nxt_uint_t    niov;
    struct iovec  iov;

    niov = nxt_sendbuf_mem_coalesce0(task, sb, &iov, 1);

    if (niov == 0 && sb->sync) {
        return 0;
    }

    return nxt_openssl_conn_io_send(task, sb, iov.iov_base, iov.iov_len);
}


static ssize_t
nxt_openssl_conn_io_send(nxt_task_t *task, nxt_sendbuf_t *sb, void *buf,
    size_t size)
{
    int                 ret;
    nxt_err_t           err;
    nxt_int_t           n;
    nxt_conn_t          *c;
    nxt_openssl_conn_t  *tls;

    tls = sb->tls;

    ret = SSL_write(tls->session, buf, size);

    if (ret <= 0) {
        err = nxt_socket_errno;
        sb->error = err;

    } else {
        err = 0;
    }

    nxt_debug(task, "SSL_write(%d, %p, %uz): %d err:%d",
              sb->socket, buf, size, ret, err);

    if (ret > 0) {
        return ret;
    }

    c = tls->conn;
    c->socket.write_ready = sb->ready;
    c->socket.error = sb->error;

    n = nxt_openssl_conn_test_error(task, c, ret, err, NXT_OPENSSL_WRITE);

    sb->ready = c->socket.write_ready;
    sb->error = c->socket.error;

    if (n == NXT_ERROR) {
        sb->error = err;
        nxt_openssl_conn_error(task, err, "SSL_write(%d, %p, %uz) failed",
                               sb->socket, buf, size);
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
    nxt_openssl_conn_t  *tls;
    nxt_work_handler_t  handler;

    c = obj;

    nxt_debug(task, "openssl conn shutdown fd:%d", c->socket.fd);

    if (c->socket.error != 0) {
        return;
    }

    c->read_state = NULL;
    tls = c->u.tls;

    if (tls == NULL) {
        return;
    }

    s = tls->session;

    if (s == NULL || !tls->handshake) {
        handler = c->write_state->ready_handler;
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
            handler = c->write_state->ready_handler;
            goto done;
        }

        if (ret == 0) {
            /*
             * If SSL_shutdown() returns 0 then it should be called
             * again.  The second SSL_shutdown() call should return
             * -1/SSL_ERROR_WANT_READ or -1/SSL_ERROR_WANT_WRITE.
             * OpenSSL prior to 0.9.8m version however never returns
             * -1 at all.  Fortunately, OpenSSL preserves internally
             * correct status available via SSL_get_error(-1).
             */
            if (once) {
                once = 0;
                mode = SSL_get_shutdown(s);
                continue;
            }

            ret = -1;
        }

        /* ret == -1 */

        break;
    }

    c->socket.read_handler = nxt_openssl_conn_io_shutdown;
    c->socket.write_handler = nxt_openssl_conn_io_shutdown;
    c->socket.error_handler = c->write_state->error_handler;

    n = nxt_openssl_conn_test_error(task, c, ret, err, NXT_OPENSSL_SHUTDOWN);

    switch (n) {

    case 0:
        handler = c->write_state->close_handler;
        break;

    case NXT_AGAIN:
        nxt_timer_add(task->thread->engine, &c->read_timer, 5000);
        return;

    default:
    case NXT_ERROR:
        c->socket.error = err;
        nxt_openssl_conn_error(task, err, "SSL_shutdown(%d) failed",
                               c->socket.fd);
        handler = c->write_state->error_handler;
    }

done:

    nxt_openssl_conn_free(task, c);

    nxt_work_queue_add(c->write_work_queue, handler, task, c, data);
}


static nxt_int_t
nxt_openssl_conn_test_error(nxt_task_t *task, nxt_conn_t *c, int ret,
    nxt_err_t sys_err, nxt_openssl_io_t io)
{
    u_long              lib_err;
    nxt_openssl_conn_t  *tls;

    tls = c->u.tls;

    tls->ssl_error = SSL_get_error(tls->session, ret);

    nxt_debug(task, "SSL_get_error(): %d", tls->ssl_error);

    switch (tls->ssl_error) {

    case SSL_ERROR_WANT_READ:

        if (io != NXT_OPENSSL_READ) {
            nxt_fd_event_block_write(task->thread->engine, &c->socket);

            c->socket.read_ready = 0;

            if (nxt_fd_event_is_disabled(c->socket.read)) {
                nxt_fd_event_enable_read(task->thread->engine, &c->socket);
            }
        }

        return NXT_AGAIN;

    case SSL_ERROR_WANT_WRITE:

        if (io != NXT_OPENSSL_WRITE) {
            nxt_fd_event_block_read(task->thread->engine, &c->socket);

            c->socket.write_ready = 0;

            if (nxt_fd_event_is_disabled(c->socket.write)) {
                nxt_fd_event_enable_write(task->thread->engine, &c->socket);
            }
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
        return 0;

    case SSL_ERROR_ZERO_RETURN:
        /* A "close notify" alert. */
        return 0;

    default: /* SSL_ERROR_SSL, etc. */
        c->socket.error = 1000;  /* Nonexistent errno code. */
        return NXT_ERROR;
    }
}


static void nxt_cdecl
nxt_openssl_conn_error(nxt_task_t *task, nxt_err_t err, const char *fmt, ...)
{
    u_char      *p, *end;
    va_list     args;
    nxt_uint_t  level;
    u_char      msg[NXT_MAX_ERROR_STR];

    level = nxt_openssl_log_error_level(err);

    if (nxt_log_level_enough(task->log, level)) {

        end = msg + sizeof(msg);

        va_start(args, fmt);
        p = nxt_vsprintf(msg, end, fmt, args);
        va_end(args);

        if (err != 0) {
            p = nxt_sprintf(p, end, " %E", err);
        }

        p = nxt_openssl_copy_error(p, end);

        nxt_log(task, level, "%*s", p - msg, msg);

    } else {
        ERR_clear_error();
    }
}


static nxt_uint_t
nxt_openssl_log_error_level(nxt_err_t err)
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
#ifdef SSL_R_NO_CIPHERS_PASSED
    case SSL_R_NO_CIPHERS_PASSED:                         /*  182 */
#endif
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


void nxt_cdecl
nxt_openssl_log_error(nxt_task_t *task, nxt_uint_t level, const char *fmt, ...)
{
    u_char   *p, *end;
    va_list  args;
    u_char   msg[NXT_MAX_ERROR_STR];

    end = msg + sizeof(msg);

    va_start(args, fmt);
    p = nxt_vsprintf(msg, end, fmt, args);
    va_end(args);

    p = nxt_openssl_copy_error(p, end);

    nxt_log(task, level, "%*s", p - msg, msg);
}


u_char *
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
     * ... followed by all queued cumbersome OpenSSL error messages
     * and drain the error queue.
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
