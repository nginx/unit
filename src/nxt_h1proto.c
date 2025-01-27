
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_upstream.h>
#include <nxt_h1proto.h>
#include <nxt_websocket.h>
#include <nxt_websocket_header.h>


/*
 * nxt_http_conn_ and nxt_h1p_conn_ prefixes are used for connection handlers.
 * nxt_h1p_idle_ prefix is used for idle connection handlers.
 * nxt_h1p_request_ prefix is used for HTTP/1 protocol request methods.
 */

#if (NXT_TLS)
static ssize_t nxt_http_idle_io_read_handler(nxt_task_t *task, nxt_conn_t *c);
static void nxt_http_conn_test(nxt_task_t *task, void *obj, void *data);
#endif
static ssize_t nxt_h1p_idle_io_read_handler(nxt_task_t *task, nxt_conn_t *c);
static void nxt_h1p_conn_proto_init(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_conn_request_init(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_conn_request_header_parse(nxt_task_t *task, void *obj,
    void *data);
static nxt_int_t nxt_h1p_header_process(nxt_task_t *task, nxt_h1proto_t *h1p,
    nxt_http_request_t *r);
static nxt_int_t nxt_h1p_header_buffer_test(nxt_task_t *task,
    nxt_h1proto_t *h1p, nxt_conn_t *c, nxt_socket_conf_t *skcf);
static nxt_int_t nxt_h1p_connection(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
static nxt_int_t nxt_h1p_upgrade(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
static nxt_int_t nxt_h1p_websocket_key(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
static nxt_int_t nxt_h1p_websocket_version(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
static nxt_int_t nxt_h1p_transfer_encoding(void *ctx, nxt_http_field_t *field,
    uintptr_t data);
static void nxt_h1p_request_body_read(nxt_task_t *task, nxt_http_request_t *r);
static void nxt_h1p_conn_request_body_read(nxt_task_t *task, void *obj,
    void *data);
static void nxt_h1p_request_local_addr(nxt_task_t *task, nxt_http_request_t *r);
static void nxt_h1p_request_header_send(nxt_task_t *task,
    nxt_http_request_t *r, nxt_work_handler_t body_handler, void *data);
static void nxt_h1p_request_send(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *out);
static nxt_buf_t *nxt_h1p_chunk_create(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *out);
static nxt_off_t nxt_h1p_request_body_bytes_sent(nxt_task_t *task,
    nxt_http_proto_t proto);
static void nxt_h1p_request_discard(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *last);
static void nxt_h1p_conn_request_error(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_conn_request_timeout(nxt_task_t *task, void *obj,
    void *data);
static void nxt_h1p_conn_request_send_timeout(nxt_task_t *task, void *obj,
    void *data);
nxt_inline void nxt_h1p_request_error(nxt_task_t *task, nxt_h1proto_t *h1p,
    nxt_http_request_t *r);
static void nxt_h1p_request_close(nxt_task_t *task, nxt_http_proto_t proto,
    nxt_socket_conf_joint_t *joint);
static void nxt_h1p_conn_sent(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_conn_close(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_conn_error(nxt_task_t *task, void *obj, void *data);
static nxt_msec_t nxt_h1p_conn_timer_value(nxt_conn_t *c, uintptr_t data);
static void nxt_h1p_keepalive(nxt_task_t *task, nxt_h1proto_t *h1p,
    nxt_conn_t *c);
static void nxt_h1p_idle_close(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_idle_timeout(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_idle_response(nxt_task_t *task, nxt_conn_t *c);
static void nxt_h1p_idle_response_sent(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_idle_response_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_h1p_idle_response_timeout(nxt_task_t *task, void *obj,
    void *data);
static nxt_msec_t nxt_h1p_idle_response_timer_value(nxt_conn_t *c,
    uintptr_t data);
static void nxt_h1p_shutdown(nxt_task_t *task, nxt_conn_t *c);
static void nxt_h1p_closing(nxt_task_t *task, nxt_conn_t *c);
static void nxt_h1p_conn_ws_shutdown(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_conn_closing(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_conn_free(nxt_task_t *task, void *obj, void *data);

static void nxt_h1p_peer_connect(nxt_task_t *task, nxt_http_peer_t *peer);
static void nxt_h1p_peer_connected(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_peer_refused(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_peer_header_send(nxt_task_t *task, nxt_http_peer_t *peer);
static nxt_int_t nxt_h1p_peer_request_target(nxt_http_request_t *r,
    nxt_str_t *target);
static void nxt_h1p_peer_header_sent(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_peer_header_read(nxt_task_t *task, nxt_http_peer_t *peer);
static ssize_t nxt_h1p_peer_io_read_handler(nxt_task_t *task, nxt_conn_t *c);
static void nxt_h1p_peer_header_read_done(nxt_task_t *task, void *obj,
    void *data);
static nxt_int_t nxt_h1p_peer_header_parse(nxt_http_peer_t *peer,
    nxt_buf_mem_t *bm);
static void nxt_h1p_peer_read(nxt_task_t *task, nxt_http_peer_t *peer);
static void nxt_h1p_peer_read_done(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_peer_body_process(nxt_task_t *task, nxt_http_peer_t *peer, nxt_buf_t *out);
static void nxt_h1p_peer_closed(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_peer_error(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_peer_send_timeout(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_peer_read_timeout(nxt_task_t *task, void *obj, void *data);
static nxt_msec_t nxt_h1p_peer_timer_value(nxt_conn_t *c, uintptr_t data);
static void nxt_h1p_peer_close(nxt_task_t *task, nxt_http_peer_t *peer);
static void nxt_h1p_peer_free(nxt_task_t *task, void *obj, void *data);
static nxt_int_t nxt_h1p_peer_transfer_encoding(void *ctx,
    nxt_http_field_t *field, uintptr_t data);

#if (NXT_TLS)
static const nxt_conn_state_t  nxt_http_idle_state;
static const nxt_conn_state_t  nxt_h1p_shutdown_state;
#endif
static const nxt_conn_state_t  nxt_h1p_idle_state;
static const nxt_conn_state_t  nxt_h1p_header_parse_state;
static const nxt_conn_state_t  nxt_h1p_read_body_state;
static const nxt_conn_state_t  nxt_h1p_request_send_state;
static const nxt_conn_state_t  nxt_h1p_timeout_response_state;
static const nxt_conn_state_t  nxt_h1p_keepalive_state;
static const nxt_conn_state_t  nxt_h1p_close_state;
static const nxt_conn_state_t  nxt_h1p_peer_connect_state;
static const nxt_conn_state_t  nxt_h1p_peer_header_send_state;
static const nxt_conn_state_t  nxt_h1p_peer_header_body_send_state;
static const nxt_conn_state_t  nxt_h1p_peer_header_read_state;
static const nxt_conn_state_t  nxt_h1p_peer_header_read_timer_state;
static const nxt_conn_state_t  nxt_h1p_peer_read_state;
static const nxt_conn_state_t  nxt_h1p_peer_close_state;


const nxt_http_proto_table_t  nxt_http_proto[3] = {
    /* NXT_HTTP_PROTO_H1 */
    {
        .body_read        = nxt_h1p_request_body_read,
        .local_addr       = nxt_h1p_request_local_addr,
        .header_send      = nxt_h1p_request_header_send,
        .send             = nxt_h1p_request_send,
        .body_bytes_sent  = nxt_h1p_request_body_bytes_sent,
        .discard          = nxt_h1p_request_discard,
        .close            = nxt_h1p_request_close,

        .peer_connect     = nxt_h1p_peer_connect,
        .peer_header_send = nxt_h1p_peer_header_send,
        .peer_header_read = nxt_h1p_peer_header_read,
        .peer_read        = nxt_h1p_peer_read,
        .peer_close       = nxt_h1p_peer_close,

        .ws_frame_start   = nxt_h1p_websocket_frame_start,
    },
    /* NXT_HTTP_PROTO_H2      */
    /* NXT_HTTP_PROTO_DEVNULL */
};


static nxt_lvlhsh_t                    nxt_h1p_fields_hash;

static nxt_http_field_proc_t           nxt_h1p_fields[] = {
    { nxt_string("Connection"),        &nxt_h1p_connection, 0 },
    { nxt_string("Upgrade"),           &nxt_h1p_upgrade, 0 },
    { nxt_string("Sec-WebSocket-Key"), &nxt_h1p_websocket_key, 0 },
    { nxt_string("Sec-WebSocket-Version"),
                                       &nxt_h1p_websocket_version, 0 },
    { nxt_string("Transfer-Encoding"), &nxt_h1p_transfer_encoding, 0 },

    { nxt_string("Host"),              &nxt_http_request_host, 0 },
    { nxt_string("Cookie"),            &nxt_http_request_field,
        offsetof(nxt_http_request_t, cookie) },
    { nxt_string("Referer"),           &nxt_http_request_field,
        offsetof(nxt_http_request_t, referer) },
    { nxt_string("User-Agent"),        &nxt_http_request_field,
        offsetof(nxt_http_request_t, user_agent) },
    { nxt_string("Content-Type"),      &nxt_http_request_field,
        offsetof(nxt_http_request_t, content_type) },
    { nxt_string("Content-Length"),    &nxt_http_request_content_length, 0 },
    { nxt_string("Authorization"),     &nxt_http_request_field,
        offsetof(nxt_http_request_t, authorization) },
#if (NXT_HAVE_OTEL)
    { nxt_string("Traceparent"),       &nxt_otel_parse_traceparent, 0 },
    { nxt_string("Tracestate"),        &nxt_otel_parse_tracestate,  0 },
#endif
};


static nxt_lvlhsh_t                    nxt_h1p_peer_fields_hash;

static nxt_http_field_proc_t           nxt_h1p_peer_fields[] = {
    { nxt_string("Connection"),        &nxt_http_proxy_skip, 0 },
    { nxt_string("Transfer-Encoding"), &nxt_h1p_peer_transfer_encoding, 0 },
    { nxt_string("Server"),            &nxt_http_proxy_skip, 0 },
    { nxt_string("Date"),              &nxt_http_proxy_date, 0 },
    { nxt_string("Content-Length"),    &nxt_http_proxy_content_length, 0 },
};


nxt_int_t
nxt_h1p_init(nxt_task_t *task)
{
    nxt_int_t  ret;

    ret = nxt_http_fields_hash(&nxt_h1p_fields_hash,
                               nxt_h1p_fields, nxt_nitems(nxt_h1p_fields));

    if (nxt_fast_path(ret == NXT_OK)) {
        ret = nxt_http_fields_hash(&nxt_h1p_peer_fields_hash,
                                   nxt_h1p_peer_fields,
                                   nxt_nitems(nxt_h1p_peer_fields));
    }

    return ret;
}


void
nxt_http_conn_init(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t               *c;
    nxt_socket_conf_t        *skcf;
    nxt_event_engine_t       *engine;
    nxt_listen_event_t       *lev;
    nxt_socket_conf_joint_t  *joint;

    c = obj;
    lev = data;

    nxt_debug(task, "http conn init");

    joint = lev->socket.data;
    skcf = joint->socket_conf;
    c->local = skcf->sockaddr;

    engine = task->thread->engine;
    c->read_work_queue = &engine->fast_work_queue;
    c->write_work_queue = &engine->fast_work_queue;

    c->read_state = &nxt_h1p_idle_state;

#if (NXT_TLS)
    if (skcf->tls != NULL) {
        c->read_state = &nxt_http_idle_state;
    }
#endif

    nxt_conn_read(engine, c);
}


#if (NXT_TLS)

static const nxt_conn_state_t  nxt_http_idle_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_conn_test,
    .close_handler = nxt_h1p_conn_close,
    .error_handler = nxt_h1p_conn_error,

    .io_read_handler = nxt_http_idle_io_read_handler,

    .timer_handler = nxt_h1p_idle_timeout,
    .timer_value = nxt_h1p_conn_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, idle_timeout),
};


static ssize_t
nxt_http_idle_io_read_handler(nxt_task_t *task, nxt_conn_t *c)
{
    size_t                   size;
    ssize_t                  n;
    nxt_buf_t                *b;
    nxt_socket_conf_joint_t  *joint;

    joint = c->listen->socket.data;

    if (nxt_slow_path(joint == NULL)) {
        /*
         * Listening socket had been closed while
         * connection was in keep-alive state.
         */
        c->read_state = &nxt_h1p_idle_close_state;
        return 0;
    }

    size = joint->socket_conf->header_buffer_size;

    b = nxt_event_engine_buf_mem_alloc(task->thread->engine, size);
    if (nxt_slow_path(b == NULL)) {
        c->socket.error = NXT_ENOMEM;
        return NXT_ERROR;
    }

    /*
     * 1 byte is enough to distinguish between SSLv3/TLS and plain HTTP.
     * 11 bytes are enough to log supported SSLv3/TLS version.
     * 16 bytes are just for more optimized kernel copy-out operation.
     */
    n = c->io->recv(c, b->mem.pos, 16, MSG_PEEK);

    if (n > 0) {
        c->read = b;

    } else {
        c->read = NULL;
        nxt_event_engine_buf_mem_free(task->thread->engine, b);
    }

    return n;
}


static void
nxt_http_conn_test(nxt_task_t *task, void *obj, void *data)
{
    u_char                   *p;
    nxt_buf_t                *b;
    nxt_conn_t               *c;
    nxt_tls_conf_t           *tls;
    nxt_event_engine_t       *engine;
    nxt_socket_conf_joint_t  *joint;

    c = obj;

    nxt_debug(task, "h1p conn https test");

    engine = task->thread->engine;
    b = c->read;
    p = b->mem.pos;

    c->read_state = &nxt_h1p_idle_state;

    if (p[0] != 0x16) {
        b->mem.free = b->mem.pos;

        nxt_conn_read(engine, c);
        return;
    }

    /* SSLv3/TLS ClientHello message. */

#if (NXT_DEBUG)
    if (nxt_buf_mem_used_size(&b->mem) >= 11) {
        u_char      major, minor;
        const char  *protocol;

        major = p[9];
        minor = p[10];

        if (major == 3) {
            if (minor == 0) {
                protocol = "SSLv";

            } else {
                protocol = "TLSv";
                major -= 2;
                minor -= 1;
            }

            nxt_debug(task, "SSL/TLS: %s%ud.%ud", protocol, major, minor);
        }
    }
#endif

    c->read = NULL;
    nxt_event_engine_buf_mem_free(engine, b);

    joint = c->listen->socket.data;

    if (nxt_slow_path(joint == NULL)) {
        /*
         * Listening socket had been closed while
         * connection was in keep-alive state.
         */
        nxt_h1p_closing(task, c);
        return;
    }

    tls = joint->socket_conf->tls;

    tls->conn_init(task, tls, c);
}

#endif


static const nxt_conn_state_t  nxt_h1p_idle_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_conn_proto_init,
    .close_handler = nxt_h1p_conn_close,
    .error_handler = nxt_h1p_conn_error,

    .io_read_handler = nxt_h1p_idle_io_read_handler,

    .timer_handler = nxt_h1p_idle_timeout,
    .timer_value = nxt_h1p_conn_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, idle_timeout),
    .timer_autoreset = 1,
};


static ssize_t
nxt_h1p_idle_io_read_handler(nxt_task_t *task, nxt_conn_t *c)
{
    size_t                   size;
    ssize_t                  n;
    nxt_buf_t                *b;
    nxt_socket_conf_joint_t  *joint;

    joint = c->listen->socket.data;

    if (nxt_slow_path(joint == NULL)) {
        /*
         * Listening socket had been closed while
         * connection was in keep-alive state.
         */
        c->read_state = &nxt_h1p_idle_close_state;
        return 0;
    }

    b = c->read;

    if (b == NULL) {
        size = joint->socket_conf->header_buffer_size;

        b = nxt_event_engine_buf_mem_alloc(task->thread->engine, size);
        if (nxt_slow_path(b == NULL)) {
            c->socket.error = NXT_ENOMEM;
            return NXT_ERROR;
        }
    }

    n = c->io->recvbuf(c, b);

    if (n > 0) {
        c->read = b;

    } else {
        c->read = NULL;
        nxt_event_engine_buf_mem_free(task->thread->engine, b);
    }

    return n;
}


static void
nxt_h1p_conn_proto_init(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t     *c;
    nxt_h1proto_t  *h1p;

    c = obj;

    nxt_debug(task, "h1p conn proto init");

    h1p = nxt_mp_zget(c->mem_pool, sizeof(nxt_h1proto_t));
    if (nxt_slow_path(h1p == NULL)) {
        nxt_h1p_closing(task, c);
        return;
    }

    c->socket.data = h1p;
    h1p->conn = c;

    nxt_h1p_conn_request_init(task, c, h1p);
}


static void
nxt_h1p_conn_request_init(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t                ret;
    nxt_conn_t               *c;
    nxt_h1proto_t            *h1p;
    nxt_socket_conf_t        *skcf;
    nxt_http_request_t       *r;
    nxt_socket_conf_joint_t  *joint;

    c = obj;
    h1p = data;

    nxt_debug(task, "h1p conn request init");

    nxt_conn_active(task->thread->engine, c);

    r = nxt_http_request_create(task);

    if (nxt_fast_path(r != NULL)) {
        h1p->request = r;
        r->proto.h1 = h1p;

        /* r->protocol = NXT_HTTP_PROTO_H1 is done by zeroing. */
        r->remote = c->remote;

#if (NXT_TLS)
        r->tls = (c->u.tls != NULL);
#endif

        r->task = c->task;
        task = &r->task;
        c->socket.task = task;
        c->read_timer.task = task;
        c->write_timer.task = task;

        ret = nxt_http_parse_request_init(&h1p->parser, r->mem_pool);

        if (nxt_fast_path(ret == NXT_OK)) {
            joint = c->listen->socket.data;
            joint->count++;

            r->conf = joint;
            skcf = joint->socket_conf;
            r->log_route = skcf->log_route;

            if (c->local == NULL) {
                c->local = skcf->sockaddr;
            }

            h1p->parser.discard_unsafe_fields = skcf->discard_unsafe_fields;

            nxt_h1p_conn_request_header_parse(task, c, h1p);

            NXT_OTEL_TRACE();

            return;
        }

        /*
         * The request is very incomplete here,
         * so "internal server error" useless here.
         */
        nxt_mp_release(r->mem_pool);
    }

    nxt_h1p_closing(task, c);
}


static const nxt_conn_state_t  nxt_h1p_header_parse_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_conn_request_header_parse,
    .close_handler = nxt_h1p_conn_request_error,
    .error_handler = nxt_h1p_conn_request_error,

    .timer_handler = nxt_h1p_conn_request_timeout,
    .timer_value = nxt_h1p_conn_request_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, header_read_timeout),
};


static void
nxt_h1p_conn_request_header_parse(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t           ret;
    nxt_conn_t          *c;
    nxt_h1proto_t       *h1p;
    nxt_http_status_t   status;
    nxt_http_request_t  *r;

    c = obj;
    h1p = data;

    nxt_debug(task, "h1p conn header parse");

    ret = nxt_http_parse_request(&h1p->parser, &c->read->mem);

    ret = nxt_expect(NXT_DONE, ret);

    if (ret != NXT_AGAIN) {
        nxt_timer_disable(task->thread->engine, &c->read_timer);
    }

    r = h1p->request;

    switch (ret) {

    case NXT_DONE:
        /*
         * By default the keepalive mode is disabled in HTTP/1.0 and
         * enabled in HTTP/1.1.  The mode can be overridden later by
         * the "Connection" field processed in nxt_h1p_connection().
         */
        h1p->keepalive = (h1p->parser.version.s.minor != '0');

        r->request_line.start = h1p->parser.method.start;
        r->request_line.length = h1p->parser.request_line_end
                                 - r->request_line.start;

        if (nxt_slow_path(r->log_route)) {
            nxt_log(task, NXT_LOG_NOTICE, "http request line \"%V\"",
                    &r->request_line);
        }

        ret = nxt_h1p_header_process(task, h1p, r);

        if (nxt_fast_path(ret == NXT_OK)) {

#if (NXT_TLS)
            if (c->u.tls == NULL && r->conf->socket_conf->tls != NULL) {
                status = NXT_HTTP_TO_HTTPS;
                goto error;
            }
#endif

            r->state->ready_handler(task, r, NULL);
            return;
        }

        status = ret;
        goto error;

    case NXT_AGAIN:
        status = nxt_h1p_header_buffer_test(task, h1p, c, r->conf->socket_conf);

        if (nxt_fast_path(status == NXT_OK)) {
            c->read_state = &nxt_h1p_header_parse_state;

            nxt_conn_read(task->thread->engine, c);
            return;
        }

        break;

    case NXT_HTTP_PARSE_INVALID:
        status = NXT_HTTP_BAD_REQUEST;
        break;

    case NXT_HTTP_PARSE_UNSUPPORTED_VERSION:
        status = NXT_HTTP_VERSION_NOT_SUPPORTED;
        break;

    case NXT_HTTP_PARSE_TOO_LARGE_FIELD:
        status = NXT_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
        break;

    default:
    case NXT_ERROR:
        status = NXT_HTTP_INTERNAL_SERVER_ERROR;
        break;
    }

    (void) nxt_h1p_header_process(task, h1p, r);

error:

    h1p->keepalive = 0;

    nxt_http_request_error(task, r, status);
}


static nxt_int_t
nxt_h1p_header_process(nxt_task_t *task, nxt_h1proto_t *h1p,
    nxt_http_request_t *r)
{
    u_char     *m;
    nxt_int_t  ret;

    r->target.start = h1p->parser.target_start;
    r->target.length = h1p->parser.target_end - h1p->parser.target_start;

    r->quoted_target = h1p->parser.quoted_target;

    if (h1p->parser.version.ui64 != 0) {
        r->version.start = h1p->parser.version.str;
        r->version.length = sizeof(h1p->parser.version.str);
    }

    r->method = &h1p->parser.method;
    r->path = &h1p->parser.path;
    r->args = &h1p->parser.args;

    r->fields = h1p->parser.fields;

    ret = nxt_http_fields_process(r->fields, &nxt_h1p_fields_hash, r);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    if (h1p->connection_upgrade && h1p->upgrade_websocket) {
        m = h1p->parser.method.start;

        if (nxt_slow_path(h1p->parser.method.length != 3
                          || m[0] != 'G'
                          || m[1] != 'E'
                          || m[2] != 'T'))
        {
            nxt_log(task, NXT_LOG_INFO, "h1p upgrade: bad method");

            return NXT_HTTP_BAD_REQUEST;
        }

        if (nxt_slow_path(h1p->parser.version.s.minor != '1')) {
            nxt_log(task, NXT_LOG_INFO, "h1p upgrade: bad protocol version");

            return NXT_HTTP_BAD_REQUEST;
        }

        if (nxt_slow_path(h1p->websocket_key == NULL)) {
            nxt_log(task, NXT_LOG_INFO,
                    "h1p upgrade: bad or absent websocket key");

            return NXT_HTTP_BAD_REQUEST;
        }

        if (nxt_slow_path(h1p->websocket_version_ok == 0)) {
            nxt_log(task, NXT_LOG_INFO,
                    "h1p upgrade: bad or absent websocket version");

            return NXT_HTTP_UPGRADE_REQUIRED;
        }

        r->websocket_handshake = 1;
    }

    return ret;
}


static nxt_int_t
nxt_h1p_header_buffer_test(nxt_task_t *task, nxt_h1proto_t *h1p, nxt_conn_t *c,
    nxt_socket_conf_t *skcf)
{
    size_t     size, used;
    nxt_buf_t  *in, *b;

    in = c->read;

    if (nxt_buf_mem_free_size(&in->mem) == 0) {
        size = skcf->large_header_buffer_size;
        used = nxt_buf_mem_used_size(&in->mem);

        if (size <= used || h1p->nbuffers >= skcf->large_header_buffers) {
            return NXT_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
        }

        b = nxt_buf_mem_alloc(c->mem_pool, size, 0);
        if (nxt_slow_path(b == NULL)) {
            return NXT_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->mem.free = nxt_cpymem(b->mem.pos, in->mem.pos, used);

        in->next = h1p->buffers;
        h1p->buffers = in;
        h1p->nbuffers++;

        c->read = b;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_h1p_connection(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    const u_char        *end;
    nxt_http_request_t  *r;

    r = ctx;
    field->hopbyhop = 1;

    end = field->value + field->value_length;

    if (nxt_memcasestrn(field->value, end, "close", 5) != NULL) {
        r->proto.h1->keepalive = 0;
    }

    if (nxt_memcasestrn(field->value, end, "keep-alive", 10) != NULL) {
        r->proto.h1->keepalive = 1;
    }

    if (nxt_memcasestrn(field->value, end, "upgrade", 7) != NULL) {
        r->proto.h1->connection_upgrade = 1;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_h1p_upgrade(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    nxt_http_request_t  *r;

    r = ctx;

    if (field->value_length == 9
        && nxt_memcasecmp(field->value, "websocket", 9) == 0)
    {
        r->proto.h1->upgrade_websocket = 1;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_h1p_websocket_key(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    nxt_http_request_t  *r;

    r = ctx;

    if (field->value_length == 24) {
        r->proto.h1->websocket_key = field;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_h1p_websocket_version(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    nxt_http_request_t  *r;

    r = ctx;

    if (field->value_length == 2
        && field->value[0] == '1' && field->value[1] == '3')
    {
        r->proto.h1->websocket_version_ok = 1;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_h1p_transfer_encoding(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    nxt_http_te_t       te;
    nxt_http_request_t  *r;

    r = ctx;
    field->skip = 1;
    field->hopbyhop = 1;

    if (field->value_length == 7
        && memcmp(field->value, "chunked", 7) == 0)
    {
        if (r->chunked_field != NULL) {
            return NXT_HTTP_BAD_REQUEST;
        }

        te = NXT_HTTP_TE_CHUNKED;
        r->chunked_field = field;

    } else {
        te = NXT_HTTP_TE_UNSUPPORTED;
    }

    r->proto.h1->transfer_encoding = te;

    return NXT_OK;
}


static void
nxt_h1p_request_body_read(nxt_task_t *task, nxt_http_request_t *r)
{
    size_t             size, body_length, body_buffer_size, body_rest;
    ssize_t            res;
    nxt_buf_t          *in, *b, *out, *chunk;
    nxt_conn_t         *c;
    nxt_h1proto_t      *h1p;
    nxt_socket_conf_t  *skcf;
    nxt_http_status_t  status;

    static const nxt_str_t tmp_name_pattern = nxt_string("/req-XXXXXXXX");

    h1p = r->proto.h1;
    skcf = r->conf->socket_conf;

    nxt_debug(task, "h1p request body read %O te:%d",
              r->content_length_n, h1p->transfer_encoding);

    switch (h1p->transfer_encoding) {

    case NXT_HTTP_TE_CHUNKED:
        if (!skcf->chunked_transform) {
            status = NXT_HTTP_LENGTH_REQUIRED;
            goto error;
        }

        if (r->content_length != NULL || !nxt_h1p_is_http11(h1p)) {
            status = NXT_HTTP_BAD_REQUEST;
            goto error;
        }

        r->chunked = 1;
        h1p->chunked_parse.mem_pool = r->mem_pool;
        break;

    case NXT_HTTP_TE_UNSUPPORTED:
        status = NXT_HTTP_NOT_IMPLEMENTED;
        goto error;

    default:
    case NXT_HTTP_TE_NONE:
        break;
    }

    if (!r->chunked &&
        (r->content_length_n == -1 || r->content_length_n == 0))
    {
        goto ready;
    }

    body_length = (size_t) r->content_length_n;

    body_buffer_size = nxt_min(skcf->body_buffer_size, body_length);

    if (body_length > body_buffer_size) {
        nxt_str_t  *tmp_path, tmp_name;

        tmp_path = &skcf->body_temp_path;

        tmp_name.length = tmp_path->length + tmp_name_pattern.length;

        b = nxt_buf_file_alloc(r->mem_pool,
                               body_buffer_size + sizeof(nxt_file_t)
                               + tmp_name.length + 1, 0);
        if (nxt_slow_path(b == NULL)) {
            status = NXT_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }

        tmp_name.start = nxt_pointer_to(b->mem.start, sizeof(nxt_file_t));

        memcpy(tmp_name.start, tmp_path->start, tmp_path->length);
        memcpy(tmp_name.start + tmp_path->length, tmp_name_pattern.start,
               tmp_name_pattern.length);
        tmp_name.start[tmp_name.length] = '\0';

        b->file = (nxt_file_t *) b->mem.start;
        nxt_memzero(b->file, sizeof(nxt_file_t));
        b->file->fd = -1;
        b->file->size = body_length;

        b->mem.start += sizeof(nxt_file_t) + tmp_name.length + 1;
        b->mem.pos = b->mem.start;
        b->mem.free = b->mem.start;

        b->file->fd = mkstemp((char *) tmp_name.start);
        if (nxt_slow_path(b->file->fd == -1)) {
            nxt_alert(task, "mkstemp(%s) failed %E", tmp_name.start, nxt_errno);

            status = NXT_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }

        nxt_debug(task, "create body tmp file \"%V\", %d",
                  &tmp_name, b->file->fd);

        unlink((char *) tmp_name.start);

    } else {
        b = nxt_buf_mem_alloc(r->mem_pool, body_buffer_size, 0);
        if (nxt_slow_path(b == NULL)) {
            status = NXT_HTTP_INTERNAL_SERVER_ERROR;
            goto error;
        }
    }

    r->body = b;

    body_rest = r->chunked ? 1 : body_length;

    in = h1p->conn->read;

    size = nxt_buf_mem_used_size(&in->mem);

    if (size != 0) {
        if (nxt_buf_is_file(b)) {
            if (r->chunked) {
                out = nxt_http_chunk_parse(task, &h1p->chunked_parse, in);

                if (h1p->chunked_parse.error) {
                    status = NXT_HTTP_INTERNAL_SERVER_ERROR;
                    goto error;
                }

                if (h1p->chunked_parse.chunk_error) {
                    status = NXT_HTTP_BAD_REQUEST;
                    goto error;
                }

                for (chunk = out; chunk != NULL; chunk = chunk->next) {
                    size = nxt_buf_mem_used_size(&chunk->mem);

                    res = nxt_fd_write(b->file->fd, chunk->mem.pos, size);
                    if (nxt_slow_path(res < (ssize_t) size)) {
                        status = NXT_HTTP_INTERNAL_SERVER_ERROR;
                        goto error;
                    }

                    b->file_end += size;

                    if ((size_t) b->file_end > skcf->max_body_size) {
                        status = NXT_HTTP_PAYLOAD_TOO_LARGE;
                        goto error;
                    }
                }

                if (h1p->chunked_parse.last) {
                    body_rest = 0;
                }

            } else {
                size = nxt_min(size, body_length);
                res = nxt_fd_write(b->file->fd, in->mem.pos, size);
                if (nxt_slow_path(res < (ssize_t) size)) {
                    status = NXT_HTTP_INTERNAL_SERVER_ERROR;
                    goto error;
                }

                b->file_end += size;

                in->mem.pos += size;
                body_rest -= size;
            }

        } else {
            size = nxt_min(body_buffer_size, size);
            b->mem.free = nxt_cpymem(b->mem.free, in->mem.pos, size);

            in->mem.pos += size;
            body_rest -= size;
        }
    }

    nxt_debug(task, "h1p body rest: %uz", body_rest);

    if (body_rest != 0) {
        in->next = h1p->buffers;
        h1p->buffers = in;
        h1p->nbuffers++;

        c = h1p->conn;
        c->read = b;
        c->read_state = &nxt_h1p_read_body_state;

        nxt_conn_read(task->thread->engine, c);
        return;
    }

    if (nxt_buf_is_file(b)) {
        b->mem.start = NULL;
        b->mem.end = NULL;
        b->mem.pos = NULL;
        b->mem.free = NULL;
    }

ready:

    r->state->ready_handler(task, r, NULL);

    return;

error:

    h1p->keepalive = 0;

    nxt_http_request_error(task, r, status);
}


static const nxt_conn_state_t  nxt_h1p_read_body_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_conn_request_body_read,
    .close_handler = nxt_h1p_conn_request_error,
    .error_handler = nxt_h1p_conn_request_error,

    .timer_handler = nxt_h1p_conn_request_timeout,
    .timer_value = nxt_h1p_conn_request_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, body_read_timeout),
    .timer_autoreset = 1,
};


static void
nxt_h1p_conn_request_body_read(nxt_task_t *task, void *obj, void *data)
{
    size_t              size, body_rest;
    ssize_t             res;
    nxt_buf_t           *b, *out, *chunk;
    nxt_conn_t          *c;
    nxt_h1proto_t       *h1p;
    nxt_socket_conf_t   *skcf;
    nxt_http_request_t  *r;
    nxt_event_engine_t  *engine;

    c = obj;
    h1p = data;

    nxt_debug(task, "h1p conn request body read");

    r = h1p->request;
    skcf = r->conf->socket_conf;

    engine = task->thread->engine;

    b = c->read;

    if (nxt_buf_is_file(b)) {

        if (r->chunked) {
            body_rest = 1;

            out = nxt_http_chunk_parse(task, &h1p->chunked_parse, b);

            if (h1p->chunked_parse.error) {
                nxt_h1p_request_error(task, h1p, r);
                return;
            }

            if (h1p->chunked_parse.chunk_error) {
                nxt_http_request_error(task, r, NXT_HTTP_BAD_REQUEST);
                return;
            }

            for (chunk = out; chunk != NULL; chunk = chunk->next) {
                size = nxt_buf_mem_used_size(&chunk->mem);
                res = nxt_fd_write(b->file->fd, chunk->mem.pos, size);
                if (nxt_slow_path(res < (ssize_t) size)) {
                    nxt_h1p_request_error(task, h1p, r);
                    return;
                }

                b->file_end += size;

                if ((size_t) b->file_end > skcf->max_body_size) {
                    nxt_h1p_request_error(task, h1p, r);
                    return;
                }
            }

            if (h1p->chunked_parse.last) {
                body_rest = 0;
            }

        } else {
            body_rest = b->file->size - b->file_end;

            size = nxt_buf_mem_used_size(&b->mem);
            size = nxt_min(size, body_rest);

            res = nxt_fd_write(b->file->fd, b->mem.pos, size);
            if (nxt_slow_path(res < (ssize_t) size)) {
                nxt_h1p_request_error(task, h1p, r);
                return;
            }

            b->file_end += size;
            body_rest -= res;

            b->mem.pos += size;

            if (b->mem.pos == b->mem.free) {
                if (body_rest >= (size_t) nxt_buf_mem_size(&b->mem)) {
                    b->mem.free = b->mem.start;

                } else {
                    /* This required to avoid reading next request. */
                    b->mem.free = b->mem.end - body_rest;
                }

                b->mem.pos = b->mem.free;
            }
        }

    } else {
        body_rest = nxt_buf_mem_free_size(&c->read->mem);
    }

    nxt_debug(task, "h1p body rest: %uz", body_rest);

    if (body_rest != 0) {
        nxt_conn_read(engine, c);

    } else {
        if (nxt_buf_is_file(b)) {
            b->mem.start = NULL;
            b->mem.end = NULL;
            b->mem.pos = NULL;
            b->mem.free = NULL;
        }

        c->read = NULL;

        r->state->ready_handler(task, r, NULL);
    }
}


static void
nxt_h1p_request_local_addr(nxt_task_t *task, nxt_http_request_t *r)
{
    r->local = nxt_conn_local_addr(task, r->proto.h1->conn);
}


#define NXT_HTTP_LAST_INFORMATIONAL                                           \
    (NXT_HTTP_CONTINUE + nxt_nitems(nxt_http_informational) - 1)

static const nxt_str_t  nxt_http_informational[] = {
    nxt_string("HTTP/1.1 100 Continue\r\n"),
    nxt_string("HTTP/1.1 101 Switching Protocols\r\n"),
};


#define NXT_HTTP_LAST_SUCCESS                                                 \
    (NXT_HTTP_OK + nxt_nitems(nxt_http_success) - 1)

static const nxt_str_t  nxt_http_success[] = {
    nxt_string("HTTP/1.1 200 OK\r\n"),
    nxt_string("HTTP/1.1 201 Created\r\n"),
    nxt_string("HTTP/1.1 202 Accepted\r\n"),
    nxt_string("HTTP/1.1 203 Non-Authoritative Information\r\n"),
    nxt_string("HTTP/1.1 204 No Content\r\n"),
    nxt_string("HTTP/1.1 205 Reset Content\r\n"),
    nxt_string("HTTP/1.1 206 Partial Content\r\n"),
};


#define NXT_HTTP_LAST_REDIRECTION                                             \
    (NXT_HTTP_MULTIPLE_CHOICES + nxt_nitems(nxt_http_redirection) - 1)

static const nxt_str_t  nxt_http_redirection[] = {
    nxt_string("HTTP/1.1 300 Multiple Choices\r\n"),
    nxt_string("HTTP/1.1 301 Moved Permanently\r\n"),
    nxt_string("HTTP/1.1 302 Found\r\n"),
    nxt_string("HTTP/1.1 303 See Other\r\n"),
    nxt_string("HTTP/1.1 304 Not Modified\r\n"),
    nxt_string("HTTP/1.1 307 Temporary Redirect\r\n"),
    nxt_string("HTTP/1.1 308 Permanent Redirect\r\n"),
};


#define NXT_HTTP_LAST_CLIENT_ERROR                                            \
    (NXT_HTTP_BAD_REQUEST + nxt_nitems(nxt_http_client_error) - 1)

static const nxt_str_t  nxt_http_client_error[] = {
    nxt_string("HTTP/1.1 400 Bad Request\r\n"),
    nxt_string("HTTP/1.1 401 Unauthorized\r\n"),
    nxt_string("HTTP/1.1 402 Payment Required\r\n"),
    nxt_string("HTTP/1.1 403 Forbidden\r\n"),
    nxt_string("HTTP/1.1 404 Not Found\r\n"),
    nxt_string("HTTP/1.1 405 Method Not Allowed\r\n"),
    nxt_string("HTTP/1.1 406 Not Acceptable\r\n"),
    nxt_string("HTTP/1.1 407 Proxy Authentication Required\r\n"),
    nxt_string("HTTP/1.1 408 Request Timeout\r\n"),
    nxt_string("HTTP/1.1 409 Conflict\r\n"),
    nxt_string("HTTP/1.1 410 Gone\r\n"),
    nxt_string("HTTP/1.1 411 Length Required\r\n"),
    nxt_string("HTTP/1.1 412 Precondition Failed\r\n"),
    nxt_string("HTTP/1.1 413 Payload Too Large\r\n"),
    nxt_string("HTTP/1.1 414 URI Too Long\r\n"),
    nxt_string("HTTP/1.1 415 Unsupported Media Type\r\n"),
    nxt_string("HTTP/1.1 416 Range Not Satisfiable\r\n"),
    nxt_string("HTTP/1.1 417 Expectation Failed\r\n"),
    nxt_string("HTTP/1.1 418 I'm a teapot\r\n"),
    nxt_string("HTTP/1.1 419 \r\n"),
    nxt_string("HTTP/1.1 420 \r\n"),
    nxt_string("HTTP/1.1 421 Misdirected Request\r\n"),
    nxt_string("HTTP/1.1 422 Unprocessable Entity\r\n"),
    nxt_string("HTTP/1.1 423 Locked\r\n"),
    nxt_string("HTTP/1.1 424 Failed Dependency\r\n"),
    nxt_string("HTTP/1.1 425 \r\n"),
    nxt_string("HTTP/1.1 426 Upgrade Required\r\n"),
    nxt_string("HTTP/1.1 427 \r\n"),
    nxt_string("HTTP/1.1 428 \r\n"),
    nxt_string("HTTP/1.1 429 \r\n"),
    nxt_string("HTTP/1.1 430 \r\n"),
    nxt_string("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
};


#define NXT_HTTP_LAST_NGINX_ERROR                                             \
    (NXT_HTTP_TO_HTTPS + nxt_nitems(nxt_http_nginx_error) - 1)

static const nxt_str_t  nxt_http_nginx_error[] = {
    nxt_string("HTTP/1.1 400 "
               "The plain HTTP request was sent to HTTPS port\r\n"),
};


#define NXT_HTTP_LAST_SERVER_ERROR                                            \
    (NXT_HTTP_INTERNAL_SERVER_ERROR + nxt_nitems(nxt_http_server_error) - 1)

static const nxt_str_t  nxt_http_server_error[] = {
    nxt_string("HTTP/1.1 500 Internal Server Error\r\n"),
    nxt_string("HTTP/1.1 501 Not Implemented\r\n"),
    nxt_string("HTTP/1.1 502 Bad Gateway\r\n"),
    nxt_string("HTTP/1.1 503 Service Unavailable\r\n"),
    nxt_string("HTTP/1.1 504 Gateway Timeout\r\n"),
    nxt_string("HTTP/1.1 505 HTTP Version Not Supported\r\n"),
};


#define UNKNOWN_STATUS_LENGTH  nxt_length("HTTP/1.1 999 \r\n")

static void
nxt_h1p_request_header_send(nxt_task_t *task, nxt_http_request_t *r,
    nxt_work_handler_t body_handler, void *data)
{
    u_char              *p;
    size_t              size;
    nxt_buf_t           *header;
    nxt_str_t           unknown_status;
    nxt_int_t           conn;
    nxt_uint_t          n;
    nxt_bool_t          http11;
    nxt_conn_t          *c;
    nxt_h1proto_t       *h1p;
    const nxt_str_t     *status;
    nxt_http_field_t    *field;
    u_char              buf[UNKNOWN_STATUS_LENGTH];

    static const char   chunked[] = "Transfer-Encoding: chunked\r\n";
    static const char   websocket_version[] = "Sec-WebSocket-Version: 13\r\n";

    static const nxt_str_t  connection[3] = {
        nxt_string("Connection: close\r\n"),
        nxt_string("Connection: keep-alive\r\n"),
        nxt_string("Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Accept: "),
    };

    nxt_debug(task, "h1p request header send");

    NXT_OTEL_TRACE();

    r->header_sent = 1;
    h1p = r->proto.h1;
    n = r->status;

    if (n >= NXT_HTTP_CONTINUE && n <= NXT_HTTP_LAST_INFORMATIONAL) {
        status = &nxt_http_informational[n - NXT_HTTP_CONTINUE];

    } else if (n >= NXT_HTTP_OK && n <= NXT_HTTP_LAST_SUCCESS) {
        status = &nxt_http_success[n - NXT_HTTP_OK];

    } else if (n >= NXT_HTTP_MULTIPLE_CHOICES
               && n <= NXT_HTTP_LAST_REDIRECTION)
    {
        status = &nxt_http_redirection[n - NXT_HTTP_MULTIPLE_CHOICES];

    } else if (n >= NXT_HTTP_BAD_REQUEST && n <= NXT_HTTP_LAST_CLIENT_ERROR) {
        status = &nxt_http_client_error[n - NXT_HTTP_BAD_REQUEST];

    } else if (n >= NXT_HTTP_TO_HTTPS && n <= NXT_HTTP_LAST_NGINX_ERROR) {
        status = &nxt_http_nginx_error[n - NXT_HTTP_TO_HTTPS];

    } else if (n >= NXT_HTTP_INTERNAL_SERVER_ERROR
               && n <= NXT_HTTP_LAST_SERVER_ERROR)
    {
        status = &nxt_http_server_error[n - NXT_HTTP_INTERNAL_SERVER_ERROR];

    } else if (n <= NXT_HTTP_STATUS_MAX) {
        (void) nxt_sprintf(buf, buf + UNKNOWN_STATUS_LENGTH,
                           "HTTP/1.1 %03d \r\n", n);

        unknown_status.length = UNKNOWN_STATUS_LENGTH;
        unknown_status.start = buf;
        status = &unknown_status;

    } else {
        status = &nxt_http_server_error[0];
    }

    size = status->length;
    /* Trailing CRLF at the end of header. */
    size += nxt_length("\r\n");

    conn = -1;

    if (r->websocket_handshake && n == NXT_HTTP_SWITCHING_PROTOCOLS) {
        h1p->websocket = 1;
        h1p->keepalive = 0;
        conn = 2;
        size += NXT_WEBSOCKET_ACCEPT_SIZE + 2;

    } else {
        http11 = nxt_h1p_is_http11(h1p);

        if (r->resp.content_length == NULL || r->resp.content_length->skip) {

            if (http11) {
                if (n != NXT_HTTP_NOT_MODIFIED
                    && n != NXT_HTTP_NO_CONTENT
                    && body_handler != NULL
                    && !h1p->websocket)
                {
                    h1p->chunked = 1;
                    size += nxt_length(chunked);
                    /* Trailing CRLF will be added by the first chunk header. */
                    size -= nxt_length("\r\n");
                }

            } else {
                h1p->keepalive = 0;
            }
        }

        if (http11 ^ h1p->keepalive) {
            conn = h1p->keepalive;
        }
    }

    if (conn >= 0) {
        size += connection[conn].length;
    }

    nxt_list_each(field, r->resp.fields) {

        if (!field->skip) {
            size += field->name_length + field->value_length;
            size += nxt_length(": \r\n");
        }

    } nxt_list_loop;

    if (nxt_slow_path(n == NXT_HTTP_UPGRADE_REQUIRED)) {
        size += nxt_length(websocket_version);
    }

    header = nxt_http_buf_mem(task, r, size);
    if (nxt_slow_path(header == NULL)) {
        nxt_h1p_request_error(task, h1p, r);
        return;
    }

    p = nxt_cpymem(header->mem.free, status->start, status->length);

    nxt_list_each(field, r->resp.fields) {

        if (!field->skip) {
            p = nxt_cpymem(p, field->name, field->name_length);
            *p++ = ':'; *p++ = ' ';
            p = nxt_cpymem(p, field->value, field->value_length);
            *p++ = '\r'; *p++ = '\n';
        }

    } nxt_list_loop;

    if (conn >= 0) {
        p = nxt_cpymem(p, connection[conn].start, connection[conn].length);
    }

    if (h1p->websocket) {
        nxt_websocket_accept(p, h1p->websocket_key->value);
        p += NXT_WEBSOCKET_ACCEPT_SIZE;

        *p++ = '\r'; *p++ = '\n';
    }

    if (nxt_slow_path(n == NXT_HTTP_UPGRADE_REQUIRED)) {
        p = nxt_cpymem(p, websocket_version, nxt_length(websocket_version));
    }

    if (h1p->chunked) {
        p = nxt_cpymem(p, chunked, nxt_length(chunked));
        /* Trailing CRLF will be added by the first chunk header. */

    } else {
        *p++ = '\r'; *p++ = '\n';
    }

    header->mem.free = p;

    h1p->header_size = nxt_buf_mem_used_size(&header->mem);

    c = h1p->conn;

    c->write = header;
    h1p->conn_write_tail = &header->next;
    c->write_state = &nxt_h1p_request_send_state;

    if (body_handler != NULL) {
        /*
         * The body handler will run before c->io->write() handler,
         * because the latter was inqueued by nxt_conn_write()
         * in engine->write_work_queue.
         */
        nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                           body_handler, task, r, data);

    } else {
        header->next = nxt_http_buf_last(r);
    }

    nxt_conn_write(task->thread->engine, c);

    if (h1p->websocket) {
        nxt_h1p_websocket_first_frame_start(task, r, c->read);
    }
}


void
nxt_h1p_complete_buffers(nxt_task_t *task, nxt_h1proto_t *h1p, nxt_bool_t all)
{
    size_t            size;
    nxt_buf_t         *b, *in, *next;
    nxt_conn_t        *c;

    nxt_debug(task, "h1p complete buffers");

    b = h1p->buffers;
    c = h1p->conn;
    in = c->read;

    if (b != NULL) {
        if (in == NULL) {
            /* A request with large body. */
            in = b;
            c->read = in;

            b = in->next;
            in->next = NULL;
        }

        while (b != NULL) {
            next = b->next;
            b->next = NULL;

            b->completion_handler(task, b, b->parent);

            b = next;
        }

        h1p->buffers = NULL;
        h1p->nbuffers = 0;
    }

    if (in != NULL) {
        size = nxt_buf_mem_used_size(&in->mem);

        if (size == 0 || all) {
            in->completion_handler(task, in, in->parent);

            c->read = NULL;
        }
    }
}


static const nxt_conn_state_t  nxt_h1p_request_send_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_conn_sent,
    .error_handler = nxt_h1p_conn_request_error,

    .timer_handler = nxt_h1p_conn_request_send_timeout,
    .timer_value = nxt_h1p_conn_request_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, send_timeout),
    .timer_autoreset = 1,
};


static void
nxt_h1p_request_send(nxt_task_t *task, nxt_http_request_t *r, nxt_buf_t *out)
{
    nxt_conn_t     *c;
    nxt_h1proto_t  *h1p;

    nxt_debug(task, "h1p request send");

    h1p = r->proto.h1;
    c = h1p->conn;

    if (h1p->chunked) {
        out = nxt_h1p_chunk_create(task, r, out);
        if (nxt_slow_path(out == NULL)) {
            nxt_h1p_request_error(task, h1p, r);
            return;
        }
    }

    if (c->write == NULL) {
        c->write = out;
        c->write_state = &nxt_h1p_request_send_state;

        nxt_conn_write(task->thread->engine, c);

    } else {
        *h1p->conn_write_tail = out;
    }

    while (out->next != NULL) {
        out = out->next;
    }

    h1p->conn_write_tail = &out->next;
}


static nxt_buf_t *
nxt_h1p_chunk_create(nxt_task_t *task, nxt_http_request_t *r, nxt_buf_t *out)
{
    nxt_off_t          size;
    nxt_buf_t          *b, **prev, *header, *tail;

    const size_t       chunk_size = 2 * nxt_length("\r\n") + NXT_OFF_T_HEXLEN;
    static const char  tail_chunk[] = "\r\n0\r\n\r\n";

    size = 0;
    prev = &out;

    for (b = out; b != NULL; b = b->next) {

        if (nxt_buf_is_last(b)) {
            tail = nxt_http_buf_mem(task, r, sizeof(tail_chunk));
            if (nxt_slow_path(tail == NULL)) {
                return NULL;
            }

            *prev = tail;
            tail->next = b;
            /*
             * The tail_chunk size with trailing zero is 8 bytes, so
             * memcpy may be inlined with just single 8 byte move operation.
             */
            nxt_memcpy(tail->mem.free, tail_chunk, sizeof(tail_chunk));
            tail->mem.free += nxt_length(tail_chunk);

            break;
        }

        size += nxt_buf_used_size(b);
        prev = &b->next;
    }

    if (size == 0) {
        return out;
    }

    header = nxt_http_buf_mem(task, r, chunk_size);
    if (nxt_slow_path(header == NULL)) {
        return NULL;
    }

    header->next = out;
    header->mem.free = nxt_sprintf(header->mem.free, header->mem.end,
                                   "\r\n%xO\r\n", size);
    return header;
}


static nxt_off_t
nxt_h1p_request_body_bytes_sent(nxt_task_t *task, nxt_http_proto_t proto)
{
    nxt_off_t      sent;
    nxt_h1proto_t  *h1p;

    h1p = proto.h1;

    sent = h1p->conn->sent - h1p->header_size;

    return (sent > 0) ? sent : 0;
}


static void
nxt_h1p_request_discard(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *last)
{
    nxt_buf_t         *b;
    nxt_conn_t        *c;
    nxt_h1proto_t     *h1p;
    nxt_work_queue_t  *wq;

    nxt_debug(task, "h1p request discard");

    h1p = r->proto.h1;
    h1p->keepalive = 0;

    c = h1p->conn;
    b = c->write;
    c->write = NULL;

    wq = &task->thread->engine->fast_work_queue;

    nxt_sendbuf_drain(task, wq, b);
    nxt_sendbuf_drain(task, wq, last);
}


static void
nxt_h1p_conn_request_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_h1proto_t       *h1p;
    nxt_http_request_t  *r;

    h1p = data;

    nxt_debug(task, "h1p conn request error");

    r = h1p->request;

    if (nxt_slow_path(r == NULL)) {
        nxt_h1p_shutdown(task, h1p->conn);
        return;
    }

    if (r->fields == NULL) {
        (void) nxt_h1p_header_process(task, h1p, r);
    }

    if (r->status == 0) {
        r->status = NXT_HTTP_BAD_REQUEST;
    }

    nxt_h1p_request_error(task, h1p, r);
}


static void
nxt_h1p_conn_request_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_timer_t         *timer;
    nxt_h1proto_t       *h1p;
    nxt_http_request_t  *r;

    timer = obj;

    nxt_debug(task, "h1p conn request timeout");

    c = nxt_read_timer_conn(timer);
    c->block_read = 1;
    /*
     * Disable SO_LINGER off during socket closing
     * to send "408 Request Timeout" error response.
     */
    c->socket.timedout = 0;

    h1p = c->socket.data;
    h1p->keepalive = 0;
    r = h1p->request;

    if (r->fields == NULL) {
        (void) nxt_h1p_header_process(task, h1p, r);
    }

    nxt_http_request_error(task, r, NXT_HTTP_REQUEST_TIMEOUT);
}


static void
nxt_h1p_conn_request_send_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t     *c;
    nxt_timer_t    *timer;
    nxt_h1proto_t  *h1p;

    timer = obj;

    nxt_debug(task, "h1p conn request send timeout");

    c = nxt_write_timer_conn(timer);
    c->block_write = 1;
    h1p = c->socket.data;

    nxt_h1p_request_error(task, h1p, h1p->request);
}


nxt_msec_t
nxt_h1p_conn_request_timer_value(nxt_conn_t *c, uintptr_t data)
{
    nxt_h1proto_t  *h1p;

    h1p = c->socket.data;

    return nxt_value_at(nxt_msec_t, h1p->request->conf->socket_conf, data);
}


nxt_inline void
nxt_h1p_request_error(nxt_task_t *task, nxt_h1proto_t *h1p,
    nxt_http_request_t *r)
{
    h1p->keepalive = 0;

    r->state->error_handler(task, r, h1p);
}


static void
nxt_h1p_request_close(nxt_task_t *task, nxt_http_proto_t proto,
    nxt_socket_conf_joint_t *joint)
{
    nxt_conn_t     *c;
    nxt_h1proto_t  *h1p;

    nxt_debug(task, "h1p request close");

    h1p = proto.h1;
    h1p->keepalive &= !h1p->request->inconsistent;
    h1p->request = NULL;

    nxt_router_conf_release(task, joint);

    c = h1p->conn;
    task = &c->task;
    c->socket.task = task;
    c->read_timer.task = task;
    c->write_timer.task = task;

    if (h1p->keepalive) {
        nxt_h1p_keepalive(task, h1p, c);

    } else {
        nxt_h1p_shutdown(task, c);
    }
}


static void
nxt_h1p_conn_sent(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_event_engine_t  *engine;

    c = obj;

    nxt_debug(task, "h1p conn sent");

    engine = task->thread->engine;

    c->write = nxt_sendbuf_completion(task, &engine->fast_work_queue, c->write);

    if (c->write != NULL) {
        nxt_conn_write(engine, c);
    }
}


static void
nxt_h1p_conn_close(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "h1p conn close");

    nxt_conn_active(task->thread->engine, c);

    nxt_h1p_shutdown(task, c);
}


static void
nxt_h1p_conn_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "h1p conn error");

    nxt_conn_active(task->thread->engine, c);

    nxt_h1p_shutdown(task, c);
}


static nxt_msec_t
nxt_h1p_conn_timer_value(nxt_conn_t *c, uintptr_t data)
{
    nxt_socket_conf_joint_t  *joint;

    joint = c->listen->socket.data;

    if (nxt_fast_path(joint != NULL)) {
        return nxt_value_at(nxt_msec_t, joint->socket_conf, data);
    }

    /*
     * Listening socket had been closed while
     * connection was in keep-alive state.
     */
    return 1;
}


static void
nxt_h1p_keepalive(nxt_task_t *task, nxt_h1proto_t *h1p, nxt_conn_t *c)
{
    size_t              size;
    nxt_buf_t           *in;
    nxt_event_engine_t  *engine;

    nxt_debug(task, "h1p keepalive");

    if (!c->tcp_nodelay) {
        nxt_conn_tcp_nodelay_on(task, c);
    }

    nxt_h1p_complete_buffers(task, h1p, 0);

    in = c->read;

    nxt_memzero(h1p, offsetof(nxt_h1proto_t, conn));

    c->sent = 0;

    engine = task->thread->engine;

    nxt_conn_idle(engine, c);

    if (in == NULL) {
        c->read_state = &nxt_h1p_keepalive_state;

        nxt_conn_read(engine, c);

    } else {
        size = nxt_buf_mem_used_size(&in->mem);

        nxt_debug(task, "h1p pipelining");

        nxt_memmove(in->mem.start, in->mem.pos, size);

        in->mem.pos = in->mem.start;
        in->mem.free = in->mem.start + size;

        nxt_h1p_conn_request_init(task, c, c->socket.data);
    }
}


static const nxt_conn_state_t  nxt_h1p_keepalive_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_conn_request_init,
    .close_handler = nxt_h1p_conn_close,
    .error_handler = nxt_h1p_conn_error,

    .io_read_handler = nxt_h1p_idle_io_read_handler,

    .timer_handler = nxt_h1p_idle_timeout,
    .timer_value = nxt_h1p_conn_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, idle_timeout),
    .timer_autoreset = 1,
};


const nxt_conn_state_t  nxt_h1p_idle_close_state
    nxt_aligned(64) =
{
    .close_handler = nxt_h1p_idle_close,
};


static void
nxt_h1p_idle_close(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "h1p idle close");

    nxt_conn_active(task->thread->engine, c);

    nxt_h1p_idle_response(task, c);
}


static void
nxt_h1p_idle_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t   *c;
    nxt_timer_t  *timer;

    timer = obj;

    nxt_debug(task, "h1p idle timeout");

    c = nxt_read_timer_conn(timer);
    c->block_read = 1;

    nxt_conn_active(task->thread->engine, c);

    nxt_h1p_idle_response(task, c);
}


#define NXT_H1P_IDLE_TIMEOUT                                                  \
    "HTTP/1.1 408 Request Timeout\r\n"                                        \
    "Server: " NXT_SERVER "\r\n"                                              \
    "Connection: close\r\n"                                                   \
    "Content-Length: 0\r\n"                                                   \
    "Date: "


static void
nxt_h1p_idle_response(nxt_task_t *task, nxt_conn_t *c)
{
    u_char     *p;
    size_t     size;
    nxt_buf_t  *out, *last;

    size = nxt_length(NXT_H1P_IDLE_TIMEOUT)
           + nxt_http_date_cache.size
           + nxt_length("\r\n\r\n");

    out = nxt_buf_mem_alloc(c->mem_pool, size, 0);
    if (nxt_slow_path(out == NULL)) {
        goto fail;
    }

    p = nxt_cpymem(out->mem.free, NXT_H1P_IDLE_TIMEOUT,
                   nxt_length(NXT_H1P_IDLE_TIMEOUT));

    p = nxt_thread_time_string(task->thread, &nxt_http_date_cache, p);

    out->mem.free = nxt_cpymem(p, "\r\n\r\n", 4);

    last = nxt_mp_zget(c->mem_pool, NXT_BUF_SYNC_SIZE);
    if (nxt_slow_path(last == NULL)) {
        goto fail;
    }

    out->next = last;
    nxt_buf_set_sync(last);
    nxt_buf_set_last(last);

    last->completion_handler = nxt_h1p_idle_response_sent;
    last->parent = c;

    c->write = out;
    c->write_state = &nxt_h1p_timeout_response_state;

    nxt_conn_write(task->thread->engine, c);
    return;

fail:

    nxt_h1p_shutdown(task, c);
}


static const nxt_conn_state_t  nxt_h1p_timeout_response_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_conn_sent,
    .error_handler = nxt_h1p_idle_response_error,

    .timer_handler = nxt_h1p_idle_response_timeout,
    .timer_value = nxt_h1p_idle_response_timer_value,
};


static void
nxt_h1p_idle_response_sent(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = data;

    nxt_debug(task, "h1p idle timeout response sent");

    nxt_h1p_shutdown(task, c);
}


static void
nxt_h1p_idle_response_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "h1p response error");

    nxt_h1p_shutdown(task, c);
}


static void
nxt_h1p_idle_response_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t   *c;
    nxt_timer_t  *timer;

    timer = obj;

    nxt_debug(task, "h1p idle timeout response timeout");

    c = nxt_read_timer_conn(timer);
    c->block_write = 1;

    nxt_h1p_shutdown(task, c);
}


static nxt_msec_t
nxt_h1p_idle_response_timer_value(nxt_conn_t *c, uintptr_t data)
{
    return 10 * 1000;
}


static void
nxt_h1p_shutdown(nxt_task_t *task, nxt_conn_t *c)
{
    nxt_timer_t    *timer;
    nxt_h1proto_t  *h1p;

    nxt_debug(task, "h1p shutdown");

    h1p = c->socket.data;

    if (h1p != NULL) {
        nxt_h1p_complete_buffers(task, h1p, 1);

        if (nxt_slow_path(h1p->websocket_timer != NULL)) {
            timer = &h1p->websocket_timer->timer;

            if (timer->handler != nxt_h1p_conn_ws_shutdown) {
                timer->handler = nxt_h1p_conn_ws_shutdown;
                nxt_timer_add(task->thread->engine, timer, 0);

            } else {
                nxt_debug(task, "h1p already scheduled ws shutdown");
            }

            return;
        }
    }

    nxt_h1p_closing(task, c);
}


static void
nxt_h1p_conn_ws_shutdown(nxt_task_t *task, void *obj, void *data)
{
    nxt_timer_t                *timer;
    nxt_h1p_websocket_timer_t  *ws_timer;

    nxt_debug(task, "h1p conn ws shutdown");

    timer = obj;
    ws_timer = nxt_timer_data(timer, nxt_h1p_websocket_timer_t, timer);

    nxt_h1p_closing(task, ws_timer->h1p->conn);
}


static void
nxt_h1p_closing(nxt_task_t *task, nxt_conn_t *c)
{
    nxt_debug(task, "h1p closing");

    c->socket.data = NULL;

#if (NXT_TLS)

    if (c->u.tls != NULL) {
        c->write_state = &nxt_h1p_shutdown_state;

        c->io->shutdown(task, c, NULL);
        return;
    }

#endif

    nxt_h1p_conn_closing(task, c, NULL);
}


#if (NXT_TLS)

static const nxt_conn_state_t  nxt_h1p_shutdown_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_conn_closing,
    .close_handler = nxt_h1p_conn_closing,
    .error_handler = nxt_h1p_conn_closing,
};

#endif


static void
nxt_h1p_conn_closing(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "h1p conn closing");

    c->write_state = &nxt_h1p_close_state;

    nxt_conn_close(task->thread->engine, c);
}


static const nxt_conn_state_t  nxt_h1p_close_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_conn_free,
};


static void
nxt_h1p_conn_free(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_listen_event_t  *lev;
    nxt_event_engine_t  *engine;

    c = obj;

    nxt_debug(task, "h1p conn free");

    engine = task->thread->engine;

    nxt_sockaddr_cache_free(engine, c);

    lev = c->listen;

    nxt_conn_free(task, c);

    nxt_router_listen_event_release(&engine->task, lev, NULL);
}


static void
nxt_h1p_peer_connect(nxt_task_t *task, nxt_http_peer_t *peer)
{
    nxt_mp_t            *mp;
    nxt_int_t           ret;
    nxt_conn_t          *c, *client;
    nxt_h1proto_t       *h1p;
    nxt_fd_event_t      *socket;
    nxt_work_queue_t    *wq;
    nxt_http_request_t  *r;

    nxt_debug(task, "h1p peer connect");

    peer->status = NXT_HTTP_UNSET;
    r = peer->request;

    mp = nxt_mp_create(1024, 128, 256, 32);

    if (nxt_slow_path(mp == NULL)) {
        goto fail;
    }

    h1p = nxt_mp_zalloc(mp, sizeof(nxt_h1proto_t));
    if (nxt_slow_path(h1p == NULL)) {
        goto fail;
    }

    ret = nxt_http_parse_request_init(&h1p->parser, r->mem_pool);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    c = nxt_conn_create(mp, task);
    if (nxt_slow_path(c == NULL)) {
        goto fail;
    }

    c->mem_pool = mp;
    h1p->conn = c;

    peer->proto.h1 = h1p;
    h1p->request = r;

    c->socket.data = peer;
    c->remote = peer->server->sockaddr;

    c->socket.write_ready = 1;
    c->write_state = &nxt_h1p_peer_connect_state;

    /*
     * TODO: queues should be implemented via client proto interface.
     */
    client = r->proto.h1->conn;

    socket = &client->socket;
    wq = socket->read_work_queue;
    c->read_work_queue = wq;
    c->socket.read_work_queue = wq;
    c->read_timer.work_queue = wq;

    wq = socket->write_work_queue;
    c->write_work_queue = wq;
    c->socket.write_work_queue = wq;
    c->write_timer.work_queue = wq;
    /* TODO END */

    nxt_conn_connect(task->thread->engine, c);

    return;

fail:

    peer->status = NXT_HTTP_INTERNAL_SERVER_ERROR;

    r->state->error_handler(task, r, peer);
}


static const nxt_conn_state_t  nxt_h1p_peer_connect_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_peer_connected,
    .close_handler = nxt_h1p_peer_refused,
    .error_handler = nxt_h1p_peer_error,

    .timer_handler = nxt_h1p_peer_send_timeout,
    .timer_value = nxt_h1p_peer_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, proxy_timeout),
};


static void
nxt_h1p_peer_connected(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    peer = data;

    nxt_debug(task, "h1p peer connected");

    r = peer->request;
    r->state->ready_handler(task, r, peer);
}


static void
nxt_h1p_peer_refused(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    peer = data;

    nxt_debug(task, "h1p peer refused");

    //peer->status = NXT_HTTP_SERVICE_UNAVAILABLE;
    peer->status = NXT_HTTP_BAD_GATEWAY;

    r = peer->request;
    r->state->error_handler(task, r, peer);
}


static void
nxt_h1p_peer_header_send(nxt_task_t *task, nxt_http_peer_t *peer)
{
    u_char              *p;
    size_t              size;
    nxt_int_t           ret;
    nxt_str_t           target;
    nxt_buf_t           *header, *body;
    nxt_conn_t          *c;
    nxt_http_field_t    *field;
    nxt_http_request_t  *r;

    nxt_debug(task, "h1p peer header send");

    r = peer->request;

    ret = nxt_h1p_peer_request_target(r, &target);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    size = r->method->length + sizeof(" ") + target.length
           + sizeof(" HTTP/1.1\r\n")
           + sizeof("Connection: close\r\n")
           + sizeof("\r\n");

    nxt_list_each(field, r->fields) {

        if (!field->hopbyhop) {
            size += field->name_length + field->value_length;
            size += nxt_length(": \r\n");
        }

    } nxt_list_loop;

    header = nxt_http_buf_mem(task, r, size);
    if (nxt_slow_path(header == NULL)) {
        goto fail;
    }

    p = header->mem.free;

    p = nxt_cpymem(p, r->method->start, r->method->length);
    *p++ = ' ';
    p = nxt_cpymem(p, target.start, target.length);
    p = nxt_cpymem(p, " HTTP/1.1\r\n", 11);
    p = nxt_cpymem(p, "Connection: close\r\n", 19);

    nxt_list_each(field, r->fields) {

        if (!field->hopbyhop) {
            p = nxt_cpymem(p, field->name, field->name_length);
            *p++ = ':'; *p++ = ' ';
            p = nxt_cpymem(p, field->value, field->value_length);
            *p++ = '\r'; *p++ = '\n';
        }

    } nxt_list_loop;

    *p++ = '\r'; *p++ = '\n';
    header->mem.free = p;
    size = p - header->mem.pos;

    c = peer->proto.h1->conn;
    c->write = header;
    c->write_state = &nxt_h1p_peer_header_send_state;

    if (r->body != NULL) {
        if (nxt_buf_is_file(r->body)) {
            body = nxt_buf_file_alloc(r->mem_pool, 0, 0);

        } else {
            body = nxt_buf_mem_alloc(r->mem_pool, 0, 0);
        }

        if (nxt_slow_path(body == NULL)) {
            goto fail;
        }

        header->next = body;

        if (nxt_buf_is_file(r->body)) {
            body->file = r->body->file;
            body->file_end = r->body->file_end;

        } else {
            body->mem = r->body->mem;
        }

        size += nxt_buf_used_size(body);

//        nxt_mp_retain(r->mem_pool);
    }

    if (size > 16384) {
        /* Use proxy_send_timeout instead of proxy_timeout. */
        c->write_state = &nxt_h1p_peer_header_body_send_state;
    }

    nxt_conn_write(task->thread->engine, c);

    return;

fail:

    r->state->error_handler(task, r, peer);
}


static nxt_int_t
nxt_h1p_peer_request_target(nxt_http_request_t *r, nxt_str_t *target)
{
    u_char  *p;
    size_t  size, encode;

    if (!r->uri_changed) {
        *target = r->target;
        return NXT_OK;
    }

    if (!r->quoted_target && r->args->length == 0) {
        *target = *r->path;
        return NXT_OK;
    }

    if (r->quoted_target) {
        encode = nxt_encode_complex_uri(NULL, r->path->start,
                                        r->path->length);
    } else {
        encode = 0;
    }

    size = r->path->length + encode * 2 + 1 + r->args->length;

    target->start = nxt_mp_nget(r->mem_pool, size);
    if (target->start == NULL) {
        return NXT_ERROR;
    }

    if (r->quoted_target) {
        p = (u_char *) nxt_encode_complex_uri(target->start, r->path->start,
                                              r->path->length);

    } else {
        p = nxt_cpymem(target->start, r->path->start, r->path->length);
    }

    if (r->args->length > 0) {
        *p++ = '?';
        p = nxt_cpymem(p, r->args->start, r->args->length);
    }

    target->length = p - target->start;

    return NXT_OK;
}


static const nxt_conn_state_t  nxt_h1p_peer_header_send_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_peer_header_sent,
    .error_handler = nxt_h1p_peer_error,

    .timer_handler = nxt_h1p_peer_send_timeout,
    .timer_value = nxt_h1p_peer_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, proxy_timeout),
};


static const nxt_conn_state_t  nxt_h1p_peer_header_body_send_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_peer_header_sent,
    .error_handler = nxt_h1p_peer_error,

    .timer_handler = nxt_h1p_peer_send_timeout,
    .timer_value = nxt_h1p_peer_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, proxy_send_timeout),
    .timer_autoreset = 1,
};


static void
nxt_h1p_peer_header_sent(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;
    nxt_event_engine_t  *engine;

    c = obj;
    peer = data;

    nxt_debug(task, "h1p peer header sent");

    engine = task->thread->engine;

    c->write = nxt_sendbuf_completion(task, &engine->fast_work_queue, c->write);

    if (c->write != NULL) {
        nxt_conn_write(engine, c);
        return;
    }

    r = peer->request;
    r->state->ready_handler(task, r, peer);
}


static void
nxt_h1p_peer_header_read(nxt_task_t *task, nxt_http_peer_t *peer)
{
    nxt_conn_t  *c;

    nxt_debug(task, "h1p peer header read");

    c = peer->proto.h1->conn;

    if (c->write_timer.enabled) {
        c->read_state = &nxt_h1p_peer_header_read_state;

    } else {
        c->read_state = &nxt_h1p_peer_header_read_timer_state;
    }

    nxt_conn_read(task->thread->engine, c);
}


static const nxt_conn_state_t  nxt_h1p_peer_header_read_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_peer_header_read_done,
    .close_handler = nxt_h1p_peer_closed,
    .error_handler = nxt_h1p_peer_error,

    .io_read_handler = nxt_h1p_peer_io_read_handler,
};


static const nxt_conn_state_t  nxt_h1p_peer_header_read_timer_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_peer_header_read_done,
    .close_handler = nxt_h1p_peer_closed,
    .error_handler = nxt_h1p_peer_error,

    .io_read_handler = nxt_h1p_peer_io_read_handler,

    .timer_handler = nxt_h1p_peer_read_timeout,
    .timer_value = nxt_h1p_peer_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, proxy_timeout),
};


static ssize_t
nxt_h1p_peer_io_read_handler(nxt_task_t *task, nxt_conn_t *c)
{
    size_t              size;
    ssize_t             n;
    nxt_buf_t           *b;
    nxt_http_peer_t     *peer;
    nxt_socket_conf_t   *skcf;
    nxt_http_request_t  *r;

    peer = c->socket.data;
    r = peer->request;
    b = c->read;

    if (b == NULL) {
        skcf = r->conf->socket_conf;

        size = (peer->header_received) ? skcf->proxy_buffer_size
                                       : skcf->proxy_header_buffer_size;

        nxt_debug(task, "h1p peer io read: %z", size);

        b = nxt_http_proxy_buf_mem_alloc(task, r, size);
        if (nxt_slow_path(b == NULL)) {
            c->socket.error = NXT_ENOMEM;
            return NXT_ERROR;
        }
    }

    n = c->io->recvbuf(c, b);

    if (n > 0) {
        c->read = b;

    } else {
        c->read = NULL;
        nxt_http_proxy_buf_mem_free(task, r, b);
    }

    return n;
}


static void
nxt_h1p_peer_header_read_done(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t           ret;
    nxt_buf_t           *b;
    nxt_conn_t          *c;
    nxt_h1proto_t       *h1p;
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;
    nxt_event_engine_t  *engine;

    c = obj;
    peer = data;

    nxt_debug(task, "h1p peer header read done");

    b = c->read;

    ret = nxt_h1p_peer_header_parse(peer, &b->mem);

    r = peer->request;

    ret = nxt_expect(NXT_DONE, ret);

    if (ret != NXT_AGAIN) {
        engine = task->thread->engine;
        nxt_timer_disable(engine, &c->write_timer);
        nxt_timer_disable(engine, &c->read_timer);
    }

    switch (ret) {

    case NXT_DONE:
        peer->fields = peer->proto.h1->parser.fields;

        ret = nxt_http_fields_process(peer->fields,
                                      &nxt_h1p_peer_fields_hash, r);
        if (nxt_slow_path(ret != NXT_OK)) {
            peer->status = NXT_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        c->read = NULL;

        peer->header_received = 1;

        h1p = peer->proto.h1;

        if (h1p->chunked) {
            if (r->resp.content_length != NULL) {
                peer->status = NXT_HTTP_BAD_GATEWAY;
                break;
            }

            h1p->chunked_parse.mem_pool = c->mem_pool;

        } else if (r->resp.content_length_n > 0) {
            h1p->remainder = r->resp.content_length_n;
        }

        if (nxt_buf_mem_used_size(&b->mem) != 0) {
            nxt_h1p_peer_body_process(task, peer, b);
            return;
        }

        r->state->ready_handler(task, r, peer);
        return;

    case NXT_AGAIN:
        if (nxt_buf_mem_free_size(&b->mem) != 0) {
            nxt_conn_read(task->thread->engine, c);
            return;
        }

        /* Fall through. */

    default:
    case NXT_ERROR:
    case NXT_HTTP_PARSE_INVALID:
    case NXT_HTTP_PARSE_UNSUPPORTED_VERSION:
    case NXT_HTTP_PARSE_TOO_LARGE_FIELD:
        peer->status = NXT_HTTP_BAD_GATEWAY;
        break;
    }

    nxt_http_proxy_buf_mem_free(task, r, b);

    r->state->error_handler(task, r, peer);
}


static nxt_int_t
nxt_h1p_peer_header_parse(nxt_http_peer_t *peer, nxt_buf_mem_t *bm)
{
    u_char     *p;
    size_t     length;
    nxt_int_t  status;

    if (peer->status < 0) {
        length = nxt_buf_mem_used_size(bm);

        if (nxt_slow_path(length < 12)) {
            return NXT_AGAIN;
        }

        p = bm->pos;

        if (nxt_slow_path(memcmp(p, "HTTP/1.", 7) != 0
                          || (p[7] != '0' && p[7] != '1')))
        {
            return NXT_ERROR;
        }

        status = nxt_int_parse(&p[9], 3);

        if (nxt_slow_path(status < 0)) {
            return NXT_ERROR;
        }

        p += 12;
        length -= 12;

        p = memchr(p, '\n', length);

        if (nxt_slow_path(p == NULL)) {
            return NXT_AGAIN;
        }

        bm->pos = p + 1;
        peer->status = status;
    }

    return nxt_http_parse_fields(&peer->proto.h1->parser, bm);
}


static void
nxt_h1p_peer_read(nxt_task_t *task, nxt_http_peer_t *peer)
{
    nxt_conn_t  *c;

    nxt_debug(task, "h1p peer read");

    c = peer->proto.h1->conn;
    c->read_state = &nxt_h1p_peer_read_state;

    nxt_conn_read(task->thread->engine, c);
}


static const nxt_conn_state_t  nxt_h1p_peer_read_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_peer_read_done,
    .close_handler = nxt_h1p_peer_closed,
    .error_handler = nxt_h1p_peer_error,

    .io_read_handler = nxt_h1p_peer_io_read_handler,

    .timer_handler = nxt_h1p_peer_read_timeout,
    .timer_value = nxt_h1p_peer_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, proxy_read_timeout),
    .timer_autoreset = 1,
};


static void
nxt_h1p_peer_read_done(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t        *out;
    nxt_conn_t       *c;
    nxt_http_peer_t  *peer;

    c = obj;
    peer = data;

    nxt_debug(task, "h1p peer read done");

    out = c->read;
    c->read = NULL;

    nxt_h1p_peer_body_process(task, peer, out);
}


static void
nxt_h1p_peer_body_process(nxt_task_t *task, nxt_http_peer_t *peer,
    nxt_buf_t *out)
{
    size_t              length;
    nxt_h1proto_t       *h1p;
    nxt_http_request_t  *r;

    h1p = peer->proto.h1;

    if (h1p->chunked) {
        out = nxt_http_chunk_parse(task, &h1p->chunked_parse, out);

        if (h1p->chunked_parse.chunk_error || h1p->chunked_parse.error) {
            peer->status = NXT_HTTP_BAD_GATEWAY;
            r = peer->request;
            r->state->error_handler(task, r, peer);
            return;
        }

        if (h1p->chunked_parse.last) {
            nxt_buf_chain_add(&out, nxt_http_buf_last(peer->request));
            peer->closed = 1;
        }

    } else if (h1p->remainder > 0) {
        length = nxt_buf_chain_length(out);
        h1p->remainder -= length;

        if (h1p->remainder == 0) {
            nxt_buf_chain_add(&out, nxt_http_buf_last(peer->request));
            peer->closed = 1;
        }
    }

    peer->body = out;

    r = peer->request;
    r->state->ready_handler(task, r, peer);
}


static void
nxt_h1p_peer_closed(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    peer = data;

    nxt_debug(task, "h1p peer closed");

    r = peer->request;

    if (peer->header_received) {
        peer->body = nxt_http_buf_last(r);
        peer->closed = 1;
        r->inconsistent = (peer->proto.h1->remainder != 0);

        r->state->ready_handler(task, r, peer);

    } else {
        peer->status = NXT_HTTP_BAD_GATEWAY;

        r->state->error_handler(task, r, peer);
    }
}


static void
nxt_h1p_peer_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    peer = data;

    nxt_debug(task, "h1p peer error");

    peer->status = NXT_HTTP_BAD_GATEWAY;

    r = peer->request;
    r->state->error_handler(task, r, peer);
}


static void
nxt_h1p_peer_send_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_timer_t         *timer;
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    timer = obj;

    nxt_debug(task, "h1p peer send timeout");

    c = nxt_write_timer_conn(timer);
    c->block_write = 1;
    c->block_read = 1;

    peer = c->socket.data;
    peer->status = NXT_HTTP_GATEWAY_TIMEOUT;

    r = peer->request;
    r->state->error_handler(task, r, peer);
}


static void
nxt_h1p_peer_read_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_timer_t         *timer;
    nxt_http_peer_t     *peer;
    nxt_http_request_t  *r;

    timer = obj;

    nxt_debug(task, "h1p peer read timeout");

    c = nxt_read_timer_conn(timer);
    c->block_write = 1;
    c->block_read = 1;

    peer = c->socket.data;
    peer->status = NXT_HTTP_GATEWAY_TIMEOUT;

    r = peer->request;
    r->state->error_handler(task, r, peer);
}


static nxt_msec_t
nxt_h1p_peer_timer_value(nxt_conn_t *c, uintptr_t data)
{
    nxt_http_peer_t  *peer;

    peer = c->socket.data;

    return nxt_value_at(nxt_msec_t, peer->request->conf->socket_conf, data);
}


static void
nxt_h1p_peer_close(nxt_task_t *task, nxt_http_peer_t *peer)
{
    nxt_conn_t  *c;

    nxt_debug(task, "h1p peer close");

    peer->closed = 1;

    c = peer->proto.h1->conn;
    task = &c->task;
    c->socket.task = task;
    c->read_timer.task = task;
    c->write_timer.task = task;

    if (c->socket.fd != -1) {
        c->write_state = &nxt_h1p_peer_close_state;

        nxt_conn_close(task->thread->engine, c);

    } else {
        nxt_h1p_peer_free(task, c, NULL);
    }
}


static const nxt_conn_state_t  nxt_h1p_peer_close_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_peer_free,
};


static void
nxt_h1p_peer_free(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "h1p peer free");

    nxt_conn_free(task, c);
}


static nxt_int_t
nxt_h1p_peer_transfer_encoding(void *ctx, nxt_http_field_t *field,
    uintptr_t data)
{
    nxt_http_request_t  *r;

    r = ctx;
    field->skip = 1;

    if (field->value_length == 7
        && memcmp(field->value, "chunked", 7) == 0)
    {
        r->peer->proto.h1->chunked = 1;
    }

    return NXT_OK;
}
