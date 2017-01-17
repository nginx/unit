
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_event_conn_proxy_client_buffer_alloc(nxt_thread_t *thr,
    void *obj, void *data);
static void nxt_event_conn_proxy_peer_connect(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_connected(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_peer_read(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_client_read_ready(nxt_thread_t *thr,
    void *obj, void *data);
static void nxt_event_conn_proxy_peer_read_ready(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_read_process(nxt_thread_t *thr,
    nxt_event_conn_proxy_t *p, nxt_event_conn_t *source,
    nxt_event_conn_t *sink);
static void nxt_event_conn_proxy_write_add(nxt_event_conn_t *c, nxt_buf_t *b);
static void nxt_event_conn_proxy_read(nxt_thread_t *thr, void *obj, void *data);
static void nxt_event_conn_proxy_client_write_ready(nxt_thread_t *thr,
    void *obj, void *data);
static void nxt_event_conn_proxy_peer_write_ready(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_write_process(nxt_thread_t *thr,
    nxt_event_conn_proxy_t *p, nxt_event_conn_t *sink,
    nxt_event_conn_t *source);
static void nxt_event_conn_proxy_read_add(nxt_event_conn_t *c, nxt_buf_t *b);
static void nxt_event_conn_proxy_close(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_error(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_read_timeout(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_write_timeout(nxt_thread_t *thr, void *obj,
    void *data);
static nxt_msec_t nxt_event_conn_proxy_timeout_value(nxt_event_conn_t *c,
    uintptr_t data);
static void nxt_event_conn_proxy_refused(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_reconnect_handler(nxt_thread_t *thr,
    void *obj, void *data);
static void nxt_event_conn_proxy_shutdown(nxt_thread_t *thr,
    nxt_event_conn_proxy_t *p, nxt_event_conn_t *source,
    nxt_event_conn_t *sink);
static void nxt_event_conn_proxy_read_error(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_write_error(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_event_conn_proxy_complete(nxt_thread_t *thr,
    nxt_event_conn_proxy_t *p);


static const nxt_event_conn_state_t  nxt_event_conn_proxy_client_wait_state;
static const nxt_event_conn_state_t
    nxt_event_conn_proxy_client_first_read_state;
static const nxt_event_conn_state_t  nxt_event_conn_proxy_peer_connect_state;
static const nxt_event_conn_state_t  nxt_event_conn_proxy_peer_wait_state;
static const nxt_event_conn_state_t  nxt_event_conn_proxy_client_read_state;
static const nxt_event_conn_state_t  nxt_event_conn_proxy_peer_read_state;
static const nxt_event_conn_state_t  nxt_event_conn_proxy_client_write_state;
static const nxt_event_conn_state_t  nxt_event_conn_proxy_peer_write_state;


nxt_event_conn_proxy_t *
nxt_event_conn_proxy_create(nxt_event_conn_t *client)
{
    nxt_thread_t            *thr;
    nxt_event_conn_t        *peer;
    nxt_event_conn_proxy_t  *p;

    p = nxt_mem_zalloc(client->mem_pool, sizeof(nxt_event_conn_proxy_t));
    if (nxt_slow_path(p == NULL)) {
        return NULL;
    }

    peer = nxt_event_conn_create(client->mem_pool, client->socket.log);
    if (nxt_slow_path(peer == NULL)) {
        return NULL;
    }

    thr = nxt_thread();

    client->socket.read_work_queue = &thr->engine->read_work_queue;
    client->socket.write_work_queue = &thr->engine->write_work_queue;
    peer->socket.read_work_queue = &thr->engine->read_work_queue;
    peer->socket.write_work_queue = &thr->engine->write_work_queue;

    peer->socket.data = client->socket.data;

    peer->read_work_queue = client->read_work_queue;
    peer->write_work_queue = client->write_work_queue;
    peer->read_timer.work_queue = client->read_work_queue;
    peer->write_timer.work_queue = client->write_work_queue;

    p->client = client;
    p->peer = peer;

    return p;
}


void
nxt_event_conn_proxy(nxt_event_conn_proxy_t *p)
{
    nxt_thread_t      *thr;
    nxt_event_conn_t  *peer;

    thr = nxt_thread();

    /*
     * Peer read event: not connected, disabled.
     * Peer write event: not connected, disabled.
     */

    if (p->client_wait_timeout == 0) {
        /*
         * Peer write event: waiting for connection
         * to be established with connect_timeout.
         */
        peer = p->peer;
        peer->write_state = &nxt_event_conn_proxy_peer_connect_state;

        nxt_event_conn_connect_enqueue(thr, peer);
    }

    /*
     * Client read event: waiting for client data with
     * client_wait_timeout before buffer allocation.
     */
    p->client->read_state = &nxt_event_conn_proxy_client_wait_state;

    nxt_event_conn_read(thr, p->client);
}


static const nxt_event_conn_state_t  nxt_event_conn_proxy_client_wait_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_NO_AUTORESET,

    nxt_event_conn_proxy_client_buffer_alloc,
    nxt_event_conn_proxy_close,
    nxt_event_conn_proxy_error,

    nxt_event_conn_proxy_read_timeout,
    nxt_event_conn_proxy_timeout_value,
    offsetof(nxt_event_conn_proxy_t, client_wait_timeout),
};


static void
nxt_event_conn_proxy_client_buffer_alloc(nxt_thread_t *thr, void *obj,
    void *data)
{
    nxt_buf_t               *b;
    nxt_event_conn_t        *client;
    nxt_event_conn_proxy_t  *p;

    client = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy client first read fd:%d",
                  client->socket.fd);

    b = nxt_buf_mem_alloc(client->mem_pool, p->client_buffer_size,
                          NXT_MEM_BUF_CUTBACK | NXT_MEM_BUF_USABLE);

    if (nxt_slow_path(b == NULL)) {
        /* An error completion. */
        nxt_event_conn_proxy_complete(thr, p);
        return;
    }

    p->client_buffer = b;
    client->read = b;

    if (p->peer->socket.fd != -1) {
        /*
         * Client read event: waiting, no timeout.
         * Client write event: blocked.
         * Peer read event: disabled.
         * Peer write event: waiting for connection to be established
         * or blocked after the connection has established.
         */
        client->read_state = &nxt_event_conn_proxy_client_read_state;

    } else {
        /*
         * Client read event: waiting for data with client_wait_timeout
         * before connecting to a peer.
         * Client write event: blocked.
         * Peer read event: not connected, disabled.
         * Peer write event: not connected, disabled.
         */
        client->read_state = &nxt_event_conn_proxy_client_first_read_state;
    }

    nxt_event_conn_read(thr, client);
}


static const nxt_event_conn_state_t
    nxt_event_conn_proxy_client_first_read_state nxt_aligned(64) =
{
    NXT_EVENT_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_event_conn_proxy_peer_connect,
    nxt_event_conn_proxy_close,
    nxt_event_conn_proxy_error,

    nxt_event_conn_proxy_read_timeout,
    nxt_event_conn_proxy_timeout_value,
    offsetof(nxt_event_conn_proxy_t, client_wait_timeout),
};


static void
nxt_event_conn_proxy_peer_connect(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t        *client;
    nxt_event_conn_proxy_t  *p;

    client = obj;
    p = data;

    /*
     * Client read event: waiting, no timeout.
     * Client write event: blocked.
     * Peer read event: disabled.
     * Peer write event: waiting for connection to be established
     * with connect_timeout.
     */
    client->read_state = &nxt_event_conn_proxy_client_read_state;

    p->peer->write_state = &nxt_event_conn_proxy_peer_connect_state;

    nxt_event_conn_connect(thr, p->peer);
}


static const nxt_event_conn_state_t  nxt_event_conn_proxy_peer_connect_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_event_conn_proxy_connected,
    nxt_event_conn_proxy_refused,
    nxt_event_conn_proxy_error,

    nxt_event_conn_proxy_write_timeout,
    nxt_event_conn_proxy_timeout_value,
    offsetof(nxt_event_conn_proxy_t, connect_timeout),
};


static void
nxt_event_conn_proxy_connected(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t        *client, *peer;
    nxt_event_conn_proxy_t  *p;

    peer = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy connected fd:%d",
                  peer->socket.fd);

    p->connected = 1;

    nxt_event_conn_tcp_nodelay_on(peer);
    nxt_event_conn_tcp_nodelay_on(p->client);

    /* Peer read event: waiting with peer_wait_timeout.  */

    peer->read_state = &nxt_event_conn_proxy_peer_wait_state;
    peer->write_state = &nxt_event_conn_proxy_peer_write_state;

    nxt_event_conn_read_enqueue(thr, peer);

    if (p->client_buffer != NULL) {
        client = p->client;

        client->read_state = &nxt_event_conn_proxy_client_read_state;
        client->write_state = &nxt_event_conn_proxy_client_write_state;
        /*
         * Send a client read data to the connected peer.
         * Client write event: blocked.
         */
        nxt_event_conn_proxy_read_process(thr, p, client, peer);
    }
}


static const nxt_event_conn_state_t  nxt_event_conn_proxy_peer_wait_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_NO_AUTORESET,

    nxt_event_conn_proxy_peer_read,
    nxt_event_conn_proxy_close,
    nxt_event_conn_proxy_error,

    nxt_event_conn_proxy_read_timeout,
    nxt_event_conn_proxy_timeout_value,
    offsetof(nxt_event_conn_proxy_t, peer_wait_timeout),
};


static void
nxt_event_conn_proxy_peer_read(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_buf_t               *b;
    nxt_event_conn_t        *peer;
    nxt_event_conn_proxy_t  *p;

    peer = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy peer read fd:%d",
                  peer->socket.fd);

    b = nxt_buf_mem_alloc(peer->mem_pool, p->peer_buffer_size,
                          NXT_MEM_BUF_CUTBACK | NXT_MEM_BUF_USABLE);

    if (nxt_slow_path(b == NULL)) {
        /* An error completion. */
        nxt_event_conn_proxy_complete(thr, p);
        return;
    }

    p->peer_buffer = b;
    peer->read = b;

    p->client->write_state = &nxt_event_conn_proxy_client_write_state;
    peer->read_state = &nxt_event_conn_proxy_peer_read_state;
    peer->write_state = &nxt_event_conn_proxy_peer_write_state;

    /*
     * Client read event: waiting, no timeout.
     * Client write event: blocked.
     * Peer read event: waiting with possible peer_wait_timeout.
     * Peer write event: blocked.
     */
    nxt_event_conn_read(thr, peer);
}


static const nxt_event_conn_state_t  nxt_event_conn_proxy_client_read_state
    nxt_aligned(64) =
{
    NXT_EVENT_BUF_PROCESS,
    NXT_EVENT_TIMER_NO_AUTORESET,

    nxt_event_conn_proxy_client_read_ready,
    nxt_event_conn_proxy_close,
    nxt_event_conn_proxy_read_error,

    NULL,
    NULL,
    0,
};


static void
nxt_event_conn_proxy_client_read_ready(nxt_thread_t *thr, void *obj,
    void *data)
{
    nxt_event_conn_t        *client;
    nxt_event_conn_proxy_t  *p;

    client = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy client read ready fd:%d",
                  client->socket.fd);

    nxt_event_conn_proxy_read_process(thr, p, client, p->peer);
}


static const nxt_event_conn_state_t  nxt_event_conn_proxy_peer_read_state
    nxt_aligned(64) =
{
    NXT_EVENT_BUF_PROCESS,
    NXT_EVENT_TIMER_NO_AUTORESET,

    nxt_event_conn_proxy_peer_read_ready,
    nxt_event_conn_proxy_close,
    nxt_event_conn_proxy_read_error,

    NULL,
    NULL,
    0,
};


static void
nxt_event_conn_proxy_peer_read_ready(nxt_thread_t *thr, void *obj,
    void *data)
{
    nxt_event_conn_t        *peer;
    nxt_event_conn_proxy_t  *p;

    peer = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy peer read ready fd:%d",
                  peer->socket.fd);

    nxt_event_conn_proxy_read_process(thr, p, peer, p->client);
}


static void
nxt_event_conn_proxy_read_process(nxt_thread_t *thr, nxt_event_conn_proxy_t *p,
    nxt_event_conn_t *source, nxt_event_conn_t *sink)
{
    nxt_buf_t  *rb, *wb;

    if (sink->socket.error != 0) {
        nxt_log_debug(thr->log, "event conn proxy sink fd:%d error:%d",
                      sink->socket.fd, sink->socket.error);

        nxt_event_conn_proxy_write_error(thr, sink, sink->socket.data);
        return;
    }

    while (source->read != NULL) {

        rb = source->read;

        if (rb->mem.pos != rb->mem.free) {

            /* Add a read part to a write chain. */

            wb = nxt_buf_mem_alloc(source->mem_pool, 0, 0);
            if (wb == NULL) {
                /* An error completion. */
                nxt_event_conn_proxy_complete(thr, p);
                return;
            }

            wb->mem.pos = rb->mem.pos;
            wb->mem.free = rb->mem.free;
            wb->mem.start = rb->mem.pos;
            wb->mem.end = rb->mem.free;

            rb->mem.pos = rb->mem.free;
            rb->mem.start = rb->mem.free;

            nxt_event_conn_proxy_write_add(sink, wb);
        }

        if (rb->mem.start != rb->mem.end) {
            nxt_thread_work_queue_push(thr, source->read_work_queue,
                                       nxt_event_conn_proxy_read,
                                       source, source->socket.data,
                                       source->socket.log);
            break;
        }

        source->read = rb->next;
        nxt_buf_free(source->mem_pool, rb);
    }

    if (p->connected) {
        nxt_event_conn_write_enqueue(thr, sink);
    }
}


static void
nxt_event_conn_proxy_write_add(nxt_event_conn_t *c, nxt_buf_t *b)
{
    nxt_buf_t  *first, *second, *prev;

    first = c->write;

    if (first == NULL) {
        c->write = b;
        return;
    }

    /*
     * A event conn proxy maintains a buffer per each direction.
     * The buffer is divided by read and write parts.  These parts are
     * linked in buffer chains.  There can be no more than two buffers
     * in write chain at any time, because an added buffer is coalesced
     * with the last buffer if possible.
     */

    second = first->next;

    if (second == NULL) {

        if (first->mem.end != b->mem.start) {
            first->next = b;
            return;
        }

        /*
         * The first buffer is just before the added buffer, so
         * expand the first buffer to the end of the added buffer.
         */
        prev = first;

    } else {
        if (second->mem.end != b->mem.start) {
            nxt_thread_log_alert("event conn proxy write: second buffer end:%p "
                                 "is not equal to added buffer start:%p",
                                 second->mem.end, b->mem.start);
            return;
        }

        /*
         * "second->mem.end == b->mem.start" must be always true here,
         * that is the second buffer is just before the added buffer,
         * so expand the second buffer to the end of added buffer.
         */
        prev = second;
    }

    prev->mem.free = b->mem.end;
    prev->mem.end = b->mem.end;

    nxt_buf_free(c->mem_pool, b);
}


static void
nxt_event_conn_proxy_read(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t        *source, *sink;
    nxt_event_conn_proxy_t  *p;

    source = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy read fd:%d", source->socket.fd);

    if (!source->socket.closed) {
        sink = (source == p->client) ? p->peer : p->client;

        if (sink->socket.error == 0) {
            nxt_event_conn_read(thr, source);
        }
    }
}


static const nxt_event_conn_state_t  nxt_event_conn_proxy_client_write_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_event_conn_proxy_client_write_ready,
    NULL,
    nxt_event_conn_proxy_write_error,

    nxt_event_conn_proxy_write_timeout,
    nxt_event_conn_proxy_timeout_value,
    offsetof(nxt_event_conn_proxy_t, client_write_timeout),
};


static void
nxt_event_conn_proxy_client_write_ready(nxt_thread_t *thr, void *obj,
    void *data)
{
    nxt_event_conn_t        *client;
    nxt_event_conn_proxy_t  *p;

    client = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy client write ready fd:%d",
                  client->socket.fd);

    nxt_event_conn_proxy_write_process(thr, p, client, p->peer);
}


static const nxt_event_conn_state_t  nxt_event_conn_proxy_peer_write_state
    nxt_aligned(64) =
{
    NXT_EVENT_NO_BUF_PROCESS,
    NXT_EVENT_TIMER_AUTORESET,

    nxt_event_conn_proxy_peer_write_ready,
    NULL,
    nxt_event_conn_proxy_write_error,

    nxt_event_conn_proxy_write_timeout,
    nxt_event_conn_proxy_timeout_value,
    offsetof(nxt_event_conn_proxy_t, peer_write_timeout),
};


static void
nxt_event_conn_proxy_peer_write_ready(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t        *peer;
    nxt_event_conn_proxy_t  *p;

    peer = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy peer write ready fd:%d",
                  peer->socket.fd);

    nxt_event_conn_proxy_write_process(thr, p, peer, p->client);
}


static void
nxt_event_conn_proxy_write_process(nxt_thread_t *thr, nxt_event_conn_proxy_t *p,
    nxt_event_conn_t *sink, nxt_event_conn_t *source)
{
    nxt_buf_t  *rb, *wb;

    while (sink->write != NULL) {

        wb = sink->write;

        if (nxt_buf_is_sync(wb)) {

            /* A sync buffer marks the end of stream. */

            sink->write = NULL;
            nxt_buf_free(sink->mem_pool, wb);
            nxt_event_conn_proxy_shutdown(thr, p, source, sink);
            return;
        }

        if (wb->mem.start != wb->mem.pos) {

            /* Add a written part to a read chain. */

            rb = nxt_buf_mem_alloc(sink->mem_pool, 0, 0);
            if (rb == NULL) {
                /* An error completion. */
                nxt_event_conn_proxy_complete(thr, p);
                return;
            }

            rb->mem.pos = wb->mem.start;
            rb->mem.free = wb->mem.start;
            rb->mem.start = wb->mem.start;
            rb->mem.end = wb->mem.pos;

            wb->mem.start = wb->mem.pos;

            nxt_event_conn_proxy_read_add(source, rb);
        }

        if (wb->mem.pos != wb->mem.free) {
            nxt_event_conn_write_enqueue(thr, sink);

            break;
        }

        sink->write = wb->next;
        nxt_buf_free(sink->mem_pool, wb);
    }

    nxt_thread_work_queue_push(thr, source->read_work_queue,
                               nxt_event_conn_proxy_read, source,
                               source->socket.data, source->socket.log);
}


static void
nxt_event_conn_proxy_read_add(nxt_event_conn_t *c, nxt_buf_t *b)
{
    nxt_buf_t  *first, *second;

    first = c->read;

    if (first == NULL) {
        c->read = b;
        return;
    }

    /*
     * A event conn proxy maintains a buffer per each direction.
     * The buffer is divided by read and write parts.  These parts are
     * linked in buffer chains.  There can be no more than two buffers
     * in read chain at any time, because an added buffer is coalesced
     * with the last buffer if possible.  The first and the second
     * buffers are also coalesced if possible.
     */

    second = first->next;

    if (second == NULL) {

        if (first->mem.start == b->mem.end) {
            /*
             * The added buffer is just before the first buffer, so expand
             * the first buffer to the beginning of the added buffer.
             */
            first->mem.pos = b->mem.start;
            first->mem.free = b->mem.start;
            first->mem.start = b->mem.start;

        } else if (first->mem.end == b->mem.start) {
            /*
             * The added buffer is just after the first buffer, so
             * expand the first buffer to the end of the added buffer.
             */
            first->mem.end = b->mem.end;

        } else {
            first->next = b;
            return;
        }

    } else {
        if (second->mem.end != b->mem.start) {
            nxt_thread_log_alert("event conn proxy read: second buffer end:%p "
                                 "is not equal to added buffer start:%p",
                                 second->mem.end, b->mem.start);
            return;
        }

        /*
         * The added buffer is just after the second buffer, so
         * expand the second buffer to the end of the added buffer.
         */
        second->mem.end = b->mem.end;

        if (first->mem.start == second->mem.end) {
            /*
             * The second buffer is just before the first buffer, so expand
             * the first buffer to the beginning of the second buffer.
             */
            first->mem.pos = second->mem.start;
            first->mem.free = second->mem.start;
            first->mem.start = second->mem.start;
            first->next = NULL;

            nxt_buf_free(c->mem_pool, second);
        }
    }

    nxt_buf_free(c->mem_pool, b);
}


static void
nxt_event_conn_proxy_close(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_buf_t               *b;
    nxt_event_conn_t        *source, *sink;
    nxt_event_conn_proxy_t  *p;

    source = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy close fd:%d", source->socket.fd);

    sink = (source == p->client) ? p->peer : p->client;

    if (sink->write == NULL) {
        nxt_event_conn_proxy_shutdown(thr, p, source, sink);
        return;
    }

    b = nxt_buf_sync_alloc(source->mem_pool, 0);
    if (b == NULL) {
        /* An error completion. */
        nxt_event_conn_proxy_complete(thr, p);
        return;
    }

    nxt_buf_chain_add(&sink->write, b);
}


static void
nxt_event_conn_proxy_error(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t        *c;
    nxt_event_conn_proxy_t  *p;

    c = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy error fd:%d", c->socket.fd);

    nxt_event_conn_proxy_close(thr, c, p);
}


static void
nxt_event_conn_proxy_read_timeout(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t   *c;
    nxt_event_timer_t  *ev;

    ev = obj;

    c = nxt_event_read_timer_conn(ev);
    c->socket.timedout = 1;
    c->socket.closed = 1;

    nxt_log_debug(thr->log, "event conn proxy read timeout fd:%d",
                  c->socket.fd);

    nxt_event_conn_proxy_close(thr, c, c->socket.data);
}


static void
nxt_event_conn_proxy_write_timeout(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t   *c;
    nxt_event_timer_t  *ev;

    ev = obj;

    c = nxt_event_write_timer_conn(ev);
    c->socket.timedout = 1;
    c->socket.closed = 1;

    nxt_log_debug(thr->log, "event conn proxy write timeout fd:%d",
                  c->socket.fd);

    nxt_event_conn_proxy_close(thr, c, c->socket.data);
}


static nxt_msec_t
nxt_event_conn_proxy_timeout_value(nxt_event_conn_t *c, uintptr_t data)
{
    nxt_msec_t              *timer;
    nxt_event_conn_proxy_t  *p;

    p = c->socket.data;

    timer = (nxt_msec_t *) ((char *) p + data);

    return *timer;
}


static void
nxt_event_conn_proxy_refused(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t        *peer;
    nxt_event_conn_proxy_t  *p;

    peer = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy refused fd:%d", peer->socket.fd);

    if (p->retries == 0) {
        /* An error completion. */
        nxt_event_conn_proxy_complete(thr, p);
        return;
    }

    p->retries--;

    nxt_socket_close(peer->socket.fd);
    peer->socket.fd = -1;
    peer->socket.error = 0;

    p->delayed = 1;

    peer->write_timer.handler = nxt_event_conn_proxy_reconnect_handler;
    nxt_event_timer_add(thr->engine, &peer->write_timer, p->reconnect_timeout);
}


static void
nxt_event_conn_proxy_reconnect_handler(nxt_thread_t *thr, void *obj,
    void *data)
{
    nxt_event_conn_t        *peer;
    nxt_event_timer_t       *ev;
    nxt_event_conn_proxy_t  *p;

    ev = obj;

    nxt_log_debug(thr->log, "event conn proxy reconnect timer");

    peer = nxt_event_write_timer_conn(ev);
    p = peer->socket.data;

    if (p->client->socket.closed) {
        nxt_event_conn_proxy_complete(thr, p);
        return;
    }

    p->delayed = 0;

    peer->write_state = &nxt_event_conn_proxy_peer_connect_state;
    /*
     * Peer read event: disabled.
     * Peer write event: waiting for connection with connect_timeout.
     */
    nxt_event_conn_connect(thr, peer);
}


static void
nxt_event_conn_proxy_shutdown(nxt_thread_t *thr, nxt_event_conn_proxy_t *p,
    nxt_event_conn_t *source, nxt_event_conn_t *sink)
{
    nxt_buf_t  *b;

    nxt_log_debug(source->socket.log,
                  "event conn proxy shutdown source fd:%d cl:%d err:%d",
                  source->socket.fd, source->socket.closed,
                  source->socket.error);

    nxt_log_debug(sink->socket.log,
                  "event conn proxy shutdown sink fd:%d cl:%d err:%d",
                  sink->socket.fd, sink->socket.closed, sink->socket.error);

    if (!p->connected || p->delayed) {
        nxt_event_conn_proxy_complete(thr, p);
        return;
    }

    if (sink->socket.error != 0 || sink->socket.closed) {
        /*
         * A socket is already closed or half-closed by
         * remote side so the shutdown() syscall is surplus
         * since the close() syscall also sends FIN.
         */
        nxt_event_conn_close(thr, sink);

    } else {
        nxt_socket_shutdown(sink->socket.fd, SHUT_WR);
    }

    if (sink->socket.error != 0
        || (sink->socket.closed && source->write == NULL))
    {
        /* The opposite direction also has been already closed. */
        nxt_event_conn_proxy_complete(thr, p);
        return;
    }

    /* Free the direction's buffer. */
    b = (source == p->client) ? p->client_buffer : p->peer_buffer;
    nxt_mem_free(source->mem_pool, b);
}


static void
nxt_event_conn_proxy_read_error(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t        *c;
    nxt_event_conn_proxy_t  *p;

    c = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy read error fd:%d", c->socket.fd);

    nxt_event_conn_proxy_close(thr, c, p);
}


static void
nxt_event_conn_proxy_write_error(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_event_conn_t        *source, *sink;
    nxt_event_conn_proxy_t  *p;

    sink = obj;
    p = data;

    nxt_log_debug(thr->log, "event conn proxy write error fd:%d",
                  sink->socket.fd);

    /* Clear data for the direction sink. */
    sink->write = NULL;

    /* Block the direction source. */
    source = (sink == p->client) ? p->peer : p->client;
    nxt_event_fd_block_read(thr->engine, &source->socket);

    if (source->write == NULL) {
        /*
         * There is no data for the opposite direction and
         * the next read from the sink will most probably fail.
         */
        nxt_event_conn_proxy_complete(thr, p);
    }
}


static void
nxt_event_conn_proxy_complete(nxt_thread_t *thr, nxt_event_conn_proxy_t *p)
{
    nxt_log_debug(p->client->socket.log, "event conn proxy complete %d:%d",
                  p->client->socket.fd, p->peer->socket.fd);

    if (p->client->socket.fd != -1) {
        nxt_event_conn_close(thr, p->client);
    }

    if (p->peer->socket.fd != -1) {
        nxt_event_conn_close(thr, p->peer);

    } else if (p->delayed) {
        nxt_thread_work_queue_drop(thr, &p->peer->write_timer);

        nxt_queue_remove(&p->peer->link);
        nxt_event_timer_delete(thr->engine, &p->peer->write_timer);
    }

    nxt_mem_free(p->client->mem_pool, p->client_buffer);
    nxt_mem_free(p->client->mem_pool, p->peer_buffer);

    p->completion_handler(thr, p, NULL);
}
