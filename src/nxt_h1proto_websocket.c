
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_h1proto.h>
#include <nxt_websocket.h>
#include <nxt_websocket_header.h>

typedef struct {
    uint16_t   code;
    uint8_t    args;
    nxt_str_t  desc;
} nxt_ws_error_t;

static void nxt_h1p_conn_ws_keepalive(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_conn_ws_frame_header_read(nxt_task_t *task, void *obj,
    void *data);
static void nxt_h1p_conn_ws_keepalive_disable(nxt_task_t *task,
    nxt_h1proto_t *h1p);
static void nxt_h1p_conn_ws_keepalive_enable(nxt_task_t *task,
    nxt_h1proto_t *h1p);
static void nxt_h1p_conn_ws_frame_process(nxt_task_t *task, nxt_conn_t *c,
    nxt_h1proto_t *h1p, nxt_websocket_header_t *wsh);
static void nxt_h1p_conn_ws_error(nxt_task_t *task, void *obj, void *data);
static ssize_t nxt_h1p_ws_io_read_handler(nxt_task_t *task, nxt_conn_t *c);
static void nxt_h1p_conn_ws_timeout(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_conn_ws_frame_payload_read(nxt_task_t *task, void *obj,
    void *data);
static void hxt_h1p_send_ws_error(nxt_task_t *task, nxt_http_request_t *r,
    const nxt_ws_error_t *err, ...);
static void nxt_h1p_conn_ws_error_sent(nxt_task_t *task, void *obj, void *data);
static void nxt_h1p_conn_ws_pong(nxt_task_t *task, void *obj, void *data);

static const nxt_conn_state_t  nxt_h1p_read_ws_frame_header_state;
static const nxt_conn_state_t  nxt_h1p_read_ws_frame_payload_state;

static const nxt_ws_error_t  nxt_ws_err_out_of_memory = {
    NXT_WEBSOCKET_CR_INTERNAL_SERVER_ERROR,
    0, nxt_string("Out of memory") };
static const nxt_ws_error_t  nxt_ws_err_too_big = {
    NXT_WEBSOCKET_CR_MESSAGE_TOO_BIG,
    1, nxt_string("Message too big: %uL bytes") };
static const nxt_ws_error_t  nxt_ws_err_invalid_close_code = {
    NXT_WEBSOCKET_CR_PROTOCOL_ERROR,
    1, nxt_string("Close code %ud is not valid") };
static const nxt_ws_error_t  nxt_ws_err_going_away = {
    NXT_WEBSOCKET_CR_GOING_AWAY,
    0, nxt_string("Remote peer is going away") };
static const nxt_ws_error_t  nxt_ws_err_not_masked = {
    NXT_WEBSOCKET_CR_PROTOCOL_ERROR,
    0, nxt_string("Not masked client frame") };
static const nxt_ws_error_t  nxt_ws_err_ctrl_fragmented = {
    NXT_WEBSOCKET_CR_PROTOCOL_ERROR,
    0, nxt_string("Fragmented control frame") };
static const nxt_ws_error_t  nxt_ws_err_ctrl_too_big = {
    NXT_WEBSOCKET_CR_PROTOCOL_ERROR,
    1, nxt_string("Control frame too big: %uL bytes") };
static const nxt_ws_error_t  nxt_ws_err_invalid_close_len = {
    NXT_WEBSOCKET_CR_PROTOCOL_ERROR,
    0, nxt_string("Close frame payload length cannot be 1") };
static const nxt_ws_error_t  nxt_ws_err_invalid_opcode = {
    NXT_WEBSOCKET_CR_PROTOCOL_ERROR,
    1, nxt_string("Unrecognized opcode %ud") };
static const nxt_ws_error_t  nxt_ws_err_cont_expected = {
    NXT_WEBSOCKET_CR_PROTOCOL_ERROR,
    1, nxt_string("Continuation expected, but %ud opcode received") };

void
nxt_h1p_websocket_first_frame_start(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *ws_frame)
{
    nxt_conn_t            *c;
    nxt_timer_t           *timer;
    nxt_h1proto_t         *h1p;
    nxt_websocket_conf_t  *websocket_conf;

    nxt_debug(task, "h1p ws first frame start");

    h1p = r->proto.h1;
    c = h1p->conn;

    if (!c->tcp_nodelay) {
        nxt_conn_tcp_nodelay_on(task, c);
    }

    websocket_conf = &r->conf->socket_conf->websocket_conf;

    if (nxt_slow_path(websocket_conf->keepalive_interval != 0)) {
        h1p->websocket_timer = nxt_mp_zget(c->mem_pool,
                                           sizeof(nxt_h1p_websocket_timer_t));
        if (nxt_slow_path(h1p->websocket_timer == NULL)) {
            hxt_h1p_send_ws_error(task, r, &nxt_ws_err_out_of_memory);
            return;
        }

        h1p->websocket_timer->keepalive_interval =
            websocket_conf->keepalive_interval;
        h1p->websocket_timer->h1p = h1p;

        timer = &h1p->websocket_timer->timer;
        timer->task = &c->task;
        timer->work_queue = &task->thread->engine->fast_work_queue;
        timer->log = &c->log;
        timer->bias = NXT_TIMER_DEFAULT_BIAS;
        timer->handler = nxt_h1p_conn_ws_keepalive;
    }

    nxt_h1p_websocket_frame_start(task, r, ws_frame);
}


void
nxt_h1p_websocket_frame_start(nxt_task_t *task, nxt_http_request_t *r,
    nxt_buf_t *ws_frame)
{
    size_t         size;
    nxt_buf_t      *in;
    nxt_conn_t     *c;
    nxt_h1proto_t  *h1p;

    nxt_debug(task, "h1p ws frame start");

    h1p = r->proto.h1;

    if (nxt_slow_path(h1p->websocket_closed)) {
        return;
    }

    c = h1p->conn;
    c->read = ws_frame;

    nxt_h1p_complete_buffers(task, h1p, 0);

    in = c->read;
    c->read_state = &nxt_h1p_read_ws_frame_header_state;

    if (in == NULL) {
        nxt_conn_read(task->thread->engine, c);
        nxt_h1p_conn_ws_keepalive_enable(task, h1p);

    } else {
        size = nxt_buf_mem_used_size(&in->mem);

        nxt_debug(task, "h1p read client ws frame");

        nxt_memmove(in->mem.start, in->mem.pos, size);

        in->mem.pos = in->mem.start;
        in->mem.free = in->mem.start + size;

        nxt_h1p_conn_ws_frame_header_read(task, c, h1p);
    }
}


static void
nxt_h1p_conn_ws_keepalive(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t                  *out;
    nxt_timer_t                *timer;
    nxt_h1proto_t              *h1p;
    nxt_http_request_t         *r;
    nxt_websocket_header_t     *wsh;
    nxt_h1p_websocket_timer_t  *ws_timer;

    nxt_debug(task, "h1p conn ws keepalive");

    timer = obj;
    ws_timer = nxt_timer_data(timer, nxt_h1p_websocket_timer_t, timer);
    h1p = ws_timer->h1p;

    r = h1p->request;
    if (nxt_slow_path(r == NULL)) {
        return;
    }

    out = nxt_http_buf_mem(task, r, 2);
    if (nxt_slow_path(out == NULL)) {
        nxt_http_request_error_handler(task, r, r->proto.any);
        return;
    }

    out->mem.start[0] = 0;
    out->mem.start[1] = 0;

    wsh = (nxt_websocket_header_t *) out->mem.start;
    out->mem.free = nxt_websocket_frame_init(wsh, 0);

    wsh->fin = 1;
    wsh->opcode = NXT_WEBSOCKET_OP_PING;

    nxt_http_request_send(task, r, out);
}


static const nxt_conn_state_t  nxt_h1p_read_ws_frame_header_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_conn_ws_frame_header_read,
    .close_handler = nxt_h1p_conn_ws_error,
    .error_handler = nxt_h1p_conn_ws_error,

    .io_read_handler = nxt_h1p_ws_io_read_handler,

    .timer_handler = nxt_h1p_conn_ws_timeout,
    .timer_value = nxt_h1p_conn_request_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, websocket_conf.read_timeout),
    .timer_autoreset = 1,
};


static void
nxt_h1p_conn_ws_frame_header_read(nxt_task_t *task, void *obj, void *data)
{
    size_t                  size, hsize, frame_size, max_frame_size;
    uint64_t                payload_len;
    nxt_conn_t              *c;
    nxt_h1proto_t           *h1p;
    nxt_http_request_t      *r;
    nxt_event_engine_t      *engine;
    nxt_websocket_header_t  *wsh;

    c = obj;
    h1p = data;

    nxt_h1p_conn_ws_keepalive_disable(task, h1p);

    size = nxt_buf_mem_used_size(&c->read->mem);

    engine = task->thread->engine;

    if (size < 2) {
        nxt_debug(task, "h1p conn ws frame header read %z", size);

        nxt_conn_read(engine, c);
        nxt_h1p_conn_ws_keepalive_enable(task, h1p);

        return;
    }

    wsh = (nxt_websocket_header_t *) c->read->mem.pos;

    hsize = nxt_websocket_frame_header_size(wsh);

    if (size < hsize) {
        nxt_debug(task, "h1p conn ws frame header read %z < %z", size, hsize);

        nxt_conn_read(engine, c);
        nxt_h1p_conn_ws_keepalive_enable(task, h1p);

        return;
    }

    r = h1p->request;
    if (nxt_slow_path(r == NULL)) {
        return;
    }

    r->ws_frame = c->read;

    if (nxt_slow_path(wsh->mask == 0)) {
        hxt_h1p_send_ws_error(task, r, &nxt_ws_err_not_masked);
        return;
    }

    if ((wsh->opcode & NXT_WEBSOCKET_OP_CTRL) != 0) {
        if (nxt_slow_path(wsh->fin == 0)) {
            hxt_h1p_send_ws_error(task, r, &nxt_ws_err_ctrl_fragmented);
            return;
        }

        if (nxt_slow_path(wsh->opcode != NXT_WEBSOCKET_OP_PING
                          && wsh->opcode != NXT_WEBSOCKET_OP_PONG
                          && wsh->opcode != NXT_WEBSOCKET_OP_CLOSE))
        {
            hxt_h1p_send_ws_error(task, r, &nxt_ws_err_invalid_opcode,
                                  wsh->opcode);
            return;
        }

        if (nxt_slow_path(wsh->payload_len > 125)) {
            hxt_h1p_send_ws_error(task, r, &nxt_ws_err_ctrl_too_big,
                                  nxt_websocket_frame_payload_len(wsh));
            return;
        }

        if (nxt_slow_path(wsh->opcode == NXT_WEBSOCKET_OP_CLOSE
                          && wsh->payload_len == 1))
        {
            hxt_h1p_send_ws_error(task, r, &nxt_ws_err_invalid_close_len);
            return;
        }

    } else {
        if (h1p->websocket_cont_expected) {
            if (nxt_slow_path(wsh->opcode != NXT_WEBSOCKET_OP_CONT)) {
                hxt_h1p_send_ws_error(task, r, &nxt_ws_err_cont_expected,
                                      wsh->opcode);
                return;
            }

        } else {
            if (nxt_slow_path(wsh->opcode != NXT_WEBSOCKET_OP_BINARY
                              && wsh->opcode != NXT_WEBSOCKET_OP_TEXT))
            {
                hxt_h1p_send_ws_error(task, r, &nxt_ws_err_invalid_opcode,
                                      wsh->opcode);
                return;
            }
        }

        h1p->websocket_cont_expected = !wsh->fin;
    }

    max_frame_size = r->conf->socket_conf->websocket_conf.max_frame_size;

    payload_len = nxt_websocket_frame_payload_len(wsh);

    if (nxt_slow_path(hsize > max_frame_size
                      || payload_len > (max_frame_size - hsize)))
    {
        hxt_h1p_send_ws_error(task, r, &nxt_ws_err_too_big, payload_len);
        return;
    }

    c->read_state = &nxt_h1p_read_ws_frame_payload_state;

    frame_size = payload_len + hsize;

    nxt_debug(task, "h1p conn ws frame header read: %z, %z", size, frame_size);

    if (frame_size <= size) {
        nxt_h1p_conn_ws_frame_process(task, c, h1p, wsh);

        return;
    }

    if (frame_size < (size_t) nxt_buf_mem_size(&c->read->mem)) {
        c->read->mem.end = c->read->mem.start + frame_size;

    } else {
        nxt_buf_t *b = nxt_buf_mem_alloc(c->mem_pool, frame_size - size, 0);

        c->read->next = b;
        c->read = b;
    }

    nxt_conn_read(engine, c);
    nxt_h1p_conn_ws_keepalive_enable(task, h1p);
}


static void
nxt_h1p_conn_ws_keepalive_disable(nxt_task_t *task, nxt_h1proto_t *h1p)
{
    nxt_timer_t  *timer;

    if (h1p->websocket_timer == NULL) {
        return;
    }

    timer = &h1p->websocket_timer->timer;

    if (nxt_slow_path(timer->handler != nxt_h1p_conn_ws_keepalive)) {
        nxt_debug(task, "h1p ws keepalive disable: scheduled ws shutdown");
        return;
    }

    nxt_timer_disable(task->thread->engine, timer);
}


static void
nxt_h1p_conn_ws_keepalive_enable(nxt_task_t *task, nxt_h1proto_t *h1p)
{
    nxt_timer_t  *timer;

    if (h1p->websocket_timer == NULL) {
        return;
    }

    timer = &h1p->websocket_timer->timer;

    if (nxt_slow_path(timer->handler != nxt_h1p_conn_ws_keepalive)) {
        nxt_debug(task, "h1p ws keepalive enable: scheduled ws shutdown");
        return;
    }

    nxt_timer_add(task->thread->engine, timer,
                  h1p->websocket_timer->keepalive_interval);
}


static void
nxt_h1p_conn_ws_frame_process(nxt_task_t *task, nxt_conn_t *c,
    nxt_h1proto_t *h1p, nxt_websocket_header_t *wsh)
{
    size_t              hsize;
    uint8_t             *p, *mask;
    uint16_t            code;
    nxt_http_request_t  *r;

    r = h1p->request;

    c->read = NULL;

    if (nxt_slow_path(wsh->opcode == NXT_WEBSOCKET_OP_PING)) {
        nxt_h1p_conn_ws_pong(task, r, NULL);
        return;
    }

    if (nxt_slow_path(wsh->opcode == NXT_WEBSOCKET_OP_CLOSE)) {
        if (wsh->payload_len >= 2) {
            hsize = nxt_websocket_frame_header_size(wsh);
            mask = nxt_pointer_to(wsh, hsize - 4);
            p = nxt_pointer_to(wsh, hsize);

            code = ((p[0] ^ mask[0]) << 8) + (p[1] ^ mask[1]);

            if (nxt_slow_path(code < 1000 || code >= 5000
                              || (code > 1003 && code < 1007)
                              || (code > 1014 && code < 3000)))
            {
                hxt_h1p_send_ws_error(task, r, &nxt_ws_err_invalid_close_code,
                                      code);
                return;
            }
        }

        h1p->websocket_closed = 1;
    }

    r->state->ready_handler(task, r, NULL);
}


static void
nxt_h1p_conn_ws_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_h1proto_t       *h1p;
    nxt_http_request_t  *r;

    h1p = data;

    nxt_debug(task, "h1p conn ws error");

    r = h1p->request;

    h1p->keepalive = 0;

    if (nxt_fast_path(r != NULL)) {
        r->state->error_handler(task, r, h1p);
    }
}


static ssize_t
nxt_h1p_ws_io_read_handler(nxt_task_t *task, nxt_conn_t *c)
{
    size_t     size;
    ssize_t    n;
    nxt_buf_t  *b;

    b = c->read;

    if (b == NULL) {
        /* Enough for control frame. */
        size = 10 + 125;

        b = nxt_buf_mem_alloc(c->mem_pool, size, 0);
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
        nxt_mp_free(c->mem_pool, b);
    }

    return n;
}


static void
nxt_h1p_conn_ws_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t          *c;
    nxt_timer_t         *timer;
    nxt_h1proto_t       *h1p;
    nxt_http_request_t  *r;

    timer = obj;

    nxt_debug(task, "h1p conn ws timeout");

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
    if (nxt_slow_path(r == NULL)) {
        return;
    }

    hxt_h1p_send_ws_error(task, r, &nxt_ws_err_going_away);
}


static const nxt_conn_state_t  nxt_h1p_read_ws_frame_payload_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_h1p_conn_ws_frame_payload_read,
    .close_handler = nxt_h1p_conn_ws_error,
    .error_handler = nxt_h1p_conn_ws_error,

    .timer_handler = nxt_h1p_conn_ws_timeout,
    .timer_value = nxt_h1p_conn_request_timer_value,
    .timer_data = offsetof(nxt_socket_conf_t, websocket_conf.read_timeout),
    .timer_autoreset = 1,
};


static void
nxt_h1p_conn_ws_frame_payload_read(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t              *c;
    nxt_h1proto_t           *h1p;
    nxt_http_request_t      *r;
    nxt_event_engine_t      *engine;
    nxt_websocket_header_t  *wsh;

    c = obj;
    h1p = data;

    nxt_h1p_conn_ws_keepalive_disable(task, h1p);

    nxt_debug(task, "h1p conn ws frame read");

    if (nxt_buf_mem_free_size(&c->read->mem) == 0) {
        r = h1p->request;
        if (nxt_slow_path(r == NULL)) {
            return;
        }

        wsh = (nxt_websocket_header_t *) r->ws_frame->mem.pos;

        nxt_h1p_conn_ws_frame_process(task, c, h1p, wsh);

        return;
    }

    engine = task->thread->engine;

    nxt_conn_read(engine, c);
    nxt_h1p_conn_ws_keepalive_enable(task, h1p);
}


static void
hxt_h1p_send_ws_error(nxt_task_t *task, nxt_http_request_t *r,
    const nxt_ws_error_t *err, ...)
{
    u_char                  *p;
    va_list                 args;
    nxt_buf_t               *out;
    nxt_str_t               desc;
    nxt_websocket_header_t  *wsh;
    u_char                  buf[125];

    if (nxt_slow_path(err->args)) {
        va_start(args, err);
        p = nxt_vsprintf(buf, buf + sizeof(buf), (char *) err->desc.start,
                         args);
        va_end(args);

        desc.start = buf;
        desc.length = p - buf;

    } else {
        desc = err->desc;
    }

    nxt_log(task, NXT_LOG_INFO, "websocket error %d: %V", err->code, &desc);

    out = nxt_http_buf_mem(task, r, 2 + sizeof(err->code) + desc.length);
    if (nxt_slow_path(out == NULL)) {
        nxt_http_request_error_handler(task, r, r->proto.any);
        return;
    }

    out->mem.start[0] = 0;
    out->mem.start[1] = 0;

    wsh = (nxt_websocket_header_t *) out->mem.start;
    p = nxt_websocket_frame_init(wsh, sizeof(err->code) + desc.length);

    wsh->fin = 1;
    wsh->opcode = NXT_WEBSOCKET_OP_CLOSE;

    *p++ = (err->code >> 8) & 0xFF;
    *p++ = err->code & 0xFF;

    out->mem.free = nxt_cpymem(p, desc.start, desc.length);
    out->next = nxt_http_buf_last(r);

    if (out->next != NULL) {
        out->next->completion_handler = nxt_h1p_conn_ws_error_sent;
    }

    nxt_http_request_send(task, r, out);
}


static void
nxt_h1p_conn_ws_error_sent(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t  *r;

    r = data;

    nxt_debug(task, "h1p conn ws error sent");

    r->state->error_handler(task, r, r->proto.any);
}


static void
nxt_h1p_conn_ws_pong(nxt_task_t *task, void *obj, void *data)
{
    uint8_t                 payload_len, i;
    nxt_buf_t               *b, *out, *next;
    nxt_http_request_t      *r;
    nxt_websocket_header_t  *wsh;
    uint8_t                 mask[4];

    nxt_debug(task, "h1p conn ws pong");

    r = obj;
    b = r->ws_frame;

    wsh = (nxt_websocket_header_t *) b->mem.pos;
    payload_len = wsh->payload_len;

    b->mem.pos += 2;

    nxt_memcpy(mask, b->mem.pos, 4);

    b->mem.pos += 4;

    out = nxt_http_buf_mem(task, r, 2 + payload_len);
    if (nxt_slow_path(out == NULL)) {
        nxt_http_request_error_handler(task, r, r->proto.any);
        return;
    }

    out->mem.start[0] = 0;
    out->mem.start[1] = 0;

    wsh = (nxt_websocket_header_t *) out->mem.start;
    out->mem.free = nxt_websocket_frame_init(wsh, payload_len);

    wsh->fin = 1;
    wsh->opcode = NXT_WEBSOCKET_OP_PONG;

    for (i = 0; i < payload_len; i++) {
        while (nxt_buf_mem_used_size(&b->mem) == 0) {
            next = b->next;
            b->next = NULL;

            nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                               b->completion_handler, task, b, b->parent);

            b = next;
        }

        *out->mem.free++ = *b->mem.pos++ ^ mask[i % 4];
    }

    r->ws_frame = b;

    nxt_http_request_send(task, r, out);

    nxt_http_request_ws_frame_start(task, r, r->ws_frame);
}
