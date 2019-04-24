
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_main_process.h>
#include <nxt_conf.h>
#include <nxt_cert.h>


typedef struct {
    nxt_conf_value_t  *root;
    nxt_mp_t          *pool;
} nxt_controller_conf_t;


typedef struct {
    nxt_http_request_parse_t  parser;
    size_t                    length;
    nxt_controller_conf_t     conf;
    nxt_conn_t                *conn;
    nxt_queue_link_t          link;
} nxt_controller_request_t;


typedef struct {
    nxt_uint_t        status;
    nxt_conf_value_t  *conf;

    u_char            *title;
    nxt_str_t         detail;
    ssize_t           offset;
    nxt_uint_t        line;
    nxt_uint_t        column;
} nxt_controller_response_t;


static void nxt_controller_process_new_port_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_controller_send_current_conf(nxt_task_t *task);
static void nxt_controller_router_ready_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static nxt_int_t nxt_controller_conf_default(void);
static void nxt_controller_conf_init_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static nxt_int_t nxt_controller_conf_send(nxt_task_t *task,
    nxt_conf_value_t *conf, nxt_port_rpc_handler_t handler, void *data);

static void nxt_controller_conn_init(nxt_task_t *task, void *obj, void *data);
static void nxt_controller_conn_read(nxt_task_t *task, void *obj, void *data);
static nxt_msec_t nxt_controller_conn_timeout_value(nxt_conn_t *c,
    uintptr_t data);
static void nxt_controller_conn_read_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_read_timeout(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_body_read(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_write(nxt_task_t *task, void *obj, void *data);
static void nxt_controller_conn_write_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_write_timeout(nxt_task_t *task, void *obj,
    void *data);
static void nxt_controller_conn_close(nxt_task_t *task, void *obj, void *data);
static void nxt_controller_conn_free(nxt_task_t *task, void *obj, void *data);

static nxt_int_t nxt_controller_request_content_length(void *ctx,
    nxt_http_field_t *field, uintptr_t data);

static void nxt_controller_process_request(nxt_task_t *task,
    nxt_controller_request_t *req);
static void nxt_controller_process_config(nxt_task_t *task,
    nxt_controller_request_t *req, nxt_str_t *path);
#if (NXT_TLS)
static void nxt_controller_process_cert(nxt_task_t *task,
    nxt_controller_request_t *req, nxt_str_t *path);
static void nxt_controller_process_cert_save(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static nxt_bool_t nxt_controller_cert_in_use(nxt_str_t *name);
#endif
static void nxt_controller_conf_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_controller_conf_store(nxt_task_t *task,
    nxt_conf_value_t *conf);
static void nxt_controller_response(nxt_task_t *task,
    nxt_controller_request_t *req, nxt_controller_response_t *resp);
static u_char *nxt_controller_date(u_char *buf, nxt_realtime_t *now,
    struct tm *tm, size_t size, const char *format);


static nxt_http_field_proc_t  nxt_controller_request_fields[] = {
    { nxt_string("Content-Length"),
      &nxt_controller_request_content_length, 0 },
};

static nxt_lvlhsh_t            nxt_controller_fields_hash;

static nxt_uint_t              nxt_controller_listening;
static nxt_uint_t              nxt_controller_router_ready;
static nxt_controller_conf_t   nxt_controller_conf;
static nxt_queue_t             nxt_controller_waiting_requests;


static const nxt_event_conn_state_t  nxt_controller_conn_read_state;
static const nxt_event_conn_state_t  nxt_controller_conn_body_read_state;
static const nxt_event_conn_state_t  nxt_controller_conn_write_state;
static const nxt_event_conn_state_t  nxt_controller_conn_close_state;


nxt_port_handlers_t  nxt_controller_process_port_handlers = {
    .quit           = nxt_worker_process_quit_handler,
    .new_port       = nxt_controller_process_new_port_handler,
    .change_file    = nxt_port_change_log_file_handler,
    .mmap           = nxt_port_mmap_handler,
    .process_ready  = nxt_controller_router_ready_handler,
    .data           = nxt_port_data_handler,
    .remove_pid     = nxt_port_remove_pid_handler,
    .rpc_ready      = nxt_port_rpc_handler,
    .rpc_error      = nxt_port_rpc_handler,
};


nxt_int_t
nxt_controller_start(nxt_task_t *task, void *data)
{
    nxt_mp_t               *mp;
    nxt_int_t              ret;
    nxt_str_t              *json;
    nxt_runtime_t          *rt;
    nxt_conf_value_t       *conf;
    nxt_conf_validation_t  vldt;
    nxt_controller_init_t  *init;

    rt = task->thread->runtime;

    ret = nxt_http_fields_hash(&nxt_controller_fields_hash, rt->mem_pool,
                               nxt_controller_request_fields,
                               nxt_nitems(nxt_controller_request_fields));

    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    nxt_queue_init(&nxt_controller_waiting_requests);

    init = data;

#if (NXT_TLS)

    if (init->certs != NULL) {
        nxt_cert_info_init(task, init->certs);
        nxt_cert_store_release(init->certs);
    }

#endif

    json = &init->conf;

    if (json->start == NULL) {
        return NXT_OK;
    }

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(mp == NULL)) {
        return NXT_ERROR;
    }

    conf = nxt_conf_json_parse_str(mp, json);
    nxt_free(json->start);

    if (nxt_slow_path(conf == NULL)) {
        nxt_alert(task, "failed to restore previous configuration: "
                  "file is corrupted or not enough memory");

        nxt_mp_destroy(mp);
        return NXT_OK;
    }

    nxt_memzero(&vldt, sizeof(nxt_conf_validation_t));

    vldt.pool = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(vldt.pool == NULL)) {
        nxt_mp_destroy(mp);
        return NXT_ERROR;
    }

    vldt.conf = conf;

    ret = nxt_conf_validate(&vldt);

    if (nxt_slow_path(ret != NXT_OK)) {

        if (ret == NXT_DECLINED) {
            nxt_alert(task, "the previous configuration is invalid: %V",
                      &vldt.error);

            nxt_mp_destroy(vldt.pool);
            nxt_mp_destroy(mp);

            return NXT_OK;
        }

        /* ret == NXT_ERROR */

        return NXT_ERROR;
    }

    nxt_mp_destroy(vldt.pool);

    nxt_controller_conf.root = conf;
    nxt_controller_conf.pool = mp;

    return NXT_OK;
}


static void
nxt_controller_process_new_port_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg)
{
    nxt_port_new_port_handler(task, msg);

    if (msg->u.new_port->type != NXT_PROCESS_ROUTER
        || !nxt_controller_router_ready)
    {
        return;
    }

    nxt_controller_send_current_conf(task);
}


static void
nxt_controller_send_current_conf(nxt_task_t *task)
{
    nxt_int_t         rc;
    nxt_runtime_t     *rt;
    nxt_conf_value_t  *conf;

    conf = nxt_controller_conf.root;

    if (conf != NULL) {
        rc = nxt_controller_conf_send(task, conf,
                                      nxt_controller_conf_init_handler, NULL);

        if (nxt_fast_path(rc == NXT_OK)) {
            return;
        }

        nxt_mp_destroy(nxt_controller_conf.pool);

        if (nxt_slow_path(nxt_controller_conf_default() != NXT_OK)) {
            nxt_abort();
        }
    }

    if (nxt_slow_path(nxt_controller_conf_default() != NXT_OK)) {
        nxt_abort();
    }

    rt = task->thread->runtime;

    if (nxt_slow_path(nxt_listen_event(task, rt->controller_socket) == NULL)) {
        nxt_abort();
    }

    nxt_controller_listening = 1;
}


static void
nxt_controller_router_ready_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg)
{
    nxt_port_t     *router_port;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    nxt_controller_router_ready = 1;

    if (router_port != NULL) {
        nxt_controller_send_current_conf(task);
    }
}


static nxt_int_t
nxt_controller_conf_default(void)
{
    nxt_mp_t          *mp;
    nxt_conf_value_t  *conf;

    static const nxt_str_t json
        = nxt_string("{ \"listeners\": {}, \"applications\": {} }");

    mp = nxt_mp_create(1024, 128, 256, 32);

    if (nxt_slow_path(mp == NULL)) {
        return NXT_ERROR;
    }

    conf = nxt_conf_json_parse_str(mp, &json);

    if (nxt_slow_path(conf == NULL)) {
        return NXT_ERROR;
    }

    nxt_controller_conf.root = conf;
    nxt_controller_conf.pool = mp;

    return NXT_OK;
}


static void
nxt_controller_conf_init_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_runtime_t  *rt;

    if (msg->port_msg.type != NXT_PORT_MSG_RPC_READY) {
        nxt_alert(task, "failed to apply previous configuration");

        nxt_mp_destroy(nxt_controller_conf.pool);

        if (nxt_slow_path(nxt_controller_conf_default() != NXT_OK)) {
            nxt_abort();
        }
    }

    if (nxt_controller_listening == 0) {
        rt = task->thread->runtime;

        if (nxt_slow_path(nxt_listen_event(task, rt->controller_socket)
                          == NULL))
        {
            nxt_abort();
        }

        nxt_controller_listening = 1;
    }
}


static nxt_int_t
nxt_controller_conf_send(nxt_task_t *task, nxt_conf_value_t *conf,
    nxt_port_rpc_handler_t handler, void *data)
{
    size_t         size;
    uint32_t       stream;
    nxt_int_t      rc;
    nxt_buf_t      *b;
    nxt_port_t     *router_port, *controller_port;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    if (nxt_slow_path(router_port == NULL || !nxt_controller_router_ready)) {
        return NXT_DECLINED;
    }

    controller_port = rt->port_by_type[NXT_PROCESS_CONTROLLER];

    size = nxt_conf_json_length(conf, NULL);

    b = nxt_port_mmap_get_buf(task, router_port, size);
    if (nxt_slow_path(b == NULL)) {
        return NXT_ERROR;
    }

    b->mem.free = nxt_conf_json_print(b->mem.free, conf, NULL);

    stream = nxt_port_rpc_register_handler(task, controller_port,
                                           handler, handler,
                                           router_port->pid, data);

    if (nxt_slow_path(stream == 0)) {
        return NXT_ERROR;
    }

    rc = nxt_port_socket_write(task, router_port, NXT_PORT_MSG_DATA_LAST, -1,
                               stream, controller_port->id, b);

    if (nxt_slow_path(rc != NXT_OK)) {
        nxt_port_rpc_cancel(task, controller_port, stream);
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_int_t
nxt_runtime_controller_socket(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_sockaddr_t       *sa;
    nxt_listen_socket_t  *ls;

    sa = rt->controller_listen;

    ls = nxt_mp_alloc(rt->mem_pool, sizeof(nxt_listen_socket_t));
    if (ls == NULL) {
        return NXT_ERROR;
    }

    ls->sockaddr = nxt_sockaddr_create(rt->mem_pool, &sa->u.sockaddr,
                                       sa->socklen, sa->length);
    if (ls->sockaddr == NULL) {
        return NXT_ERROR;
    }

    ls->sockaddr->type = sa->type;
    nxt_sockaddr_text(ls->sockaddr);

    nxt_listen_socket_remote_size(ls);

    ls->socket = -1;
    ls->backlog = NXT_LISTEN_BACKLOG;
    ls->read_after_accept = 1;
    ls->flags = NXT_NONBLOCK;

#if 0
    /* STUB */
    wq = nxt_mp_zget(cf->mem_pool, sizeof(nxt_work_queue_t));
    if (wq == NULL) {
        return NXT_ERROR;
    }
    nxt_work_queue_name(wq, "listen");
    /**/

    ls->work_queue = wq;
#endif
    ls->handler = nxt_controller_conn_init;

    if (nxt_listen_socket_create(task, ls, 0) != NXT_OK) {
        return NXT_ERROR;
    }

    rt->controller_socket = ls;

    return NXT_OK;
}


static void
nxt_controller_conn_init(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t                 *b;
    nxt_conn_t                *c;
    nxt_event_engine_t        *engine;
    nxt_controller_request_t  *r;

    c = obj;

    nxt_debug(task, "controller conn init fd:%d", c->socket.fd);

    r = nxt_mp_zget(c->mem_pool, sizeof(nxt_controller_request_t));
    if (nxt_slow_path(r == NULL)) {
        nxt_controller_conn_free(task, c, NULL);
        return;
    }

    r->conn = c;

    if (nxt_slow_path(nxt_http_parse_request_init(&r->parser, c->mem_pool)
                      != NXT_OK))
    {
        nxt_controller_conn_free(task, c, NULL);
        return;
    }

    b = nxt_buf_mem_alloc(c->mem_pool, 1024, 0);
    if (nxt_slow_path(b == NULL)) {
        nxt_controller_conn_free(task, c, NULL);
        return;
    }

    c->read = b;
    c->socket.data = r;
    c->socket.read_ready = 1;
    c->read_state = &nxt_controller_conn_read_state;

    engine = task->thread->engine;
    c->read_work_queue = &engine->read_work_queue;
    c->write_work_queue = &engine->write_work_queue;

    nxt_conn_read(engine, c);
}


static const nxt_event_conn_state_t  nxt_controller_conn_read_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_controller_conn_read,
    .close_handler = nxt_controller_conn_close,
    .error_handler = nxt_controller_conn_read_error,

    .timer_handler = nxt_controller_conn_read_timeout,
    .timer_value = nxt_controller_conn_timeout_value,
    .timer_data = 60 * 1000,
};


static void
nxt_controller_conn_read(nxt_task_t *task, void *obj, void *data)
{
    size_t                    preread;
    nxt_buf_t                 *b;
    nxt_int_t                 rc;
    nxt_conn_t                *c;
    nxt_controller_request_t  *r;

    c = obj;
    r = data;

    nxt_debug(task, "controller conn read");

    nxt_queue_remove(&c->link);
    nxt_queue_self(&c->link);

    b = c->read;

    rc = nxt_http_parse_request(&r->parser, &b->mem);

    if (nxt_slow_path(rc != NXT_DONE)) {

        if (rc == NXT_AGAIN) {
            if (nxt_buf_mem_free_size(&b->mem) == 0) {
                nxt_log(task, NXT_LOG_ERR, "too long request headers");
                nxt_controller_conn_close(task, c, r);
                return;
            }

            nxt_conn_read(task->thread->engine, c);
            return;
        }

        /* rc == NXT_ERROR */

        nxt_log(task, NXT_LOG_ERR, "parsing error");

        nxt_controller_conn_close(task, c, r);
        return;
    }

    rc = nxt_http_fields_process(r->parser.fields, &nxt_controller_fields_hash,
                                 r);

    if (nxt_slow_path(rc != NXT_OK)) {
        nxt_controller_conn_close(task, c, r);
        return;
    }

    preread = nxt_buf_mem_used_size(&b->mem);

    nxt_debug(task, "controller request header parsing complete, "
                    "body length: %uz, preread: %uz",
                    r->length, preread);

    if (preread >= r->length) {
        nxt_controller_process_request(task, r);
        return;
    }

    if (r->length - preread > (size_t) nxt_buf_mem_free_size(&b->mem)) {
        b = nxt_buf_mem_alloc(c->mem_pool, r->length, 0);
        if (nxt_slow_path(b == NULL)) {
            nxt_controller_conn_free(task, c, NULL);
            return;
        }

        b->mem.free = nxt_cpymem(b->mem.free, c->read->mem.pos, preread);

        c->read = b;
    }

    c->read_state = &nxt_controller_conn_body_read_state;

    nxt_conn_read(task->thread->engine, c);
}


static nxt_msec_t
nxt_controller_conn_timeout_value(nxt_conn_t *c, uintptr_t data)
{
    return (nxt_msec_t) data;
}


static void
nxt_controller_conn_read_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn read error");

    nxt_controller_conn_close(task, c, data);
}


static void
nxt_controller_conn_read_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_timer_t  *timer;
    nxt_conn_t   *c;

    timer = obj;

    c = nxt_read_timer_conn(timer);
    c->socket.timedout = 1;
    c->socket.closed = 1;

    nxt_debug(task, "controller conn read timeout");

    nxt_controller_conn_close(task, c, data);
}


static const nxt_event_conn_state_t  nxt_controller_conn_body_read_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_controller_conn_body_read,
    .close_handler = nxt_controller_conn_close,
    .error_handler = nxt_controller_conn_read_error,

    .timer_handler = nxt_controller_conn_read_timeout,
    .timer_value = nxt_controller_conn_timeout_value,
    .timer_data = 60 * 1000,
    .timer_autoreset = 1,
};


static void
nxt_controller_conn_body_read(nxt_task_t *task, void *obj, void *data)
{
    size_t                    read;
    nxt_buf_t                 *b;
    nxt_conn_t                *c;
    nxt_controller_request_t  *r;

    c = obj;
    r = data;
    b = c->read;

    read = nxt_buf_mem_used_size(&b->mem);

    nxt_debug(task, "controller conn body read: %uz of %uz",
              read, r->length);

    if (read >= r->length) {
        nxt_controller_process_request(task, r);
        return;
    }

    nxt_conn_read(task->thread->engine, c);
}


static const nxt_event_conn_state_t  nxt_controller_conn_write_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_controller_conn_write,
    .error_handler = nxt_controller_conn_write_error,

    .timer_handler = nxt_controller_conn_write_timeout,
    .timer_value = nxt_controller_conn_timeout_value,
    .timer_data = 60 * 1000,
    .timer_autoreset = 1,
};


static void
nxt_controller_conn_write(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t   *b;
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn write");

    b = c->write;

    if (b->mem.pos != b->mem.free) {
        nxt_conn_write(task->thread->engine, c);
        return;
    }

    nxt_debug(task, "controller conn write complete");

    nxt_controller_conn_close(task, c, data);
}


static void
nxt_controller_conn_write_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn write error");

    nxt_controller_conn_close(task, c, data);
}


static void
nxt_controller_conn_write_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t   *c;
    nxt_timer_t  *timer;

    timer = obj;

    c = nxt_write_timer_conn(timer);
    c->socket.timedout = 1;
    c->socket.closed = 1;

    nxt_debug(task, "controller conn write timeout");

    nxt_controller_conn_close(task, c, data);
}


static const nxt_event_conn_state_t  nxt_controller_conn_close_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_controller_conn_free,
};


static void
nxt_controller_conn_close(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn close");

    nxt_queue_remove(&c->link);

    c->write_state = &nxt_controller_conn_close_state;

    nxt_conn_close(task->thread->engine, c);
}


static void
nxt_controller_conn_free(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "controller conn free");

    nxt_sockaddr_cache_free(task->thread->engine, c);

    nxt_conn_free(task, c);
}


static nxt_int_t
nxt_controller_request_content_length(void *ctx, nxt_http_field_t *field,
    uintptr_t data)
{
    off_t                     length;
    nxt_controller_request_t  *r;

    r = ctx;

    length = nxt_off_t_parse(field->value, field->value_length);

    if (nxt_fast_path(length >= 0)) {

        if (nxt_slow_path(length > NXT_SIZE_T_MAX)) {
            nxt_log_error(NXT_LOG_ERR, &r->conn->log,
                          "Content-Length is too big");
            return NXT_ERROR;
        }

        r->length = length;
        return NXT_OK;
    }

    nxt_log_error(NXT_LOG_ERR, &r->conn->log, "Content-Length is invalid");

    return NXT_ERROR;
}


static void
nxt_controller_process_request(nxt_task_t *task, nxt_controller_request_t *req)
{
    uint32_t                   i, count;
    nxt_str_t                  path;
    nxt_conn_t                 *c;
    nxt_conf_value_t           *value;
    nxt_controller_response_t  resp;
#if (NXT_TLS)
    nxt_conf_value_t           *certs;

    static nxt_str_t certificates = nxt_string("certificates");
#endif
    static nxt_str_t config = nxt_string("config");

    c = req->conn;
    path = req->parser.path;

    if (path.length > 1 && path.start[path.length - 1] == '/') {
        path.length--;
    }

    if (nxt_str_start(&path, "/config", 7)
        && (path.length == 7 || path.start[7] == '/'))
    {
        if (path.length == 7) {
            path.length = 1;

        } else {
            path.length -= 7;
            path.start += 7;
        }

        nxt_controller_process_config(task, req, &path);
        return;
    }

#if (NXT_TLS)

    if (nxt_str_start(&path, "/certificates", 13)
        && (path.length == 13 || path.start[13] == '/'))
    {
        if (path.length == 13) {
            path.length = 1;

        } else {
            path.length -= 13;
            path.start += 13;
        }

        nxt_controller_process_cert(task, req, &path);
        return;
    }

#endif

    nxt_memzero(&resp, sizeof(nxt_controller_response_t));

    if (path.length == 1 && path.start[0] == '/') {

        if (!nxt_str_eq(&req->parser.method, "GET", 3)) {
            goto invalid_method;
        }

        count = 1;
#if (NXT_TLS)
        count++;
#endif

        value = nxt_conf_create_object(c->mem_pool, count);
        if (nxt_slow_path(value == NULL)) {
            goto alloc_fail;
        }

        i = 0;

#if (NXT_TLS)
        certs = nxt_cert_info_get_all(c->mem_pool);
        if (nxt_slow_path(certs == NULL)) {
            goto alloc_fail;
        }

        nxt_conf_set_member(value, &certificates, certs, i++);
#endif

        nxt_conf_set_member(value, &config, nxt_controller_conf.root, i);

        resp.status = 200;
        resp.conf = value;

        nxt_controller_response(task, req, &resp);
        return;
    }

    resp.status = 404;
    resp.title = (u_char *) "Value doesn't exist.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

invalid_method:

    resp.status = 405;
    resp.title = (u_char *) "Invalid method.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

alloc_fail:

    resp.status = 500;
    resp.title = (u_char *) "Memory allocation failed.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;
}


static void
nxt_controller_process_config(nxt_task_t *task, nxt_controller_request_t *req,
    nxt_str_t *path)
{
    nxt_mp_t                   *mp;
    nxt_int_t                  rc;
    nxt_conn_t                 *c;
    nxt_bool_t                 post;
    nxt_buf_mem_t              *mbuf;
    nxt_conf_op_t              *ops;
    nxt_conf_value_t           *value;
    nxt_conf_validation_t      vldt;
    nxt_conf_json_error_t      error;
    nxt_controller_response_t  resp;

    static const nxt_str_t empty_obj = nxt_string("{}");

    nxt_memzero(&resp, sizeof(nxt_controller_response_t));

    c = req->conn;

    if (nxt_str_eq(&req->parser.method, "GET", 3)) {

        value = nxt_conf_get_path(nxt_controller_conf.root, path);

        if (value == NULL) {
            goto not_found;
        }

        resp.status = 200;
        resp.conf = value;

        nxt_controller_response(task, req, &resp);
        return;
    }

    if (nxt_str_eq(&req->parser.method, "POST", 4)) {
        if (path->length == 1) {
            goto not_allowed;
        }

        post = 1;

    } else {
        post = 0;
    }

    if (post || nxt_str_eq(&req->parser.method, "PUT", 3)) {

        if (!nxt_queue_is_empty(&nxt_controller_waiting_requests)) {
            nxt_queue_insert_tail(&nxt_controller_waiting_requests, &req->link);
            return;
        }

        mp = nxt_mp_create(1024, 128, 256, 32);

        if (nxt_slow_path(mp == NULL)) {
            goto alloc_fail;
        }

        mbuf = &c->read->mem;

        nxt_memzero(&error, sizeof(nxt_conf_json_error_t));

        value = nxt_conf_json_parse(mp, mbuf->pos, mbuf->free, &error);

        if (value == NULL) {
            nxt_mp_destroy(mp);

            if (error.pos == NULL) {
                goto alloc_fail;
            }

            resp.status = 400;
            resp.title = (u_char *) "Invalid JSON.";
            resp.detail.length = nxt_strlen(error.detail);
            resp.detail.start = error.detail;
            resp.offset = error.pos - mbuf->pos;

            nxt_conf_json_position(mbuf->pos, error.pos,
                                   &resp.line, &resp.column);

            nxt_controller_response(task, req, &resp);
            return;
        }

        if (path->length != 1) {
            rc = nxt_conf_op_compile(c->mem_pool, &ops,
                                     nxt_controller_conf.root,
                                     path, value, post);

            if (rc != NXT_CONF_OP_OK) {
                nxt_mp_destroy(mp);

                switch (rc) {
                case NXT_CONF_OP_NOT_FOUND:
                    goto not_found;

                case NXT_CONF_OP_NOT_ALLOWED:
                    goto not_allowed;
                }

                /* rc == NXT_CONF_OP_ERROR */
                goto alloc_fail;
            }

            value = nxt_conf_clone(mp, ops, nxt_controller_conf.root);

            if (nxt_slow_path(value == NULL)) {
                nxt_mp_destroy(mp);
                goto alloc_fail;
            }
        }

        nxt_memzero(&vldt, sizeof(nxt_conf_validation_t));

        vldt.conf = value;
        vldt.pool = c->mem_pool;

        rc = nxt_conf_validate(&vldt);

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_mp_destroy(mp);

            if (rc == NXT_DECLINED) {
                resp.detail = vldt.error;
                goto invalid_conf;
            }

            /* rc == NXT_ERROR */
            goto alloc_fail;
        }

        rc = nxt_controller_conf_send(task, value,
                                      nxt_controller_conf_handler, req);

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_mp_destroy(mp);

            if (rc == NXT_DECLINED) {
                goto no_router;
            }

            /* rc == NXT_ERROR */
            goto alloc_fail;
        }

        req->conf.root = value;
        req->conf.pool = mp;

        nxt_queue_insert_head(&nxt_controller_waiting_requests, &req->link);

        return;
    }

    if (nxt_str_eq(&req->parser.method, "DELETE", 6)) {

        if (!nxt_queue_is_empty(&nxt_controller_waiting_requests)) {
            nxt_queue_insert_tail(&nxt_controller_waiting_requests, &req->link);
            return;
        }

        if (path->length == 1) {
            mp = nxt_mp_create(1024, 128, 256, 32);

            if (nxt_slow_path(mp == NULL)) {
                goto alloc_fail;
            }

            value = nxt_conf_json_parse_str(mp, &empty_obj);

        } else {
            rc = nxt_conf_op_compile(c->mem_pool, &ops,
                                     nxt_controller_conf.root,
                                     path, NULL, 0);

            if (rc != NXT_OK) {
                if (rc == NXT_CONF_OP_NOT_FOUND) {
                    goto not_found;
                }

                /* rc == NXT_CONF_OP_ERROR */
                goto alloc_fail;
            }

            mp = nxt_mp_create(1024, 128, 256, 32);

            if (nxt_slow_path(mp == NULL)) {
                goto alloc_fail;
            }

            value = nxt_conf_clone(mp, ops, nxt_controller_conf.root);
        }

        if (nxt_slow_path(value == NULL)) {
            nxt_mp_destroy(mp);
            goto alloc_fail;
        }

        nxt_memzero(&vldt, sizeof(nxt_conf_validation_t));

        vldt.conf = value;
        vldt.pool = c->mem_pool;

        rc = nxt_conf_validate(&vldt);

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_mp_destroy(mp);

            if (rc == NXT_DECLINED) {
                resp.detail = vldt.error;
                goto invalid_conf;
            }

            /* rc == NXT_ERROR */
            goto alloc_fail;
        }

        rc = nxt_controller_conf_send(task, value,
                                      nxt_controller_conf_handler, req);

        if (nxt_slow_path(rc != NXT_OK)) {
            nxt_mp_destroy(mp);

            if (rc == NXT_DECLINED) {
                goto no_router;
            }

            /* rc == NXT_ERROR */
            goto alloc_fail;
        }

        req->conf.root = value;
        req->conf.pool = mp;

        nxt_queue_insert_head(&nxt_controller_waiting_requests, &req->link);

        return;
    }

not_allowed:

    resp.status = 405;
    resp.title = (u_char *) "Method isn't allowed.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

not_found:

    resp.status = 404;
    resp.title = (u_char *) "Value doesn't exist.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

invalid_conf:

    resp.status = 400;
    resp.title = (u_char *) "Invalid configuration.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

alloc_fail:

    resp.status = 500;
    resp.title = (u_char *) "Memory allocation failed.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

no_router:

    resp.status = 500;
    resp.title = (u_char *) "Router process isn't available.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;
}


#if (NXT_TLS)

static void
nxt_controller_process_cert(nxt_task_t *task,
    nxt_controller_request_t *req, nxt_str_t *path)
{
    u_char                     *p;
    nxt_str_t                  name;
    nxt_int_t                  ret;
    nxt_conn_t                 *c;
    nxt_cert_t                 *cert;
    nxt_conf_value_t           *value;
    nxt_controller_response_t  resp;

    name.length = path->length - 1;
    name.start = path->start + 1;

    p = nxt_memchr(name.start, '/', name.length);

    if (p != NULL) {
        name.length = p - name.start;

        path->length -= p - path->start;
        path->start = p;

    } else {
        path = NULL;
    }

    nxt_memzero(&resp, sizeof(nxt_controller_response_t));

    c = req->conn;

    if (nxt_str_eq(&req->parser.method, "GET", 3)) {

        if (name.length != 0) {
            value = nxt_cert_info_get(&name);
            if (value == NULL) {
                goto cert_not_found;
            }

            if (path != NULL) {
                value = nxt_conf_get_path(value, path);
                if (value == NULL) {
                    goto not_found;
                }
            }

        } else {
            value = nxt_cert_info_get_all(c->mem_pool);
            if (value == NULL) {
                goto alloc_fail;
            }
        }

        resp.status = 200;
        resp.conf = value;

        nxt_controller_response(task, req, &resp);
        return;
    }

    if (name.length == 0 || path != NULL) {
        goto invalid_name;
    }

    if (nxt_str_eq(&req->parser.method, "PUT", 3)) {
        value = nxt_cert_info_get(&name);
        if (value != NULL) {
            goto exists_cert;
        }

        cert = nxt_cert_mem(task, &c->read->mem);
        if (cert == NULL) {
            goto invalid_cert;
        }

        ret = nxt_cert_info_save(&name, cert);

        nxt_cert_destroy(cert);

        if (nxt_slow_path(ret != NXT_OK)) {
            goto alloc_fail;
        }

        nxt_cert_store_get(task, &name, c->mem_pool,
                           nxt_controller_process_cert_save, req);
        return;
    }

    if (nxt_str_eq(&req->parser.method, "DELETE", 6)) {

        if (nxt_controller_cert_in_use(&name)) {
            goto cert_in_use;
        }

        if (nxt_cert_info_delete(&name) != NXT_OK) {
            goto cert_not_found;
        }

        nxt_cert_store_delete(task, &name, c->mem_pool);

        resp.status = 200;
        resp.title = (u_char *) "Certificate deleted.";

        nxt_controller_response(task, req, &resp);
        return;
    }

    resp.status = 405;
    resp.title = (u_char *) "Invalid method.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

invalid_name:

    resp.status = 400;
    resp.title = (u_char *) "Invalid certificate name.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

invalid_cert:

    resp.status = 400;
    resp.title = (u_char *) "Invalid certificate.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

exists_cert:

    resp.status = 400;
    resp.title = (u_char *) "Certificate already exists.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

cert_in_use:

    resp.status = 400;
    resp.title = (u_char *) "Certificate is used in the configuration.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

cert_not_found:

    resp.status = 404;
    resp.title = (u_char *) "Certificate doesn't exist.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

not_found:

    resp.status = 404;
    resp.title = (u_char *) "Invalid path.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;

alloc_fail:

    resp.status = 500;
    resp.title = (u_char *) "Memory allocation failed.";
    resp.offset = -1;

    nxt_controller_response(task, req, &resp);
    return;
}


static void
nxt_controller_process_cert_save(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_conn_t                *c;
    nxt_buf_mem_t             *mbuf;
    nxt_controller_request_t  *req;
    nxt_controller_response_t  resp;

    req = data;

    nxt_memzero(&resp, sizeof(nxt_controller_response_t));

    if (msg == NULL || msg->port_msg.type == _NXT_PORT_MSG_RPC_ERROR) {
        resp.status = 500;
        resp.title = (u_char *) "Failed to store certificate.";

        nxt_controller_response(task, req, &resp);
        return;
    }

    c = req->conn;

    mbuf = &c->read->mem;

    nxt_fd_write(msg->fd, mbuf->pos, nxt_buf_mem_used_size(mbuf));

    nxt_fd_close(msg->fd);

    nxt_memzero(&resp, sizeof(nxt_controller_response_t));

    resp.status = 200;
    resp.title = (u_char *) "Certificate chain uploaded.";

    nxt_controller_response(task, req, &resp);
}


static nxt_bool_t
nxt_controller_cert_in_use(nxt_str_t *name)
{
    uint32_t          next;
    nxt_str_t         str;
    nxt_conf_value_t  *listeners, *listener, *value;

    static nxt_str_t  listeners_path = nxt_string("/listeners");
    static nxt_str_t  certificate_path = nxt_string("/tls/certificate");

    listeners = nxt_conf_get_path(nxt_controller_conf.root, &listeners_path);

    if (listeners != NULL) {
        next = 0;

        for ( ;; ) {
            listener = nxt_conf_next_object_member(listeners, &str, &next);
            if (listener == NULL) {
                break;
            }

            value = nxt_conf_get_path(listener, &certificate_path);
            if (value == NULL) {
                continue;
            }

            nxt_conf_get_string(value, &str);

            if (nxt_strstr_eq(&str, name)) {
                return 1;
            }
        }
    }

    return 0;
}

#endif


static void
nxt_controller_conf_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_queue_t                queue;
    nxt_controller_request_t   *req;
    nxt_controller_response_t  resp;

    req = data;

    nxt_debug(task, "controller conf ready: %*s",
              nxt_buf_mem_used_size(&msg->buf->mem), msg->buf->mem.pos);

    nxt_queue_remove(&req->link);

    nxt_memzero(&resp, sizeof(nxt_controller_response_t));

    if (msg->port_msg.type == NXT_PORT_MSG_RPC_READY) {
        nxt_mp_destroy(nxt_controller_conf.pool);

        nxt_controller_conf = req->conf;

        nxt_controller_conf_store(task, req->conf.root);

        resp.status = 200;
        resp.title = (u_char *) "Reconfiguration done.";

    } else {
        nxt_mp_destroy(req->conf.pool);

        resp.status = 500;
        resp.title = (u_char *) "Failed to apply new configuration.";
        resp.offset = -1;
    }

    nxt_controller_response(task, req, &resp);

    nxt_queue_init(&queue);
    nxt_queue_add(&queue, &nxt_controller_waiting_requests);

    nxt_queue_init(&nxt_controller_waiting_requests);

    nxt_queue_each(req, &queue, nxt_controller_request_t, link) {
        nxt_controller_process_request(task, req);
    } nxt_queue_loop;
}


static void
nxt_controller_conf_store(nxt_task_t *task, nxt_conf_value_t *conf)
{
    size_t         size;
    nxt_buf_t      *b;
    nxt_port_t     *main_port;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    main_port = rt->port_by_type[NXT_PROCESS_MAIN];

    size = nxt_conf_json_length(conf, NULL);

    b = nxt_buf_mem_ts_alloc(task, task->thread->engine->mem_pool, size);

    if (nxt_fast_path(b != NULL)) {
        b->mem.free = nxt_conf_json_print(b->mem.free, conf, NULL);

        (void) nxt_port_socket_write(task, main_port, NXT_PORT_MSG_CONF_STORE,
                                     -1, 0, -1, b);
    }
}


static void
nxt_controller_response(nxt_task_t *task, nxt_controller_request_t *req,
    nxt_controller_response_t *resp)
{
    size_t                  size;
    nxt_str_t               status_line, str;
    nxt_buf_t               *b, *body;
    nxt_conn_t              *c;
    nxt_uint_t              n;
    nxt_conf_value_t        *value, *location;
    nxt_conf_json_pretty_t  pretty;

    static nxt_str_t  success_str = nxt_string("success");
    static nxt_str_t  error_str = nxt_string("error");
    static nxt_str_t  detail_str = nxt_string("detail");
    static nxt_str_t  location_str = nxt_string("location");
    static nxt_str_t  offset_str = nxt_string("offset");
    static nxt_str_t  line_str = nxt_string("line");
    static nxt_str_t  column_str = nxt_string("column");

    static nxt_time_string_t  date_cache = {
        (nxt_atomic_uint_t) -1,
        nxt_controller_date,
        "%s, %02d %s %4d %02d:%02d:%02d GMT",
        nxt_length("Wed, 31 Dec 1986 16:40:00 GMT"),
        NXT_THREAD_TIME_GMT,
        NXT_THREAD_TIME_SEC,
    };

    switch (resp->status) {

    case 200:
        nxt_str_set(&status_line, "200 OK");
        break;

    case 400:
        nxt_str_set(&status_line, "400 Bad Request");
        break;

    case 404:
        nxt_str_set(&status_line, "404 Not Found");
        break;

    case 405:
        nxt_str_set(&status_line, "405 Method Not Allowed");
        break;

    default:
        nxt_str_set(&status_line, "500 Internal Server Error");
        break;
    }

    c = req->conn;
    value = resp->conf;

    if (value == NULL) {
        n = 1
            + (resp->detail.length != 0)
            + (resp->status >= 400 && resp->offset != -1);

        value = nxt_conf_create_object(c->mem_pool, n);

        if (nxt_slow_path(value == NULL)) {
            nxt_controller_conn_close(task, c, req);
            return;
        }

        str.length = nxt_strlen(resp->title);
        str.start = resp->title;

        if (resp->status < 400) {
            nxt_conf_set_member_string(value, &success_str, &str, 0);

        } else {
            nxt_conf_set_member_string(value, &error_str, &str, 0);
        }

        n = 0;

        if (resp->detail.length != 0) {
            n++;

            nxt_conf_set_member_string(value, &detail_str, &resp->detail, n);
        }

        if (resp->status >= 400 && resp->offset != -1) {
            n++;

            location = nxt_conf_create_object(c->mem_pool,
                                              resp->line != 0 ? 3 : 1);

            nxt_conf_set_member(value, &location_str, location, n);

            nxt_conf_set_member_integer(location, &offset_str, resp->offset, 0);

            if (resp->line != 0) {
                nxt_conf_set_member_integer(location, &line_str,
                                            resp->line, 1);

                nxt_conf_set_member_integer(location, &column_str,
                                            resp->column, 2);
            }
        }
    }

    nxt_memzero(&pretty, sizeof(nxt_conf_json_pretty_t));

    size = nxt_conf_json_length(value, &pretty) + 2;

    body = nxt_buf_mem_alloc(c->mem_pool, size, 0);
    if (nxt_slow_path(body == NULL)) {
        nxt_controller_conn_close(task, c, req);
        return;
    }

    nxt_memzero(&pretty, sizeof(nxt_conf_json_pretty_t));

    body->mem.free = nxt_conf_json_print(body->mem.free, value, &pretty);

    body->mem.free = nxt_cpymem(body->mem.free, "\r\n", 2);

    size = nxt_length("HTTP/1.1 " "\r\n") + status_line.length
           + nxt_length("Server: " NXT_SERVER "\r\n")
           + nxt_length("Date: Wed, 31 Dec 1986 16:40:00 GMT\r\n")
           + nxt_length("Content-Type: application/json\r\n")
           + nxt_length("Content-Length: " "\r\n") + NXT_SIZE_T_LEN
           + nxt_length("Connection: close\r\n")
           + nxt_length("\r\n");

    b = nxt_buf_mem_alloc(c->mem_pool, size, 0);
    if (nxt_slow_path(b == NULL)) {
        nxt_controller_conn_close(task, c, req);
        return;
    }

    b->next = body;

    nxt_str_set(&str, "HTTP/1.1 ");

    b->mem.free = nxt_cpymem(b->mem.free, str.start, str.length);
    b->mem.free = nxt_cpymem(b->mem.free, status_line.start,
                             status_line.length);

    nxt_str_set(&str, "\r\n"
                      "Server: " NXT_SERVER "\r\n"
                      "Date: ");

    b->mem.free = nxt_cpymem(b->mem.free, str.start, str.length);

    b->mem.free = nxt_thread_time_string(task->thread, &date_cache,
                                         b->mem.free);

    nxt_str_set(&str, "\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: ");

    b->mem.free = nxt_cpymem(b->mem.free, str.start, str.length);

    b->mem.free = nxt_sprintf(b->mem.free, b->mem.end, "%uz",
                              nxt_buf_mem_used_size(&body->mem));

    nxt_str_set(&str, "\r\n"
                      "Connection: close\r\n"
                      "\r\n");

    b->mem.free = nxt_cpymem(b->mem.free, str.start, str.length);

    c->write = b;
    c->write_state = &nxt_controller_conn_write_state;

    nxt_conn_write(task->thread->engine, c);
}


static u_char *
nxt_controller_date(u_char *buf, nxt_realtime_t *now, struct tm *tm,
    size_t size, const char *format)
{
    static const char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri",
                                   "Sat" };

    static const char  *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    return nxt_sprintf(buf, buf + size, format,
                       week[tm->tm_wday], tm->tm_mday,
                       month[tm->tm_mon], tm->tm_year + 1900,
                       tm->tm_hour, tm->tm_min, tm->tm_sec);
}
