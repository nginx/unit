
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_conf.h>


typedef struct {
    nxt_str_t         type;
    uint32_t          workers;
    nxt_msec_t        timeout;
    uint32_t          requests;
    nxt_conf_value_t  *limits_value;
} nxt_router_app_conf_t;


typedef struct {
    nxt_str_t  application;
} nxt_router_listener_conf_t;


typedef struct nxt_req_app_link_s nxt_req_app_link_t;


typedef struct {
    uint32_t             stream;
    nxt_conn_t           *conn;
    nxt_app_t            *app;
    nxt_port_t           *app_port;
    nxt_app_parse_ctx_t  *ap;
    nxt_req_app_link_t   *ra;

    nxt_queue_link_t     link;     /* for nxt_conn_t.requests */
} nxt_req_conn_link_t;


struct nxt_req_app_link_s {
    uint32_t             stream;
    nxt_port_t           *app_port;
    nxt_pid_t            app_pid;
    nxt_port_t           *reply_port;
    nxt_app_parse_ctx_t  *ap;
    nxt_req_conn_link_t  *rc;

    nxt_queue_link_t     link; /* for nxt_app_t.requests */

    nxt_mp_t             *mem_pool;
    nxt_work_t           work;

    int                  err_code;
    const char           *err_str;
};


typedef struct {
    nxt_socket_conf_t       *socket_conf;
    nxt_router_temp_conf_t  *temp_conf;
} nxt_socket_rpc_t;


static nxt_int_t nxt_router_start_worker(nxt_task_t *task, nxt_app_t *app);

static void nxt_router_ra_error(nxt_task_t *task, nxt_req_app_link_t *ra,
    int code, const char* str);

static nxt_router_temp_conf_t *nxt_router_temp_conf(nxt_task_t *task);
static void nxt_router_conf_apply(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conf_ready(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
static void nxt_router_conf_error(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
static void nxt_router_conf_send(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_port_msg_type_t type);
static void nxt_router_listen_sockets_sort(nxt_router_t *router,
    nxt_router_temp_conf_t *tmcf);

static nxt_int_t nxt_router_conf_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, u_char *start, u_char *end);
static nxt_app_t *nxt_router_app_find(nxt_queue_t *queue, nxt_str_t *name);
static nxt_app_t *nxt_router_listener_application(nxt_router_temp_conf_t *tmcf,
    nxt_str_t *name);
static void nxt_router_listen_socket_rpc_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_socket_conf_t *skcf);
static void nxt_router_listen_socket_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_listen_socket_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static nxt_socket_conf_t *nxt_router_socket_conf(nxt_task_t *task, nxt_mp_t *mp,
    nxt_sockaddr_t *sa);

static nxt_int_t nxt_router_engines_create(nxt_task_t *task,
    nxt_router_t *router, nxt_router_temp_conf_t *tmcf,
    const nxt_event_interface_t *interface);
static nxt_int_t nxt_router_engine_conf_create(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf);
static nxt_int_t nxt_router_engine_conf_update(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf);
static nxt_int_t nxt_router_engine_conf_delete(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf);
static void nxt_router_engine_socket_count(nxt_queue_t *sockets);
static nxt_int_t nxt_router_engine_joints_create(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf, nxt_queue_t *sockets,
    nxt_work_handler_t handler);
static nxt_int_t nxt_router_engine_quit(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf);
static nxt_int_t nxt_router_engine_joints_delete(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf, nxt_queue_t *sockets);

static nxt_int_t nxt_router_threads_create(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_router_temp_conf_t *tmcf);
static nxt_int_t nxt_router_thread_create(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_event_engine_t *engine);
static void nxt_router_apps_sort(nxt_task_t *task, nxt_router_t *router,
    nxt_router_temp_conf_t *tmcf);

static void nxt_router_engines_post(nxt_router_t *router,
    nxt_router_temp_conf_t *tmcf);
static void nxt_router_engine_post(nxt_event_engine_t *engine,
    nxt_work_t *jobs);

static void nxt_router_thread_start(void *data);
static void nxt_router_listen_socket_create(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_listen_socket_update(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_listen_socket_delete(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_worker_thread_quit(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_listen_socket_close(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_listen_socket_release(nxt_task_t *task,
    nxt_socket_conf_joint_t *joint);
static void nxt_router_thread_exit_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_conf_release(nxt_task_t *task,
    nxt_socket_conf_joint_t *joint);

static void nxt_router_app_port_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_app_port_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);

static nxt_port_t * nxt_router_app_get_idle_port(nxt_app_t *app);
static void nxt_router_app_port_release(nxt_task_t *task, nxt_port_t *port,
    uint32_t request_failed, uint32_t got_response);

static void nxt_router_conn_init(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_http_header_parse(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_conn_http_body_read(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_process_http_request(nxt_task_t *task,
    nxt_conn_t *c, nxt_app_parse_ctx_t *ap);
static void nxt_router_process_http_request_mp(nxt_task_t *task,
    nxt_req_app_link_t *ra);
static nxt_int_t nxt_python_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg);
static nxt_int_t nxt_php_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg);
static nxt_int_t nxt_go_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg);
static void nxt_router_conn_ready(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_close(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_free(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_error(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_timeout(nxt_task_t *task, void *obj, void *data);
static void nxt_router_app_timeout(nxt_task_t *task, void *obj, void *data);
static nxt_msec_t nxt_router_conn_timeout_value(nxt_conn_t *c, uintptr_t data);

static void nxt_router_gen_error(nxt_task_t *task, nxt_conn_t *c, int code,
    const char* str);

static nxt_router_t  *nxt_router;


static nxt_app_prepare_msg_t  nxt_app_prepare_msg[] = {
    nxt_python_prepare_msg,
    nxt_php_prepare_msg,
    nxt_go_prepare_msg,
};


nxt_int_t
nxt_router_start(nxt_task_t *task, void *data)
{
    nxt_int_t      ret;
    nxt_router_t   *router;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    ret = nxt_app_http_init(task, rt);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    router = nxt_zalloc(sizeof(nxt_router_t));
    if (nxt_slow_path(router == NULL)) {
        return NXT_ERROR;
    }

    nxt_queue_init(&router->engines);
    nxt_queue_init(&router->sockets);
    nxt_queue_init(&router->apps);

    nxt_router = router;

    return NXT_OK;
}


static void
nxt_router_start_worker_handler(nxt_task_t *task, nxt_port_t *port, void *data)
{
    size_t         size;
    uint32_t       stream;
    nxt_app_t      *app;
    nxt_buf_t      *b;
    nxt_port_t     *main_port;
    nxt_runtime_t  *rt;

    app = data;

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];

    nxt_debug(task, "app '%V' %p start worker", &app->name, app);

    size = app->name.length + 1 + app->conf.length;

    b = nxt_buf_mem_ts_alloc(task, task->thread->engine->mem_pool, size);

    if (nxt_slow_path(b == NULL)) {
        goto failed;
    }

    nxt_buf_cpystr(b, &app->name);
    *b->mem.free++ = '\0';
    nxt_buf_cpystr(b, &app->conf);

    stream = nxt_port_rpc_register_handler(task, port,
                                           nxt_router_app_port_ready,
                                           nxt_router_app_port_error,
                                           -1, app);

    if (nxt_slow_path(stream == 0)) {
        nxt_mp_release(b->data, b);

        goto failed;
    }

    nxt_port_socket_write(task, main_port, NXT_PORT_MSG_START_WORKER, -1,
                          stream, port->id, b);

    return;

failed:

    nxt_thread_mutex_lock(&app->mutex);

    app->pending_workers--;

    nxt_thread_mutex_unlock(&app->mutex);

    nxt_router_app_use(task, app, -1);
}


static nxt_int_t
nxt_router_start_worker(nxt_task_t *task, nxt_app_t *app)
{
    nxt_int_t      res;
    nxt_port_t     *router_port;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    nxt_router_app_use(task, app, 1);

    res = nxt_port_post(task, router_port, nxt_router_start_worker_handler,
                        app);

    if (res == NXT_OK) {
        return res;
    }

    nxt_thread_mutex_lock(&app->mutex);

    app->pending_workers--;

    nxt_thread_mutex_unlock(&app->mutex);

    nxt_router_app_use(task, app, -1);

    return NXT_ERROR;
}


nxt_inline void
nxt_router_ra_init(nxt_task_t *task, nxt_req_app_link_t *ra,
    nxt_req_conn_link_t *rc)
{
    nxt_event_engine_t  *engine;

    engine = task->thread->engine;

    nxt_memzero(ra, sizeof(nxt_req_app_link_t));

    ra->stream = rc->stream;
    ra->app_pid = -1;
    ra->rc = rc;
    rc->ra = ra;
    ra->reply_port = engine->port;
    ra->ap = rc->ap;

    ra->work.handler = NULL;
    ra->work.task = &engine->task;
    ra->work.obj = ra;
    ra->work.data = engine;
}


nxt_inline nxt_req_app_link_t *
nxt_router_ra_create(nxt_task_t *task, nxt_req_app_link_t *ra_src)
{
    nxt_mp_t            *mp;
    nxt_req_app_link_t  *ra;

    mp = ra_src->ap->mem_pool;

    ra = nxt_mp_retain(mp, sizeof(nxt_req_app_link_t));

    if (nxt_slow_path(ra == NULL)) {

        ra_src->rc->ra = NULL;
        ra_src->rc = NULL;

        return NULL;
    }

    nxt_router_ra_init(task, ra, ra_src->rc);

    ra->mem_pool = mp;

    return ra;
}


static void
nxt_router_ra_release(nxt_task_t *task, void *obj, void *data)
{
    nxt_req_app_link_t   *ra;
    nxt_event_engine_t   *engine;
    nxt_req_conn_link_t  *rc;

    ra = obj;
    engine = data;

    if (task->thread->engine != engine) {
        if (ra->app_port != NULL) {
            ra->app_pid = ra->app_port->pid;
        }

        ra->work.handler = nxt_router_ra_release;
        ra->work.task = &engine->task;
        ra->work.next = NULL;

        nxt_debug(task, "ra stream #%uD post release to %p",
                  ra->stream, engine);

        nxt_event_engine_post(engine, &ra->work);

        return;
    }

    nxt_debug(task, "ra stream #%uD release", ra->stream);

    rc = ra->rc;

    if (rc != NULL) {
        if (ra->app_pid != -1) {
            nxt_port_rpc_ex_set_peer(task, engine->port, rc, ra->app_pid);
        }

        rc->app_port = ra->app_port;

        ra->app_port = NULL;
        rc->ra = NULL;
        ra->rc = NULL;
    }

    if (ra->app_port != NULL) {
        nxt_router_app_port_release(task, ra->app_port, 0, 1);

        ra->app_port = NULL;
    }

    if (ra->mem_pool != NULL) {
        nxt_mp_release(ra->mem_pool, ra);
    }
}


static void
nxt_router_ra_abort(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t           *c;
    nxt_req_app_link_t   *ra;
    nxt_req_conn_link_t  *rc;
    nxt_event_engine_t   *engine;

    ra = obj;
    engine = data;

    if (task->thread->engine != engine) {
        ra->work.handler = nxt_router_ra_abort;
        ra->work.task = &engine->task;
        ra->work.next = NULL;

        nxt_debug(task, "ra stream #%uD post abort to %p", ra->stream, engine);

        nxt_event_engine_post(engine, &ra->work);

        return;
    }

    nxt_debug(task, "ra stream #%uD abort", ra->stream);

    rc = ra->rc;

    if (rc != NULL) {
        c = rc->conn;

        nxt_router_gen_error(task, c, 500,
                             "Failed to start application worker");

        rc->ra = NULL;
        ra->rc = NULL;
    }

    if (ra->app_port != NULL) {
        nxt_router_app_port_release(task, ra->app_port, 0, 1);

        ra->app_port = NULL;
    }

    if (ra->mem_pool != NULL) {
        nxt_mp_release(ra->mem_pool, ra);
    }
}


static void
nxt_router_ra_error_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_req_app_link_t   *ra;

    ra = obj;

    nxt_router_ra_error(task, ra, ra->err_code, ra->err_str);
}


static void
nxt_router_ra_error(nxt_task_t *task, nxt_req_app_link_t *ra, int code,
    const char* str)
{
    nxt_conn_t           *c;
    nxt_req_conn_link_t  *rc;
    nxt_event_engine_t   *engine;

    engine = ra->work.data;

    if (task->thread->engine != engine) {
        ra->err_code = code;
        ra->err_str = str;

        ra->work.handler = nxt_router_ra_error_handler;
        ra->work.task = &engine->task;
        ra->work.next = NULL;

        nxt_debug(task, "ra stream #%uD post error to %p", ra->stream, engine);

        nxt_event_engine_post(engine, &ra->work);

        return;
    }

    nxt_debug(task, "ra stream #%uD error", ra->stream);

    rc = ra->rc;

    if (rc != NULL) {
        c = rc->conn;

        nxt_router_gen_error(task, c, code, str);

        rc->ra = NULL;
        ra->rc = NULL;
    }

    if (ra->app_port != NULL) {
        nxt_router_app_port_release(task, ra->app_port, 0, 1);

        ra->app_port = NULL;
    }

    if (ra->mem_pool != NULL) {
        nxt_mp_release(ra->mem_pool, ra);
    }
}


nxt_inline void
nxt_router_rc_unlink(nxt_task_t *task, nxt_req_conn_link_t *rc)
{
    nxt_req_app_link_t  *ra;

    if (rc->app_port != NULL) {
        nxt_router_app_port_release(task, rc->app_port, 0, 1);

        rc->app_port = NULL;
    }

    ra = rc->ra;

    if (ra != NULL) {
        rc->ra = NULL;
        ra->rc = NULL;

        nxt_thread_mutex_lock(&rc->app->mutex);

        if (ra->link.next != NULL) {
            nxt_queue_remove(&ra->link);

            ra->link.next = NULL;

        } else {
            ra = NULL;
        }

        nxt_thread_mutex_unlock(&rc->app->mutex);
    }

    if (ra != NULL) {
        nxt_router_ra_release(task, ra, ra->work.data);
    }

    if (rc->app != NULL) {
        nxt_router_app_use(task, rc->app, -1);

        rc->app = NULL;
    }

    if (rc->ap != NULL) {
        nxt_app_http_req_done(task, rc->ap);

        rc->ap = NULL;
    }

    nxt_queue_remove(&rc->link);

    rc->conn = NULL;
}


void
nxt_router_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_new_port_handler(task, msg);

    if (msg->port_msg.stream == 0) {
        return;
    }

    if (msg->u.new_port == NULL ||
        msg->u.new_port->type != NXT_PROCESS_WORKER)
    {
        msg->port_msg.type = _NXT_PORT_MSG_RPC_ERROR;
    }

    nxt_port_rpc_handler(task, msg);
}


void
nxt_router_conf_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_int_t               ret;
    nxt_buf_t               *b;
    nxt_router_temp_conf_t  *tmcf;

    tmcf = nxt_router_temp_conf(task);
    if (nxt_slow_path(tmcf == NULL)) {
        return;
    }

    b = nxt_buf_chk_make_plain(tmcf->conf->mem_pool, msg->buf, msg->size);

    nxt_assert(b != NULL);

    tmcf->conf->router = nxt_router;
    tmcf->stream = msg->port_msg.stream;
    tmcf->port = nxt_runtime_port_find(task->thread->runtime,
                                       msg->port_msg.pid,
                                       msg->port_msg.reply_port);

    ret = nxt_router_conf_create(task, tmcf, b->mem.pos, b->mem.free);

    if (nxt_fast_path(ret == NXT_OK)) {
        nxt_router_conf_apply(task, tmcf, NULL);

    } else {
        nxt_router_conf_error(task, tmcf);
    }
}


static void
nxt_router_worker_remove_pid(nxt_task_t *task, nxt_port_t *port, void *data)
{
    union {
        nxt_pid_t  removed_pid;
        void       *data;
    } u;

    u.data = data;

    nxt_port_rpc_remove_peer(task, port, u.removed_pid);
}


void
nxt_router_remove_pid_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_event_engine_t  *engine;

    nxt_port_remove_pid_handler(task, msg);

    if (msg->port_msg.stream == 0) {
        return;
    }

    nxt_queue_each(engine, &nxt_router->engines, nxt_event_engine_t, link0)
    {
        nxt_port_post(task, engine->port, nxt_router_worker_remove_pid,
                      msg->u.data);
    }
    nxt_queue_loop;

    msg->port_msg.type = _NXT_PORT_MSG_RPC_ERROR;

    nxt_port_rpc_handler(task, msg);
}


static nxt_router_temp_conf_t *
nxt_router_temp_conf(nxt_task_t *task)
{
    nxt_mp_t                *mp, *tmp;
    nxt_router_conf_t       *rtcf;
    nxt_router_temp_conf_t  *tmcf;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(mp == NULL)) {
        return NULL;
    }

    rtcf = nxt_mp_zget(mp, sizeof(nxt_router_conf_t));
    if (nxt_slow_path(rtcf == NULL)) {
        goto fail;
    }

    rtcf->mem_pool = mp;

    tmp = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(tmp == NULL)) {
        goto fail;
    }

    tmcf = nxt_mp_zget(tmp, sizeof(nxt_router_temp_conf_t));
    if (nxt_slow_path(tmcf == NULL)) {
        goto temp_fail;
    }

    tmcf->mem_pool = tmp;
    tmcf->conf = rtcf;
    tmcf->count = 1;
    tmcf->engine = task->thread->engine;

    tmcf->engines = nxt_array_create(tmcf->mem_pool, 4,
                                     sizeof(nxt_router_engine_conf_t));
    if (nxt_slow_path(tmcf->engines == NULL)) {
        goto temp_fail;
    }

    nxt_queue_init(&tmcf->deleting);
    nxt_queue_init(&tmcf->keeping);
    nxt_queue_init(&tmcf->updating);
    nxt_queue_init(&tmcf->pending);
    nxt_queue_init(&tmcf->creating);
    nxt_queue_init(&tmcf->apps);
    nxt_queue_init(&tmcf->previous);

    return tmcf;

temp_fail:

    nxt_mp_destroy(tmp);

fail:

    nxt_mp_destroy(mp);

    return NULL;
}


static void
nxt_router_conf_apply(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t                    ret;
    nxt_router_t                 *router;
    nxt_runtime_t                *rt;
    nxt_queue_link_t             *qlk;
    nxt_socket_conf_t            *skcf;
    nxt_router_temp_conf_t       *tmcf;
    const nxt_event_interface_t  *interface;

    tmcf = obj;

    qlk = nxt_queue_first(&tmcf->pending);

    if (qlk != nxt_queue_tail(&tmcf->pending)) {
        nxt_queue_remove(qlk);
        nxt_queue_insert_tail(&tmcf->creating, qlk);

        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);

        nxt_router_listen_socket_rpc_create(task, tmcf, skcf);

        return;
    }

    rt = task->thread->runtime;

    interface = nxt_service_get(rt->services, "engine", NULL);

    router = tmcf->conf->router;

    ret = nxt_router_engines_create(task, router, tmcf, interface);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    ret = nxt_router_threads_create(task, rt, tmcf);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    nxt_router_apps_sort(task, router, tmcf);

    nxt_router_engines_post(router, tmcf);

    nxt_queue_add(&router->sockets, &tmcf->updating);
    nxt_queue_add(&router->sockets, &tmcf->creating);

    nxt_router_conf_ready(task, tmcf);

    return;

fail:

    nxt_router_conf_error(task, tmcf);

    return;
}


static void
nxt_router_conf_wait(nxt_task_t *task, void *obj, void *data)
{
    nxt_joint_job_t  *job;

    job = obj;

    nxt_router_conf_ready(task, job->tmcf);
}


static void
nxt_router_conf_ready(nxt_task_t *task, nxt_router_temp_conf_t *tmcf)
{
    nxt_debug(task, "temp conf count:%D", tmcf->count);

    if (--tmcf->count == 0) {
        nxt_router_conf_send(task, tmcf, NXT_PORT_MSG_RPC_READY_LAST);
    }
}


static void
nxt_router_conf_error(nxt_task_t *task, nxt_router_temp_conf_t *tmcf)
{
    nxt_socket_t       s;
    nxt_router_t       *router;
    nxt_queue_link_t   *qlk;
    nxt_socket_conf_t  *skcf;

    nxt_log(task, NXT_LOG_CRIT, "failed to apply new conf");

    for (qlk = nxt_queue_first(&tmcf->creating);
         qlk != nxt_queue_tail(&tmcf->creating);
         qlk = nxt_queue_next(qlk))
    {
        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);
        s = skcf->listen.socket;

        if (s != -1) {
            nxt_socket_close(task, s);
        }

        nxt_free(skcf->socket);
    }

    router = tmcf->conf->router;

    nxt_queue_add(&router->sockets, &tmcf->keeping);
    nxt_queue_add(&router->sockets, &tmcf->deleting);

    // TODO: new engines and threads

    nxt_mp_destroy(tmcf->conf->mem_pool);

    nxt_router_conf_send(task, tmcf, NXT_PORT_MSG_RPC_ERROR);
}


static void
nxt_router_conf_send(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_port_msg_type_t type)
{
    nxt_port_socket_write(task, tmcf->port, type, -1, tmcf->stream, 0, NULL);
}


static nxt_conf_map_t  nxt_router_conf[] = {
    {
        nxt_string("listeners_threads"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_router_conf_t, threads),
    },
};


static nxt_conf_map_t  nxt_router_app_conf[] = {
    {
        nxt_string("type"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_router_app_conf_t, type),
    },

    {
        nxt_string("workers"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_router_app_conf_t, workers),
    },

    {
        nxt_string("limits"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_router_app_conf_t, limits_value),
    },
};


static nxt_conf_map_t  nxt_router_app_limits_conf[] = {
    {
        nxt_string("timeout"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_router_app_conf_t, timeout),
    },

    {
        nxt_string("requests"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_router_app_conf_t, requests),
    },
};


static nxt_conf_map_t  nxt_router_listener_conf[] = {
    {
        nxt_string("application"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_router_listener_conf_t, application),
    },
};


static nxt_conf_map_t  nxt_router_http_conf[] = {
    {
        nxt_string("header_buffer_size"),
        NXT_CONF_MAP_SIZE,
        offsetof(nxt_socket_conf_t, header_buffer_size),
    },

    {
        nxt_string("large_header_buffer_size"),
        NXT_CONF_MAP_SIZE,
        offsetof(nxt_socket_conf_t, large_header_buffer_size),
    },

    {
        nxt_string("large_header_buffers"),
        NXT_CONF_MAP_SIZE,
        offsetof(nxt_socket_conf_t, large_header_buffers),
    },

    {
        nxt_string("body_buffer_size"),
        NXT_CONF_MAP_SIZE,
        offsetof(nxt_socket_conf_t, body_buffer_size),
    },

    {
        nxt_string("max_body_size"),
        NXT_CONF_MAP_SIZE,
        offsetof(nxt_socket_conf_t, max_body_size),
    },

    {
        nxt_string("header_read_timeout"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_socket_conf_t, header_read_timeout),
    },

    {
        nxt_string("body_read_timeout"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_socket_conf_t, body_read_timeout),
    },
};


static nxt_int_t
nxt_router_conf_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    u_char *start, u_char *end)
{
    u_char                      *p;
    size_t                      size;
    nxt_mp_t                    *mp;
    uint32_t                    next;
    nxt_int_t                   ret;
    nxt_str_t                   name;
    nxt_app_t                   *app, *prev;
    nxt_sockaddr_t              *sa;
    nxt_conf_value_t            *conf, *http;
    nxt_conf_value_t            *applications, *application;
    nxt_conf_value_t            *listeners, *listener;
    nxt_socket_conf_t           *skcf;
    nxt_app_lang_module_t       *lang;
    nxt_router_app_conf_t       apcf;
    nxt_router_listener_conf_t  lscf;

    static nxt_str_t  http_path = nxt_string("/http");
    static nxt_str_t  applications_path = nxt_string("/applications");
    static nxt_str_t  listeners_path = nxt_string("/listeners");

    conf = nxt_conf_json_parse(tmcf->mem_pool, start, end, NULL);
    if (conf == NULL) {
        nxt_log(task, NXT_LOG_CRIT, "configuration parsing error");
        return NXT_ERROR;
    }

    mp = tmcf->conf->mem_pool;

    ret = nxt_conf_map_object(mp, conf, nxt_router_conf,
                              nxt_nitems(nxt_router_conf), tmcf->conf);
    if (ret != NXT_OK) {
        nxt_log(task, NXT_LOG_CRIT, "root map error");
        return NXT_ERROR;
    }

    if (tmcf->conf->threads == 0) {
        tmcf->conf->threads = nxt_ncpu;
    }

    applications = nxt_conf_get_path(conf, &applications_path);
    if (applications == NULL) {
        nxt_log(task, NXT_LOG_CRIT, "no \"applications\" block");
        return NXT_ERROR;
    }

    next = 0;

    for ( ;; ) {
        application = nxt_conf_next_object_member(applications, &name, &next);
        if (application == NULL) {
            break;
        }

        nxt_debug(task, "application \"%V\"", &name);

        size = nxt_conf_json_length(application, NULL);

        app = nxt_malloc(sizeof(nxt_app_t) + name.length + size);
        if (app == NULL) {
            goto fail;
        }

        nxt_memzero(app, sizeof(nxt_app_t));

        app->name.start = nxt_pointer_to(app, sizeof(nxt_app_t));
        app->conf.start = nxt_pointer_to(app, sizeof(nxt_app_t) + name.length);

        p = nxt_conf_json_print(app->conf.start, application, NULL);
        app->conf.length = p - app->conf.start;

        nxt_assert(app->conf.length <= size);

        nxt_debug(task, "application conf \"%V\"", &app->conf);

        prev = nxt_router_app_find(&tmcf->conf->router->apps, &name);

        if (prev != NULL && nxt_strstr_eq(&app->conf, &prev->conf)) {
            nxt_free(app);

            nxt_queue_remove(&prev->link);
            nxt_queue_insert_tail(&tmcf->previous, &prev->link);
            continue;
        }

        apcf.workers = 1;
        apcf.timeout = 0;
        apcf.requests = 0;
        apcf.limits_value = NULL;

        ret = nxt_conf_map_object(mp, application, nxt_router_app_conf,
                                  nxt_nitems(nxt_router_app_conf), &apcf);
        if (ret != NXT_OK) {
            nxt_log(task, NXT_LOG_CRIT, "application map error");
            goto app_fail;
        }

        if (apcf.limits_value != NULL) {

            if (nxt_conf_type(apcf.limits_value) != NXT_CONF_OBJECT) {
                nxt_log(task, NXT_LOG_CRIT, "application limits is not object");
                goto app_fail;
            }

            ret = nxt_conf_map_object(mp, apcf.limits_value,
                                      nxt_router_app_limits_conf,
                                      nxt_nitems(nxt_router_app_limits_conf),
                                      &apcf);
            if (ret != NXT_OK) {
                nxt_log(task, NXT_LOG_CRIT, "application limits map error");
                goto app_fail;
            }
        }

        nxt_debug(task, "application type: %V", &apcf.type);
        nxt_debug(task, "application workers: %D", apcf.workers);
        nxt_debug(task, "application timeout: %D", apcf.timeout);
        nxt_debug(task, "application requests: %D", apcf.requests);

        lang = nxt_app_lang_module(task->thread->runtime, &apcf.type);

        if (lang == NULL) {
            nxt_log(task, NXT_LOG_CRIT, "unknown application type: \"%V\"",
                    &apcf.type);
            goto app_fail;
        }

        nxt_debug(task, "application language module: \"%s\"", lang->file);

        ret = nxt_thread_mutex_create(&app->mutex);
        if (ret != NXT_OK) {
            goto app_fail;
        }

        nxt_queue_init(&app->ports);
        nxt_queue_init(&app->requests);

        app->name.length = name.length;
        nxt_memcpy(app->name.start, name.start, name.length);

        app->type = lang->type;
        app->max_workers = apcf.workers;
        app->timeout = apcf.timeout;
        app->live = 1;
        app->max_pending_responses = 2;
        app->prepare_msg = nxt_app_prepare_msg[lang->type];

        nxt_queue_insert_tail(&tmcf->apps, &app->link);

        nxt_router_app_use(task, app, 1);
    }

    http = nxt_conf_get_path(conf, &http_path);
#if 0
    if (http == NULL) {
        nxt_log(task, NXT_LOG_CRIT, "no \"http\" block");
        return NXT_ERROR;
    }
#endif

    listeners = nxt_conf_get_path(conf, &listeners_path);
    if (listeners == NULL) {
        nxt_log(task, NXT_LOG_CRIT, "no \"listeners\" block");
        return NXT_ERROR;
    }

    next = 0;

    for ( ;; ) {
        listener = nxt_conf_next_object_member(listeners, &name, &next);
        if (listener == NULL) {
            break;
        }

        sa = nxt_sockaddr_parse(mp, &name);
        if (sa == NULL) {
            nxt_log(task, NXT_LOG_CRIT, "invalid listener \"%V\"", &name);
            goto fail;
        }

        sa->type = SOCK_STREAM;

        nxt_debug(task, "router listener: \"%*s\"",
                  sa->length, nxt_sockaddr_start(sa));

        skcf = nxt_router_socket_conf(task, mp, sa);
        if (skcf == NULL) {
            goto fail;
        }

        ret = nxt_conf_map_object(mp, listener, nxt_router_listener_conf,
                                  nxt_nitems(nxt_router_listener_conf), &lscf);
        if (ret != NXT_OK) {
            nxt_log(task, NXT_LOG_CRIT, "listener map error");
            goto fail;
        }

        nxt_debug(task, "application: %V", &lscf.application);

        // STUB, default values if http block is not defined.
        skcf->header_buffer_size = 2048;
        skcf->large_header_buffer_size = 8192;
        skcf->large_header_buffers = 4;
        skcf->body_buffer_size = 16 * 1024;
        skcf->max_body_size = 2 * 1024 * 1024;
        skcf->header_read_timeout = 5000;
        skcf->body_read_timeout = 5000;

        if (http != NULL) {
            ret = nxt_conf_map_object(mp, http, nxt_router_http_conf,
                                      nxt_nitems(nxt_router_http_conf), skcf);
            if (ret != NXT_OK) {
                nxt_log(task, NXT_LOG_CRIT, "http map error");
                goto fail;
            }
        }

        skcf->listen.handler = nxt_router_conn_init;
        skcf->router_conf = tmcf->conf;
        skcf->router_conf->count++;
        skcf->application = nxt_router_listener_application(tmcf,
                                                            &lscf.application);

        nxt_queue_insert_tail(&tmcf->pending, &skcf->link);
    }

    nxt_router_listen_sockets_sort(tmcf->conf->router, tmcf);

    return NXT_OK;

app_fail:

    nxt_free(app);

fail:

    nxt_queue_each(app, &tmcf->apps, nxt_app_t, link) {

        nxt_queue_remove(&app->link);
        nxt_thread_mutex_destroy(&app->mutex);
        nxt_free(app);

    } nxt_queue_loop;

    return NXT_ERROR;
}


static nxt_app_t *
nxt_router_app_find(nxt_queue_t *queue, nxt_str_t *name)
{
    nxt_app_t  *app;

    nxt_queue_each(app, queue, nxt_app_t, link) {

        if (nxt_strstr_eq(name, &app->name)) {
            return app;
        }

    } nxt_queue_loop;

    return NULL;
}


static nxt_app_t *
nxt_router_listener_application(nxt_router_temp_conf_t *tmcf, nxt_str_t *name)
{
    nxt_app_t  *app;

    app = nxt_router_app_find(&tmcf->apps, name);

    if (app == NULL) {
        app = nxt_router_app_find(&tmcf->previous, name);
    }

    return app;
}


static nxt_socket_conf_t *
nxt_router_socket_conf(nxt_task_t *task, nxt_mp_t *mp, nxt_sockaddr_t *sa)
{
    nxt_socket_conf_t  *skcf;

    skcf = nxt_mp_zget(mp, sizeof(nxt_socket_conf_t));
    if (nxt_slow_path(skcf == NULL)) {
        return NULL;
    }

    skcf->sockaddr = sa;

    skcf->listen.sockaddr = sa;

    nxt_listen_socket_remote_size(&skcf->listen, sa);

    skcf->listen.socket = -1;
    skcf->listen.backlog = NXT_LISTEN_BACKLOG;
    skcf->listen.flags = NXT_NONBLOCK;
    skcf->listen.read_after_accept = 1;

    return skcf;
}


static void
nxt_router_listen_sockets_sort(nxt_router_t *router,
    nxt_router_temp_conf_t *tmcf)
{
    nxt_queue_link_t   *nqlk, *oqlk, *next;
    nxt_socket_conf_t  *nskcf, *oskcf;

    for (nqlk = nxt_queue_first(&tmcf->pending);
         nqlk != nxt_queue_tail(&tmcf->pending);
         nqlk = next)
    {
        next = nxt_queue_next(nqlk);
        nskcf = nxt_queue_link_data(nqlk, nxt_socket_conf_t, link);

        for (oqlk = nxt_queue_first(&router->sockets);
             oqlk != nxt_queue_tail(&router->sockets);
             oqlk = nxt_queue_next(oqlk))
        {
            oskcf = nxt_queue_link_data(oqlk, nxt_socket_conf_t, link);

            if (nxt_sockaddr_cmp(nskcf->sockaddr, oskcf->sockaddr)) {
                nskcf->socket = oskcf->socket;
                nskcf->listen.socket = oskcf->listen.socket;

                nxt_queue_remove(oqlk);
                nxt_queue_insert_tail(&tmcf->keeping, oqlk);

                nxt_queue_remove(nqlk);
                nxt_queue_insert_tail(&tmcf->updating, nqlk);

                break;
            }
        }
    }

    nxt_queue_add(&tmcf->deleting, &router->sockets);
    nxt_queue_init(&router->sockets);
}


static void
nxt_router_listen_socket_rpc_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_socket_conf_t *skcf)
{
    uint32_t          stream;
    nxt_buf_t         *b;
    nxt_port_t        *main_port, *router_port;
    nxt_runtime_t     *rt;
    nxt_socket_rpc_t  *rpc;

    rpc = nxt_mp_alloc(tmcf->mem_pool, sizeof(nxt_socket_rpc_t));
    if (rpc == NULL) {
        goto fail;
    }

    rpc->socket_conf = skcf;
    rpc->temp_conf = tmcf;

    b = nxt_buf_mem_alloc(tmcf->mem_pool, skcf->sockaddr->sockaddr_size, 0);
    if (b == NULL) {
        goto fail;
    }

    b->mem.free = nxt_cpymem(b->mem.free, skcf->sockaddr,
                             skcf->sockaddr->sockaddr_size);

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    stream = nxt_port_rpc_register_handler(task, router_port,
                                           nxt_router_listen_socket_ready,
                                           nxt_router_listen_socket_error,
                                           main_port->pid, rpc);
    if (stream == 0) {
        goto fail;
    }

    nxt_port_socket_write(task, main_port, NXT_PORT_MSG_SOCKET, -1,
                          stream, router_port->id, b);

    return;

fail:

    nxt_router_conf_error(task, tmcf);
}


static void
nxt_router_listen_socket_ready(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_int_t            ret;
    nxt_socket_t         s;
    nxt_socket_rpc_t     *rpc;
    nxt_router_socket_t  *rtsk;

    rpc = data;

    s = msg->fd;

    ret = nxt_socket_nonblocking(task, s);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    nxt_socket_defer_accept(task, s, rpc->socket_conf->sockaddr);

    ret = nxt_listen_socket(task, s, NXT_LISTEN_BACKLOG);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    rtsk = nxt_malloc(sizeof(nxt_router_socket_t));
    if (nxt_slow_path(rtsk == NULL)) {
        goto fail;
    }

    rtsk->count = 0;
    rtsk->fd = s;

    rpc->socket_conf->listen.socket = s;
    rpc->socket_conf->socket = rtsk;

    nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                       nxt_router_conf_apply, task, rpc->temp_conf, NULL);

    return;

fail:

    nxt_socket_close(task, s);

    nxt_router_conf_error(task, rpc->temp_conf);
}


static void
nxt_router_listen_socket_error(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    u_char                  *p;
    size_t                  size;
    uint8_t                 error;
    nxt_buf_t               *in, *out;
    nxt_sockaddr_t          *sa;
    nxt_socket_rpc_t        *rpc;
    nxt_router_temp_conf_t  *tmcf;

    static nxt_str_t  socket_errors[] = {
        nxt_string("ListenerSystem"),
        nxt_string("ListenerNoIPv6"),
        nxt_string("ListenerPort"),
        nxt_string("ListenerInUse"),
        nxt_string("ListenerNoAddress"),
        nxt_string("ListenerNoAccess"),
        nxt_string("ListenerPath"),
    };

    rpc = data;
    sa = rpc->socket_conf->sockaddr;
    tmcf = rpc->temp_conf;

    in = nxt_buf_chk_make_plain(tmcf->mem_pool, msg->buf, msg->size);

    nxt_assert(in != NULL);

    p = in->mem.pos;

    error = *p++;

    size = sizeof("listen socket error: ") - 1
           + sizeof("{listener: \"\", code:\"\", message: \"\"}") - 1
           + sa->length + socket_errors[error].length + (in->mem.free - p);

    out = nxt_buf_mem_alloc(tmcf->mem_pool, size, 0);
    if (nxt_slow_path(out == NULL)) {
        return;
    }

    out->mem.free = nxt_sprintf(out->mem.free, out->mem.end,
                        "listen socket error: "
                        "{listener: \"%*s\", code:\"%V\", message: \"%*s\"}",
                        sa->length, nxt_sockaddr_start(sa),
                        &socket_errors[error], in->mem.free - p, p);

    nxt_debug(task, "%*s", out->mem.free - out->mem.pos, out->mem.pos);

    nxt_router_conf_error(task, tmcf);
}


static nxt_int_t
nxt_router_engines_create(nxt_task_t *task, nxt_router_t *router,
    nxt_router_temp_conf_t *tmcf, const nxt_event_interface_t *interface)
{
    nxt_int_t                 ret;
    nxt_uint_t                n, threads;
    nxt_queue_link_t          *qlk;
    nxt_router_engine_conf_t  *recf;

    threads = tmcf->conf->threads;

    tmcf->engines = nxt_array_create(tmcf->mem_pool, threads,
                                     sizeof(nxt_router_engine_conf_t));
    if (nxt_slow_path(tmcf->engines == NULL)) {
        return NXT_ERROR;
    }

    n = 0;

    for (qlk = nxt_queue_first(&router->engines);
         qlk != nxt_queue_tail(&router->engines);
         qlk = nxt_queue_next(qlk))
    {
        recf = nxt_array_zero_add(tmcf->engines);
        if (nxt_slow_path(recf == NULL)) {
            return NXT_ERROR;
        }

        recf->engine = nxt_queue_link_data(qlk, nxt_event_engine_t, link0);

        if (n < threads) {
            recf->action = NXT_ROUTER_ENGINE_KEEP;
            ret = nxt_router_engine_conf_update(tmcf, recf);

        } else {
            recf->action = NXT_ROUTER_ENGINE_DELETE;
            ret = nxt_router_engine_conf_delete(tmcf, recf);
        }

        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

        n++;
    }

    tmcf->new_threads = n;

    while (n < threads) {
        recf = nxt_array_zero_add(tmcf->engines);
        if (nxt_slow_path(recf == NULL)) {
            return NXT_ERROR;
        }

        recf->action = NXT_ROUTER_ENGINE_ADD;

        recf->engine = nxt_event_engine_create(task, interface, NULL, 0, 0);
        if (nxt_slow_path(recf->engine == NULL)) {
            return NXT_ERROR;
        }

        ret = nxt_router_engine_conf_create(tmcf, recf);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

        n++;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_router_engine_conf_create(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf)
{
    nxt_int_t              ret;
    nxt_thread_spinlock_t  *lock;

    ret = nxt_router_engine_joints_create(tmcf, recf, &tmcf->creating,
                                          nxt_router_listen_socket_create);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    ret = nxt_router_engine_joints_create(tmcf, recf, &tmcf->updating,
                                          nxt_router_listen_socket_create);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    lock = &tmcf->conf->router->lock;

    nxt_thread_spin_lock(lock);

    nxt_router_engine_socket_count(&tmcf->creating);
    nxt_router_engine_socket_count(&tmcf->updating);

    nxt_thread_spin_unlock(lock);

    return ret;
}


static nxt_int_t
nxt_router_engine_conf_update(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf)
{
    nxt_int_t              ret;
    nxt_thread_spinlock_t  *lock;

    ret = nxt_router_engine_joints_create(tmcf, recf, &tmcf->creating,
                                          nxt_router_listen_socket_create);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    ret = nxt_router_engine_joints_create(tmcf, recf, &tmcf->updating,
                                          nxt_router_listen_socket_update);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    ret = nxt_router_engine_joints_delete(tmcf, recf, &tmcf->deleting);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    lock = &tmcf->conf->router->lock;

    nxt_thread_spin_lock(lock);

    nxt_router_engine_socket_count(&tmcf->creating);

    nxt_thread_spin_unlock(lock);

    return ret;
}


static nxt_int_t
nxt_router_engine_conf_delete(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf)
{
    nxt_int_t  ret;

    ret = nxt_router_engine_quit(tmcf, recf);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    ret = nxt_router_engine_joints_delete(tmcf, recf, &tmcf->updating);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    return nxt_router_engine_joints_delete(tmcf, recf, &tmcf->deleting);
}


static nxt_int_t
nxt_router_engine_joints_create(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf, nxt_queue_t *sockets,
    nxt_work_handler_t handler)
{
    nxt_joint_job_t          *job;
    nxt_queue_link_t         *qlk;
    nxt_socket_conf_t        *skcf;
    nxt_socket_conf_joint_t  *joint;

    for (qlk = nxt_queue_first(sockets);
         qlk != nxt_queue_tail(sockets);
         qlk = nxt_queue_next(qlk))
    {
        job = nxt_mp_get(tmcf->mem_pool, sizeof(nxt_joint_job_t));
        if (nxt_slow_path(job == NULL)) {
            return NXT_ERROR;
        }

        job->work.next = recf->jobs;
        recf->jobs = &job->work;

        job->task = tmcf->engine->task;
        job->work.handler = handler;
        job->work.task = &job->task;
        job->work.obj = job;
        job->tmcf = tmcf;

        tmcf->count++;

        joint = nxt_mp_alloc(tmcf->conf->mem_pool,
                             sizeof(nxt_socket_conf_joint_t));
        if (nxt_slow_path(joint == NULL)) {
            return NXT_ERROR;
        }

        job->work.data = joint;

        joint->count = 1;

        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);
        skcf->count++;
        joint->socket_conf = skcf;

        joint->engine = recf->engine;
    }

    return NXT_OK;
}


static void
nxt_router_engine_socket_count(nxt_queue_t *sockets)
{
    nxt_queue_link_t   *qlk;
    nxt_socket_conf_t  *skcf;

    for (qlk = nxt_queue_first(sockets);
         qlk != nxt_queue_tail(sockets);
         qlk = nxt_queue_next(qlk))
    {
        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);
        skcf->socket->count++;
    }
}


static nxt_int_t
nxt_router_engine_quit(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf)
{
    nxt_joint_job_t  *job;

    job = nxt_mp_get(tmcf->mem_pool, sizeof(nxt_joint_job_t));
    if (nxt_slow_path(job == NULL)) {
        return NXT_ERROR;
    }

    job->work.next = recf->jobs;
    recf->jobs = &job->work;

    job->task = tmcf->engine->task;
    job->work.handler = nxt_router_worker_thread_quit;
    job->work.task = &job->task;
    job->work.obj = NULL;
    job->work.data = NULL;
    job->tmcf = NULL;

    return NXT_OK;
}


static nxt_int_t
nxt_router_engine_joints_delete(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf, nxt_queue_t *sockets)
{
    nxt_joint_job_t   *job;
    nxt_queue_link_t  *qlk;

    for (qlk = nxt_queue_first(sockets);
         qlk != nxt_queue_tail(sockets);
         qlk = nxt_queue_next(qlk))
    {
        job = nxt_mp_get(tmcf->mem_pool, sizeof(nxt_joint_job_t));
        if (nxt_slow_path(job == NULL)) {
            return NXT_ERROR;
        }

        job->work.next = recf->jobs;
        recf->jobs = &job->work;

        job->task = tmcf->engine->task;
        job->work.handler = nxt_router_listen_socket_delete;
        job->work.task = &job->task;
        job->work.obj = job;
        job->work.data = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);
        job->tmcf = tmcf;

        tmcf->count++;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_router_threads_create(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_router_temp_conf_t *tmcf)
{
    nxt_int_t                 ret;
    nxt_uint_t                i, threads;
    nxt_router_engine_conf_t  *recf;

    recf = tmcf->engines->elts;
    threads = tmcf->conf->threads;

    for (i = tmcf->new_threads; i < threads; i++) {
        ret = nxt_router_thread_create(task, rt, recf[i].engine);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_router_thread_create(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_event_engine_t *engine)
{
    nxt_int_t            ret;
    nxt_thread_link_t    *link;
    nxt_thread_handle_t  handle;

    link = nxt_zalloc(sizeof(nxt_thread_link_t));

    if (nxt_slow_path(link == NULL)) {
        return NXT_ERROR;
    }

    link->start = nxt_router_thread_start;
    link->engine = engine;
    link->work.handler = nxt_router_thread_exit_handler;
    link->work.task = task;
    link->work.data = link;

    nxt_queue_insert_tail(&rt->engines, &engine->link);

    ret = nxt_thread_create(&handle, link);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_queue_remove(&engine->link);
    }

    return ret;
}


static void
nxt_router_apps_sort(nxt_task_t *task, nxt_router_t *router,
    nxt_router_temp_conf_t *tmcf)
{
    nxt_app_t   *app;
    nxt_port_t  *port;

    nxt_queue_each(app, &router->apps, nxt_app_t, link) {

        nxt_queue_remove(&app->link);

        nxt_debug(task, "about to free app '%V' %p", &app->name, app);

        app->live = 0;

        do {
            port = nxt_router_app_get_idle_port(app);
            if (port == NULL) {
                break;
            }

            nxt_debug(task, "port %p send quit", port);

            nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT, -1, 0, 0,
                                  NULL);

            nxt_port_use(task, port, -1);
        } while (1);

        nxt_router_app_use(task, app, -1);

    } nxt_queue_loop;

    nxt_queue_add(&router->apps, &tmcf->previous);
    nxt_queue_add(&router->apps, &tmcf->apps);
}


static void
nxt_router_engines_post(nxt_router_t *router, nxt_router_temp_conf_t *tmcf)
{
    nxt_uint_t                n;
    nxt_event_engine_t        *engine;
    nxt_router_engine_conf_t  *recf;

    recf = tmcf->engines->elts;

    for (n = tmcf->engines->nelts; n != 0; n--) {
        engine = recf->engine;

        switch (recf->action) {

        case NXT_ROUTER_ENGINE_KEEP:
            break;

        case NXT_ROUTER_ENGINE_ADD:
            nxt_queue_insert_tail(&router->engines, &engine->link0);
            break;

        case NXT_ROUTER_ENGINE_DELETE:
            nxt_queue_remove(&engine->link0);
            break;
        }

        nxt_router_engine_post(engine, recf->jobs);

        recf++;
    }
}


static void
nxt_router_engine_post(nxt_event_engine_t *engine, nxt_work_t *jobs)
{
    nxt_work_t  *work, *next;

    for (work = jobs; work != NULL; work = next) {
        next = work->next;
        work->next = NULL;

        nxt_event_engine_post(engine, work);
    }
}


static nxt_port_handlers_t  nxt_router_app_port_handlers = {
    .mmap = nxt_port_mmap_handler,
    .data = nxt_port_rpc_handler,
};


static void
nxt_router_thread_start(void *data)
{
    nxt_int_t           ret;
    nxt_port_t          *port;
    nxt_task_t          *task;
    nxt_thread_t        *thread;
    nxt_thread_link_t   *link;
    nxt_event_engine_t  *engine;

    link = data;
    engine = link->engine;
    task = &engine->task;

    thread = nxt_thread();

    nxt_event_engine_thread_adopt(engine);

    /* STUB */
    thread->runtime = engine->task.thread->runtime;

    engine->task.thread = thread;
    engine->task.log = thread->log;
    thread->engine = engine;
    thread->task = &engine->task;
#if 0
    thread->fiber = &engine->fibers->fiber;
#endif

    engine->mem_pool = nxt_mp_create(4096, 128, 1024, 64);
    if (nxt_slow_path(engine->mem_pool == NULL)) {
        return;
    }

    port = nxt_port_new(task, nxt_port_get_next_id(), nxt_pid,
                        NXT_PROCESS_ROUTER);
    if (nxt_slow_path(port == NULL)) {
        return;
    }

    ret = nxt_port_socket_init(task, port, 0);
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_use(task, port, -1);
        return;
    }

    engine->port = port;

    nxt_port_enable(task, port, &nxt_router_app_port_handlers);

    nxt_event_engine_start(engine);
}


static void
nxt_router_listen_socket_create(nxt_task_t *task, void *obj, void *data)
{
    nxt_joint_job_t          *job;
    nxt_listen_event_t       *listen;
    nxt_listen_socket_t      *ls;
    nxt_socket_conf_joint_t  *joint;

    job = obj;
    joint = data;

    ls = &joint->socket_conf->listen;

    nxt_queue_insert_tail(&task->thread->engine->joints, &joint->link);

    listen = nxt_listen_event(task, ls);
    if (nxt_slow_path(listen == NULL)) {
        nxt_router_listen_socket_release(task, joint);
        return;
    }

    listen->socket.data = joint;

    job->work.next = NULL;
    job->work.handler = nxt_router_conf_wait;

    nxt_event_engine_post(job->tmcf->engine, &job->work);
}


nxt_inline nxt_listen_event_t *
nxt_router_listen_event(nxt_queue_t *listen_connections,
    nxt_socket_conf_t *skcf)
{
    nxt_socket_t        fd;
    nxt_queue_link_t    *qlk;
    nxt_listen_event_t  *listen;

    fd = skcf->socket->fd;

    for (qlk = nxt_queue_first(listen_connections);
         qlk != nxt_queue_tail(listen_connections);
         qlk = nxt_queue_next(qlk))
    {
        listen = nxt_queue_link_data(qlk, nxt_listen_event_t, link);

        if (fd == listen->socket.fd) {
            return listen;
        }
    }

    return NULL;
}


static void
nxt_router_listen_socket_update(nxt_task_t *task, void *obj, void *data)
{
    nxt_joint_job_t          *job;
    nxt_event_engine_t       *engine;
    nxt_listen_event_t       *listen;
    nxt_socket_conf_joint_t  *joint, *old;

    job = obj;
    joint = data;

    engine = task->thread->engine;

    nxt_queue_insert_tail(&engine->joints, &joint->link);

    listen = nxt_router_listen_event(&engine->listen_connections,
                                     joint->socket_conf);

    old = listen->socket.data;
    listen->socket.data = joint;
    listen->listen = &joint->socket_conf->listen;

    job->work.next = NULL;
    job->work.handler = nxt_router_conf_wait;

    nxt_event_engine_post(job->tmcf->engine, &job->work);

    /*
     * The task is allocated from configuration temporary
     * memory pool so it can be freed after engine post operation.
     */

    nxt_router_conf_release(&engine->task, old);
}


static void
nxt_router_listen_socket_delete(nxt_task_t *task, void *obj, void *data)
{
    nxt_joint_job_t     *job;
    nxt_socket_conf_t   *skcf;
    nxt_listen_event_t  *listen;
    nxt_event_engine_t  *engine;

    job = obj;
    skcf = data;

    engine = task->thread->engine;

    listen = nxt_router_listen_event(&engine->listen_connections, skcf);

    nxt_fd_event_delete(engine, &listen->socket);

    nxt_debug(task, "engine %p: listen socket delete: %d", engine,
              listen->socket.fd);

    listen->timer.handler = nxt_router_listen_socket_close;
    listen->timer.work_queue = &engine->fast_work_queue;

    nxt_timer_add(engine, &listen->timer, 0);

    job->work.next = NULL;
    job->work.handler = nxt_router_conf_wait;

    nxt_event_engine_post(job->tmcf->engine, &job->work);
}


static void
nxt_router_worker_thread_quit(nxt_task_t *task, void *obj, void *data)
{
    nxt_event_engine_t  *engine;

    nxt_debug(task, "router worker thread quit");

    engine = task->thread->engine;

    engine->shutdown = 1;

    if (nxt_queue_is_empty(&engine->joints)) {
        nxt_thread_exit(task->thread);
    }
}


static void
nxt_router_listen_socket_close(nxt_task_t *task, void *obj, void *data)
{
    nxt_timer_t              *timer;
    nxt_listen_event_t       *listen;
    nxt_socket_conf_joint_t  *joint;

    timer = obj;
    listen = nxt_timer_data(timer, nxt_listen_event_t, timer);
    joint = listen->socket.data;

    nxt_debug(task, "engine %p: listen socket close: %d", task->thread->engine,
              listen->socket.fd);

    nxt_queue_remove(&listen->link);

    /* 'task' refers to listen->task and we cannot use after nxt_free() */
    task = &task->thread->engine->task;

    nxt_free(listen);

    nxt_router_listen_socket_release(task, joint);
}


static void
nxt_router_listen_socket_release(nxt_task_t *task,
    nxt_socket_conf_joint_t *joint)
{
    nxt_socket_conf_t      *skcf;
    nxt_router_socket_t    *rtsk;
    nxt_thread_spinlock_t  *lock;

    skcf = joint->socket_conf;
    rtsk = skcf->socket;
    lock = &skcf->router_conf->router->lock;

    nxt_thread_spin_lock(lock);

    nxt_debug(task, "engine %p: listen socket release: rtsk->count %D",
              task->thread->engine, rtsk->count);

    if (--rtsk->count != 0) {
        rtsk = NULL;
    }

    nxt_thread_spin_unlock(lock);

    if (rtsk != NULL) {
        nxt_socket_close(task, rtsk->fd);
        nxt_free(rtsk);
        skcf->socket = NULL;
    }

    nxt_router_conf_release(task, joint);
}


static void
nxt_router_conf_release(nxt_task_t *task, nxt_socket_conf_joint_t *joint)
{
    nxt_bool_t             exit;
    nxt_socket_conf_t      *skcf;
    nxt_router_conf_t      *rtcf;
    nxt_event_engine_t     *engine;
    nxt_thread_spinlock_t  *lock;

    nxt_debug(task, "conf joint %p count: %D", joint, joint->count);

    if (--joint->count != 0) {
        return;
    }

    nxt_queue_remove(&joint->link);

    skcf = joint->socket_conf;
    rtcf = skcf->router_conf;
    lock = &rtcf->router->lock;

    nxt_thread_spin_lock(lock);

    nxt_debug(task, "conf skcf %p: %D, rtcf %p: %D", skcf, skcf->count,
              rtcf, rtcf->count);

    if (--skcf->count != 0) {
        rtcf = NULL;

    } else {
        nxt_queue_remove(&skcf->link);

        if (--rtcf->count != 0) {
            rtcf = NULL;
        }
    }

    nxt_thread_spin_unlock(lock);

    /* TODO remove engine->port */
    /* TODO excude from connected ports */

    /* The joint content can be used before memory pool destruction. */
    engine = joint->engine;
    exit = (engine->shutdown && nxt_queue_is_empty(&engine->joints));

    if (rtcf != NULL) {
        nxt_debug(task, "old router conf is destroyed");

        nxt_mp_thread_adopt(rtcf->mem_pool);

        nxt_mp_destroy(rtcf->mem_pool);
    }

    if (exit) {
        nxt_thread_exit(task->thread);
    }
}


static void
nxt_router_thread_exit_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_port_t           *port;
    nxt_thread_link_t    *link;
    nxt_event_engine_t   *engine;
    nxt_thread_handle_t  handle;

    handle = (nxt_thread_handle_t) obj;
    link = data;

    nxt_thread_wait(handle);

    engine = link->engine;

    nxt_queue_remove(&engine->link);

    port = engine->port;

    // TODO notify all apps

    port->engine = task->thread->engine;
    nxt_mp_thread_adopt(port->mem_pool);
    nxt_port_use(task, port, -1);

    nxt_mp_thread_adopt(engine->mem_pool);
    nxt_mp_destroy(engine->mem_pool);

    nxt_event_engine_free(engine);

    nxt_free(link);
}


static const nxt_conn_state_t  nxt_router_conn_read_header_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_router_conn_http_header_parse,
    .close_handler = nxt_router_conn_close,
    .error_handler = nxt_router_conn_error,

    .timer_handler = nxt_router_conn_timeout,
    .timer_value = nxt_router_conn_timeout_value,
    .timer_data = offsetof(nxt_socket_conf_t, header_read_timeout),
};


static const nxt_conn_state_t  nxt_router_conn_read_body_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_router_conn_http_body_read,
    .close_handler = nxt_router_conn_close,
    .error_handler = nxt_router_conn_error,

    .timer_handler = nxt_router_conn_timeout,
    .timer_value = nxt_router_conn_timeout_value,
    .timer_data = offsetof(nxt_socket_conf_t, body_read_timeout),
    .timer_autoreset = 1,
};


static void
nxt_router_conn_init(nxt_task_t *task, void *obj, void *data)
{
    size_t                   size;
    nxt_conn_t               *c;
    nxt_event_engine_t       *engine;
    nxt_socket_conf_joint_t  *joint;

    c = obj;
    joint = data;

    nxt_debug(task, "router conn init");

    joint->count++;

    size = joint->socket_conf->header_buffer_size;
    c->read = nxt_buf_mem_alloc(c->mem_pool, size, 0);

    c->socket.data = NULL;

    engine = task->thread->engine;
    c->read_work_queue = &engine->fast_work_queue;
    c->write_work_queue = &engine->fast_work_queue;

    c->read_state = &nxt_router_conn_read_header_state;

    nxt_conn_read(engine, c);
}


static const nxt_conn_state_t  nxt_router_conn_write_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_router_conn_ready,
    .close_handler = nxt_router_conn_close,
    .error_handler = nxt_router_conn_error,
};


static void
nxt_router_response_ready_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    size_t               dump_size;
    nxt_buf_t            *b, *last;
    nxt_conn_t           *c;
    nxt_req_conn_link_t  *rc;

    b = msg->buf;
    rc = data;

    c = rc->conn;

    dump_size = nxt_buf_used_size(b);

    if (dump_size > 300) {
        dump_size = 300;
    }

    nxt_debug(task, "%srouter app data (%z): %*s",
              msg->port_msg.last ? "last " : "", msg->size, dump_size,
              b->mem.pos);

    if (msg->size == 0) {
        b = NULL;
    }

    if (msg->port_msg.last != 0) {
        nxt_debug(task, "router data create last buf");

        last = nxt_buf_sync_alloc(c->mem_pool, NXT_BUF_SYNC_LAST);
        if (nxt_slow_path(last == NULL)) {
            /* TODO pogorevaTb */
        }

        nxt_buf_chain_add(&b, last);

        nxt_router_rc_unlink(task, rc);
    }

    if (b == NULL) {
        return;
    }

    if (msg->buf == b) {
        /* Disable instant buffer completion/re-using by port. */
        msg->buf = NULL;
    }

    if (c->write == NULL) {
        c->write = b;
        c->write_state = &nxt_router_conn_write_state;

        nxt_conn_write(task->thread->engine, c);

    } else {
        nxt_debug(task, "router data attach out bufs to existing chain");

        nxt_buf_chain_add(&c->write, b);
    }
}


static void
nxt_router_response_error_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_req_conn_link_t  *rc;

    rc = data;

    nxt_router_gen_error(task, rc->conn, 500,
                         "Application terminated unexpectedly");

    nxt_router_rc_unlink(task, rc);
}


nxt_inline const char *
nxt_router_text_by_code(int code)
{
    switch (code) {
    case 400: return "Bad request";
    case 404: return "Not found";
    case 403: return "Forbidden";
    case 408: return "Request Timeout";
    case 411: return "Length Required";
    case 413: return "Request Entity Too Large";
    case 500:
    default:  return "Internal server error";
    }
}


static nxt_buf_t *
nxt_router_get_error_buf(nxt_task_t *task, nxt_mp_t *mp, int code,
    const char* str)
{
    nxt_buf_t  *b, *last;

    b = nxt_buf_mem_alloc(mp, 16384, 0);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->mem.free = nxt_sprintf(b->mem.free, b->mem.end,
        "HTTP/1.0 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: close\r\n\r\n",
        code, nxt_router_text_by_code(code));

    b->mem.free = nxt_cpymem(b->mem.free, str, nxt_strlen(str));

    nxt_log_alert(task->log, "error %d: %s", code, str);

    last = nxt_buf_sync_alloc(mp, NXT_BUF_SYNC_LAST);

    if (nxt_slow_path(last == NULL)) {
        nxt_mp_free(mp, b);
        return NULL;
    }

    nxt_buf_chain_add(&b, last);

    return b;
}



static void
nxt_router_gen_error(nxt_task_t *task, nxt_conn_t *c, int code,
    const char* str)
{
    nxt_mp_t   *mp;
    nxt_buf_t  *b;

    /* TODO: fix when called in the middle of response */

    mp = c->mem_pool;

    b = nxt_router_get_error_buf(task, mp, code, str);

    if (c->socket.fd == -1) {
        nxt_mp_free(mp, b->next);
        nxt_mp_free(mp, b);
        return;
    }

    if (c->write == NULL) {
        c->write = b;
        c->write_state = &nxt_router_conn_write_state;

        nxt_conn_write(task->thread->engine, c);

    } else {
        nxt_debug(task, "router data attach out bufs to existing chain");

        nxt_buf_chain_add(&c->write, b);
    }
}


static void
nxt_router_app_port_ready(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_app_t   *app;
    nxt_port_t  *port;

    app = data;
    port = msg->u.new_port;

    nxt_assert(app != NULL);
    nxt_assert(port != NULL);

    port->app = app;

    nxt_thread_mutex_lock(&app->mutex);

    nxt_assert(app->pending_workers != 0);

    app->pending_workers--;
    app->workers++;

    nxt_thread_mutex_unlock(&app->mutex);

    nxt_debug(task, "app '%V' %p new port ready", &app->name, app);

    nxt_router_app_port_release(task, port, 0, 0);
}


static void
nxt_router_app_port_error(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_app_t           *app;
    nxt_queue_link_t    *lnk;
    nxt_req_app_link_t  *ra;

    app = data;

    nxt_assert(app != NULL);

    nxt_debug(task, "app '%V' %p start error", &app->name, app);

    nxt_thread_mutex_lock(&app->mutex);

    nxt_assert(app->pending_workers != 0);

    app->pending_workers--;

    if (!nxt_queue_is_empty(&app->requests)) {
        lnk = nxt_queue_last(&app->requests);
        nxt_queue_remove(lnk);
        lnk->next = NULL;

        ra = nxt_queue_link_data(lnk, nxt_req_app_link_t, link);

    } else {
        ra = NULL;
    }

    nxt_thread_mutex_unlock(&app->mutex);

    if (ra != NULL) {
        nxt_debug(task, "app '%V' %p abort next stream #%uD",
                  &app->name, app, ra->stream);

        nxt_router_ra_abort(task, ra, ra->work.data);
    }

    nxt_router_app_use(task, app, -1);
}


void
nxt_router_app_use(nxt_task_t *task, nxt_app_t *app, int i)
{
    int  c;

    c = nxt_atomic_fetch_add(&app->use_count, i);

    if (i < 0 && c == -i) {

        nxt_assert(app->live == 0);
        nxt_assert(app->workers == 0);
        nxt_assert(app->pending_workers == 0);
        nxt_assert(nxt_queue_is_empty(&app->requests) != 0);
        nxt_assert(nxt_queue_is_empty(&app->ports) != 0);

        nxt_thread_mutex_destroy(&app->mutex);
        nxt_free(app);
    }
}


nxt_inline nxt_port_t *
nxt_router_app_get_port_unsafe(nxt_app_t *app, int *use_delta)
{
    nxt_port_t        *port;
    nxt_queue_link_t  *lnk;

    lnk = nxt_queue_first(&app->ports);
    nxt_queue_remove(lnk);

    port = nxt_queue_link_data(lnk, nxt_port_t, app_link);

    port->app_requests++;

    if (app->live &&
         (app->max_pending_responses == 0 ||
            (port->app_requests - port->app_responses) <
                app->max_pending_responses) )
    {
        nxt_queue_insert_tail(&app->ports, lnk);

    } else {
        lnk->next = NULL;

        (*use_delta)--;
    }

    return port;
}


static nxt_port_t *
nxt_router_app_get_idle_port(nxt_app_t *app)
{
    nxt_port_t  *port;

    port = NULL;

    nxt_thread_mutex_lock(&app->mutex);

    nxt_queue_each(port, &app->ports, nxt_port_t, app_link) {

        if (port->app_requests > port->app_responses) {
            port = NULL;

            continue;
        }

        nxt_queue_remove(&port->app_link);
        port->app_link.next = NULL;

        break;

    } nxt_queue_loop;

    nxt_thread_mutex_unlock(&app->mutex);

    return port;
}


static void
nxt_router_app_process_request(nxt_task_t *task, void *obj, void *data)
{
    nxt_app_t           *app;
    nxt_req_app_link_t  *ra;

    app = obj;
    ra = data;

    nxt_assert(app != NULL);
    nxt_assert(ra != NULL);
    nxt_assert(ra->app_port != NULL);

    nxt_debug(task, "app '%V' %p process next stream #%uD",
              &app->name, app, ra->stream);

    nxt_router_process_http_request_mp(task, ra);
}


static void
nxt_router_app_port_release(nxt_task_t *task, nxt_port_t *port,
    uint32_t request_failed, uint32_t got_response)
{
    int                 use_delta, ra_use_delta;
    nxt_app_t           *app;
    nxt_queue_link_t    *lnk;
    nxt_req_app_link_t  *ra;

    nxt_assert(port != NULL);
    nxt_assert(port->app != NULL);

    app = port->app;

    use_delta = (request_failed == 0 && got_response == 0) ? 0 : -1;

    nxt_thread_mutex_lock(&app->mutex);

    port->app_requests -= request_failed;
    port->app_responses += got_response;

    if (app->live != 0 &&
        port->pair[1] != -1 &&
        port->app_link.next == NULL &&
        (app->max_pending_responses == 0 ||
            (port->app_requests - port->app_responses) <
                app->max_pending_responses) )
    {
        nxt_queue_insert_tail(&app->ports, &port->app_link);
        use_delta++;
    }

    if (app->live != 0 &&
        !nxt_queue_is_empty(&app->ports) &&
        !nxt_queue_is_empty(&app->requests))
    {
        lnk = nxt_queue_first(&app->requests);
        nxt_queue_remove(lnk);
        lnk->next = NULL;

        ra = nxt_queue_link_data(lnk, nxt_req_app_link_t, link);

        ra_use_delta = 1;
        ra->app_port = nxt_router_app_get_port_unsafe(app, &ra_use_delta);

    } else {
        ra = NULL;
        ra_use_delta = 0;
    }

    nxt_thread_mutex_unlock(&app->mutex);

    if (ra != NULL) {
        nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                           nxt_router_app_process_request,
                           &task->thread->engine->task, app, ra);

        goto adjust_use;
    }

    /* ? */
    if (port->pair[1] == -1) {
        nxt_debug(task, "app '%V' %p port %p already closed (pid %PI dead?)",
                  &app->name, app, port, port->pid);

        goto adjust_use;
    }

    if (app->live == 0) {
        nxt_debug(task, "app '%V' %p is not alive, send QUIT to port",
                  &app->name, app);

        nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT,
                              -1, 0, 0, NULL);

        goto adjust_use;
    }

    nxt_debug(task, "app '%V' %p requests queue is empty, keep the port",
              &app->name, app);

adjust_use:

    if (use_delta != 0) {
        nxt_port_use(task, port, use_delta);
    }

    if (ra_use_delta != 0) {
        nxt_port_use(task, ra->app_port, ra_use_delta);
    }
}


void
nxt_router_app_port_close(nxt_task_t *task, nxt_port_t *port)
{
    nxt_app_t   *app;
    nxt_bool_t  unchain, start_worker;

    app = port->app;

    nxt_assert(app != NULL);

    nxt_thread_mutex_lock(&app->mutex);

    unchain = port->app_link.next != NULL;

    if (unchain) {
        nxt_queue_remove(&port->app_link);
        port->app_link.next = NULL;
    }

    app->workers--;

    start_worker = app->live != 0 &&
                   nxt_queue_is_empty(&app->requests) == 0 &&
                   app->workers + app->pending_workers < app->max_workers;

    if (start_worker) {
        app->pending_workers++;
    }

    nxt_thread_mutex_unlock(&app->mutex);

    nxt_debug(task, "app '%V' %p port %p close", &app->name, app, port);

    if (unchain) {
        nxt_port_use(task, port, -1);
    }

    if (start_worker) {
        nxt_router_start_worker(task, app);
    }
}


static nxt_int_t
nxt_router_app_port(nxt_task_t *task, nxt_req_app_link_t *ra)
{
    int                      use_delta;
    nxt_int_t                res;
    nxt_app_t                *app;
    nxt_bool_t               can_start_worker;
    nxt_conn_t               *c;
    nxt_port_t               *port;
    nxt_event_engine_t       *engine;
    nxt_socket_conf_joint_t  *joint;

    port = NULL;
    use_delta = 1;
    c = ra->rc->conn;

    joint = c->listen->socket.data;
    app = joint->socket_conf->application;

    if (app == NULL) {
        nxt_router_gen_error(task, c, 500,
                             "Application is NULL in socket_conf");
        return NXT_ERROR;
    }

    ra->rc->app = app;

    nxt_router_app_use(task, app, 1);

    engine = task->thread->engine;

    nxt_timer_disable(engine, &c->read_timer);

    if (app->timeout != 0) {
        c->read_timer.handler = nxt_router_app_timeout;
        nxt_timer_add(engine, &c->read_timer, app->timeout);
    }

    can_start_worker = 0;

    nxt_thread_mutex_lock(&app->mutex);

    if (!nxt_queue_is_empty(&app->ports)) {
        port = nxt_router_app_get_port_unsafe(app, &use_delta);

    } else {
        ra = nxt_router_ra_create(task, ra);

        if (nxt_fast_path(ra != NULL)) {
            nxt_queue_insert_tail(&app->requests, &ra->link);

            can_start_worker = (app->workers + app->pending_workers) <
                                  app->max_workers;
            if (can_start_worker) {
                app->pending_workers++;
            }
        }

        port = NULL;
    }

    nxt_thread_mutex_unlock(&app->mutex);

    if (nxt_slow_path(ra == NULL)) {
        nxt_router_gen_error(task, c, 500, "Failed to allocate "
                             "req<->app link");
        return NXT_ERROR;
    }

    if (port != NULL) {
        nxt_debug(task, "already have port for app '%V' %p ", &app->name, app);

        ra->app_port = port;

        if (use_delta != 0) {
            nxt_port_use(task, port, use_delta);
        }
        return NXT_OK;
    }

    nxt_debug(task, "ra stream #%uD allocated", ra->stream);

    if (!can_start_worker) {
        nxt_debug(task, "app '%V' %p too many running or pending workers",
                  &app->name, app);

        return NXT_AGAIN;
    }

    res = nxt_router_start_worker(task, app);

    if (nxt_slow_path(res != NXT_OK)) {
        nxt_router_gen_error(task, c, 500, "Failed to start worker");

        return NXT_ERROR;
    }

    return NXT_AGAIN;
}


static void
nxt_router_conn_http_header_parse(nxt_task_t *task, void *obj, void *data)
{
    size_t                    size;
    nxt_int_t                 ret;
    nxt_buf_t                 *buf;
    nxt_conn_t                *c;
    nxt_sockaddr_t            *local;
    nxt_app_parse_ctx_t       *ap;
    nxt_app_request_body_t    *b;
    nxt_socket_conf_joint_t   *joint;
    nxt_app_request_header_t  *h;

    c = obj;
    ap = data;
    buf = c->read;
    joint = c->listen->socket.data;

    nxt_debug(task, "router conn http header parse");

    if (ap == NULL) {
        ap = nxt_app_http_req_init(task);
        if (nxt_slow_path(ap == NULL)) {
            nxt_router_gen_error(task, c, 500,
                                 "Failed to allocate parse context");
            return;
        }

        c->socket.data = ap;

        ap->r.remote.start = nxt_sockaddr_address(c->remote);
        ap->r.remote.length = c->remote->address_length;

        local = joint->socket_conf->sockaddr;
        ap->r.local.start = nxt_sockaddr_address(local);
        ap->r.local.length = local->address_length;

        ap->r.header.buf = buf;
    }

    h = &ap->r.header;
    b = &ap->r.body;

    ret = nxt_app_http_req_header_parse(task, ap, buf);

    nxt_debug(task, "http parse request header: %d", ret);

    switch (nxt_expect(NXT_DONE, ret)) {

    case NXT_DONE:
        nxt_debug(task, "router request header parsing complete, "
                  "content length: %O, preread: %uz",
                  h->parsed_content_length, nxt_buf_mem_used_size(&buf->mem));

        if (b->done) {
            nxt_router_process_http_request(task, c, ap);

            return;
        }

        if (joint->socket_conf->max_body_size > 0
            && (size_t) h->parsed_content_length
               > joint->socket_conf->max_body_size)
        {
            nxt_router_gen_error(task, c, 413, "Content-Length too big");
            return;
        }

        if (nxt_buf_mem_free_size(&buf->mem) == 0) {
            size = nxt_min(joint->socket_conf->body_buffer_size,
                           (size_t) h->parsed_content_length);

            buf->next = nxt_buf_mem_alloc(c->mem_pool, size, 0);
            if (nxt_slow_path(buf->next == NULL)) {
                nxt_router_gen_error(task, c, 500, "Failed to allocate "
                                     "buffer for request body");
                return;
            }

            c->read = buf->next;

            b->preread_size += nxt_buf_mem_used_size(&buf->mem);
        }

        if (b->buf == NULL) {
            b->buf = c->read;
        }

        c->read_state = &nxt_router_conn_read_body_state;
        break;

    case NXT_ERROR:
        nxt_router_gen_error(task, c, 400, "Request header parse error");
        return;

    default:  /* NXT_AGAIN */

        if (c->read->mem.free == c->read->mem.end) {
            size = joint->socket_conf->large_header_buffer_size;

            if (size <= (size_t) nxt_buf_mem_used_size(&buf->mem)
                || ap->r.header.bufs
                   >= joint->socket_conf->large_header_buffers)
            {
                nxt_router_gen_error(task, c, 413,
                                     "Too long request headers");
                return;
            }

            buf->next = nxt_buf_mem_alloc(c->mem_pool, size, 0);
            if (nxt_slow_path(buf->next == NULL)) {
                nxt_router_gen_error(task, c, 500,
                                     "Failed to allocate large header "
                                     "buffer");
                return;
            }

            ap->r.header.bufs++;

            size = c->read->mem.free - c->read->mem.pos;

            c->read = nxt_buf_cpy(buf->next, c->read->mem.pos, size);
        }

    }

    nxt_conn_read(task->thread->engine, c);
}


static void
nxt_router_conn_http_body_read(nxt_task_t *task, void *obj, void *data)
{
    size_t                    size;
    nxt_int_t                 ret;
    nxt_buf_t                 *buf;
    nxt_conn_t                *c;
    nxt_app_parse_ctx_t       *ap;
    nxt_app_request_body_t    *b;
    nxt_socket_conf_joint_t   *joint;
    nxt_app_request_header_t  *h;

    c = obj;
    ap = data;
    buf = c->read;

    nxt_debug(task, "router conn http body read");

    nxt_assert(ap != NULL);

    b = &ap->r.body;
    h = &ap->r.header;

    ret = nxt_app_http_req_body_read(task, ap, buf);

    nxt_debug(task, "http read request body: %d", ret);

    switch (nxt_expect(NXT_DONE, ret)) {

    case NXT_DONE:
        nxt_router_process_http_request(task, c, ap);
        return;

    case NXT_ERROR:
        nxt_router_gen_error(task, c, 500, "Read body error");
        return;

    default:  /* NXT_AGAIN */

        if (nxt_buf_mem_free_size(&buf->mem) == 0) {
            joint = c->listen->socket.data;

            b->preread_size += nxt_buf_mem_used_size(&buf->mem);

            size = nxt_min(joint->socket_conf->body_buffer_size,
                           (size_t) h->parsed_content_length - b->preread_size);

            buf->next = nxt_buf_mem_alloc(c->mem_pool, size, 0);
            if (nxt_slow_path(buf->next == NULL)) {
                nxt_router_gen_error(task, c, 500, "Failed to allocate "
                                     "buffer for request body");
                return;
            }

            c->read = buf->next;
        }

        nxt_debug(task, "router request body read again, rest: %uz",
                  h->parsed_content_length - b->preread_size);
    }

    nxt_conn_read(task->thread->engine, c);
}


static void
nxt_router_process_http_request(nxt_task_t *task, nxt_conn_t *c,
    nxt_app_parse_ctx_t *ap)
{
    nxt_int_t            res;
    nxt_port_t           *port;
    nxt_event_engine_t   *engine;
    nxt_req_app_link_t   ra_local, *ra;
    nxt_req_conn_link_t  *rc;

    engine = task->thread->engine;

    rc = nxt_port_rpc_register_handler_ex(task, engine->port,
                                          nxt_router_response_ready_handler,
                                          nxt_router_response_error_handler,
                                          sizeof(nxt_req_conn_link_t));

    if (nxt_slow_path(rc == NULL)) {
        nxt_router_gen_error(task, c, 500, "Failed to allocate "
                             "req<->conn link");

        return;
    }

    rc->stream = nxt_port_rpc_ex_stream(rc);
    rc->conn = c;

    nxt_queue_insert_tail(&c->requests, &rc->link);

    nxt_debug(task, "stream #%uD linked to conn %p at engine %p",
              rc->stream, c, engine);

    rc->ap = ap;
    c->socket.data = NULL;

    ra = &ra_local;
    nxt_router_ra_init(task, ra, rc);

    res = nxt_router_app_port(task, ra);

    if (res != NXT_OK) {
        return;
    }

    port = ra->app_port;

    if (nxt_slow_path(port == NULL)) {
        nxt_router_gen_error(task, c, 500, "Application port not found");
        return;
    }

    nxt_port_rpc_ex_set_peer(task, engine->port, rc, port->pid);

    nxt_router_process_http_request_mp(task, ra);
}


static void
nxt_router_process_http_request_mp(nxt_task_t *task, nxt_req_app_link_t *ra)
{
    uint32_t             request_failed;
    nxt_int_t            res;
    nxt_port_t           *port, *c_port, *reply_port;
    nxt_app_wmsg_t       wmsg;
    nxt_app_parse_ctx_t  *ap;

    nxt_assert(ra->app_port != NULL);

    port = ra->app_port;
    reply_port = ra->reply_port;
    ap = ra->ap;

    request_failed = 1;

    c_port = nxt_process_connected_port_find(port->process, reply_port->pid,
                                             reply_port->id);
    if (nxt_slow_path(c_port != reply_port)) {
        res = nxt_port_send_port(task, port, reply_port, 0);

        if (nxt_slow_path(res != NXT_OK)) {
            nxt_router_ra_error(task, ra, 500,
                                "Failed to send reply port to application");
            ra = NULL;
            goto release_port;
        }

        nxt_process_connected_port_add(port->process, reply_port);
    }

    wmsg.port = port;
    wmsg.write = NULL;
    wmsg.buf = &wmsg.write;
    wmsg.stream = ra->stream;

    res = port->app->prepare_msg(task, &ap->r, &wmsg);

    if (nxt_slow_path(res != NXT_OK)) {
        nxt_router_ra_error(task, ra, 500,
                            "Failed to prepare message for application");
        ra = NULL;
        goto release_port;
    }

    nxt_debug(task, "about to send %d bytes buffer to worker port %d",
                    nxt_buf_used_size(wmsg.write),
                    wmsg.port->socket.fd);

    request_failed = 0;

    res = nxt_port_socket_write(task, wmsg.port, NXT_PORT_MSG_DATA,
                                 -1, ra->stream, reply_port->id, wmsg.write);

    if (nxt_slow_path(res != NXT_OK)) {
        nxt_router_ra_error(task, ra, 500,
                            "Failed to send message to application");
        ra = NULL;
        goto release_port;
    }

release_port:

    nxt_router_app_port_release(task, port, request_failed, 0);

    if (ra != NULL) {
        if (request_failed != 0) {
            ra->app_port = 0;
        }

        nxt_router_ra_release(task, ra, ra->work.data);
    }
}


static nxt_int_t
nxt_python_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg)
{
    nxt_int_t                 rc;
    nxt_buf_t                 *b;
    nxt_http_field_t          *field;
    nxt_app_request_header_t  *h;

    static const nxt_str_t prefix = nxt_string("HTTP_");
    static const nxt_str_t eof = nxt_null_string;

    h = &r->header;

#define RC(S)                                                                 \
    do {                                                                      \
        rc = (S);                                                             \
        if (nxt_slow_path(rc != NXT_OK)) {                                    \
            goto fail;                                                        \
        }                                                                     \
    } while(0)

#define NXT_WRITE(N)                                                          \
    RC(nxt_app_msg_write_str(task, wmsg, N))

    /* TODO error handle, async mmap buffer assignment */

    NXT_WRITE(&h->method);
    NXT_WRITE(&h->target);

    if (h->path.start == h->target.start) {
        NXT_WRITE(&eof);

    } else {
        NXT_WRITE(&h->path);
    }

    if (h->query.start != NULL) {
        RC(nxt_app_msg_write_size(task, wmsg,
                                  h->query.start - h->target.start + 1));
    } else {
        RC(nxt_app_msg_write_size(task, wmsg, 0));
    }

    NXT_WRITE(&h->version);

    NXT_WRITE(&r->remote);
    NXT_WRITE(&r->local);

    NXT_WRITE(&h->host);
    NXT_WRITE(&h->content_type);
    NXT_WRITE(&h->content_length);

    nxt_list_each(field, h->fields) {
        RC(nxt_app_msg_write_prefixed_upcase(task, wmsg,
                                             &prefix, &field->name));
        NXT_WRITE(&field->value);

    } nxt_list_loop;

    /* end-of-headers mark */
    NXT_WRITE(&eof);

    RC(nxt_app_msg_write_size(task, wmsg, r->body.preread_size));

    for(b = r->body.buf; b != NULL; b = b->next) {
        RC(nxt_app_msg_write_raw(task, wmsg, b->mem.pos,
                                 nxt_buf_mem_used_size(&b->mem)));
    }

#undef NXT_WRITE
#undef RC

    return NXT_OK;

fail:

    return NXT_ERROR;
}


static nxt_int_t
nxt_php_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg)
{
    nxt_int_t                 rc;
    nxt_buf_t                 *b;
    nxt_bool_t                method_is_post;
    nxt_http_field_t          *field;
    nxt_app_request_header_t  *h;

    static const nxt_str_t prefix = nxt_string("HTTP_");
    static const nxt_str_t eof = nxt_null_string;

    h = &r->header;

#define RC(S)                                                                 \
    do {                                                                      \
        rc = (S);                                                             \
        if (nxt_slow_path(rc != NXT_OK)) {                                    \
            goto fail;                                                        \
        }                                                                     \
    } while(0)

#define NXT_WRITE(N)                                                          \
    RC(nxt_app_msg_write_str(task, wmsg, N))

    /* TODO error handle, async mmap buffer assignment */

    NXT_WRITE(&h->method);
    NXT_WRITE(&h->target);

    if (h->path.start == h->target.start) {
        NXT_WRITE(&eof);

    } else {
        NXT_WRITE(&h->path);
    }

    if (h->query.start != NULL) {
        RC(nxt_app_msg_write_size(task, wmsg,
                                  h->query.start - h->target.start + 1));
    } else {
        RC(nxt_app_msg_write_size(task, wmsg, 0));
    }

    NXT_WRITE(&h->version);

    // PHP_SELF
    // SCRIPT_NAME
    // SCRIPT_FILENAME
    // DOCUMENT_ROOT

    NXT_WRITE(&r->remote);
    NXT_WRITE(&r->local);

    NXT_WRITE(&h->host);
    NXT_WRITE(&h->cookie);
    NXT_WRITE(&h->content_type);
    NXT_WRITE(&h->content_length);

    RC(nxt_app_msg_write_size(task, wmsg, h->parsed_content_length));
    RC(nxt_app_msg_write_size(task, wmsg, r->body.preread_size));

    method_is_post = h->method.length == 4 &&
                     h->method.start[0] == 'P' &&
                     h->method.start[1] == 'O' &&
                     h->method.start[2] == 'S' &&
                     h->method.start[3] == 'T';

    if (method_is_post) {
        for(b = r->body.buf; b != NULL; b = b->next) {
            RC(nxt_app_msg_write_raw(task, wmsg, b->mem.pos,
                                     nxt_buf_mem_used_size(&b->mem)));
        }
    }

    nxt_list_each(field, h->fields) {
        RC(nxt_app_msg_write_prefixed_upcase(task, wmsg,
                                             &prefix, &field->name));
        NXT_WRITE(&field->value);

    } nxt_list_loop;

    /* end-of-headers mark */
    NXT_WRITE(&eof);

    if (!method_is_post) {
        for(b = r->body.buf; b != NULL; b = b->next) {
            RC(nxt_app_msg_write_raw(task, wmsg, b->mem.pos,
                                     nxt_buf_mem_used_size(&b->mem)));
        }
    }

#undef NXT_WRITE
#undef RC

    return NXT_OK;

fail:

    return NXT_ERROR;
}


static nxt_int_t
nxt_go_prepare_msg(nxt_task_t *task, nxt_app_request_t *r, nxt_app_wmsg_t *wmsg)
{
    nxt_int_t                 rc;
    nxt_buf_t                 *b;
    nxt_http_field_t          *field;
    nxt_app_request_header_t  *h;

    static const nxt_str_t eof = nxt_null_string;

    h = &r->header;

#define RC(S)                                                                 \
    do {                                                                      \
        rc = (S);                                                             \
        if (nxt_slow_path(rc != NXT_OK)) {                                    \
            goto fail;                                                        \
        }                                                                     \
    } while(0)

#define NXT_WRITE(N)                                                          \
    RC(nxt_app_msg_write_str(task, wmsg, N))

    /* TODO error handle, async mmap buffer assignment */

    NXT_WRITE(&h->method);
    NXT_WRITE(&h->target);

    if (h->path.start == h->target.start) {
        NXT_WRITE(&eof);

    } else {
        NXT_WRITE(&h->path);
    }

    if (h->query.start != NULL) {
        RC(nxt_app_msg_write_size(task, wmsg,
                                  h->query.start - h->target.start + 1));
    } else {
        RC(nxt_app_msg_write_size(task, wmsg, 0));
    }

    NXT_WRITE(&h->version);
    NXT_WRITE(&r->remote);

    NXT_WRITE(&h->host);
    NXT_WRITE(&h->cookie);
    NXT_WRITE(&h->content_type);
    NXT_WRITE(&h->content_length);

    RC(nxt_app_msg_write_size(task, wmsg, h->parsed_content_length));

    nxt_list_each(field, h->fields) {
        NXT_WRITE(&field->name);
        NXT_WRITE(&field->value);

    } nxt_list_loop;

    /* end-of-headers mark */
    NXT_WRITE(&eof);

    RC(nxt_app_msg_write_size(task, wmsg, r->body.preread_size));

    for(b = r->body.buf; b != NULL; b = b->next) {
        RC(nxt_app_msg_write_raw(task, wmsg, b->mem.pos,
                                 nxt_buf_mem_used_size(&b->mem)));
    }

#undef NXT_WRITE
#undef RC

    return NXT_OK;

fail:

    return NXT_ERROR;
}


static const nxt_conn_state_t  nxt_router_conn_close_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_router_conn_free,
};


static void
nxt_router_conn_ready(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t         *b;
    nxt_bool_t        last;
    nxt_conn_t        *c;
    nxt_work_queue_t  *wq;

    nxt_debug(task, "router conn ready %p", obj);

    c = obj;
    b = c->write;

    wq = &task->thread->engine->fast_work_queue;

    last = 0;

    while (b != NULL) {
        if (!nxt_buf_is_sync(b)) {
            if (nxt_buf_used_size(b) > 0) {
                break;
            }
        }

        if (nxt_buf_is_last(b)) {
            last = 1;
        }

        nxt_work_queue_add(wq, b->completion_handler, task, b, b->parent);

        b = b->next;
    }

    c->write = b;

    if (b != NULL) {
        nxt_debug(task, "router conn %p has more data to write", obj);

        nxt_conn_write(task->thread->engine, c);

    } else {
        nxt_debug(task, "router conn %p no more data to write, last = %d", obj,
                  last);

        if (last != 0) {
            nxt_debug(task, "enqueue router conn close %p (ready handler)", c);

            nxt_work_queue_add(wq, nxt_router_conn_close, task, c,
                               c->socket.data);
        }
    }
}


static void
nxt_router_conn_close(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "router conn close");

    c->write_state = &nxt_router_conn_close_state;

    nxt_conn_close(task->thread->engine, c);
}


static void
nxt_router_conn_mp_cleanup(nxt_task_t *task, void *obj, void *data)
{
    nxt_socket_conf_joint_t  *joint;

    joint = obj;

    nxt_router_conf_release(task, joint);
}


static void
nxt_router_conn_free(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t               *c;
    nxt_event_engine_t       *engine;
    nxt_req_conn_link_t      *rc;
    nxt_app_parse_ctx_t      *ap;
    nxt_socket_conf_joint_t  *joint;

    c = obj;
    ap = data;

    nxt_debug(task, "router conn close done");

    if (ap != NULL) {
        nxt_app_http_req_done(task, ap);

        c->socket.data = NULL;
    }

    nxt_queue_each(rc, &c->requests, nxt_req_conn_link_t, link) {

        nxt_debug(task, "conn %p close, stream #%uD", c, rc->stream);

        nxt_router_rc_unlink(task, rc);

        nxt_port_rpc_cancel(task, task->thread->engine->port, rc->stream);

    } nxt_queue_loop;

    nxt_queue_remove(&c->link);

    engine = task->thread->engine;

    nxt_sockaddr_cache_free(engine, c);

    joint = c->listen->socket.data;

    nxt_mp_cleanup(c->mem_pool, nxt_router_conn_mp_cleanup,
                   &engine->task, joint, NULL);

    nxt_mp_release(c->mem_pool, c);
}


static void
nxt_router_conn_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "router conn error");

    if (c->socket.fd != -1) {
        c->write_state = &nxt_router_conn_close_state;

        nxt_conn_close(task->thread->engine, c);
    }
}


static void
nxt_router_conn_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t   *c;
    nxt_timer_t  *timer;

    timer = obj;

    nxt_debug(task, "router conn timeout");

    c = nxt_read_timer_conn(timer);

    if (c->read_state == &nxt_router_conn_read_header_state) {
        nxt_router_gen_error(task, c, 408, "Read header timeout");

    } else {
        nxt_router_gen_error(task, c, 408, "Read body timeout");
    }
}


static void
nxt_router_app_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t   *c;
    nxt_timer_t  *timer;

    timer = obj;

    nxt_debug(task, "router app timeout");

    c = nxt_read_timer_conn(timer);

    nxt_router_gen_error(task, c, 408, "Application timeout");
}


static nxt_msec_t
nxt_router_conn_timeout_value(nxt_conn_t *c, uintptr_t data)
{
    nxt_socket_conf_joint_t  *joint;

    joint = c->listen->socket.data;

    return nxt_value_at(nxt_msec_t, joint->socket_conf, data);
}
