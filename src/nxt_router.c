
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_conf.h>
#include <nxt_http.h>


typedef struct {
    nxt_str_t         type;
    uint32_t          processes;
    uint32_t          max_processes;
    uint32_t          spare_processes;
    nxt_msec_t        timeout;
    nxt_msec_t        res_timeout;
    nxt_msec_t        idle_timeout;
    uint32_t          requests;
    nxt_conf_value_t  *limits_value;
    nxt_conf_value_t  *processes_value;
} nxt_router_app_conf_t;


typedef struct {
    nxt_str_t  application;
} nxt_router_listener_conf_t;


typedef struct nxt_msg_info_s {
    nxt_buf_t                 *buf;
    nxt_port_mmap_tracking_t  tracking;
    nxt_work_handler_t        completion_handler;
} nxt_msg_info_t;


typedef struct nxt_req_app_link_s nxt_req_app_link_t;


typedef struct {
    uint32_t                 stream;
    nxt_app_t                *app;
    nxt_port_t               *app_port;
    nxt_app_parse_ctx_t      *ap;
    nxt_msg_info_t           msg_info;
    nxt_req_app_link_t       *ra;

    nxt_queue_link_t         link;     /* for nxt_conn_t.requests */
} nxt_req_conn_link_t;


struct nxt_req_app_link_s {
    uint32_t             stream;
    nxt_atomic_t         use_count;
    nxt_port_t           *app_port;
    nxt_port_t           *reply_port;
    nxt_app_parse_ctx_t  *ap;
    nxt_msg_info_t       msg_info;
    nxt_req_conn_link_t  *rc;

    nxt_nsec_t           res_time;

    nxt_queue_link_t     link_app_requests; /* for nxt_app_t.requests */
    nxt_queue_link_t     link_port_pending; /* for nxt_port_t.pending_requests */
    nxt_queue_link_t     link_app_pending;  /* for nxt_app_t.pending */

    nxt_mp_t             *mem_pool;
    nxt_work_t           work;

    int                  err_code;
    const char           *err_str;
};


typedef struct {
    nxt_socket_conf_t       *socket_conf;
    nxt_router_temp_conf_t  *temp_conf;
} nxt_socket_rpc_t;


typedef struct {
    nxt_app_t               *app;
    nxt_router_temp_conf_t  *temp_conf;
} nxt_app_rpc_t;


struct nxt_port_select_state_s {
    nxt_app_t           *app;
    nxt_req_app_link_t  *ra;

    nxt_port_t          *failed_port;
    int                 failed_port_use_delta;

    uint8_t             start_process;    /* 1 bit */
    nxt_req_app_link_t  *shared_ra;
    nxt_port_t          *port;
};

typedef struct nxt_port_select_state_s nxt_port_select_state_t;

static void nxt_router_greet_controller(nxt_task_t *task,
    nxt_port_t *controller_port);

static void nxt_router_port_select(nxt_task_t *task,
    nxt_port_select_state_t *state);

static nxt_int_t nxt_router_port_post_select(nxt_task_t *task,
    nxt_port_select_state_t *state);

static nxt_int_t nxt_router_start_app_process(nxt_task_t *task, nxt_app_t *app);

nxt_inline void
nxt_router_ra_inc_use(nxt_req_app_link_t *ra)
{
    nxt_atomic_fetch_add(&ra->use_count, 1);
}

nxt_inline void
nxt_router_ra_dec_use(nxt_req_app_link_t *ra)
{
#if (NXT_DEBUG)
    int  c;

    c = nxt_atomic_fetch_add(&ra->use_count, -1);

    nxt_assert(c > 1);
#else
    (void) nxt_atomic_fetch_add(&ra->use_count, -1);
#endif
}

static void nxt_router_ra_use(nxt_task_t *task, nxt_req_app_link_t *ra, int i);

static nxt_router_temp_conf_t *nxt_router_temp_conf(nxt_task_t *task);
static void nxt_router_conf_apply(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conf_ready(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
static void nxt_router_conf_error(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
static void nxt_router_conf_send(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_port_msg_type_t type);

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
static void nxt_router_app_rpc_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_app_t *app);
static void nxt_router_app_prefork_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_app_prefork_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static nxt_socket_conf_t *nxt_router_socket_conf(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_str_t *name);
static nxt_int_t nxt_router_listen_socket_find(nxt_router_temp_conf_t *tmcf,
    nxt_socket_conf_t *nskcf, nxt_sockaddr_t *sa);

static nxt_int_t nxt_router_engines_create(nxt_task_t *task,
    nxt_router_t *router, nxt_router_temp_conf_t *tmcf,
    const nxt_event_interface_t *interface);
static nxt_int_t nxt_router_engine_conf_create(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf);
static nxt_int_t nxt_router_engine_conf_update(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf);
static nxt_int_t nxt_router_engine_conf_delete(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf);
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
static void nxt_router_thread_exit_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_listen_socket_release(nxt_task_t *task,
    nxt_socket_conf_t *skcf);

static void nxt_router_access_log_writer(nxt_task_t *task,
    nxt_http_request_t *r, nxt_router_access_log_t *access_log);
static u_char *nxt_router_access_log_date(u_char *buf, nxt_realtime_t *now,
    struct tm *tm, size_t size, const char *format);
static void nxt_router_access_log_open(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
static void nxt_router_access_log_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_access_log_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_access_log_release(nxt_task_t *task,
    nxt_thread_spinlock_t *lock, nxt_router_access_log_t *access_log);
static void nxt_router_access_log_reopen_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_access_log_reopen_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_access_log_reopen_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);

static void nxt_router_app_port_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_app_port_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);

static void nxt_router_app_quit(nxt_task_t *task, nxt_app_t *app);
static void nxt_router_app_port_release(nxt_task_t *task, nxt_port_t *port,
    uint32_t request_failed, uint32_t got_response);
static nxt_int_t nxt_router_app_port(nxt_task_t *task, nxt_app_t *app,
    nxt_req_app_link_t *ra);

static void nxt_router_app_prepare_request(nxt_task_t *task,
    nxt_req_app_link_t *ra);
static nxt_int_t nxt_python_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg);
static nxt_int_t nxt_php_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg);
static nxt_int_t nxt_go_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg);
static nxt_int_t nxt_perl_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg);
static nxt_int_t nxt_ruby_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg);

static void nxt_router_app_timeout(nxt_task_t *task, void *obj, void *data);
static void nxt_router_adjust_idle_timer(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_app_idle_timeout(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_app_release_handler(nxt_task_t *task, void *obj,
    void *data);

static const nxt_http_request_state_t  nxt_http_request_send_state;
static void nxt_http_request_send_body(nxt_task_t *task, void *obj, void *data);

static nxt_router_t  *nxt_router;


static nxt_app_prepare_msg_t  nxt_app_prepare_msg[] = {
    nxt_python_prepare_msg,
    nxt_php_prepare_msg,
    nxt_go_prepare_msg,
    nxt_perl_prepare_msg,
    nxt_ruby_prepare_msg,
};


nxt_port_handlers_t  nxt_router_process_port_handlers = {
    .quit         = nxt_worker_process_quit_handler,
    .new_port     = nxt_router_new_port_handler,
    .change_file  = nxt_port_change_log_file_handler,
    .mmap         = nxt_port_mmap_handler,
    .data         = nxt_router_conf_data_handler,
    .remove_pid   = nxt_router_remove_pid_handler,
    .access_log   = nxt_router_access_log_reopen_handler,
    .rpc_ready    = nxt_port_rpc_handler,
    .rpc_error    = nxt_port_rpc_handler,
};


nxt_int_t
nxt_router_start(nxt_task_t *task, void *data)
{
    nxt_int_t      ret;
    nxt_port_t     *controller_port;
    nxt_router_t   *router;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    ret = nxt_http_init(task, rt);
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

    controller_port = rt->port_by_type[NXT_PROCESS_CONTROLLER];
    if (controller_port != NULL) {
        nxt_router_greet_controller(task, controller_port);
    }

    return NXT_OK;
}


static void
nxt_router_greet_controller(nxt_task_t *task, nxt_port_t *controller_port)
{
    nxt_port_socket_write(task, controller_port, NXT_PORT_MSG_PROCESS_READY,
                          -1, 0, 0, NULL);
}


static void
nxt_router_start_app_process_handler(nxt_task_t *task, nxt_port_t *port,
    void *data)
{
    size_t         size;
    uint32_t       stream;
    nxt_mp_t       *mp;
    nxt_int_t      ret;
    nxt_app_t      *app;
    nxt_buf_t      *b;
    nxt_port_t     *main_port;
    nxt_runtime_t  *rt;

    app = data;

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];

    nxt_debug(task, "app '%V' %p start process", &app->name, app);

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
        goto failed;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_START_WORKER, -1,
                                stream, port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, port, stream);
        goto failed;
    }

    return;

failed:

    if (b != NULL) {
        mp = b->data;
        nxt_mp_free(mp, b);
        nxt_mp_release(mp);
    }

    nxt_thread_mutex_lock(&app->mutex);

    app->pending_processes--;

    nxt_thread_mutex_unlock(&app->mutex);

    nxt_router_app_use(task, app, -1);
}


static nxt_int_t
nxt_router_start_app_process(nxt_task_t *task, nxt_app_t *app)
{
    nxt_int_t      res;
    nxt_port_t     *router_port;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    nxt_router_app_use(task, app, 1);

    res = nxt_port_post(task, router_port, nxt_router_start_app_process_handler,
                        app);

    if (res == NXT_OK) {
        return res;
    }

    nxt_thread_mutex_lock(&app->mutex);

    app->pending_processes--;

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
    ra->use_count = 1;
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

    if (ra_src->mem_pool != NULL) {
        return ra_src;
    }

    mp = ra_src->ap->mem_pool;

    ra = nxt_mp_alloc(mp, sizeof(nxt_req_app_link_t));

    if (nxt_slow_path(ra == NULL)) {

        ra_src->rc->ra = NULL;
        ra_src->rc = NULL;

        return NULL;
    }

    nxt_mp_retain(mp);

    nxt_router_ra_init(task, ra, ra_src->rc);

    ra->mem_pool = mp;

    return ra;
}


nxt_inline nxt_bool_t
nxt_router_msg_cancel(nxt_task_t *task, nxt_msg_info_t *msg_info,
    uint32_t stream)
{
    nxt_buf_t   *b, *next;
    nxt_bool_t  cancelled;

    if (msg_info->buf == NULL) {
        return 0;
    }

    cancelled = nxt_port_mmap_tracking_cancel(task, &msg_info->tracking,
                                              stream);

    if (cancelled) {
        nxt_debug(task, "stream #%uD: cancelled by router", stream);
    }

    for (b = msg_info->buf; b != NULL; b = next) {
        next = b->next;

        b->completion_handler = msg_info->completion_handler;

        if (b->is_port_mmap_sent) {
            b->is_port_mmap_sent = cancelled == 0;
            b->completion_handler(task, b, b->parent);
        }
    }

    msg_info->buf = NULL;

    return cancelled;
}


static void
nxt_router_ra_update_peer(nxt_task_t *task, nxt_req_app_link_t *ra);


static void
nxt_router_ra_update_peer_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_req_app_link_t  *ra;

    ra = obj;

    nxt_router_ra_update_peer(task, ra);

    nxt_router_ra_use(task, ra, -1);
}


static void
nxt_router_ra_update_peer(nxt_task_t *task, nxt_req_app_link_t *ra)
{
    nxt_event_engine_t   *engine;
    nxt_req_conn_link_t  *rc;

    engine = ra->work.data;

    if (task->thread->engine != engine) {
        nxt_router_ra_inc_use(ra);

        ra->work.handler = nxt_router_ra_update_peer_handler;
        ra->work.task = &engine->task;
        ra->work.next = NULL;

        nxt_debug(task, "ra stream #%uD post update peer to %p",
                  ra->stream, engine);

        nxt_event_engine_post(engine, &ra->work);

        return;
    }

    nxt_debug(task, "ra stream #%uD update peer", ra->stream);

    rc = ra->rc;

    if (rc != NULL && ra->app_port != NULL) {
        nxt_port_rpc_ex_set_peer(task, engine->port, rc, ra->app_port->pid);
    }

    nxt_router_ra_use(task, ra, -1);
}


static void
nxt_router_ra_release(nxt_task_t *task, nxt_req_app_link_t *ra)
{
    nxt_mp_t                *mp;
    nxt_req_conn_link_t     *rc;

    nxt_assert(task->thread->engine == ra->work.data);
    nxt_assert(ra->use_count == 0);

    nxt_debug(task, "ra stream #%uD release", ra->stream);

    rc = ra->rc;

    if (rc != NULL) {
        if (nxt_slow_path(ra->err_code != 0)) {
            nxt_http_request_error(task, rc->ap->request, ra->err_code);

        } else {
            rc->app_port = ra->app_port;
            rc->msg_info = ra->msg_info;

            if (rc->app->timeout != 0) {
                rc->ap->timer.handler = nxt_router_app_timeout;
                rc->ap->timer_data = rc;
                nxt_timer_add(task->thread->engine, &rc->ap->timer,
                              rc->app->timeout);
            }

            ra->app_port = NULL;
            ra->msg_info.buf = NULL;
        }

        rc->ra = NULL;
        ra->rc = NULL;
    }

    if (ra->app_port != NULL) {
        nxt_router_app_port_release(task, ra->app_port, 0, 1);

        ra->app_port = NULL;
    }

    nxt_router_msg_cancel(task, &ra->msg_info, ra->stream);

    mp = ra->mem_pool;

    if (mp != NULL) {
        nxt_mp_free(mp, ra);
        nxt_mp_release(mp);
    }
}


static void
nxt_router_ra_release_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_req_app_link_t  *ra;

    ra = obj;

    nxt_assert(ra->work.data == data);

    nxt_atomic_fetch_add(&ra->use_count, -1);

    nxt_router_ra_release(task, ra);
}


static void
nxt_router_ra_use(nxt_task_t *task, nxt_req_app_link_t *ra, int i)
{
    int                 c;
    nxt_event_engine_t  *engine;

    c = nxt_atomic_fetch_add(&ra->use_count, i);

    if (i < 0 && c == -i) {
        engine = ra->work.data;

        if (task->thread->engine == engine) {
            nxt_router_ra_release(task, ra);

            return;
        }

        nxt_router_ra_inc_use(ra);

        ra->work.handler = nxt_router_ra_release_handler;
        ra->work.task = &engine->task;
        ra->work.next = NULL;

        nxt_debug(task, "ra stream #%uD post release to %p",
                  ra->stream, engine);

        nxt_event_engine_post(engine, &ra->work);
    }
}


nxt_inline void
nxt_router_ra_error(nxt_req_app_link_t *ra, int code, const char *str)
{
    ra->app_port = NULL;
    ra->err_code = code;
    ra->err_str = str;
}


nxt_inline void
nxt_router_ra_pending(nxt_task_t *task, nxt_app_t *app, nxt_req_app_link_t *ra)
{
    nxt_queue_insert_tail(&ra->app_port->pending_requests,
                          &ra->link_port_pending);
    nxt_queue_insert_tail(&app->pending, &ra->link_app_pending);

    nxt_router_ra_inc_use(ra);

    ra->res_time = nxt_thread_monotonic_time(task->thread) + app->res_timeout;

    nxt_debug(task, "ra stream #%uD enqueue to pending_requests", ra->stream);
}


nxt_inline nxt_bool_t
nxt_queue_chk_remove(nxt_queue_link_t *lnk)
{
    if (lnk->next != NULL) {
        nxt_queue_remove(lnk);

        lnk->next = NULL;

        return 1;
    }

    return 0;
}


nxt_inline void
nxt_router_rc_unlink(nxt_task_t *task, nxt_req_conn_link_t *rc)
{
    int                 ra_use_delta;
    nxt_req_app_link_t  *ra;

    if (rc->app_port != NULL) {
        nxt_router_app_port_release(task, rc->app_port, 0, 1);

        rc->app_port = NULL;
    }

    nxt_router_msg_cancel(task, &rc->msg_info, rc->stream);

    ra = rc->ra;

    if (ra != NULL) {
        rc->ra = NULL;
        ra->rc = NULL;

        ra_use_delta = 0;

        nxt_thread_mutex_lock(&rc->app->mutex);

        if (ra->link_app_requests.next == NULL
            && ra->link_port_pending.next == NULL
            && ra->link_app_pending.next == NULL)
        {
            ra = NULL;

        } else {
            ra_use_delta -= nxt_queue_chk_remove(&ra->link_app_requests);
            ra_use_delta -= nxt_queue_chk_remove(&ra->link_port_pending);
            nxt_queue_chk_remove(&ra->link_app_pending);
        }

        nxt_thread_mutex_unlock(&rc->app->mutex);

        if (ra != NULL) {
            nxt_router_ra_use(task, ra, ra_use_delta);
        }
    }

    if (rc->app != NULL) {
        nxt_router_app_use(task, rc->app, -1);

        rc->app = NULL;
    }

    if (rc->ap != NULL) {
        rc->ap->timer_data = NULL;

        nxt_app_http_req_done(task, rc->ap);

        rc->ap = NULL;
    }
}


void
nxt_router_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_new_port_handler(task, msg);

    if (msg->u.new_port != NULL
        && msg->u.new_port->type == NXT_PROCESS_CONTROLLER)
    {
        nxt_router_greet_controller(task, msg->u.new_port);
    }

    if (msg->port_msg.stream == 0) {
        return;
    }

    if (msg->u.new_port == NULL
        || msg->u.new_port->type != NXT_PROCESS_WORKER)
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

    nxt_debug(task, "nxt_router_conf_data_handler(%O): %*s",
              nxt_buf_used_size(msg->buf),
              (size_t) nxt_buf_used_size(msg->buf), msg->buf->mem.pos);

    tmcf->router_conf->router = nxt_router;
    tmcf->stream = msg->port_msg.stream;
    tmcf->port = nxt_runtime_port_find(task->thread->runtime,
                                       msg->port_msg.pid,
                                       msg->port_msg.reply_port);

    b = nxt_buf_chk_make_plain(tmcf->router_conf->mem_pool,
                               msg->buf, msg->size);
    if (nxt_slow_path(b == NULL)) {
        nxt_router_conf_error(task, tmcf);

        return;
    }

    ret = nxt_router_conf_create(task, tmcf, b->mem.pos, b->mem.free);

    if (nxt_fast_path(ret == NXT_OK)) {
        nxt_router_conf_apply(task, tmcf, NULL);

    } else {
        nxt_router_conf_error(task, tmcf);
    }
}


static void
nxt_router_app_process_remove_pid(nxt_task_t *task, nxt_port_t *port,
    void *data)
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
        nxt_port_post(task, engine->port, nxt_router_app_process_remove_pid,
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
    tmcf->router_conf = rtcf;
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


nxt_inline nxt_bool_t
nxt_router_app_can_start(nxt_app_t *app)
{
    return app->processes + app->pending_processes < app->max_processes
            && app->pending_processes < app->max_pending_processes;
}


nxt_inline nxt_bool_t
nxt_router_app_need_start(nxt_app_t *app)
{
    return app->idle_processes + app->pending_processes
            < app->spare_processes;
}


static void
nxt_router_conf_apply(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t                    ret;
    nxt_app_t                    *app;
    nxt_router_t                 *router;
    nxt_runtime_t                *rt;
    nxt_queue_link_t             *qlk;
    nxt_socket_conf_t            *skcf;
    nxt_router_conf_t            *rtcf;
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

    nxt_queue_each(app, &tmcf->apps, nxt_app_t, link) {

        if (nxt_router_app_need_start(app)) {
            nxt_router_app_rpc_create(task, tmcf, app);
            return;
        }

    } nxt_queue_loop;

    rtcf = tmcf->router_conf;

    if (rtcf->access_log != NULL && rtcf->access_log->fd == -1) {
        nxt_router_access_log_open(task, tmcf);
        return;
    }

    rt = task->thread->runtime;

    interface = nxt_service_get(rt->services, "engine", NULL);

    router = rtcf->router;

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

    router->access_log = rtcf->access_log;

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
    nxt_app_t          *app;
    nxt_queue_t        new_socket_confs;
    nxt_socket_t       s;
    nxt_router_t       *router;
    nxt_queue_link_t   *qlk;
    nxt_socket_conf_t  *skcf;
    nxt_router_conf_t  *rtcf;

    nxt_alert(task, "failed to apply new conf");

    for (qlk = nxt_queue_first(&tmcf->creating);
         qlk != nxt_queue_tail(&tmcf->creating);
         qlk = nxt_queue_next(qlk))
    {
        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);
        s = skcf->listen->socket;

        if (s != -1) {
            nxt_socket_close(task, s);
        }

        nxt_free(skcf->listen);
    }

    nxt_queue_init(&new_socket_confs);
    nxt_queue_add(&new_socket_confs, &tmcf->updating);
    nxt_queue_add(&new_socket_confs, &tmcf->pending);
    nxt_queue_add(&new_socket_confs, &tmcf->creating);

    nxt_queue_each(skcf, &new_socket_confs, nxt_socket_conf_t, link) {

        if (skcf->application != NULL) {
            nxt_router_app_use(task, skcf->application, -1);
            skcf->application = NULL;
        }

    } nxt_queue_loop;

    nxt_queue_each(app, &tmcf->apps, nxt_app_t, link) {

        nxt_router_app_quit(task, app);

    } nxt_queue_loop;

    rtcf = tmcf->router_conf;
    router = rtcf->router;

    nxt_queue_add(&router->sockets, &tmcf->keeping);
    nxt_queue_add(&router->sockets, &tmcf->deleting);

    nxt_queue_add(&router->apps, &tmcf->previous);

    // TODO: new engines and threads

    nxt_router_access_log_release(task, &router->lock, rtcf->access_log);

    nxt_mp_destroy(rtcf->mem_pool);

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
        nxt_string("limits"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_router_app_conf_t, limits_value),
    },

    {
        nxt_string("processes"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_router_app_conf_t, processes),
    },

    {
        nxt_string("processes"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_router_app_conf_t, processes_value),
    },
};


static nxt_conf_map_t  nxt_router_app_limits_conf[] = {
    {
        nxt_string("timeout"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_router_app_conf_t, timeout),
    },

    {
        nxt_string("reschedule_timeout"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_router_app_conf_t, res_timeout),
    },

    {
        nxt_string("requests"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_router_app_conf_t, requests),
    },
};


static nxt_conf_map_t  nxt_router_app_processes_conf[] = {
    {
        nxt_string("spare"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_router_app_conf_t, spare_processes),
    },

    {
        nxt_string("max"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_router_app_conf_t, max_processes),
    },

    {
        nxt_string("idle_timeout"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_router_app_conf_t, idle_timeout),
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
        nxt_string("idle_timeout"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_socket_conf_t, idle_timeout),
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

    {
        nxt_string("send_timeout"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_socket_conf_t, send_timeout),
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
    nxt_str_t                   name, path;
    nxt_app_t                   *app, *prev;
    nxt_router_t                *router;
    nxt_conf_value_t            *conf, *http, *value;
    nxt_conf_value_t            *applications, *application;
    nxt_conf_value_t            *listeners, *listener;
    nxt_socket_conf_t           *skcf;
    nxt_event_engine_t          *engine;
    nxt_app_lang_module_t       *lang;
    nxt_router_app_conf_t       apcf;
    nxt_router_access_log_t     *access_log;
    nxt_router_listener_conf_t  lscf;

    static nxt_str_t  http_path = nxt_string("/settings/http");
    static nxt_str_t  applications_path = nxt_string("/applications");
    static nxt_str_t  listeners_path = nxt_string("/listeners");
    static nxt_str_t  access_log_path = nxt_string("/access_log");

    conf = nxt_conf_json_parse(tmcf->mem_pool, start, end, NULL);
    if (conf == NULL) {
        nxt_alert(task, "configuration parsing error");
        return NXT_ERROR;
    }

    mp = tmcf->router_conf->mem_pool;

    ret = nxt_conf_map_object(mp, conf, nxt_router_conf,
                              nxt_nitems(nxt_router_conf), tmcf->router_conf);
    if (ret != NXT_OK) {
        nxt_alert(task, "root map error");
        return NXT_ERROR;
    }

    if (tmcf->router_conf->threads == 0) {
        tmcf->router_conf->threads = nxt_ncpu;
    }

    applications = nxt_conf_get_path(conf, &applications_path);
    if (applications == NULL) {
        nxt_alert(task, "no \"applications\" block");
        return NXT_ERROR;
    }

    router = tmcf->router_conf->router;

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

        prev = nxt_router_app_find(&router->apps, &name);

        if (prev != NULL && nxt_strstr_eq(&app->conf, &prev->conf)) {
            nxt_free(app);

            nxt_queue_remove(&prev->link);
            nxt_queue_insert_tail(&tmcf->previous, &prev->link);
            continue;
        }

        apcf.processes = 1;
        apcf.max_processes = 1;
        apcf.spare_processes = 0;
        apcf.timeout = 0;
        apcf.res_timeout = 1000;
        apcf.idle_timeout = 15000;
        apcf.requests = 0;
        apcf.limits_value = NULL;
        apcf.processes_value = NULL;

        ret = nxt_conf_map_object(mp, application, nxt_router_app_conf,
                                  nxt_nitems(nxt_router_app_conf), &apcf);
        if (ret != NXT_OK) {
            nxt_alert(task, "application map error");
            goto app_fail;
        }

        if (apcf.limits_value != NULL) {

            if (nxt_conf_type(apcf.limits_value) != NXT_CONF_OBJECT) {
                nxt_alert(task, "application limits is not object");
                goto app_fail;
            }

            ret = nxt_conf_map_object(mp, apcf.limits_value,
                                      nxt_router_app_limits_conf,
                                      nxt_nitems(nxt_router_app_limits_conf),
                                      &apcf);
            if (ret != NXT_OK) {
                nxt_alert(task, "application limits map error");
                goto app_fail;
            }
        }

        if (apcf.processes_value != NULL
            && nxt_conf_type(apcf.processes_value) == NXT_CONF_OBJECT)
        {
            ret = nxt_conf_map_object(mp, apcf.processes_value,
                                      nxt_router_app_processes_conf,
                                      nxt_nitems(nxt_router_app_processes_conf),
                                      &apcf);
            if (ret != NXT_OK) {
                nxt_alert(task, "application processes map error");
                goto app_fail;
            }

        } else {
            apcf.max_processes = apcf.processes;
            apcf.spare_processes = apcf.processes;
        }

        nxt_debug(task, "application type: %V", &apcf.type);
        nxt_debug(task, "application processes: %D", apcf.processes);
        nxt_debug(task, "application request timeout: %M", apcf.timeout);
        nxt_debug(task, "application reschedule timeout: %M", apcf.res_timeout);
        nxt_debug(task, "application requests: %D", apcf.requests);

        lang = nxt_app_lang_module(task->thread->runtime, &apcf.type);

        if (lang == NULL) {
            nxt_alert(task, "unknown application type: \"%V\"", &apcf.type);
            goto app_fail;
        }

        nxt_debug(task, "application language module: \"%s\"", lang->file);

        ret = nxt_thread_mutex_create(&app->mutex);
        if (ret != NXT_OK) {
            goto app_fail;
        }

        nxt_queue_init(&app->ports);
        nxt_queue_init(&app->spare_ports);
        nxt_queue_init(&app->idle_ports);
        nxt_queue_init(&app->requests);
        nxt_queue_init(&app->pending);

        app->name.length = name.length;
        nxt_memcpy(app->name.start, name.start, name.length);

        app->type = lang->type;
        app->max_processes = apcf.max_processes;
        app->spare_processes = apcf.spare_processes;
        app->max_pending_processes = apcf.spare_processes
                                      ? apcf.spare_processes : 1;
        app->timeout = apcf.timeout;
        app->res_timeout = apcf.res_timeout * 1000000;
        app->idle_timeout = apcf.idle_timeout;
        app->live = 1;
        app->max_pending_responses = 2;
        app->max_requests = apcf.requests;
        app->prepare_msg = nxt_app_prepare_msg[lang->type];

        engine = task->thread->engine;

        app->engine = engine;

        app->idle_timer.precision = NXT_TIMER_DEFAULT_PRECISION;
        app->idle_timer.work_queue = &engine->fast_work_queue;
        app->idle_timer.handler = nxt_router_app_idle_timeout;
        app->idle_timer.task = &engine->task;
        app->idle_timer.log = app->idle_timer.task->log;

        app->adjust_idle_work.handler = nxt_router_adjust_idle_timer;
        app->adjust_idle_work.task = &engine->task;
        app->adjust_idle_work.obj = app;

        nxt_queue_insert_tail(&tmcf->apps, &app->link);

        nxt_router_app_use(task, app, 1);
    }

    http = nxt_conf_get_path(conf, &http_path);
#if 0
    if (http == NULL) {
        nxt_alert(task, "no \"http\" block");
        return NXT_ERROR;
    }
#endif

    listeners = nxt_conf_get_path(conf, &listeners_path);
    if (listeners == NULL) {
        nxt_alert(task, "no \"listeners\" block");
        return NXT_ERROR;
    }

    next = 0;

    for ( ;; ) {
        listener = nxt_conf_next_object_member(listeners, &name, &next);
        if (listener == NULL) {
            break;
        }

        skcf = nxt_router_socket_conf(task, tmcf, &name);
        if (skcf == NULL) {
            goto fail;
        }

        ret = nxt_conf_map_object(mp, listener, nxt_router_listener_conf,
                                  nxt_nitems(nxt_router_listener_conf), &lscf);
        if (ret != NXT_OK) {
            nxt_alert(task, "listener map error");
            goto fail;
        }

        nxt_debug(task, "application: %V", &lscf.application);

        // STUB, default values if http block is not defined.
        skcf->header_buffer_size = 2048;
        skcf->large_header_buffer_size = 8192;
        skcf->large_header_buffers = 4;
        skcf->body_buffer_size = 16 * 1024;
        skcf->max_body_size = 8 * 1024 * 1024;
        skcf->idle_timeout = 180 * 1000;
        skcf->header_read_timeout = 30 * 1000;
        skcf->body_read_timeout = 30 * 1000;
        skcf->send_timeout = 30 * 1000;

        if (http != NULL) {
            ret = nxt_conf_map_object(mp, http, nxt_router_http_conf,
                                      nxt_nitems(nxt_router_http_conf), skcf);
            if (ret != NXT_OK) {
                nxt_alert(task, "http map error");
                goto fail;
            }
        }

        skcf->listen->handler = nxt_http_conn_init;
        skcf->router_conf = tmcf->router_conf;
        skcf->router_conf->count++;
        skcf->application = nxt_router_listener_application(tmcf,
                                                            &lscf.application);
        nxt_router_app_use(task, skcf->application, 1);
    }

    value = nxt_conf_get_path(conf, &access_log_path);

    if (value != NULL) {
        nxt_conf_get_string(value, &path);

        access_log = router->access_log;

        if (access_log != NULL && nxt_strstr_eq(&path, &access_log->path)) {
            nxt_thread_spin_lock(&router->lock);
            access_log->count++;
            nxt_thread_spin_unlock(&router->lock);

        } else {
            access_log = nxt_malloc(sizeof(nxt_router_access_log_t)
                                    + path.length);
            if (access_log == NULL) {
                nxt_alert(task, "failed to allocate access log structure");
                goto fail;
            }

            access_log->fd = -1;
            access_log->handler = &nxt_router_access_log_writer;
            access_log->count = 1;

            access_log->path.length = path.length;
            access_log->path.start = (u_char *) access_log
                                     + sizeof(nxt_router_access_log_t);

            nxt_memcpy(access_log->path.start, path.start, path.length);
        }

        tmcf->router_conf->access_log = access_log;
    }

    nxt_queue_add(&tmcf->deleting, &router->sockets);
    nxt_queue_init(&router->sockets);

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
nxt_router_socket_conf(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_str_t *name)
{
    size_t               size;
    nxt_int_t            ret;
    nxt_bool_t           wildcard;
    nxt_sockaddr_t       *sa;
    nxt_socket_conf_t    *skcf;
    nxt_listen_socket_t  *ls;

    sa = nxt_sockaddr_parse(tmcf->mem_pool, name);
    if (nxt_slow_path(sa == NULL)) {
        nxt_alert(task, "invalid listener \"%V\"", name);
        return NULL;
    }

    sa->type = SOCK_STREAM;

    nxt_debug(task, "router listener: \"%*s\"",
              (size_t) sa->length, nxt_sockaddr_start(sa));

    skcf = nxt_mp_zget(tmcf->router_conf->mem_pool, sizeof(nxt_socket_conf_t));
    if (nxt_slow_path(skcf == NULL)) {
        return NULL;
    }

    size = nxt_sockaddr_size(sa);

    ret = nxt_router_listen_socket_find(tmcf, skcf, sa);

    if (ret != NXT_OK) {

        ls = nxt_zalloc(sizeof(nxt_listen_socket_t) + size);
        if (nxt_slow_path(ls == NULL)) {
            return NULL;
        }

        skcf->listen = ls;

        ls->sockaddr = nxt_pointer_to(ls, sizeof(nxt_listen_socket_t));
        nxt_memcpy(ls->sockaddr, sa, size);

        nxt_listen_socket_remote_size(ls);

        ls->socket = -1;
        ls->backlog = NXT_LISTEN_BACKLOG;
        ls->flags = NXT_NONBLOCK;
        ls->read_after_accept = 1;
    }

    switch (sa->u.sockaddr.sa_family) {
#if (NXT_HAVE_UNIX_DOMAIN)
    case AF_UNIX:
        wildcard = 0;
        break;
#endif
#if (NXT_INET6)
    case AF_INET6:
        wildcard = IN6_IS_ADDR_UNSPECIFIED(&sa->u.sockaddr_in6.sin6_addr);
        break;
#endif
    case AF_INET:
    default:
        wildcard = (sa->u.sockaddr_in.sin_addr.s_addr == INADDR_ANY);
        break;
    }

    if (!wildcard) {
        skcf->sockaddr = nxt_mp_zget(tmcf->router_conf->mem_pool, size);
        if (nxt_slow_path(skcf->sockaddr == NULL)) {
            return NULL;
        }

        nxt_memcpy(skcf->sockaddr, sa, size);
    }

    return skcf;
}


static nxt_int_t
nxt_router_listen_socket_find(nxt_router_temp_conf_t *tmcf,
    nxt_socket_conf_t *nskcf, nxt_sockaddr_t *sa)
{
    nxt_router_t       *router;
    nxt_queue_link_t   *qlk;
    nxt_socket_conf_t  *skcf;

    router = tmcf->router_conf->router;

    for (qlk = nxt_queue_first(&router->sockets);
         qlk != nxt_queue_tail(&router->sockets);
         qlk = nxt_queue_next(qlk))
    {
        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);

        if (nxt_sockaddr_cmp(skcf->listen->sockaddr, sa)) {
            nskcf->listen = skcf->listen;

            nxt_queue_remove(qlk);
            nxt_queue_insert_tail(&tmcf->keeping, qlk);

            nxt_queue_insert_tail(&tmcf->updating, &nskcf->link);

            return NXT_OK;
        }
    }

    nxt_queue_insert_tail(&tmcf->pending, &nskcf->link);

    return NXT_DECLINED;
}


static void
nxt_router_listen_socket_rpc_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_socket_conf_t *skcf)
{
    size_t            size;
    uint32_t          stream;
    nxt_int_t         ret;
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

    size = nxt_sockaddr_size(skcf->listen->sockaddr);

    b = nxt_buf_mem_alloc(tmcf->mem_pool, size, 0);
    if (b == NULL) {
        goto fail;
    }

    b->mem.free = nxt_cpymem(b->mem.free, skcf->listen->sockaddr, size);

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    stream = nxt_port_rpc_register_handler(task, router_port,
                                           nxt_router_listen_socket_ready,
                                           nxt_router_listen_socket_error,
                                           main_port->pid, rpc);
    if (nxt_slow_path(stream == 0)) {
        goto fail;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_SOCKET, -1,
                                stream, router_port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, router_port, stream);
        goto fail;
    }

    return;

fail:

    nxt_router_conf_error(task, tmcf);
}


static void
nxt_router_listen_socket_ready(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_int_t         ret;
    nxt_socket_t      s;
    nxt_socket_rpc_t  *rpc;

    rpc = data;

    s = msg->fd;

    ret = nxt_socket_nonblocking(task, s);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    nxt_socket_defer_accept(task, s, rpc->socket_conf->listen->sockaddr);

    ret = nxt_listen_socket(task, s, NXT_LISTEN_BACKLOG);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    rpc->socket_conf->listen->socket = s;

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
    sa = rpc->socket_conf->listen->sockaddr;
    tmcf = rpc->temp_conf;

    in = nxt_buf_chk_make_plain(tmcf->mem_pool, msg->buf, msg->size);

    if (nxt_slow_path(in == NULL)) {
        return;
    }

    p = in->mem.pos;

    error = *p++;

    size = nxt_length("listen socket error: ")
           + nxt_length("{listener: \"\", code:\"\", message: \"\"}")
           + sa->length + socket_errors[error].length + (in->mem.free - p);

    out = nxt_buf_mem_alloc(tmcf->mem_pool, size, 0);
    if (nxt_slow_path(out == NULL)) {
        return;
    }

    out->mem.free = nxt_sprintf(out->mem.free, out->mem.end,
                        "listen socket error: "
                        "{listener: \"%*s\", code:\"%V\", message: \"%*s\"}",
                        (size_t) sa->length, nxt_sockaddr_start(sa),
                        &socket_errors[error], in->mem.free - p, p);

    nxt_debug(task, "%*s", out->mem.free - out->mem.pos, out->mem.pos);

    nxt_router_conf_error(task, tmcf);
}


static void
nxt_router_app_rpc_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_app_t *app)
{
    size_t         size;
    uint32_t       stream;
    nxt_int_t      ret;
    nxt_buf_t      *b;
    nxt_port_t     *main_port, *router_port;
    nxt_runtime_t  *rt;
    nxt_app_rpc_t  *rpc;

    rpc = nxt_mp_alloc(tmcf->mem_pool, sizeof(nxt_app_rpc_t));
    if (rpc == NULL) {
        goto fail;
    }

    rpc->app = app;
    rpc->temp_conf = tmcf;

    nxt_debug(task, "app '%V' prefork", &app->name);

    size = app->name.length + 1 + app->conf.length;

    b = nxt_buf_mem_alloc(tmcf->mem_pool, size, 0);
    if (nxt_slow_path(b == NULL)) {
        goto fail;
    }

    nxt_buf_cpystr(b, &app->name);
    *b->mem.free++ = '\0';
    nxt_buf_cpystr(b, &app->conf);

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    stream = nxt_port_rpc_register_handler(task, router_port,
                                           nxt_router_app_prefork_ready,
                                           nxt_router_app_prefork_error,
                                           -1, rpc);
    if (nxt_slow_path(stream == 0)) {
        goto fail;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_START_WORKER, -1,
                                stream, router_port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, router_port, stream);
        goto fail;
    }

    app->pending_processes++;

    return;

fail:

    nxt_router_conf_error(task, tmcf);
}


static void
nxt_router_app_prefork_ready(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_app_t           *app;
    nxt_port_t          *port;
    nxt_app_rpc_t       *rpc;
    nxt_event_engine_t  *engine;

    rpc = data;
    app = rpc->app;

    port = msg->u.new_port;
    port->app = app;

    nxt_router_app_use(task, app, 1);

    app->pending_processes--;
    app->processes++;
    app->idle_processes++;

    engine = task->thread->engine;

    nxt_queue_insert_tail(&app->ports, &port->app_link);
    nxt_queue_insert_tail(&app->spare_ports, &port->idle_link);

    port->idle_start = 0;

    nxt_port_inc_use(port);

    nxt_work_queue_add(&engine->fast_work_queue,
                       nxt_router_conf_apply, task, rpc->temp_conf, NULL);
}


static void
nxt_router_app_prefork_error(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_app_t               *app;
    nxt_app_rpc_t           *rpc;
    nxt_router_temp_conf_t  *tmcf;

    rpc = data;
    app = rpc->app;
    tmcf = rpc->temp_conf;

    nxt_log(task, NXT_LOG_WARN, "failed to start application \"%V\"",
            &app->name);

    app->pending_processes--;

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

    threads = tmcf->router_conf->threads;

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
    nxt_int_t  ret;

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

    return ret;
}


static nxt_int_t
nxt_router_engine_conf_update(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf)
{
    nxt_int_t  ret;

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

        joint = nxt_mp_alloc(tmcf->router_conf->mem_pool,
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
    threads = tmcf->router_conf->threads;

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
    nxt_app_t  *app;

    nxt_queue_each(app, &router->apps, nxt_app_t, link) {

        nxt_router_app_quit(task, app);

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
    .rpc_error = nxt_port_rpc_handler,
    .mmap      = nxt_port_mmap_handler,
    .data      = nxt_port_rpc_handler,
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
    nxt_socket_conf_t        *skcf;
    nxt_listen_event_t       *lev;
    nxt_listen_socket_t      *ls;
    nxt_thread_spinlock_t    *lock;
    nxt_socket_conf_joint_t  *joint;

    job = obj;
    joint = data;

    nxt_queue_insert_tail(&task->thread->engine->joints, &joint->link);

    skcf = joint->socket_conf;
    ls = skcf->listen;

    lev = nxt_listen_event(task, ls);
    if (nxt_slow_path(lev == NULL)) {
        nxt_router_listen_socket_release(task, skcf);
        return;
    }

    lev->socket.data = joint;

    lock = &skcf->router_conf->router->lock;

    nxt_thread_spin_lock(lock);
    ls->count++;
    nxt_thread_spin_unlock(lock);

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
    nxt_listen_event_t  *lev;

    fd = skcf->listen->socket;

    for (qlk = nxt_queue_first(listen_connections);
         qlk != nxt_queue_tail(listen_connections);
         qlk = nxt_queue_next(qlk))
    {
        lev = nxt_queue_link_data(qlk, nxt_listen_event_t, link);

        if (fd == lev->socket.fd) {
            return lev;
        }
    }

    return NULL;
}


static void
nxt_router_listen_socket_update(nxt_task_t *task, void *obj, void *data)
{
    nxt_joint_job_t          *job;
    nxt_event_engine_t       *engine;
    nxt_listen_event_t       *lev;
    nxt_socket_conf_joint_t  *joint, *old;

    job = obj;
    joint = data;

    engine = task->thread->engine;

    nxt_queue_insert_tail(&engine->joints, &joint->link);

    lev = nxt_router_listen_event(&engine->listen_connections,
                                  joint->socket_conf);

    old = lev->socket.data;
    lev->socket.data = joint;
    lev->listen = joint->socket_conf->listen;

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
    nxt_listen_event_t  *lev;
    nxt_event_engine_t  *engine;

    job = obj;
    skcf = data;

    engine = task->thread->engine;

    lev = nxt_router_listen_event(&engine->listen_connections, skcf);

    nxt_fd_event_delete(engine, &lev->socket);

    nxt_debug(task, "engine %p: listen socket delete: %d", engine,
              lev->socket.fd);

    lev->timer.handler = nxt_router_listen_socket_close;
    lev->timer.work_queue = &engine->fast_work_queue;

    nxt_timer_add(engine, &lev->timer, 0);

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
    nxt_listen_event_t       *lev;
    nxt_socket_conf_joint_t  *joint;

    timer = obj;
    lev = nxt_timer_data(timer, nxt_listen_event_t, timer);

    nxt_debug(task, "engine %p: listen socket close: %d", task->thread->engine,
              lev->socket.fd);

    nxt_queue_remove(&lev->link);

    joint = lev->socket.data;
    lev->socket.data = NULL;

    /* 'task' refers to lev->task and we cannot use after nxt_free() */
    task = &task->thread->engine->task;

    nxt_router_listen_socket_release(task, joint->socket_conf);

    nxt_router_listen_event_release(task, lev, joint);
}


static void
nxt_router_listen_socket_release(nxt_task_t *task, nxt_socket_conf_t *skcf)
{
    nxt_listen_socket_t    *ls;
    nxt_thread_spinlock_t  *lock;

    ls = skcf->listen;
    lock = &skcf->router_conf->router->lock;

    nxt_thread_spin_lock(lock);

    nxt_debug(task, "engine %p: listen socket release: ls->count %D",
              task->thread->engine, ls->count);

    if (--ls->count != 0) {
        ls = NULL;
    }

    nxt_thread_spin_unlock(lock);

    if (ls != NULL) {
        nxt_socket_close(task, ls->socket);
        nxt_free(ls);
    }
}


void
nxt_router_listen_event_release(nxt_task_t *task, nxt_listen_event_t *lev,
    nxt_socket_conf_joint_t *joint)
{
    nxt_event_engine_t  *engine;

    nxt_debug(task, "listen event count: %D", lev->count);

    if (--lev->count == 0) {
        nxt_free(lev);
    }

    if (joint != NULL) {
        nxt_router_conf_release(task, joint);
    }

    engine = task->thread->engine;

    if (engine->shutdown && nxt_queue_is_empty(&engine->joints)) {
        nxt_thread_exit(task->thread);
    }
}


void
nxt_router_conf_release(nxt_task_t *task, nxt_socket_conf_joint_t *joint)
{
    nxt_app_t              *app;
    nxt_socket_conf_t      *skcf;
    nxt_router_conf_t      *rtcf;
    nxt_thread_spinlock_t  *lock;

    nxt_debug(task, "conf joint %p count: %D", joint, joint->count);

    if (--joint->count != 0) {
        return;
    }

    nxt_queue_remove(&joint->link);

    /*
     * The joint content can not be safely used after the critical
     * section protected by the spinlock because its memory pool may
     * be already destroyed by another thread.
     */
    skcf = joint->socket_conf;
    app = skcf->application;
    rtcf = skcf->router_conf;
    lock = &rtcf->router->lock;

    nxt_thread_spin_lock(lock);

    nxt_debug(task, "conf skcf %p: %D, rtcf %p: %D", skcf, skcf->count,
              rtcf, rtcf->count);

    if (--skcf->count != 0) {
        rtcf = NULL;
        app = NULL;

    } else {
        nxt_queue_remove(&skcf->link);

        if (--rtcf->count != 0) {
            rtcf = NULL;
        }
    }

    nxt_thread_spin_unlock(lock);

    if (app != NULL) {
        nxt_router_app_use(task, app, -1);
    }

    /* TODO remove engine->port */
    /* TODO excude from connected ports */

    if (rtcf != NULL) {
        nxt_debug(task, "old router conf is destroyed");

        nxt_router_access_log_release(task, lock, rtcf->access_log);

        nxt_mp_thread_adopt(rtcf->mem_pool);

        nxt_mp_destroy(rtcf->mem_pool);
    }
}


static void
nxt_router_access_log_writer(nxt_task_t *task, nxt_http_request_t *r,
    nxt_router_access_log_t *access_log)
{
    size_t     size;
    u_char     *buf, *p;
    nxt_off_t  bytes;

    static nxt_time_string_t  date_cache = {
        (nxt_atomic_uint_t) -1,
        nxt_router_access_log_date,
        "%02d/%s/%4d:%02d:%02d:%02d %c%02d%02d",
        nxt_length("31/Dec/1986:19:40:00 +0300"),
        NXT_THREAD_TIME_LOCAL,
        NXT_THREAD_TIME_SEC,
    };

    size = r->remote->address_length
           + 6                  /* ' - - [' */
           + date_cache.size
           + 3                  /* '] "' */
           + r->method->length
           + 1                  /* space */
           + r->target.length
           + 1                  /* space */
           + r->version.length
           + 2                  /* '" ' */
           + 3                  /* status */
           + 1                  /* space */
           + NXT_OFF_T_LEN
           + 2                  /* ' "' */
           + (r->referer != NULL ? r->referer->value_length : 1)
           + 3                  /* '" "' */
           + (r->user_agent != NULL ? r->user_agent->value_length : 1)
           + 2                  /* '"\n' */
    ;

    buf = nxt_mp_nget(r->mem_pool, size);
    if (nxt_slow_path(buf == NULL)) {
        return;
    }

    p = nxt_cpymem(buf, nxt_sockaddr_address(r->remote),
                   r->remote->address_length);

    p = nxt_cpymem(p, " - - [", 6);

    p = nxt_thread_time_string(task->thread, &date_cache, p);

    p = nxt_cpymem(p, "] \"", 3);

    if (r->method->length != 0) {
        p = nxt_cpymem(p, r->method->start, r->method->length);

        if (r->target.length != 0) {
            *p++ = ' ';
            p = nxt_cpymem(p, r->target.start, r->target.length);

            if (r->version.length != 0) {
                *p++ = ' ';
                p = nxt_cpymem(p, r->version.start, r->version.length);
            }
        }

    } else {
        *p++ = '-';
    }

    p = nxt_cpymem(p, "\" ", 2);

    p = nxt_sprintf(p, p + 3, "%03d", r->status);

    *p++ = ' ';

    bytes = nxt_http_proto_body_bytes_sent[r->protocol](task, r->proto);

    p = nxt_sprintf(p, p + NXT_OFF_T_LEN, "%O", bytes);

    p = nxt_cpymem(p, " \"", 2);

    if (r->referer != NULL) {
        p = nxt_cpymem(p, r->referer->value, r->referer->value_length);

    } else {
        *p++ = '-';
    }

    p = nxt_cpymem(p, "\" \"", 3);

    if (r->user_agent != NULL) {
        p = nxt_cpymem(p, r->user_agent->value, r->user_agent->value_length);

    } else {
        *p++ = '-';
    }

    p = nxt_cpymem(p, "\"\n", 2);

    nxt_fd_write(access_log->fd, buf, p - buf);
}


static u_char *
nxt_router_access_log_date(u_char *buf, nxt_realtime_t *now, struct tm *tm,
    size_t size, const char *format)
{
    u_char  sign;
    time_t  gmtoff;

    static const char  *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    gmtoff = nxt_timezone(tm) / 60;

    if (gmtoff < 0) {
        gmtoff = -gmtoff;
        sign = '-';

    } else {
        sign = '+';
    }

    return nxt_sprintf(buf, buf + size, format,
                       tm->tm_mday, month[tm->tm_mon], tm->tm_year + 1900,
                       tm->tm_hour, tm->tm_min, tm->tm_sec,
                       sign, gmtoff / 60, gmtoff % 60);
}


static void
nxt_router_access_log_open(nxt_task_t *task, nxt_router_temp_conf_t *tmcf)
{
    uint32_t                 stream;
    nxt_int_t                ret;
    nxt_buf_t                *b;
    nxt_port_t               *main_port, *router_port;
    nxt_runtime_t            *rt;
    nxt_router_access_log_t  *access_log;

    access_log = tmcf->router_conf->access_log;

    b = nxt_buf_mem_alloc(tmcf->mem_pool, access_log->path.length + 1, 0);
    if (nxt_slow_path(b == NULL)) {
        goto fail;
    }

    nxt_buf_cpystr(b, &access_log->path);
    *b->mem.free++ = '\0';

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    stream = nxt_port_rpc_register_handler(task, router_port,
                                           nxt_router_access_log_ready,
                                           nxt_router_access_log_error,
                                           -1, tmcf);
    if (nxt_slow_path(stream == 0)) {
        goto fail;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_ACCESS_LOG, -1,
                                stream, router_port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, router_port, stream);
        goto fail;
    }

    return;

fail:

    nxt_router_conf_error(task, tmcf);
}


static void
nxt_router_access_log_ready(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_router_temp_conf_t   *tmcf;
    nxt_router_access_log_t  *access_log;

    tmcf = data;

    access_log = tmcf->router_conf->access_log;

    access_log->fd = msg->fd;

    nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                       nxt_router_conf_apply, task, tmcf, NULL);
}


static void
nxt_router_access_log_error(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_router_temp_conf_t  *tmcf;

    tmcf = data;

    nxt_router_conf_error(task, tmcf);
}


static void
nxt_router_access_log_release(nxt_task_t *task, nxt_thread_spinlock_t *lock,
    nxt_router_access_log_t *access_log)
{
    if (access_log == NULL) {
        return;
    }

    nxt_thread_spin_lock(lock);

    if (--access_log->count != 0) {
        access_log = NULL;
    }

    nxt_thread_spin_unlock(lock);

    if (access_log != NULL) {

        if (access_log->fd != -1) {
            nxt_fd_close(access_log->fd);
        }

        nxt_free(access_log);
    }
}


typedef struct {
    nxt_mp_t                 *mem_pool;
    nxt_router_access_log_t  *access_log;
} nxt_router_access_log_reopen_t;


void
nxt_router_access_log_reopen_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_mp_t                        *mp;
    uint32_t                        stream;
    nxt_int_t                       ret;
    nxt_buf_t                       *b;
    nxt_port_t                      *main_port, *router_port;
    nxt_runtime_t                   *rt;
    nxt_router_access_log_t         *access_log;
    nxt_router_access_log_reopen_t  *reopen;

    access_log = nxt_router->access_log;

    if (access_log == NULL) {
        return;
    }

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(mp == NULL)) {
        return;
    }

    reopen = nxt_mp_get(mp, sizeof(nxt_router_access_log_reopen_t));
    if (nxt_slow_path(reopen == NULL)) {
        goto fail;
    }

    reopen->mem_pool = mp;
    reopen->access_log = access_log;

    b = nxt_buf_mem_alloc(mp, access_log->path.length + 1, 0);
    if (nxt_slow_path(b == NULL)) {
        goto fail;
    }

    b->completion_handler = nxt_router_access_log_reopen_completion;

    nxt_buf_cpystr(b, &access_log->path);
    *b->mem.free++ = '\0';

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    stream = nxt_port_rpc_register_handler(task, router_port,
                                           nxt_router_access_log_reopen_ready,
                                           nxt_router_access_log_reopen_error,
                                           -1, reopen);
    if (nxt_slow_path(stream == 0)) {
        goto fail;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_ACCESS_LOG, -1,
                                stream, router_port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, router_port, stream);
        goto fail;
    }

    nxt_mp_retain(mp);

    return;

fail:

    nxt_mp_destroy(mp);
}


static void
nxt_router_access_log_reopen_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t   *mp;
    nxt_buf_t  *b;

    b = obj;
    mp = b->data;

    nxt_mp_release(mp);
}


static void
nxt_router_access_log_reopen_ready(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_router_access_log_t         *access_log;
    nxt_router_access_log_reopen_t  *reopen;

    reopen = data;

    access_log = reopen->access_log;

    if (access_log == nxt_router->access_log) {

        if (nxt_slow_path(dup2(msg->fd, access_log->fd) == -1)) {
            nxt_alert(task, "dup2(%FD, %FD) failed %E",
                      msg->fd, access_log->fd, nxt_errno);
        }
    }

    nxt_fd_close(msg->fd);
    nxt_mp_release(reopen->mem_pool);
}


static void
nxt_router_access_log_reopen_error(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_router_access_log_reopen_t  *reopen;

    reopen = data;

    nxt_mp_release(reopen->mem_pool);
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


static void
nxt_router_response_ready_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    size_t               dump_size;
    nxt_int_t            ret;
    nxt_buf_t            *b;
    nxt_http_request_t   *r;
    nxt_req_conn_link_t  *rc;
    nxt_app_parse_ctx_t  *ar;

    b = msg->buf;
    rc = data;

    dump_size = nxt_buf_used_size(b);

    if (dump_size > 300) {
        dump_size = 300;
    }

    nxt_debug(task, "%srouter app data (%uz): %*s",
              msg->port_msg.last ? "last " : "", msg->size, dump_size,
              b->mem.pos);

    if (msg->size == 0) {
        b = NULL;
    }

    ar = rc->ap;
    if (nxt_slow_path(ar == NULL)) {
        return;
    }

    if (ar->request->error) {
        nxt_router_rc_unlink(task, rc);
        return;
    }

    if (msg->port_msg.last != 0) {
        nxt_debug(task, "router data create last buf");

        nxt_buf_chain_add(&b, nxt_http_buf_last(ar->request));

        nxt_router_rc_unlink(task, rc);

    } else {
        if (rc->app != NULL && rc->app->timeout != 0) {
            ar->timer.handler = nxt_router_app_timeout;
            ar->timer_data = rc;
            nxt_timer_add(task->thread->engine, &ar->timer, rc->app->timeout);
        }
    }

    if (b == NULL) {
        return;
    }

    if (msg->buf == b) {
        /* Disable instant buffer completion/re-using by port. */
        msg->buf = NULL;
    }

    r = ar->request;

    if (r->header_sent) {
        nxt_buf_chain_add(&r->out, b);
        nxt_http_request_send_body(task, r, NULL);

    } else {
        ret = nxt_http_parse_fields(&ar->resp_parser, &b->mem);
        if (nxt_slow_path(ret != NXT_DONE)) {
            goto fail;
        }

        r->resp.fields = ar->resp_parser.fields;

        ret = nxt_http_fields_process(r->resp.fields,
                                      &nxt_response_fields_hash, r);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }

        if (nxt_buf_mem_used_size(&b->mem) == 0) {
            nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                               b->completion_handler, task, b, b->parent);

            b = b->next;
        }

        if (b != NULL) {
            nxt_buf_chain_add(&r->out, b);
        }

        r->state = &nxt_http_request_send_state;

        nxt_http_request_header_send(task, r);
    }

    return;

fail:

    nxt_http_request_error(task, r, NXT_HTTP_SERVICE_UNAVAILABLE);

    nxt_router_rc_unlink(task, rc);
}


static const nxt_http_request_state_t  nxt_http_request_send_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_http_request_send_body,
    .error_handler = nxt_http_request_close_handler,
};


static void
nxt_http_request_send_body(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t           *out;
    nxt_http_request_t  *r;

    r = obj;

    out = r->out;

    if (out != NULL) {
        r->out = NULL;
        nxt_http_request_send(task, r, out);
    }
}


static void
nxt_router_response_error_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_int_t            res;
    nxt_port_t           *port;
    nxt_bool_t           cancelled;
    nxt_req_app_link_t   *ra;
    nxt_req_conn_link_t  *rc;

    rc = data;

    ra = rc->ra;

    if (ra != NULL) {
        cancelled = nxt_router_msg_cancel(task, &ra->msg_info, ra->stream);

        if (cancelled) {
            nxt_router_ra_inc_use(ra);

            res = nxt_router_app_port(task, rc->app, ra);

            if (res == NXT_OK) {
                port = ra->app_port;

                if (nxt_slow_path(port == NULL)) {
                    nxt_log(task, NXT_LOG_ERR, "port is NULL in cancelled ra");
                    return;
                }

                nxt_port_rpc_ex_set_peer(task, task->thread->engine->port, rc,
                                         port->pid);

                nxt_router_app_prepare_request(task, ra);
            }

            msg->port_msg.last = 0;

            return;
        }
    }

    if (rc->ap != NULL) {
        nxt_http_request_error(task, rc->ap->request,
                               NXT_HTTP_SERVICE_UNAVAILABLE);
    }

    nxt_router_rc_unlink(task, rc);
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

    nxt_assert(app->pending_processes != 0);

    app->pending_processes--;
    app->processes++;

    nxt_thread_mutex_unlock(&app->mutex);

    nxt_debug(task, "app '%V' new port ready, pid %PI, %d/%d",
              &app->name, port->pid, app->processes, app->pending_processes);

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

    nxt_assert(app->pending_processes != 0);

    app->pending_processes--;

    if (!nxt_queue_is_empty(&app->requests)) {
        lnk = nxt_queue_last(&app->requests);
        nxt_queue_remove(lnk);
        lnk->next = NULL;

        ra = nxt_queue_link_data(lnk, nxt_req_app_link_t, link_app_requests);

    } else {
        ra = NULL;
    }

    nxt_thread_mutex_unlock(&app->mutex);

    if (ra != NULL) {
        nxt_debug(task, "app '%V' %p abort next stream #%uD",
                  &app->name, app, ra->stream);

        nxt_router_ra_error(ra, 500, "Failed to start application process");
        nxt_router_ra_use(task, ra, -1);
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
        nxt_assert(app->processes == 0);
        nxt_assert(app->idle_processes == 0);
        nxt_assert(app->pending_processes == 0);
        nxt_assert(nxt_queue_is_empty(&app->requests));
        nxt_assert(nxt_queue_is_empty(&app->ports));
        nxt_assert(nxt_queue_is_empty(&app->spare_ports));
        nxt_assert(nxt_queue_is_empty(&app->idle_ports));

        nxt_thread_mutex_destroy(&app->mutex);
        nxt_free(app);
    }
}


nxt_inline nxt_bool_t
nxt_router_app_first_port_busy(nxt_app_t *app)
{
    nxt_port_t        *port;
    nxt_queue_link_t  *lnk;

    lnk = nxt_queue_first(&app->ports);
    port = nxt_queue_link_data(lnk, nxt_port_t, app_link);

    return port->app_pending_responses > 0;
}


nxt_inline nxt_port_t *
nxt_router_pop_first_port(nxt_app_t *app)
{
    nxt_port_t        *port;
    nxt_queue_link_t  *lnk;

    lnk = nxt_queue_first(&app->ports);
    nxt_queue_remove(lnk);

    port = nxt_queue_link_data(lnk, nxt_port_t, app_link);

    port->app_pending_responses++;

    if (nxt_queue_chk_remove(&port->idle_link)) {
        app->idle_processes--;

        if (port->idle_start == 0) {
            nxt_assert(app->idle_processes < app->spare_processes);

        } else {
            nxt_assert(app->idle_processes >= app->spare_processes);

            port->idle_start = 0;
        }
    }

    if ((app->max_pending_responses == 0
            || port->app_pending_responses < app->max_pending_responses)
        && (app->max_requests == 0
            || port->app_responses + port->app_pending_responses
                < app->max_requests))
    {
        nxt_queue_insert_tail(&app->ports, lnk);

        nxt_port_inc_use(port);

    } else {
        lnk->next = NULL;
    }

    return port;
}


nxt_inline nxt_port_t *
nxt_router_app_get_port_for_quit(nxt_app_t *app)
{
    nxt_port_t  *port;

    port = NULL;

    nxt_thread_mutex_lock(&app->mutex);

    nxt_queue_each(port, &app->ports, nxt_port_t, app_link) {

        if (port->app_pending_responses > 0) {
            port = NULL;

            continue;
        }

        /* Caller is responsible to decrease port use count. */
        nxt_queue_chk_remove(&port->app_link);

        if (nxt_queue_chk_remove(&port->idle_link)) {
            app->idle_processes--;
        }

        /* Caller is responsible to decrease app use count. */
        port->app = NULL;
        app->processes--;

        break;

    } nxt_queue_loop;

    nxt_thread_mutex_unlock(&app->mutex);

    return port;
}


static void
nxt_router_app_quit(nxt_task_t *task, nxt_app_t *app)
{
    nxt_port_t  *port;

    nxt_queue_remove(&app->link);

    app->live = 0;

    for ( ;; ) {
        port = nxt_router_app_get_port_for_quit(app);
        if (port == NULL) {
            break;
        }

        nxt_debug(task, "send QUIT to app '%V' pid %PI", &app->name, port->pid);

        nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT, -1, 0, 0, NULL);

        nxt_port_use(task, port, -1);
        nxt_router_app_use(task, app, -1);
    }

    if (nxt_timer_is_in_tree(&app->idle_timer)) {
        nxt_assert(app->engine == task->thread->engine);

        app->idle_timer.handler = nxt_router_app_release_handler;
        nxt_timer_add(app->engine, &app->idle_timer, 0);

    } else {
        nxt_router_app_use(task, app, -1);
    }
}


static void
nxt_router_app_process_request(nxt_task_t *task, void *obj, void *data)
{
    nxt_req_app_link_t  *ra;

    ra = data;

#if (NXT_DEBUG)
    {
    nxt_app_t  *app;

    app = obj;

    nxt_assert(app != NULL);
    nxt_assert(ra != NULL);
    nxt_assert(ra->app_port != NULL);

    nxt_debug(task, "app '%V' %p process next stream #%uD",
              &app->name, app, ra->stream);
    }
#endif

    nxt_router_app_prepare_request(task, ra);
}


static void
nxt_router_app_port_release(nxt_task_t *task, nxt_port_t *port,
    uint32_t request_failed, uint32_t got_response)
{
    nxt_app_t                *app;
    nxt_bool_t               port_unchained;
    nxt_bool_t               send_quit, cancelled, adjust_idle_timer;
    nxt_queue_link_t         *lnk;
    nxt_req_app_link_t       *ra, *pending_ra, *re_ra;
    nxt_port_select_state_t  state;

    nxt_assert(port != NULL);
    nxt_assert(port->app != NULL);

    ra = NULL;

    app = port->app;

    nxt_thread_mutex_lock(&app->mutex);

    port->app_pending_responses -= request_failed + got_response;
    port->app_responses += got_response;

    if (nxt_slow_path(app->live == 0)) {
        goto app_dead;
    }

    if (port->pair[1] != -1
        && (app->max_pending_responses == 0
            || port->app_pending_responses < app->max_pending_responses)
        && (app->max_requests == 0
            || port->app_responses + port->app_pending_responses
                < app->max_requests))
    {
        if (port->app_link.next == NULL) {
            if (port->app_pending_responses > 0) {
                nxt_queue_insert_tail(&app->ports, &port->app_link);

            } else {
                nxt_queue_insert_head(&app->ports, &port->app_link);
            }

            nxt_port_inc_use(port);

        } else {
            if (port->app_pending_responses == 0
                && nxt_queue_first(&app->ports) != &port->app_link)
            {
                nxt_queue_remove(&port->app_link);
                nxt_queue_insert_head(&app->ports, &port->app_link);
            }
        }
    }

    if (!nxt_queue_is_empty(&app->ports)
        && !nxt_queue_is_empty(&app->requests))
    {
        lnk = nxt_queue_first(&app->requests);
        nxt_queue_remove(lnk);
        lnk->next = NULL;

        ra = nxt_queue_link_data(lnk, nxt_req_app_link_t, link_app_requests);

        ra->app_port = nxt_router_pop_first_port(app);

        if (ra->app_port->app_pending_responses > 1) {
            nxt_router_ra_pending(task, app, ra);
        }
    }

app_dead:

    /* Pop first pending request for this port. */
    if ((request_failed > 0 || got_response > 0)
        && !nxt_queue_is_empty(&port->pending_requests))
    {
        lnk = nxt_queue_first(&port->pending_requests);
        nxt_queue_remove(lnk);
        lnk->next = NULL;

        pending_ra = nxt_queue_link_data(lnk, nxt_req_app_link_t,
                                         link_port_pending);

        nxt_assert(pending_ra->link_app_pending.next != NULL);

        nxt_queue_remove(&pending_ra->link_app_pending);
        pending_ra->link_app_pending.next = NULL;

    } else {
        pending_ra = NULL;
    }

    /* Try to cancel and re-schedule first stalled request for this app. */
    if (got_response > 0 && !nxt_queue_is_empty(&app->pending)) {
        lnk = nxt_queue_first(&app->pending);

        re_ra = nxt_queue_link_data(lnk, nxt_req_app_link_t, link_app_pending);

        if (re_ra->res_time <= nxt_thread_monotonic_time(task->thread)) {

            nxt_debug(task, "app '%V' stalled request #%uD detected",
                      &app->name, re_ra->stream);

            cancelled = nxt_router_msg_cancel(task, &re_ra->msg_info,
                                              re_ra->stream);

            if (cancelled) {
                nxt_router_ra_inc_use(re_ra);

                state.ra = re_ra;
                state.app = app;

                nxt_router_port_select(task, &state);

                goto re_ra_cancelled;
            }
        }
    }

    re_ra = NULL;

re_ra_cancelled:

    send_quit = (app->live == 0 && port->app_pending_responses == 0)
                || (app->max_requests > 0 && port->app_pending_responses == 0
                    && port->app_responses >= app->max_requests);

    if (send_quit) {
        port_unchained = nxt_queue_chk_remove(&port->app_link);

        port->app = NULL;
        app->processes--;

    } else {
        port_unchained = 0;
    }

    adjust_idle_timer = 0;

    if (port->pair[1] != -1 && !send_quit && port->app_pending_responses == 0) {
        nxt_assert(port->idle_link.next == NULL);

        if (app->idle_processes == app->spare_processes
            && app->adjust_idle_work.data == NULL)
        {
            adjust_idle_timer = 1;
            app->adjust_idle_work.data = app;
            app->adjust_idle_work.next = NULL;
        }

        if (app->idle_processes < app->spare_processes) {
            nxt_queue_insert_tail(&app->spare_ports, &port->idle_link);

        } else {
            nxt_queue_insert_tail(&app->idle_ports, &port->idle_link);

            port->idle_start = task->thread->engine->timers.now;
        }

        app->idle_processes++;
    }

    nxt_thread_mutex_unlock(&app->mutex);

    if (adjust_idle_timer) {
        nxt_router_app_use(task, app, 1);
        nxt_event_engine_post(app->engine, &app->adjust_idle_work);
    }

    if (pending_ra != NULL) {
        nxt_router_ra_use(task, pending_ra, -1);
    }

    if (re_ra != NULL) {
        if (nxt_router_port_post_select(task, &state) == NXT_OK) {
            nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                               nxt_router_app_process_request,
                               &task->thread->engine->task, app, re_ra);
        }
    }

    if (ra != NULL) {
        nxt_router_ra_use(task, ra, -1);

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

    if (send_quit) {
        nxt_debug(task, "app '%V' %p send QUIT to port",
                  &app->name, app);

        nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT,
                              -1, 0, 0, NULL);

        if (port_unchained) {
            nxt_port_use(task, port, -1);
        }

        nxt_router_app_use(task, app, -1);

        goto adjust_use;
    }

    nxt_debug(task, "app '%V' %p requests queue is empty, keep the port",
              &app->name, app);

adjust_use:

    if (request_failed > 0 || got_response > 0) {
        nxt_port_use(task, port, -1);
    }
}


void
nxt_router_app_port_close(nxt_task_t *task, nxt_port_t *port)
{
    nxt_app_t         *app;
    nxt_bool_t        unchain, start_process;
    nxt_port_t        *idle_port;
    nxt_queue_link_t  *idle_lnk;

    app = port->app;

    nxt_assert(app != NULL);

    nxt_thread_mutex_lock(&app->mutex);

    unchain = nxt_queue_chk_remove(&port->app_link);

    if (nxt_queue_chk_remove(&port->idle_link)) {
        app->idle_processes--;

        if (port->idle_start == 0
            && app->idle_processes >= app->spare_processes)
        {
            nxt_assert(!nxt_queue_is_empty(&app->idle_ports));

            idle_lnk = nxt_queue_last(&app->idle_ports);
            idle_port = nxt_queue_link_data(idle_lnk, nxt_port_t, idle_link);
            nxt_queue_remove(idle_lnk);

            nxt_queue_insert_tail(&app->spare_ports, idle_lnk);

            idle_port->idle_start = 0;
        }
    }

    app->processes--;

    start_process = app->live != 0
                    && !task->thread->engine->shutdown
                    && nxt_router_app_can_start(app)
                    && (!nxt_queue_is_empty(&app->requests)
                        || nxt_router_app_need_start(app));

    if (start_process) {
        app->pending_processes++;
    }

    nxt_thread_mutex_unlock(&app->mutex);

    nxt_debug(task, "app '%V' pid %PI closed", &app->name, port->pid);

    if (unchain) {
        nxt_port_use(task, port, -1);
    }

    if (start_process) {
        nxt_router_start_app_process(task, app);
    }
}


static void
nxt_router_adjust_idle_timer(nxt_task_t *task, void *obj, void *data)
{
    nxt_app_t           *app;
    nxt_bool_t          queued;
    nxt_port_t          *port;
    nxt_msec_t          timeout, threshold;
    nxt_queue_link_t    *lnk;
    nxt_event_engine_t  *engine;

    app = obj;
    queued = (data == app);

    nxt_debug(task, "nxt_router_adjust_idle_timer: app \"%V\", queued %b",
              &app->name, queued);

    engine = task->thread->engine;

    nxt_assert(app->engine == engine);

    threshold = engine->timers.now + app->idle_timer.precision;
    timeout = 0;

    nxt_thread_mutex_lock(&app->mutex);

    if (queued) {
        app->adjust_idle_work.data = NULL;
    }

    while (app->idle_processes > app->spare_processes) {

        nxt_assert(!nxt_queue_is_empty(&app->idle_ports));

        lnk = nxt_queue_first(&app->idle_ports);
        port = nxt_queue_link_data(lnk, nxt_port_t, idle_link);

        timeout = port->idle_start + app->idle_timeout;

        if (timeout > threshold) {
            break;
        }

        nxt_queue_remove(lnk);
        lnk->next = NULL;

        nxt_queue_chk_remove(&port->app_link);

        app->idle_processes--;
        app->processes--;
        port->app = NULL;

        nxt_thread_mutex_unlock(&app->mutex);

        nxt_debug(task, "app '%V' send QUIT to idle port %PI",
                  &app->name, port->pid);

        nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT, -1, 0, 0, NULL);

        nxt_port_use(task, port, -1);
        nxt_router_app_use(task, app, -1);

        nxt_thread_mutex_lock(&app->mutex);
    }

    nxt_thread_mutex_unlock(&app->mutex);

    if (timeout > threshold) {
        nxt_timer_add(engine, &app->idle_timer, timeout - threshold);

    } else {
        nxt_timer_disable(engine, &app->idle_timer);
    }

    if (queued) {
        nxt_router_app_use(task, app, -1);
    }
}


static void
nxt_router_app_idle_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_app_t    *app;
    nxt_timer_t  *timer;

    timer = obj;
    app = nxt_container_of(timer, nxt_app_t, idle_timer);

    nxt_router_adjust_idle_timer(task, app, NULL);
}


static void
nxt_router_app_release_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_app_t    *app;
    nxt_timer_t  *timer;

    timer = obj;
    app = nxt_container_of(timer, nxt_app_t, idle_timer);

    nxt_router_app_use(task, app, -1);
}


static void
nxt_router_port_select(nxt_task_t *task, nxt_port_select_state_t *state)
{
    nxt_app_t           *app;
    nxt_bool_t          can_start_process;
    nxt_req_app_link_t  *ra;

    ra = state->ra;
    app = state->app;

    state->failed_port_use_delta = 0;

    if (nxt_queue_chk_remove(&ra->link_app_requests))
    {
        nxt_router_ra_dec_use(ra);
    }

    if (nxt_queue_chk_remove(&ra->link_port_pending))
    {
        nxt_assert(ra->link_app_pending.next != NULL);

        nxt_queue_remove(&ra->link_app_pending);
        ra->link_app_pending.next = NULL;

        nxt_router_ra_dec_use(ra);
    }

    state->failed_port = ra->app_port;

    if (ra->app_port != NULL) {
        state->failed_port_use_delta--;

        state->failed_port->app_pending_responses--;

        if (nxt_queue_chk_remove(&state->failed_port->app_link)) {
            state->failed_port_use_delta--;
        }

        ra->app_port = NULL;
    }

    can_start_process = nxt_router_app_can_start(app);

    state->port = NULL;
    state->start_process = 0;

    if (nxt_queue_is_empty(&app->ports)
        || (can_start_process && nxt_router_app_first_port_busy(app)) )
    {
        ra = nxt_router_ra_create(task, ra);

        if (nxt_slow_path(ra == NULL)) {
            goto fail;
        }

        if (nxt_slow_path(state->failed_port != NULL)) {
            nxt_queue_insert_head(&app->requests, &ra->link_app_requests);

        } else {
            nxt_queue_insert_tail(&app->requests, &ra->link_app_requests);
        }

        nxt_router_ra_inc_use(ra);

        nxt_debug(task, "ra stream #%uD enqueue to app->requests", ra->stream);

        if (can_start_process) {
            app->pending_processes++;
            state->start_process = 1;
        }

    } else {
        state->port = nxt_router_pop_first_port(app);

        if (state->port->app_pending_responses > 1) {
            ra = nxt_router_ra_create(task, ra);

            if (nxt_slow_path(ra == NULL)) {
                goto fail;
            }

            ra->app_port = state->port;

            nxt_router_ra_pending(task, app, ra);
        }

        if (can_start_process && nxt_router_app_need_start(app)) {
            app->pending_processes++;
            state->start_process = 1;
        }
    }

fail:

    state->shared_ra = ra;
}


static nxt_int_t
nxt_router_port_post_select(nxt_task_t *task, nxt_port_select_state_t *state)
{
    nxt_int_t           res;
    nxt_app_t           *app;
    nxt_req_app_link_t  *ra;

    ra = state->shared_ra;
    app = state->app;

    if (state->failed_port_use_delta != 0) {
        nxt_port_use(task, state->failed_port, state->failed_port_use_delta);
    }

    if (nxt_slow_path(ra == NULL)) {
        if (state->port != NULL) {
            nxt_port_use(task, state->port, -1);
        }

        nxt_router_ra_error(state->ra, 500,
                            "Failed to allocate shared req<->app link");
        nxt_router_ra_use(task, state->ra, -1);

        return NXT_ERROR;
    }

    if (state->port != NULL) {
        nxt_debug(task, "already have port for app '%V' %p ", &app->name, app);

        ra->app_port = state->port;

        if (state->start_process) {
            nxt_router_start_app_process(task, app);
        }

        return NXT_OK;
    }

    if (!state->start_process) {
        nxt_debug(task, "app '%V' %p too many running or pending processes",
                  &app->name, app);

        return NXT_AGAIN;
    }

    res = nxt_router_start_app_process(task, app);

    if (nxt_slow_path(res != NXT_OK)) {
        nxt_router_ra_error(ra, 500, "Failed to start app process");
        nxt_router_ra_use(task, ra, -1);

        return NXT_ERROR;
    }

    return NXT_AGAIN;
}


static nxt_int_t
nxt_router_app_port(nxt_task_t *task, nxt_app_t *app, nxt_req_app_link_t *ra)
{
    nxt_port_select_state_t  state;

    state.ra = ra;
    state.app = app;

    nxt_thread_mutex_lock(&app->mutex);

    nxt_router_port_select(task, &state);

    nxt_thread_mutex_unlock(&app->mutex);

    return nxt_router_port_post_select(task, &state);
}


void
nxt_router_process_http_request(nxt_task_t *task, nxt_app_parse_ctx_t *ar)
{
    nxt_int_t            res;
    nxt_app_t            *app;
    nxt_port_t           *port;
    nxt_event_engine_t   *engine;
    nxt_http_request_t   *r;
    nxt_req_app_link_t   ra_local, *ra;
    nxt_req_conn_link_t  *rc;

    r = ar->request;
    app = r->conf->socket_conf->application;

    if (app == NULL) {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    engine = task->thread->engine;

    rc = nxt_port_rpc_register_handler_ex(task, engine->port,
                                          nxt_router_response_ready_handler,
                                          nxt_router_response_error_handler,
                                          sizeof(nxt_req_conn_link_t));

    if (nxt_slow_path(rc == NULL)) {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rc->stream = nxt_port_rpc_ex_stream(rc);
    rc->app = app;

    nxt_router_app_use(task, app, 1);

    rc->ap = ar;

    ra = &ra_local;
    nxt_router_ra_init(task, ra, rc);

    res = nxt_router_app_port(task, app, ra);

    if (res != NXT_OK) {
        return;
    }

    ra = rc->ra;
    port = ra->app_port;

    nxt_assert(port != NULL);

    nxt_port_rpc_ex_set_peer(task, engine->port, rc, port->pid);

    nxt_router_app_prepare_request(task, ra);
}


static void
nxt_router_dummy_buf_completion(nxt_task_t *task, void *obj, void *data)
{
}


static void
nxt_router_app_prepare_request(nxt_task_t *task, nxt_req_app_link_t *ra)
{
    uint32_t             request_failed;
    nxt_buf_t            *b;
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
            nxt_router_ra_error(ra, 500,
                                "Failed to send reply port to application");
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
        nxt_router_ra_error(ra, 500,
                            "Failed to prepare message for application");
        goto release_port;
    }

    nxt_debug(task, "about to send %O bytes buffer to app process port %d",
                    nxt_buf_used_size(wmsg.write),
                    wmsg.port->socket.fd);

    request_failed = 0;

    ra->msg_info.buf = wmsg.write;
    ra->msg_info.completion_handler = wmsg.write->completion_handler;

    for (b = wmsg.write; b != NULL; b = b->next) {
        b->completion_handler = nxt_router_dummy_buf_completion;
    }

    res = nxt_port_mmap_get_tracking(task, port, &ra->msg_info.tracking,
                                     ra->stream);
    if (nxt_slow_path(res != NXT_OK)) {
        nxt_router_ra_error(ra, 500,
                            "Failed to get tracking area");
        goto release_port;
    }

    res = nxt_port_socket_twrite(task, wmsg.port, NXT_PORT_MSG_DATA,
                                 -1, ra->stream, reply_port->id, wmsg.write,
                                 &ra->msg_info.tracking);

    if (nxt_slow_path(res != NXT_OK)) {
        nxt_router_ra_error(ra, 500,
                            "Failed to send message to application");
        goto release_port;
    }

release_port:

    nxt_router_app_port_release(task, port, request_failed, 0);

    nxt_router_ra_update_peer(task, ra);
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
        RC(nxt_app_msg_write_prefixed_upcase(task, wmsg, &prefix, field->name,
                                             field->name_length));
        RC(nxt_app_msg_write(task, wmsg, field->value, field->value_length));

    } nxt_list_loop;

    /* end-of-headers mark */
    NXT_WRITE(&eof);

    RC(nxt_app_msg_write_size(task, wmsg, r->body.preread_size));

    for (b = r->body.buf; b != NULL; b = b->next) {
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

    for (b = r->body.buf; b != NULL; b = b->next) {
        RC(nxt_app_msg_write_raw(task, wmsg, b->mem.pos,
                                 nxt_buf_mem_used_size(&b->mem)));
    }

    nxt_list_each(field, h->fields) {
        RC(nxt_app_msg_write_prefixed_upcase(task, wmsg, &prefix, field->name,
                                             field->name_length));
        RC(nxt_app_msg_write(task, wmsg, field->value, field->value_length));

    } nxt_list_loop;

    /* end-of-headers mark */
    NXT_WRITE(&eof);

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
        RC(nxt_app_msg_write(task, wmsg, field->name, field->name_length));
        RC(nxt_app_msg_write(task, wmsg, field->value, field->value_length));

    } nxt_list_loop;

    /* end-of-headers mark */
    NXT_WRITE(&eof);

    RC(nxt_app_msg_write_size(task, wmsg, r->body.preread_size));

    for (b = r->body.buf; b != NULL; b = b->next) {
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
nxt_perl_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg)
{
    nxt_int_t                 rc;
    nxt_str_t                 str;
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

    if (h->query.length) {
        str.start = h->target.start;
        str.length = (h->target.length - h->query.length) - 1;

        RC(nxt_app_msg_write_str(task, wmsg, &str));

    } else {
        NXT_WRITE(&eof);
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
        RC(nxt_app_msg_write_prefixed_upcase(task, wmsg, &prefix,
                                             field->name, field->name_length));
        RC(nxt_app_msg_write(task, wmsg, field->value, field->value_length));
    } nxt_list_loop;

    /* end-of-headers mark */
    NXT_WRITE(&eof);

    RC(nxt_app_msg_write_size(task, wmsg, r->body.preread_size));

    for (b = r->body.buf; b != NULL; b = b->next) {

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
nxt_ruby_prepare_msg(nxt_task_t *task, nxt_app_request_t *r,
    nxt_app_wmsg_t *wmsg)
{
    nxt_int_t                 rc;
    nxt_str_t                 str;
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

    if (h->query.length) {
        str.start = h->target.start;
        str.length = (h->target.length - h->query.length) - 1;

        RC(nxt_app_msg_write_str(task, wmsg, &str));

    } else {
        NXT_WRITE(&eof);
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
        RC(nxt_app_msg_write_prefixed_upcase(task, wmsg, &prefix,
                                             field->name, field->name_length));
        RC(nxt_app_msg_write(task, wmsg, field->value, field->value_length));
    } nxt_list_loop;

    /* end-of-headers mark */
    NXT_WRITE(&eof);

    RC(nxt_app_msg_write_size(task, wmsg, r->body.preread_size));

    for (b = r->body.buf; b != NULL; b = b->next) {

        RC(nxt_app_msg_write_raw(task, wmsg, b->mem.pos,
                                 nxt_buf_mem_used_size(&b->mem)));
    }

#undef NXT_WRITE
#undef RC

    return NXT_OK;

fail:

    return NXT_ERROR;
}


static void
nxt_router_app_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_app_t                *app;
    nxt_bool_t               cancelled, unlinked;
    nxt_port_t               *port;
    nxt_timer_t              *timer;
    nxt_queue_link_t         *lnk;
    nxt_req_app_link_t       *pending_ra;
    nxt_app_parse_ctx_t      *ar;
    nxt_req_conn_link_t      *rc;
    nxt_port_select_state_t  state;

    timer = obj;

    nxt_debug(task, "router app timeout");

    ar = nxt_timer_data(timer, nxt_app_parse_ctx_t, timer);
    rc = ar->timer_data;
    app = rc->app;

    if (app == NULL) {
        goto generate_error;
    }

    port = NULL;
    pending_ra = NULL;

    if (rc->app_port != NULL) {
        port = rc->app_port;
        rc->app_port = NULL;
    }

    if (port == NULL && rc->ra != NULL && rc->ra->app_port != NULL) {
        port = rc->ra->app_port;
        rc->ra->app_port = NULL;
    }

    if (port == NULL) {
        goto generate_error;
    }

    nxt_thread_mutex_lock(&app->mutex);

    unlinked = nxt_queue_chk_remove(&port->app_link);

    if (!nxt_queue_is_empty(&port->pending_requests)) {
        lnk = nxt_queue_first(&port->pending_requests);

        pending_ra = nxt_queue_link_data(lnk, nxt_req_app_link_t,
                                         link_port_pending);

        nxt_assert(pending_ra->link_app_pending.next != NULL);

        nxt_debug(task, "app '%V' pending request #%uD found",
                  &app->name, pending_ra->stream);

        cancelled = nxt_router_msg_cancel(task, &pending_ra->msg_info,
                                          pending_ra->stream);

        if (cancelled) {
            nxt_router_ra_inc_use(pending_ra);

            state.ra = pending_ra;
            state.app = app;

            nxt_router_port_select(task, &state);

        } else {
            pending_ra = NULL;
        }
    }

    nxt_thread_mutex_unlock(&app->mutex);

    if (pending_ra != NULL
        && nxt_router_port_post_select(task, &state) == NXT_OK)
    {
        nxt_router_app_prepare_request(task, pending_ra);
    }

    nxt_debug(task, "send quit to app '%V' pid %PI", &app->name, port->pid);

    nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT, -1, 0, 0, NULL);

    nxt_port_use(task, port, unlinked ? -2 : -1);

generate_error:

    nxt_http_request_error(task, ar->request, NXT_HTTP_SERVICE_UNAVAILABLE);

    nxt_router_rc_unlink(task, rc);
}
