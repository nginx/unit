
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_conf.h>


typedef struct {
    nxt_str_t  type;
    uint32_t   workers;
} nxt_router_app_conf_t;


typedef struct {
    nxt_str_t  application;
} nxt_router_listener_conf_t;


typedef struct nxt_req_app_link_s nxt_req_app_link_t;
typedef struct nxt_start_worker_s nxt_start_worker_t;

struct nxt_start_worker_s {
    nxt_app_t              *app;
    nxt_req_app_link_t     *ra;

    nxt_work_t             work;
};


struct nxt_req_app_link_s {
    nxt_req_id_t         req_id;
    nxt_port_t           *app_port;
    nxt_port_t           *reply_port;
    nxt_app_parse_ctx_t  *ap;
    nxt_req_conn_link_t  *rc;

    nxt_queue_link_t     link; /* for nxt_app_t.requests */

    nxt_mp_t             *mem_pool;
    nxt_work_t           work;
};


static nxt_router_temp_conf_t *nxt_router_temp_conf(nxt_task_t *task);
static nxt_int_t nxt_router_conf_new(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, u_char *start, u_char *end);
static void nxt_router_conf_success(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
static void nxt_router_conf_error(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
static void nxt_router_conf_send(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, u_char *start, size_t size);
static void nxt_router_conf_buf_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_listen_sockets_sort(nxt_router_t *router,
    nxt_router_temp_conf_t *tmcf);

static nxt_int_t nxt_router_conf_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, u_char *start, u_char *end);
static nxt_app_t *nxt_router_app_find(nxt_queue_t *queue, nxt_str_t *name);
static nxt_app_t *nxt_router_listener_application(nxt_router_temp_conf_t *tmcf,
    nxt_str_t *name);
static nxt_int_t nxt_router_listen_sockets_stub_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
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
static nxt_int_t nxt_router_engine_joints_delete(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf, nxt_queue_t *sockets);

static nxt_int_t nxt_router_threads_create(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_router_temp_conf_t *tmcf);
static nxt_int_t nxt_router_thread_create(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_event_engine_t *engine);
static void nxt_router_apps_sort(nxt_router_t *router,
    nxt_router_temp_conf_t *tmcf);

static void nxt_router_engines_post(nxt_router_temp_conf_t *tmcf);
static void nxt_router_engine_post(nxt_router_engine_conf_t *recf);

static void nxt_router_thread_start(void *data);
static void nxt_router_listen_socket_create(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_listen_socket_update(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_listen_socket_delete(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_listen_socket_close(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_listen_socket_release(nxt_task_t *task,
    nxt_socket_conf_joint_t *joint);
static void nxt_router_thread_exit_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_conf_release(nxt_task_t *task,
    nxt_socket_conf_joint_t *joint);

static void nxt_router_send_sw_request(nxt_task_t *task, void *obj,
    void *data);
static nxt_bool_t nxt_router_app_free(nxt_task_t *task, nxt_app_t *app);
static nxt_port_t * nxt_router_app_get_port(nxt_app_t *app, uint32_t req_id);
static void nxt_router_app_release_port(nxt_task_t *task, void *obj,
    void *data);

static void nxt_router_conn_init(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_http_header_parse(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_process_http_request(nxt_task_t *task,
    nxt_conn_t *c, nxt_app_parse_ctx_t *ap);
static void nxt_router_process_http_request_mp(nxt_task_t *task,
    nxt_req_app_link_t *ra, nxt_port_t *port);
static void nxt_router_conn_ready(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_close(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_free(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_error(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_timeout(nxt_task_t *task, void *obj, void *data);
static nxt_msec_t nxt_router_conn_timeout_value(nxt_conn_t *c, uintptr_t data);

static void nxt_router_gen_error(nxt_task_t *task, nxt_conn_t *c, int code,
    const char* fmt, ...);

static nxt_router_t  *nxt_router;

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


static nxt_start_worker_t *
nxt_router_sw_create(nxt_task_t *task, nxt_app_t *app, nxt_req_app_link_t *ra)
{
    nxt_port_t          *master_port;
    nxt_runtime_t       *rt;
    nxt_start_worker_t  *sw;

    sw = nxt_zalloc(sizeof(nxt_start_worker_t));

    if (nxt_slow_path(sw == NULL)) {
        return NULL;
    }

    sw->app = app;
    sw->ra = ra;

    nxt_debug(task, "sw %p create, request #%uxD, app '%V' %p", sw,
                    ra->req_id, &app->name, app);

    rt = task->thread->runtime;
    master_port = rt->port_by_type[NXT_PROCESS_MASTER];

    sw->work.handler = nxt_router_send_sw_request;
    sw->work.task = &master_port->engine->task;
    sw->work.obj = sw;
    sw->work.data = task->thread->engine;
    sw->work.next = NULL;

    if (task->thread->engine != master_port->engine) {
        nxt_debug(task, "sw %p post send to master engine %p", sw,
                  master_port->engine);

        nxt_event_engine_post(master_port->engine, &sw->work);

    } else {
        nxt_router_send_sw_request(task, sw, sw->work.data);
    }

    return sw;
}


nxt_inline void
nxt_router_sw_release(nxt_task_t *task, nxt_start_worker_t *sw)
{
    nxt_debug(task, "sw %p release", sw);

    nxt_free(sw);
}


static nxt_req_app_link_t *
nxt_router_ra_create(nxt_task_t *task, nxt_req_conn_link_t *rc)
{
    nxt_mp_t            *mp;
    nxt_req_app_link_t  *ra;

    mp = rc->conn->mem_pool;

    ra = nxt_mp_retain(mp, sizeof(nxt_req_app_link_t));

    if (nxt_slow_path(ra == NULL)) {
        return NULL;
    }

    nxt_debug(task, "ra #%uxD create", ra->req_id);

    nxt_memzero(ra, sizeof(nxt_req_app_link_t));

    ra->req_id = rc->req_id;
    ra->app_port = NULL;
    ra->rc = rc;

    ra->mem_pool = mp;

    ra->work.handler = NULL;
    ra->work.task = &task->thread->engine->task;
    ra->work.obj = ra;
    ra->work.data = task->thread->engine;

    return ra;
}


static void
nxt_router_ra_release(nxt_task_t *task, void *obj, void *data)
{
    nxt_req_app_link_t  *ra;
    nxt_event_engine_t  *engine;

    ra = obj;
    engine = data;

    if (task->thread->engine != engine) {
        ra->work.handler = nxt_router_ra_release;
        ra->work.task = &engine->task;
        ra->work.next = NULL;

        nxt_debug(task, "ra #%uxD post release to %p", ra->req_id, engine);

        nxt_event_engine_post(engine, &ra->work);

        return;
    }

    nxt_debug(task, "ra #%uxD release", ra->req_id);

    if (ra->app_port != NULL) {

        if (ra->rc->conn != NULL) {
            ra->rc->app_port = ra->app_port;

        } else {
            nxt_router_app_release_port(task, ra->app_port, ra->app_port->app);
        }
    }

    nxt_mp_release(ra->mem_pool, ra);
}


void
nxt_router_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_new_port_handler(task, msg);

    if (msg->port_msg.stream == 0) {
        return;
    }

    if (msg->new_port == NULL || msg->new_port->type != NXT_PROCESS_WORKER) {
        msg->port_msg.type = _NXT_PORT_MSG_RPC_ERROR;
    }

    nxt_port_rpc_handler(task, msg);
}


void
nxt_router_conf_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    size_t                  dump_size;
    nxt_buf_t               *b;
    nxt_int_t               ret;
    nxt_router_temp_conf_t  *tmcf;

    b = msg->buf;

    dump_size = nxt_buf_used_size(b);

    if (dump_size > 300) {
        dump_size = 300;
    }

    nxt_debug(task, "router conf data (%z): %*s",
              msg->size, dump_size, b->mem.pos);

    tmcf = nxt_router_temp_conf(task);
    if (nxt_slow_path(tmcf == NULL)) {
        return;
    }

    tmcf->conf->router = nxt_router;
    tmcf->stream = msg->port_msg.stream;
    tmcf->port = nxt_runtime_port_find(task->thread->runtime,
                                       msg->port_msg.pid, 0);

    ret = nxt_router_conf_new(task, tmcf, b->mem.pos, b->mem.free);

    b->mem.pos = b->mem.free;

    if (ret == NXT_OK) {
        nxt_router_conf_success(task, tmcf);
        return;
    }

    nxt_log(task, NXT_LOG_CRIT, "failed to apply new conf");

    nxt_router_conf_error(task, tmcf);
}


void
nxt_router_remove_pid_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_remove_pid_handler(task, msg);

    if (msg->port_msg.stream == 0) {
        return;
    }

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


static nxt_int_t
nxt_router_conf_new(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    u_char *start, u_char *end)
{
    nxt_int_t                    ret;
    nxt_router_t                 *router;
    nxt_runtime_t                *rt;
    const nxt_event_interface_t  *interface;

    ret = nxt_router_conf_create(task, tmcf, start, end);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    router = tmcf->conf->router;

    nxt_router_listen_sockets_sort(router, tmcf);

    ret = nxt_router_listen_sockets_stub_create(task, tmcf);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    rt = task->thread->runtime;

    interface = nxt_service_get(rt->services, "engine", NULL);

    ret = nxt_router_engines_create(task, router, tmcf, interface);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    ret = nxt_router_threads_create(task, rt, tmcf);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    nxt_router_apps_sort(router, tmcf);

    nxt_router_engines_post(tmcf);

    nxt_queue_add(&router->sockets, &tmcf->updating);
    nxt_queue_add(&router->sockets, &tmcf->creating);

    return NXT_OK;
}


static void
nxt_router_conf_wait(nxt_task_t *task, void *obj, void *data)
{
    nxt_joint_job_t  *job;

    job = obj;

    nxt_router_conf_success(task, job->tmcf);
}


static void
nxt_router_conf_success(nxt_task_t *task, nxt_router_temp_conf_t *tmcf)
{
    nxt_debug(task, "temp conf count:%D", tmcf->count);

    if (--tmcf->count == 0) {
        nxt_router_conf_send(task, tmcf, (u_char *) "OK", 2);
    }
}


static void
nxt_router_conf_error(nxt_task_t *task, nxt_router_temp_conf_t *tmcf)
{
    nxt_socket_t       s;
    nxt_router_t       *router;
    nxt_queue_link_t   *qlk;
    nxt_socket_conf_t  *skcf;

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

    nxt_router_conf_send(task, tmcf, (u_char *) "ERROR", 5);
}


static void
nxt_router_conf_send(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    u_char *start, size_t size)
{
    nxt_buf_t  *b;

    b = nxt_buf_mem_alloc(tmcf->mem_pool, size, 0);
    if (nxt_slow_path(b == NULL)) {
        return;
    }

    b->mem.free = nxt_cpymem(b->mem.free, start, size);

    b->parent = tmcf->mem_pool;
    b->completion_handler = nxt_router_conf_buf_completion;

    nxt_port_socket_write(task, tmcf->port, NXT_PORT_MSG_DATA_LAST, -1,
                          tmcf->stream, 0, b);
}


static void
nxt_router_conf_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t  *mp;

    /* nxt_router_temp_conf_t mem pool. */
    mp = data;

    nxt_mp_destroy(mp);
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
        nxt_string("header_read_timeout"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_socket_conf_t, header_read_timeout),
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
    nxt_app_type_t              type;
    nxt_sockaddr_t              *sa;
    nxt_conf_value_t            *conf, *http;
    nxt_conf_value_t            *applications, *application;
    nxt_conf_value_t            *listeners, *listener;
    nxt_socket_conf_t           *skcf;
    nxt_router_app_conf_t       apcf;
    nxt_router_listener_conf_t  lscf;

    static nxt_str_t  http_path = nxt_string("/http");
    static nxt_str_t  applications_path = nxt_string("/applications");
    static nxt_str_t  listeners_path = nxt_string("/listeners");

    conf = nxt_conf_json_parse(tmcf->mem_pool, start, end);
    if (conf == NULL) {
        nxt_log(task, NXT_LOG_CRIT, "configuration parsing error");
        return NXT_ERROR;
    }

    ret = nxt_conf_map_object(conf, nxt_router_conf,
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

        ret = nxt_conf_map_object(application, nxt_router_app_conf,
                                  nxt_nitems(nxt_router_app_conf), &apcf);
        if (ret != NXT_OK) {
            nxt_log(task, NXT_LOG_CRIT, "application map error");
            goto app_fail;
        }

        nxt_debug(task, "application type: %V", &apcf.type);
        nxt_debug(task, "application workers: %D", apcf.workers);

        type = nxt_app_parse_type(&apcf.type);

        if (type == NXT_APP_UNKNOWN) {
            nxt_log(task, NXT_LOG_CRIT, "unknown application type: \"%V\"",
                    &apcf.type);
            goto app_fail;
        }

        if (nxt_app_modules[type] == NULL) {
            nxt_log(task, NXT_LOG_CRIT, "unsupported application type: \"%V\"",
                    &apcf.type);
            goto app_fail;
        }

        ret = nxt_thread_mutex_create(&app->mutex);
        if (ret != NXT_OK) {
            goto app_fail;
        }

        nxt_queue_init(&app->ports);
        nxt_queue_init(&app->requests);

        app->name.length = name.length;
        nxt_memcpy(app->name.start, name.start, name.length);

        app->type = type;
        app->max_workers = apcf.workers;
        app->live = 1;
        app->module = nxt_app_modules[type];

        nxt_queue_insert_tail(&tmcf->apps, &app->link);
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

    mp = tmcf->conf->mem_pool;

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

        ret = nxt_conf_map_object(listener, nxt_router_listener_conf,
                                  nxt_nitems(nxt_router_listener_conf), &lscf);
        if (ret != NXT_OK) {
            nxt_log(task, NXT_LOG_CRIT, "listener map error");
            goto fail;
        }

        nxt_debug(task, "application: %V", &lscf.application);

        // STUB, default values if http block is not defined.
        skcf->header_buffer_size = 2048;
        skcf->large_header_buffer_size = 8192;
        skcf->header_read_timeout = 5000;

        if (http != NULL) {
            ret = nxt_conf_map_object(http, nxt_router_http_conf,
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
    skcf->listen.socklen = sa->socklen;
    skcf->listen.address_length = sa->length;

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


static nxt_int_t
nxt_router_listen_sockets_stub_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf)
{
    nxt_int_t            ret;
    nxt_socket_t         s;
    nxt_queue_link_t     *qlk, *nqlk;
    nxt_socket_conf_t    *skcf;
    nxt_router_socket_t  *rtsk;

    for (qlk = nxt_queue_first(&tmcf->pending);
         qlk != nxt_queue_tail(&tmcf->pending);
         qlk = nqlk)
    {
        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);

        s = nxt_listen_socket_create0(task, skcf->sockaddr, NXT_NONBLOCK);
        if (nxt_slow_path(s == -1)) {
            return NXT_ERROR;
        }

        ret = nxt_listen_socket(task, s, NXT_LISTEN_BACKLOG);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }

        skcf->listen.socket = s;

        rtsk = nxt_malloc(sizeof(nxt_router_socket_t));
        if (nxt_slow_path(rtsk == NULL)) {
            goto fail;
        }

        rtsk->count = 0;
        rtsk->fd = skcf->listen.socket;
        skcf->socket = rtsk;

        nqlk = nxt_queue_next(qlk);
        nxt_queue_remove(qlk);
        nxt_queue_insert_tail(&tmcf->creating, qlk);
    }

    return NXT_OK;

fail:

    nxt_socket_close(task, s);

    return NXT_ERROR;
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
            ret = nxt_router_engine_conf_update(tmcf, recf);

        } else {
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

        recf->engine = nxt_event_engine_create(task, interface, NULL, 0, 0);
        if (nxt_slow_path(recf->engine == NULL)) {
            return NXT_ERROR;
        }

        ret = nxt_router_engine_conf_create(tmcf, recf);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

        nxt_queue_insert_tail(&router->engines, &recf->engine->link0);

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
nxt_router_apps_sort(nxt_router_t *router, nxt_router_temp_conf_t *tmcf)
{
    nxt_app_t    *app;
    nxt_port_t   *port;

    nxt_queue_each(app, &router->apps, nxt_app_t, link) {

        nxt_queue_remove(&app->link);

        nxt_thread_log_debug("about to remove app '%V' %p", &app->name, app);

        app->live = 0;

        if (nxt_router_app_free(NULL, app) != 0) {
            continue;
        }

        if (!nxt_queue_is_empty(&app->requests)) {

            nxt_thread_log_debug("app '%V' %p pending requests found",
                                 &app->name, app);
            continue;
        }

        do {
            port = nxt_router_app_get_port(app, 0);
            if (port == NULL) {
                break;
            }

            nxt_thread_log_debug("port %p send quit", port);

            nxt_port_socket_write(&port->engine->task, port,
                                  NXT_PORT_MSG_QUIT, -1, 0, 0, NULL);
        } while (1);

    } nxt_queue_loop;

    nxt_queue_add(&router->apps, &tmcf->previous);
    nxt_queue_add(&router->apps, &tmcf->apps);
}


static void
nxt_router_engines_post(nxt_router_temp_conf_t *tmcf)
{
    nxt_uint_t                n;
    nxt_router_engine_conf_t  *recf;

    recf = tmcf->engines->elts;

    for (n = tmcf->engines->nelts; n != 0; n--) {
        nxt_router_engine_post(recf);
        recf++;
    }
}


static void
nxt_router_engine_post(nxt_router_engine_conf_t *recf)
{
    nxt_work_t  *work, *next;

    for (work = recf->jobs; work != NULL; work = next) {
        next = work->next;
        work->next = NULL;

        nxt_event_engine_post(recf->engine, work);
    }
}


static void
nxt_router_app_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);

static nxt_port_handler_t  nxt_router_app_port_handlers[] = {
    NULL, /* NXT_PORT_MSG_QUIT         */
    NULL, /* NXT_PORT_MSG_NEW_PORT     */
    NULL, /* NXT_PORT_MSG_CHANGE_FILE  */
    /* TODO: remove mmap_handler from app ports */
    nxt_port_mmap_handler, /* NXT_PORT_MSG_MMAP         */
    nxt_router_app_data_handler,
    NULL, /* NXT_PORT_MSG_REMOVE_PID   */
    NULL, /* NXT_PORT_MSG_READY        */
    NULL, /* NXT_PORT_MSG_START_WORKER */
    nxt_port_rpc_handler,
    nxt_port_rpc_handler,
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
    thread->fiber = &engine->fibers->fiber;

    engine->mem_pool = nxt_mp_create(4096, 128, 1024, 64);

    port = nxt_port_new(nxt_port_get_next_id(), nxt_pid, NXT_PROCESS_ROUTER);
    if (nxt_slow_path(port == NULL)) {
        return;
    }

    ret = nxt_port_socket_init(task, port, 0);
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_mp_release(port->mem_pool, port);
        return;
    }

    engine->port = port;

    nxt_port_enable(task, port, nxt_router_app_port_handlers);

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
    exit = nxt_queue_is_empty(&joint->engine->joints);

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

    nxt_mp_thread_adopt(port->mem_pool);
    nxt_port_release(port);

    nxt_mp_thread_adopt(engine->mem_pool);
    nxt_mp_destroy(engine->mem_pool);

    nxt_event_engine_free(engine);

    nxt_free(link);
}


static const nxt_conn_state_t  nxt_router_conn_read_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_router_conn_http_header_parse,
    .close_handler = nxt_router_conn_close,
    .error_handler = nxt_router_conn_error,

    .timer_handler = nxt_router_conn_timeout,
    .timer_value = nxt_router_conn_timeout_value,
    .timer_data = offsetof(nxt_socket_conf_t, header_read_timeout),
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

    c->read_state = &nxt_router_conn_read_state;

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
nxt_router_app_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    size_t               dump_size;
    nxt_buf_t            *b, *i, *last;
    nxt_conn_t           *c;
    nxt_req_conn_link_t  *rc;
    nxt_event_engine_t   *engine;

    b = msg->buf;
    engine = task->thread->engine;

    rc = nxt_event_engine_request_find(engine, msg->port_msg.stream);
    if (nxt_slow_path(rc == NULL)) {

        nxt_debug(task, "request id %08uxD not found", msg->port_msg.stream);

        /* Mark buffers as read. */
        for (i = b; i != NULL; i = i->next) {
            i->mem.pos = i->mem.free;
        }

        return;
    }

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

        if (rc->app_port != NULL) {
            nxt_router_app_release_port(task, rc->app_port, rc->app_port->app);

            rc->app_port = NULL;
        }
    }

    if (b == NULL) {
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

nxt_inline const char *
nxt_router_text_by_code(int code)
{
    switch (code) {
    case 400: return "Bad request";
    case 404: return "Not found";
    case 403: return "Forbidden";
    case 500:
    default:  return "Internal server error";
    }
}


static nxt_buf_t *
nxt_router_get_error_buf(nxt_task_t *task, nxt_mp_t *mp, int code,
    const char* fmt, va_list args)
{
    nxt_buf_t   *b, *last;
    const char  *msg;

    b = nxt_buf_mem_ts_alloc(task, mp, 16384);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->mem.free = nxt_sprintf(b->mem.free, b->mem.end,
        "HTTP/1.0 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Connection: close\r\n\r\n",
        code, nxt_router_text_by_code(code));

    msg = (const char *) b->mem.free;

    b->mem.free = nxt_vsprintf(b->mem.free, b->mem.end, fmt, args);

    nxt_log_alert(task->log, "error %d: %s", code, msg);

    last = nxt_buf_mem_ts_alloc(task, mp, 0);

    if (nxt_slow_path(last == NULL)) {
        nxt_mp_release(mp, b);
        return NULL;
    }

    nxt_buf_set_sync(last);
    nxt_buf_set_last(last);

    nxt_buf_chain_add(&b, last);

    return b;
}



static void
nxt_router_gen_error(nxt_task_t *task, nxt_conn_t *c, int code,
    const char* fmt, ...)
{
    va_list    args;
    nxt_buf_t  *b;

    va_start(args, fmt);
    b = nxt_router_get_error_buf(task, c->mem_pool, code, fmt, args);
    va_end(args);

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
nxt_router_sw_ready(nxt_task_t *task, nxt_port_recv_msg_t *msg, void *data)
{
    nxt_start_worker_t  *sw;

    sw = data;

    nxt_assert(sw != NULL);
    nxt_assert(sw->app->pending_workers != 0);

    msg->new_port->app = sw->app;

    sw->app->pending_workers--;
    sw->app->workers++;

    nxt_debug(task, "sw %p got port %p", sw, msg->new_port);

    nxt_router_app_release_port(task, msg->new_port, sw->app);

    nxt_router_sw_release(task, sw);
}


static void
nxt_router_sw_error(nxt_task_t *task, nxt_port_recv_msg_t *msg, void *data)
{
    nxt_start_worker_t  *sw;

    sw = data;

    nxt_assert(sw != NULL);
    nxt_assert(sw->app->pending_workers != 0);

    sw->app->pending_workers--;

    nxt_debug(task, "sw %p error, failed to start app '%V'", sw, &sw->app->name);

    nxt_router_sw_release(task, sw);
}


static void
nxt_router_send_sw_request(nxt_task_t *task, void *obj, void *data)
{
    size_t              size;
    uint32_t            stream;
    nxt_buf_t           *b;
    nxt_app_t           *app;
    nxt_port_t          *master_port, *router_port;
    nxt_runtime_t       *rt;
    nxt_start_worker_t  *sw;

    sw = obj;
    app = sw->app;

    nxt_queue_insert_tail(&app->requests, &sw->ra->link);

    if (app->workers + app->pending_workers >= app->max_workers) {
        nxt_debug(task, "app '%V' %p %uD/%uD running/penging workers, "
                  "post sw #%uxD release to %p", &app->name, app,
                  "sw %p release", &app->name, app,
                   app->workers, app->pending_workers, sw);

        nxt_router_sw_release(task, sw);

        return;
    }

    app->pending_workers++;

    nxt_debug(task, "sw %p send", sw);

    rt = task->thread->runtime;
    master_port = rt->port_by_type[NXT_PROCESS_MASTER];
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];

    size = app->name.length + 1 + app->conf.length;

    b = nxt_buf_mem_alloc(master_port->mem_pool, size, 0);

    nxt_buf_cpystr(b, &app->name);
    *b->mem.free++ = '\0';
    nxt_buf_cpystr(b, &app->conf);

    stream = nxt_port_rpc_register_handler(task, router_port,
                                           nxt_router_sw_ready,
                                           nxt_router_sw_error,
                                           master_port->pid, sw);

    nxt_port_socket_write(task, master_port, NXT_PORT_MSG_START_WORKER, -1,
                          stream, router_port->id, b);
}


static nxt_bool_t
nxt_router_app_free(nxt_task_t *task, nxt_app_t *app)
{
    nxt_queue_link_t    *lnk;
    nxt_req_app_link_t  *ra;

    nxt_thread_log_debug("app '%V' %p state: %d/%uD/%uD/%d", &app->name, app,
                         app->live, app->workers, app->pending_workers,
                         nxt_queue_is_empty(&app->requests));

    if (app->live == 0 && app->workers == 0 &&
        app->pending_workers == 0 &&
        nxt_queue_is_empty(&app->requests)) {

        nxt_thread_mutex_destroy(&app->mutex);
        nxt_free(app);

        return 1;
    }

    if (app->live == 1 && nxt_queue_is_empty(&app->requests) == 0 &&
       (app->workers + app->pending_workers < app->max_workers)) {

        lnk = nxt_queue_first(&app->requests);
        nxt_queue_remove(lnk);

        ra = nxt_queue_link_data(lnk, nxt_req_app_link_t, link);

        nxt_router_sw_create(task, app, ra);
    }

    return 0;
}


static nxt_port_t *
nxt_router_app_get_port(nxt_app_t *app, uint32_t req_id)
{
    nxt_port_t        *port;
    nxt_queue_link_t  *lnk;

    port = NULL;

    nxt_thread_mutex_lock(&app->mutex);

    if (!nxt_queue_is_empty(&app->ports)) {
        lnk = nxt_queue_first(&app->ports);
        nxt_queue_remove(lnk);

        lnk->next = NULL;

        port = nxt_queue_link_data(lnk, nxt_port_t, app_link);

        port->app_req_id = req_id;
    }

    nxt_thread_mutex_unlock(&app->mutex);

    return port;
}


static void
nxt_router_app_release_port(nxt_task_t *task, void *obj, void *data)
{
    nxt_app_t            *app;
    nxt_port_t           *port;
    nxt_work_t           *work;
    nxt_queue_link_t     *lnk;
    nxt_req_app_link_t   *ra;

    port = obj;
    app = data;

    nxt_assert(app != NULL);
    nxt_assert(app == port->app);
    nxt_assert(port->app_link.next == NULL);


    if (task->thread->engine != port->engine) {
        work = &port->work;

        nxt_debug(task, "post release port to engine %p", port->engine);

        work->next = NULL;
        work->handler = nxt_router_app_release_port;
        work->task = &port->engine->task;
        work->obj = port;
        work->data = app;

        nxt_event_engine_post(port->engine, work);

        return;
    }

    if (!nxt_queue_is_empty(&app->requests)) {
        lnk = nxt_queue_first(&app->requests);
        nxt_queue_remove(lnk);

        ra = nxt_queue_link_data(lnk, nxt_req_app_link_t, link);

        nxt_debug(task, "app '%V' %p process next request #%uxD",
                  &app->name, app, ra->req_id);

        ra->app_port = port;
        port->app_req_id = ra->req_id;

        nxt_router_process_http_request_mp(task, ra, port);

        nxt_router_ra_release(task, ra, ra->work.data);

        return;
    }

    port->app_req_id = 0;

    if (port->pair[1] == -1) {
        nxt_debug(task, "app '%V' %p port already closed (pid %PI dead?)",
                  &app->name, app, port->pid);

        app->workers--;
        nxt_router_app_free(task, app);

        port->app = NULL;

        nxt_port_release(port);

        return;
    }

    if (!app->live) {
        nxt_debug(task, "app '%V' %p is not alive, send QUIT to port",
                  &app->name, app);

        nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT,
                              -1, 0, 0, NULL);

        return;
    }

    nxt_debug(task, "app '%V' %p requests queue is empty, keep the port",
              &app->name, app);

    nxt_thread_mutex_lock(&app->mutex);

    nxt_queue_insert_head(&app->ports, &port->app_link);

    nxt_thread_mutex_unlock(&app->mutex);
}


nxt_bool_t
nxt_router_app_remove_port(nxt_port_t *port)
{
    nxt_app_t   *app;
    nxt_bool_t  busy;

    app = port->app;
    busy = port->app_req_id != 0;

    if (app == NULL) {
        nxt_thread_log_debug("port %p app remove, no app", port);

        nxt_assert(port->app_link.next == NULL);

        return 1;
    }

    nxt_thread_mutex_lock(&app->mutex);

    if (port->app_link.next != NULL) {

        nxt_queue_remove(&port->app_link);
        port->app_link.next = NULL;

    }

    nxt_thread_mutex_unlock(&app->mutex);

    if (busy == 0) {
        nxt_thread_log_debug("port %p app remove, free, app '%V' %p", port,
                             &app->name, app);

        app->workers--;
        nxt_router_app_free(&port->engine->task, app);

        return 1;
    }

    nxt_thread_log_debug("port %p app remove, busy, app '%V' %p, req #%uxD",
                         port, &app->name, app, port->app_req_id);

    return 0;
}


static nxt_int_t
nxt_router_app_port(nxt_task_t *task, nxt_req_app_link_t *ra)
{
    nxt_app_t                *app;
    nxt_conn_t               *c;
    nxt_port_t               *port;
    nxt_start_worker_t       *sw;
    nxt_socket_conf_joint_t  *joint;

    port = NULL;
    c = ra->rc->conn;

    joint = c->listen->socket.data;
    app = joint->socket_conf->application;

    if (app == NULL) {
        nxt_router_gen_error(task, c, 500,
                             "Application is NULL in socket_conf");
        return NXT_ERROR;
    }


    port = nxt_router_app_get_port(app, ra->req_id);

    if (port != NULL) {
        nxt_debug(task, "already have port for app '%V'", &app->name);

        ra->app_port = port;
        return NXT_OK;
    }

    sw = nxt_router_sw_create(task, app, ra);

    if (nxt_slow_path(sw == NULL)) {
        nxt_router_gen_error(task, c, 500,
                             "Failed to allocate start worker struct");
        return NXT_ERROR;
    }

    return NXT_AGAIN;
}


static void
nxt_router_conn_http_header_parse(nxt_task_t *task, void *obj, void *data)
{
    size_t                    size, preread;
    nxt_int_t                 ret;
    nxt_buf_t                 *b;
    nxt_conn_t                *c;
    nxt_app_parse_ctx_t       *ap;
    nxt_socket_conf_joint_t   *joint;
    nxt_app_request_header_t  *h;

    c = obj;
    ap = data;
    b = c->read;

    nxt_debug(task, "router conn http header parse");

    if (ap == NULL) {
        ap = nxt_mp_zget(c->mem_pool, sizeof(nxt_app_parse_ctx_t));
        if (nxt_slow_path(ap == NULL)) {
            nxt_router_conn_close(task, c, data);
            return;
        }

        ret = nxt_app_http_req_init(task, ap);
        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_router_conn_close(task, c, data);
            return;
        }

        c->socket.data = ap;

        ap->r.remote.start = nxt_sockaddr_address(c->remote);
        ap->r.remote.length = c->remote->address_length;
    }

    h = &ap->r.header;

    ret = nxt_app_http_req_parse(task, ap, b);

    nxt_debug(task, "http parse request: %d", ret);

    switch (nxt_expect(NXT_DONE, ret)) {

    case NXT_DONE:
        preread = nxt_buf_mem_used_size(&b->mem);

        nxt_debug(task, "router request header parsing complete, "
                  "content length: %O, preread: %uz",
                  h->parsed_content_length, preread);

        nxt_router_process_http_request(task, c, ap);
        return;

    case NXT_ERROR:
        nxt_router_conn_close(task, c, data);
        return;

    default:  /* NXT_AGAIN */

        if (h->done == 0) {

            if (c->read->mem.free == c->read->mem.end) {
                joint = c->listen->socket.data;
                size = joint->socket_conf->large_header_buffer_size;

                if (size > (size_t) nxt_buf_mem_size(&b->mem)) {
                    b = nxt_buf_mem_alloc(c->mem_pool, size, 0);
                    if (nxt_slow_path(b == NULL)) {
                        nxt_router_conn_close(task, c, data);
                        return;
                    }

                    size = c->read->mem.free - c->read->mem.pos;

                    c->read = nxt_buf_cpy(b, c->read->mem.pos, size);
                } else {
                    nxt_router_gen_error(task, c, 400,
                                         "Too long request headers");
                    return;
                }
            }
        }

        if (ap->r.body.done == 0) {

            preread = nxt_buf_mem_used_size(&b->mem);

            if (h->parsed_content_length - preread >
                (size_t) nxt_buf_mem_free_size(&b->mem)) {

                b = nxt_buf_mem_alloc(c->mem_pool, h->parsed_content_length, 0);
                if (nxt_slow_path(b == NULL)) {
                    nxt_router_gen_error(task, c, 500, "Failed to allocate "
                                         "buffer for request body");
                    return;
                }

                c->read = nxt_buf_cpy(b, c->read->mem.pos, preread);
            }

            nxt_debug(task, "router request body read again, rest: %uz",
                      h->parsed_content_length - preread);

        }

    }

    nxt_conn_read(task->thread->engine, c);
}


static void
nxt_router_process_http_request(nxt_task_t *task, nxt_conn_t *c,
    nxt_app_parse_ctx_t *ap)
{
    nxt_mp_t             *port_mp;
    nxt_int_t            res;
    nxt_port_t           *port;
    nxt_req_id_t         req_id;
    nxt_event_engine_t   *engine;
    nxt_req_app_link_t   *ra;
    nxt_req_conn_link_t  *rc;

    engine = task->thread->engine;

    do {
        req_id = nxt_random(&task->thread->random);
    } while (nxt_event_engine_request_find(engine, req_id) != NULL);

    rc = nxt_conn_request_add(c, req_id);

    if (nxt_slow_path(rc == NULL)) {
        nxt_router_gen_error(task, c, 500, "Failed to allocate "
                             "req->conn link");

        return;
    }

    nxt_event_engine_request_add(engine, rc);

    nxt_debug(task, "req_id %uxD linked to conn %p at engine %p",
              req_id, c, engine);


    ra = nxt_router_ra_create(task, rc);

    ra->ap = ap;
    ra->reply_port = engine->port;

    res = nxt_router_app_port(task, ra);

    if (res != NXT_OK) {
        return;
    }

    port = ra->app_port;

    if (nxt_slow_path(port == NULL)) {
        nxt_router_gen_error(task, rc->conn, 500, "Application port not found");
        return;
    }

    port_mp = port->mem_pool;
    port->mem_pool = c->mem_pool;

    nxt_router_process_http_request_mp(task, ra, port);

    port->mem_pool = port_mp;


    nxt_router_ra_release(task, ra, ra->work.data);
}


static void
nxt_router_process_http_request_mp(nxt_task_t *task, nxt_req_app_link_t *ra,
    nxt_port_t *port)
{
    nxt_int_t            res;
    nxt_port_t           *c_port, *reply_port;
    nxt_conn_t           *c;
    nxt_app_wmsg_t       wmsg;
    nxt_app_parse_ctx_t  *ap;

    reply_port = ra->reply_port;
    ap = ra->ap;
    c = ra->rc->conn;

    c_port = nxt_process_connected_port_find(port->process, reply_port->pid,
                                             reply_port->id);
    if (nxt_slow_path(c_port != reply_port)) {
        res = nxt_port_send_port(task, port, reply_port, 0);

        if (nxt_slow_path(res != NXT_OK)) {
            nxt_router_gen_error(task, c, 500,
                                 "Failed to send reply port to application");
            return;
        }

        nxt_process_connected_port_add(port->process, reply_port);
    }

    wmsg.port = port;
    wmsg.write = NULL;
    wmsg.buf = &wmsg.write;
    wmsg.stream = ra->req_id;

    res = port->app->module->prepare_msg(task, &ap->r, &wmsg);

    if (nxt_slow_path(res != NXT_OK)) {
        nxt_router_gen_error(task, c, 500,
                             "Failed to prepare message for application");
        return;
    }

    nxt_debug(task, "about to send %d bytes buffer to worker port %d",
                    nxt_buf_used_size(wmsg.write),
                    wmsg.port->socket.fd);

    res = nxt_port_socket_write(task, wmsg.port, NXT_PORT_MSG_DATA,
                                 -1, ra->req_id, reply_port->id, wmsg.write);

    if (nxt_slow_path(res != NXT_OK)) {
        nxt_router_gen_error(task, c, 500,
                             "Failed to send message to application");
        return;
    }
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
    nxt_req_conn_link_t      *rc;
    nxt_socket_conf_joint_t  *joint;

    c = obj;

    nxt_debug(task, "router conn close done");

    nxt_queue_each(rc, &c->requests, nxt_req_conn_link_t, link) {

        nxt_debug(task, "conn %p close, req %uxD", c, rc->req_id);

        if (rc->app_port != NULL) {
            nxt_router_app_release_port(task, rc->app_port, rc->app_port->app);

            rc->app_port = NULL;
        }

        rc->conn = NULL;

        nxt_event_engine_request_remove(task->thread->engine, rc);

    } nxt_queue_loop;

    nxt_queue_remove(&c->link);

    joint = c->listen->socket.data;

    task = &task->thread->engine->task;

    nxt_mp_cleanup(c->mem_pool, nxt_router_conn_mp_cleanup, task, joint, NULL);

    nxt_mp_release(c->mem_pool, c);
}


static void
nxt_router_conn_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t  *c;

    c = obj;

    nxt_debug(task, "router conn error");

    c->write_state = &nxt_router_conn_close_state;

    nxt_conn_close(task->thread->engine, c);
}


static void
nxt_router_conn_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t   *c;
    nxt_timer_t  *timer;

    timer = obj;

    nxt_debug(task, "router conn timeout");

    c = nxt_read_timer_conn(timer);

    c->write_state = &nxt_router_conn_close_state;

    nxt_conn_close(task->thread->engine, c);
}


static nxt_msec_t
nxt_router_conn_timeout_value(nxt_conn_t *c, uintptr_t data)
{
    nxt_socket_conf_joint_t  *joint;

    joint = c->listen->socket.data;

    return nxt_value_at(nxt_msec_t, joint->socket_conf, data);
}
