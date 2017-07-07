
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_conf.h>
#include <nxt_application.h>


typedef struct {
    nxt_str_t  application_type;
    uint32_t   application_workers;
} nxt_router_listener_conf_t;


static nxt_router_temp_conf_t *nxt_router_temp_conf(nxt_task_t *task,
    nxt_router_t *router);
static void nxt_router_listen_sockets_sort(nxt_router_t *router,
    nxt_router_temp_conf_t *tmcf);

static nxt_int_t nxt_router_conf_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, u_char *start, u_char *end);
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
static nxt_int_t nxt_router_engine_joints_create(nxt_mp_t *mp,
    nxt_router_engine_conf_t *recf, nxt_queue_t *sockets, nxt_array_t *array,
    nxt_work_handler_t handler);
static nxt_int_t nxt_router_engine_joints_delete(nxt_router_engine_conf_t *recf,
    nxt_queue_t *sockets);

static nxt_int_t nxt_router_threads_create(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_router_temp_conf_t *tmcf);
static nxt_int_t nxt_router_thread_create(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_event_engine_t *engine);

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

static void nxt_router_conn_init(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_http_header_parse(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_process_http_request(nxt_task_t *task,
    nxt_conn_t *c, nxt_app_parse_ctx_t *ap);
static void nxt_router_conn_ready(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_close(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_free(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_error(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_timeout(nxt_task_t *task, void *obj, void *data);
static nxt_msec_t nxt_router_conn_timeout_value(nxt_conn_t *c, uintptr_t data);

static nxt_router_t  *nxt_router;

nxt_int_t
nxt_router_start(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_int_t     ret;
    nxt_router_t  *router;

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

    nxt_router = router;

    return NXT_OK;
}


nxt_int_t
nxt_router_new_conf(nxt_task_t *task, nxt_runtime_t *rt, nxt_router_t *router,
    u_char *start, u_char *end)
{
    nxt_int_t                    ret;
    nxt_router_temp_conf_t       *tmcf;
    const nxt_event_interface_t  *interface;

    tmcf = nxt_router_temp_conf(task, router);
    if (nxt_slow_path(tmcf == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_router_conf_create(task, tmcf, start, end);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    nxt_router_listen_sockets_sort(router, tmcf);

    ret = nxt_router_listen_sockets_stub_create(task, tmcf);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    interface = nxt_service_get(rt->services, "engine", NULL);

    ret = nxt_router_engines_create(task, router, tmcf, interface);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    ret = nxt_router_threads_create(task, rt, tmcf);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    nxt_router_engines_post(tmcf);

    nxt_queue_add(&router->sockets, &tmcf->updating);
    nxt_queue_add(&router->sockets, &tmcf->creating);

//    nxt_mp_destroy(tmcf->mem_pool);

    return NXT_OK;
}


static nxt_router_temp_conf_t *
nxt_router_temp_conf(nxt_task_t *task, nxt_router_t *router)
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
    rtcf->router = router;
    rtcf->count = 1;

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

    return tmcf;

temp_fail:

    nxt_mp_destroy(tmp);

fail:

    nxt_mp_destroy(mp);

    return NULL;
}


static nxt_conf_map_t  nxt_router_conf[] = {
    {
        nxt_string("threads"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_router_conf_t, threads),
    },

    {
        nxt_null_string, 0, 0,
    },
};


static nxt_conf_map_t  nxt_router_listener_conf[] = {
    {
        nxt_string("_application_type"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_router_listener_conf_t, application_type),
    },

    {
        nxt_string("_application_workers"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_router_listener_conf_t, application_workers),
    },

    {
        nxt_null_string, 0, 0,
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

    {
        nxt_null_string, 0, 0,
    },
};


static nxt_int_t
nxt_router_conf_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    u_char *start, u_char *end)
{
    nxt_mp_t                    *mp;
    uint32_t                    next;
    nxt_int_t                   ret;
    nxt_str_t                   name;
    nxt_sockaddr_t              *sa;
    nxt_conf_value_t            *conf, *listeners, *router, *http, *listener;
    nxt_socket_conf_t           *skcf;
    nxt_router_listener_conf_t  lscf;

    static nxt_str_t  router_path = nxt_string("/router");
    static nxt_str_t  http_path = nxt_string("/http");
    static nxt_str_t  listeners_path = nxt_string("/listeners");

    conf = nxt_conf_json_parse(tmcf->mem_pool, start, end);
    if (conf == NULL) {
        nxt_log(task, NXT_LOG_CRIT, "configuration parsing error");
        return NXT_ERROR;
    }

    router = nxt_conf_get_path(conf, &router_path);

    if (router == NULL) {
        nxt_log(task, NXT_LOG_CRIT, "no \"/router\" block");
        return NXT_ERROR;
    }

    ret = nxt_conf_map_object(router, nxt_router_conf, tmcf->conf);
    if (ret != NXT_OK) {
        nxt_log(task, NXT_LOG_CRIT, "router map error");
        return NXT_ERROR;
    }

    if (tmcf->conf->threads == 0) {
        tmcf->conf->threads = nxt_ncpu;
    }

    http = nxt_conf_get_path(conf, &http_path);

    if (http == NULL) {
        nxt_log(task, NXT_LOG_CRIT, "no \"/http\" block");
        return NXT_ERROR;
    }

    listeners = nxt_conf_get_path(conf, &listeners_path);

    if (listeners == NULL) {
        nxt_log(task, NXT_LOG_CRIT, "no \"/listeners\" block");
        return NXT_ERROR;
    }

    mp = tmcf->conf->mem_pool;

    next = 0;

    for ( ;; ) {
        listener = nxt_conf_next_object_member(listeners, &name, &next);
        if (listener == NULL) {
            break;
        }

        sa = nxt_sockaddr_parse(mp, &name);
        if (sa == NULL) {
            nxt_log(task, NXT_LOG_CRIT, "invalid listener \"%V\"", &name);
            return NXT_ERROR;
        }

        sa->type = SOCK_STREAM;

        nxt_debug(task, "router listener: \"%*s\"",
                  sa->length, nxt_sockaddr_start(sa));

        skcf = nxt_router_socket_conf(task, mp, sa);
        if (skcf == NULL) {
            return NXT_ERROR;
        }

        ret = nxt_conf_map_object(listener, nxt_router_listener_conf, &lscf);
        if (ret != NXT_OK) {
            nxt_log(task, NXT_LOG_CRIT, "listener map error");
            return NXT_ERROR;
        }

        nxt_debug(task, "router type: %V", &lscf.application_type);
        nxt_debug(task, "router workers: %D", lscf.application_workers);

        ret = nxt_conf_map_object(http, nxt_router_http_conf, skcf);
        if (ret != NXT_OK) {
            nxt_log(task, NXT_LOG_CRIT, "http map error");
            return NXT_ERROR;
        }

        skcf->listen.handler = nxt_router_conn_init;
        skcf->router_conf = tmcf->conf;

        nxt_queue_insert_tail(&tmcf->pending, &skcf->link);
    }

    return NXT_OK;
}


static nxt_socket_conf_t *
nxt_router_socket_conf(nxt_task_t *task, nxt_mp_t *mp, nxt_sockaddr_t *sa)
{
    nxt_socket_conf_t  *conf;

    conf = nxt_mp_zget(mp, sizeof(nxt_socket_conf_t));
    if (nxt_slow_path(conf == NULL)) {
        return NULL;
    }

    conf->sockaddr = sa;

    conf->listen.sockaddr = sa;
    conf->listen.socklen = sa->socklen;
    conf->listen.address_length = sa->length;

    conf->listen.socket = -1;
    conf->listen.backlog = NXT_LISTEN_BACKLOG;
    conf->listen.flags = NXT_NONBLOCK;
    conf->listen.read_after_accept = 1;

    return conf;
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
        rtsk = nxt_malloc(sizeof(nxt_router_socket_t));
        if (nxt_slow_path(rtsk == NULL)) {
            return NXT_ERROR;
        }

        rtsk->count = 0;

        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);
        skcf->socket = rtsk;

        s = nxt_listen_socket_create0(task, skcf->sockaddr, NXT_NONBLOCK);
        if (nxt_slow_path(s == -1)) {
            return NXT_ERROR;
        }

        ret = nxt_listen_socket(task, s, NXT_LISTEN_BACKLOG);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }

        skcf->listen.socket = s;

        rtsk->fd = s;

        nqlk = nxt_queue_next(qlk);
        nxt_queue_remove(qlk);
        nxt_queue_insert_tail(&tmcf->creating, qlk);
    }

    return NXT_OK;
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
        // STUB
        recf->task = recf->engine->task;

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
        // STUB
        recf->task = recf->engine->task;

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
    nxt_mp_t               *mp;
    nxt_int_t              ret;
    nxt_thread_spinlock_t  *lock;

    recf->creating = nxt_array_create(tmcf->mem_pool, 4, sizeof(nxt_work_t));
    if (nxt_slow_path(recf->creating == NULL)) {
        return NXT_ERROR;
    }

    mp = tmcf->conf->mem_pool;

    ret = nxt_router_engine_joints_create(mp, recf, &tmcf->creating,
                            recf->creating, nxt_router_listen_socket_create);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    ret = nxt_router_engine_joints_create(mp, recf, &tmcf->updating,
                            recf->creating, nxt_router_listen_socket_create);
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
    nxt_mp_t               *mp;
    nxt_int_t              ret;
    nxt_thread_spinlock_t  *lock;

    recf->creating = nxt_array_create(tmcf->mem_pool, 4, sizeof(nxt_work_t));
    if (nxt_slow_path(recf->creating == NULL)) {
        return NXT_ERROR;
    }

    mp = tmcf->conf->mem_pool;

    ret = nxt_router_engine_joints_create(mp, recf, &tmcf->creating,
                            recf->creating, nxt_router_listen_socket_create);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    recf->updating = nxt_array_create(tmcf->mem_pool, 4, sizeof(nxt_work_t));
    if (nxt_slow_path(recf->updating == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_router_engine_joints_create(mp, recf, &tmcf->updating,
                            recf->updating, nxt_router_listen_socket_update);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    recf->deleting = nxt_array_create(tmcf->mem_pool, 4, sizeof(nxt_work_t));
    if (nxt_slow_path(recf->deleting == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_router_engine_joints_delete(recf, &tmcf->deleting);
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

    recf->deleting = nxt_array_create(tmcf->mem_pool, 4, sizeof(nxt_work_t));
    if (nxt_slow_path(recf->deleting == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_router_engine_joints_delete(recf, &tmcf->updating);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    return nxt_router_engine_joints_delete(recf, &tmcf->deleting);
}


static nxt_int_t
nxt_router_engine_joints_create(nxt_mp_t *mp, nxt_router_engine_conf_t *recf,
    nxt_queue_t *sockets, nxt_array_t *array,
    nxt_work_handler_t handler)
{
    nxt_work_t               *work;
    nxt_queue_link_t         *qlk;
    nxt_socket_conf_joint_t  *joint;

    for (qlk = nxt_queue_first(sockets);
         qlk != nxt_queue_tail(sockets);
         qlk = nxt_queue_next(qlk))
    {
        work = nxt_array_add(array);
        if (nxt_slow_path(work == NULL)) {
            return NXT_ERROR;
        }

        work->next = NULL;
        work->handler = handler;
        work->task = &recf->task;
        work->obj = recf->engine;

        joint = nxt_mp_alloc(mp, sizeof(nxt_socket_conf_joint_t));
        if (nxt_slow_path(joint == NULL)) {
            return NXT_ERROR;
        }

        work->data = joint;

        joint->count = 1;
        joint->socket_conf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);
        joint->engine = recf->engine;

        nxt_queue_insert_tail(&joint->engine->joints, &joint->link);
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
nxt_router_engine_joints_delete(nxt_router_engine_conf_t *recf,
    nxt_queue_t *sockets)
{
    nxt_work_t        *work;
    nxt_queue_link_t  *qlk;

    for (qlk = nxt_queue_first(sockets);
         qlk != nxt_queue_tail(sockets);
         qlk = nxt_queue_next(qlk))
    {
        work = nxt_array_add(recf->deleting);
        if (nxt_slow_path(work == NULL)) {
            return NXT_ERROR;
        }

        work->next = NULL;
        work->handler = nxt_router_listen_socket_delete;
        work->task = &recf->task;
        work->obj = recf->engine;
        work->data = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);
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
    nxt_port_t           *port;
    nxt_process_t        *process;
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

    process = nxt_runtime_process_find(rt, nxt_pid);
    if (nxt_slow_path(process == NULL)) {
        return NXT_ERROR;
    }

    port = nxt_process_port_new(process);
    if (nxt_slow_path(port == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_port_socket_init(task, port, 0);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    port->engine = 0;
    port->type = NXT_PROCESS_ROUTER;

    engine->port = port;

    nxt_runtime_port_add(rt, port);

    ret = nxt_thread_create(&handle, link);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_queue_remove(&engine->link);
    }

    return ret;
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
    nxt_uint_t  n;
    nxt_work_t  *work;

    if (recf->creating != NULL) {
        work = recf->creating->elts;

        for (n = recf->creating->nelts; n != 0; n--) {
            nxt_event_engine_post(recf->engine, work);
            work++;
        }
    }

    if (recf->updating != NULL) {
        work = recf->updating->elts;

        for (n = recf->updating->nelts; n != 0; n--) {
            nxt_event_engine_post(recf->engine, work);
            work++;
        }
    }

    if (recf->deleting != NULL) {
        work = recf->deleting->elts;

        for (n = recf->deleting->nelts; n != 0; n--) {
            nxt_event_engine_post(recf->engine, work);
            work++;
        }
    }
}


static void
nxt_router_app_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);

static nxt_port_handler_t  nxt_router_app_port_handlers[] = {
    NULL,
    nxt_port_new_port_handler,
    nxt_port_change_log_file_handler,
    nxt_port_mmap_handler,
    nxt_router_app_data_handler,
};


static void
nxt_router_thread_start(void *data)
{
    nxt_task_t          *task;
    nxt_thread_t        *thread;
    nxt_thread_link_t   *link;
    nxt_event_engine_t  *engine;

    link = data;
    engine = link->engine;
    task = &engine->task;

    thread = nxt_thread();

    /* STUB */
    thread->runtime = engine->task.thread->runtime;

    engine->task.thread = thread;
    engine->task.log = thread->log;
    thread->engine = engine;
    thread->task = &engine->task;
    thread->fiber = &engine->fibers->fiber;

    engine->port->socket.task = task;
    nxt_port_create(task, engine->port, nxt_router_app_port_handlers);

    engine->mem_pool = nxt_mp_create(4096, 128, 1024, 64);

    nxt_event_engine_start(engine);
}


static void
nxt_router_listen_socket_create(nxt_task_t *task, void *obj, void *data)
{
    nxt_listen_event_t       *listen;
    nxt_listen_socket_t      *ls;
    nxt_socket_conf_joint_t  *joint;

    joint = data;

    ls = &joint->socket_conf->listen;

    listen = nxt_listen_event(task, ls);
    if (nxt_slow_path(listen == NULL)) {
        nxt_router_listen_socket_release(task, joint);
        return;
    }

    listen->socket.data = joint;
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
    nxt_event_engine_t       *engine;
    nxt_listen_event_t       *listen;
    nxt_socket_conf_joint_t  *joint, *old;

    engine = obj;
    joint = data;

    listen = nxt_router_listen_event(&engine->listen_connections,
                                     joint->socket_conf);

    old = listen->socket.data;
    listen->socket.data = joint;

    nxt_router_conf_release(task, old);
}


static void
nxt_router_listen_socket_delete(nxt_task_t *task, void *obj, void *data)
{
    nxt_socket_conf_t   *skcf;
    nxt_listen_event_t  *listen;
    nxt_event_engine_t  *engine;

    engine = obj;
    skcf = data;

    listen = nxt_router_listen_event(&engine->listen_connections, skcf);

    nxt_fd_event_delete(engine, &listen->socket);

    listen->timer.handler = nxt_router_listen_socket_close;
    listen->timer.work_queue = &engine->fast_work_queue;

    nxt_timer_add(engine, &listen->timer, 0);
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
    nxt_socket_conf_t      *skcf;
    nxt_router_conf_t      *rtcf;
    nxt_thread_spinlock_t  *lock;

    nxt_debug(task, "conf joint count: %D", joint->count);

    if (--joint->count != 0) {
        return;
    }

    nxt_queue_remove(&joint->link);

    skcf = joint->socket_conf;
    rtcf = skcf->router_conf;
    lock = &rtcf->router->lock;

    nxt_thread_spin_lock(lock);

    if (--skcf->count != 0) {
        rtcf = NULL;

    } else {
        nxt_queue_remove(&skcf->link);

        if (--rtcf->count != 0) {
            rtcf = NULL;
        }
    }

    nxt_thread_spin_unlock(lock);

    if (rtcf != NULL) {
        nxt_debug(task, "old router conf is destroyed");
        nxt_mp_destroy(rtcf->mem_pool);
    }

    if (nxt_queue_is_empty(&joint->engine->joints)) {
        nxt_thread_exit(task->thread);
    }
}


static void
nxt_router_thread_exit_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_thread_link_t    *link;
    nxt_event_engine_t   *engine;
    nxt_thread_handle_t  handle;

    handle = (nxt_thread_handle_t) obj;
    link = data;

    nxt_thread_wait(handle);

    engine = link->engine;

    nxt_queue_remove(&engine->link);

    nxt_mp_destroy(engine->mem_pool);

    nxt_event_engine_free(engine);

    nxt_free(link);

    // TODO: free port
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


void
nxt_router_conf_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    size_t     dump_size;
    nxt_buf_t  *b;
    nxt_int_t  ret;

    b = msg->buf;

    dump_size = nxt_buf_used_size(b);

    if (dump_size > 300) {
        dump_size = 300;
    }

    nxt_debug(task, "router conf data (%z): %*s",
              msg->size, dump_size, b->mem.pos);

    ret = nxt_router_new_conf(task, task->thread->runtime, nxt_router,
                              b->mem.pos, b->mem.free);

    b->mem.pos = b->mem.free;

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_log_alert(task->log, "Failed to apply new conf");
    }
}


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


nxt_inline nxt_port_t *
nxt_router_app_port(nxt_task_t *task)
{
    nxt_port_t     *port;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    nxt_runtime_port_each(rt, port) {

        if (nxt_pid == port->pid) {
            continue;
        }

        if (port->type == NXT_PROCESS_WORKER) {
            return port;
        }

    } nxt_runtime_port_loop;

    return NULL;
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
                    nxt_memcpy(b->mem.pos, c->read->mem.pos, size);

                    b->mem.free += size;
                    c->read = b;
                } else {
                    // TODO 500 Too long request headers
                    nxt_log_alert(task->log, "Too long request headers");
                }
            }
        }

        if (ap->r.body.done == 0) {

            preread = nxt_buf_mem_used_size(&b->mem);

            if (h->parsed_content_length - preread >
                (size_t) nxt_buf_mem_free_size(&b->mem)) {

                b = nxt_buf_mem_alloc(c->mem_pool, h->parsed_content_length, 0);
                if (nxt_slow_path(b == NULL)) {
                    // TODO 500 Failed to allocate buffer for request body
                    nxt_log_alert(task->log, "Failed to allocate buffer for "
                                  "request body");
                }

                b->mem.free = nxt_cpymem(b->mem.free, c->read->mem.pos,
                                         preread);

                c->read = b;
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
    nxt_port_t           *port, *c_port;
    nxt_req_id_t         req_id;
    nxt_app_wmsg_t       wmsg;
    nxt_event_engine_t   *engine;
    nxt_req_conn_link_t  *rc;

    if (nxt_slow_path(nxt_app == NULL)) {
        // 500 Application not found
        nxt_log_alert(task->log, "application is NULL");
    }

    port = nxt_router_app_port(task);

    if (nxt_slow_path(port == NULL)) {
        // 500 Application port not found
        nxt_log_alert(task->log, "application port not found");
    }

    engine = task->thread->engine;

    do {
        req_id = nxt_random(&nxt_random_data);
    } while (nxt_event_engine_request_find(engine, req_id) != NULL);

    rc = nxt_conn_request_add(c, req_id);

    if (nxt_slow_path(rc == NULL)) {
        // 500 Failed to allocate req->conn link
        nxt_log_alert(task->log, "failed to allocate req->conn link");
    }

    nxt_event_engine_request_add(engine, rc);

    nxt_debug(task, "req_id %uxD linked to conn %p at engine %p",
              req_id, c, engine);

    port_mp = port->mem_pool;
    port->mem_pool = c->mem_pool;

    c_port = nxt_process_connected_port_find(port->process,
                                             engine->port->pid,
                                             engine->port->id);
    if (nxt_slow_path(c_port != engine->port)) {
        res = nxt_port_send_port(task, port, engine->port);

        if (nxt_slow_path(res != NXT_OK)) {
            // 500 Failed to send reply port
            nxt_log_alert(task->log, "failed to send reply port to application");
        }

        nxt_process_connected_port_add(port->process, engine->port);
    }

    wmsg.port = port;
    wmsg.write = NULL;
    wmsg.buf = &wmsg.write;
    wmsg.stream = req_id;

    res = nxt_app->prepare_msg(task, &ap->r, &wmsg);

    if (nxt_slow_path(res != NXT_OK)) {
        // 500 Failed to prepare message
        nxt_log_alert(task->log, "failed to prepare message for application");
    }

    nxt_debug(task, "about to send %d bytes buffer to worker port %d",
                    nxt_buf_used_size(wmsg.write),
                    wmsg.port->socket.fd);

    res = nxt_port_socket_write(task, wmsg.port, NXT_PORT_MSG_DATA,
                                 -1, req_id, engine->port->id, wmsg.write);

    if (nxt_slow_path(res != NXT_OK)) {
        // 500 Failed to send message
        nxt_log_alert(task->log, "failed to send message to application");
    }

    port->mem_pool = port_mp;
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
nxt_router_conn_free(nxt_task_t *task, void *obj, void *data)
{
    nxt_conn_t               *c;
    nxt_req_conn_link_t      *rc;
    nxt_socket_conf_joint_t  *joint;

    c = obj;

    nxt_debug(task, "router conn close done");

    joint = c->listen->socket.data;
    nxt_router_conf_release(task, joint);

    nxt_queue_each(rc, &c->requests, nxt_req_conn_link_t, link) {

        nxt_debug(task, "conn %p close, req %uxD", c, rc->req_id);

        nxt_event_engine_request_remove(task->thread->engine, rc);

    } nxt_queue_loop;

    nxt_queue_remove(&c->link);

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
