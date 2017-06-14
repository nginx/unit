
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>


static nxt_router_temp_conf_t *nxt_router_temp_conf(nxt_task_t *task,
    nxt_router_t *router);
static void nxt_router_listen_sockets_sort(nxt_router_t *router,
    nxt_router_temp_conf_t *tmcf);

static nxt_int_t nxt_router_stub_conf(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
static nxt_int_t nxt_router_listen_sockets_stub_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf);
static nxt_socket_conf_t *nxt_router_socket_conf(nxt_task_t *task,
    nxt_mem_pool_t *mp, nxt_sockaddr_t *sa);
static nxt_sockaddr_t *nxt_router_listen_sockaddr_stub(nxt_task_t *task,
    nxt_mem_pool_t *mp, uint32_t port);

static nxt_int_t nxt_router_engines_create(nxt_task_t *task,
    nxt_router_t *router, nxt_router_temp_conf_t *tmcf,
    const nxt_event_interface_t *interface);
static nxt_int_t nxt_router_engine_conf_create(nxt_task_t *task,
    nxt_mem_pool_t *mp, nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf);
static nxt_int_t nxt_router_engine_conf_update(nxt_task_t *task,
    nxt_mem_pool_t *mp, nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf);
static nxt_int_t nxt_router_engine_conf_delete(nxt_task_t *task,
    nxt_mem_pool_t *mp, nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf);
static nxt_int_t nxt_router_engine_joints_create(nxt_task_t *task,
    nxt_mem_pool_t *mp, nxt_router_engine_conf_t *recf, nxt_queue_t *sockets,
    nxt_array_t *array, nxt_work_handler_t handler);
static nxt_int_t nxt_router_engine_joints_delete(nxt_task_t *task,
    nxt_router_engine_conf_t *recf, nxt_queue_t *sockets, nxt_array_t *array);

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
static void nxt_router_conn_close(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_free(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_error(nxt_task_t *task, void *obj, void *data);
static void nxt_router_conn_timeout(nxt_task_t *task, void *obj, void *data);
static nxt_msec_t nxt_router_conn_timeout_value(nxt_conn_t *c, uintptr_t data);


nxt_int_t
nxt_router_start(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_int_t                    ret;
    nxt_router_t                 *router;
    nxt_router_temp_conf_t       *tmcf;
    const nxt_event_interface_t  *interface;

    router = nxt_zalloc(sizeof(nxt_router_t));
    if (nxt_slow_path(router == NULL)) {
        return NXT_ERROR;
    }

    nxt_queue_init(&router->engines);
    nxt_queue_init(&router->sockets);

    /**/

    tmcf = nxt_router_temp_conf(task, router);
    if (nxt_slow_path(tmcf == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_router_stub_conf(task, tmcf);
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

    return NXT_OK;
}


static nxt_router_temp_conf_t *
nxt_router_temp_conf(nxt_task_t *task, nxt_router_t *router)
{
    nxt_mem_pool_t          *mp, *tmp;
    nxt_router_conf_t       *rtcf;
    nxt_router_temp_conf_t  *tmcf;

    mp = nxt_mem_pool_create(1024);
    if (nxt_slow_path(mp == NULL)) {
        return NULL;
    }

    rtcf = nxt_mem_zalloc(mp, sizeof(nxt_router_conf_t));
    if (nxt_slow_path(rtcf == NULL)) {
        goto fail;
    }

    rtcf->mem_pool = mp;
    rtcf->router = router;
    rtcf->count = 1;

    tmp = nxt_mem_pool_create(1024);
    if (nxt_slow_path(tmp == NULL)) {
        goto fail;
    }

    tmcf = nxt_mem_zalloc(tmp, sizeof(nxt_router_temp_conf_t));
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

    nxt_mem_pool_destroy(tmp);

fail:

    nxt_mem_pool_destroy(mp);

    return NULL;
}


static nxt_int_t
nxt_router_stub_conf(nxt_task_t *task, nxt_router_temp_conf_t *tmcf)
{
    nxt_sockaddr_t     *sa;
    nxt_mem_pool_t     *mp;
    nxt_socket_conf_t  *skcf;

    tmcf->conf->threads = 1;

    mp = tmcf->conf->mem_pool;

    sa = nxt_router_listen_sockaddr_stub(task, mp, 8000);
    skcf = nxt_router_socket_conf(task, mp, sa);

    skcf->listen.handler = nxt_router_conn_init;
    skcf->listen.mem_pool_size = nxt_listen_socket_pool_min_size(&skcf->listen)
                        + sizeof(nxt_conn_proxy_t)
                        + sizeof(nxt_conn_t)
                        + 4 * sizeof(nxt_buf_t);

    skcf->header_buffer_size = 2048;
    skcf->large_header_buffer_size = 8192;
    skcf->header_read_timeout = 5000;

    nxt_queue_insert_tail(&tmcf->pending, &skcf->link);

    sa = nxt_router_listen_sockaddr_stub(task, mp, 8001);
    skcf = nxt_router_socket_conf(task, mp, sa);

    skcf->listen.handler = nxt_stream_connection_init;
    skcf->listen.mem_pool_size = nxt_listen_socket_pool_min_size(&skcf->listen)
                        + sizeof(nxt_conn_proxy_t)
                        + sizeof(nxt_conn_t)
                        + 4 * sizeof(nxt_buf_t);

    skcf->header_read_timeout = 5000;

    nxt_queue_insert_tail(&tmcf->pending, &skcf->link);

    return NXT_OK;
}


static nxt_socket_conf_t *
nxt_router_socket_conf(nxt_task_t *task, nxt_mem_pool_t *mp, nxt_sockaddr_t *sa)
{
    nxt_socket_conf_t  *conf;

    conf = nxt_mem_zalloc(mp, sizeof(nxt_socket_conf_t));
    if (nxt_slow_path(conf == NULL)) {
        return NULL;
    }

    conf->listen.sockaddr = sa;

    conf->listen.socket = -1;
    conf->listen.backlog = NXT_LISTEN_BACKLOG;
    conf->listen.flags = NXT_NONBLOCK;
    conf->listen.read_after_accept = 1;

    return conf;
}


static nxt_sockaddr_t *
nxt_router_listen_sockaddr_stub(nxt_task_t *task, nxt_mem_pool_t *mp,
    uint32_t port)
{
    nxt_sockaddr_t      *sa;
    struct sockaddr_in  sin;

    nxt_memzero(&sin, sizeof(struct sockaddr_in));

    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    sa = nxt_sockaddr_create(mp, (struct sockaddr *) &sin,
                             sizeof(struct sockaddr_in), NXT_INET_ADDR_STR_LEN);
    if (nxt_slow_path(sa == NULL)) {
        return NULL;
    }

    sa->type = SOCK_STREAM;

    nxt_sockaddr_text(sa);

    return sa;
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

            if (nxt_sockaddr_cmp(nskcf->listen.sockaddr,
                                 oskcf->listen.sockaddr))
            {
                nxt_queue_remove(oqlk);
                nxt_queue_insert_tail(&tmcf->keeping, oqlk);

                nxt_queue_remove(nqlk);
                nxt_queue_insert_tail(&tmcf->updating, nqlk);

                break;
            }
        }
    }

    nxt_queue_add(&tmcf->deleting, &router->sockets);
}


static nxt_int_t
nxt_router_listen_sockets_stub_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf)
{
    nxt_queue_link_t   *qlk, *nqlk;
    nxt_socket_conf_t  *skcf;

    for (qlk = nxt_queue_first(&tmcf->pending);
         qlk != nxt_queue_tail(&tmcf->pending);
         qlk = nqlk)
    {
        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);

        if (nxt_listen_socket_create(task, &skcf->listen, 0) != NXT_OK) {
            return NXT_ERROR;
        }

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
    nxt_mem_pool_t            *mp;
    nxt_queue_link_t          *qlk;
    nxt_router_engine_conf_t  *recf;

    mp = tmcf->conf->mem_pool;
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

        recf->engine = nxt_queue_link_data(qlk, nxt_event_engine_t, link);
        // STUB
        recf->task = recf->engine->task;

        if (n < threads) {
            ret = nxt_router_engine_conf_update(task, mp, tmcf, recf);

        } else {
            ret = nxt_router_engine_conf_delete(task, mp, tmcf, recf);
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

        ret = nxt_router_engine_conf_create(task, mp, tmcf, recf);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

        n++;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_router_engine_conf_create(nxt_task_t *task, nxt_mem_pool_t *mp,
    nxt_router_temp_conf_t *tmcf, nxt_router_engine_conf_t *recf)
{
    nxt_int_t  ret;

    recf->creating = nxt_array_create(tmcf->mem_pool, 4, sizeof(nxt_work_t));
    if (nxt_slow_path(recf->creating == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_router_engine_joints_create(task, mp, recf, &tmcf->creating,
                            recf->creating, nxt_router_listen_socket_create);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    return nxt_router_engine_joints_create(task, mp, recf, &tmcf->updating,
                            recf->creating, nxt_router_listen_socket_create);
}


static nxt_int_t
nxt_router_engine_conf_update(nxt_task_t *task, nxt_mem_pool_t *mp,
    nxt_router_temp_conf_t *tmcf, nxt_router_engine_conf_t *recf)
{
    nxt_int_t  ret;

    recf->creating = nxt_array_create(tmcf->mem_pool, 4, sizeof(nxt_work_t));
    if (nxt_slow_path(recf->creating == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_router_engine_joints_create(task, mp, recf, &tmcf->creating,
                            recf->creating, nxt_router_listen_socket_create);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    recf->updating = nxt_array_create(tmcf->mem_pool, 4, sizeof(nxt_work_t));
    if (nxt_slow_path(recf->updating == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_router_engine_joints_create(task, mp, recf, &tmcf->updating,
                            recf->updating, nxt_router_listen_socket_update);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    recf->deleting = nxt_array_create(tmcf->mem_pool, 4, sizeof(nxt_work_t));
    if (nxt_slow_path(recf->deleting == NULL)) {
        return NXT_ERROR;
    }

    return nxt_router_engine_joints_delete(task, recf, &tmcf->deleting,
                                           recf->deleting);
}


static nxt_int_t
nxt_router_engine_conf_delete(nxt_task_t *task, nxt_mem_pool_t *mp,
    nxt_router_temp_conf_t *tmcf, nxt_router_engine_conf_t *recf)
{
    nxt_int_t  ret;

    recf->deleting = nxt_array_create(tmcf->mem_pool, 4, sizeof(nxt_work_t));
    if (nxt_slow_path(recf->deleting == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_router_engine_joints_delete(task, recf, &tmcf->updating,
                                          recf->deleting);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    return nxt_router_engine_joints_delete(task, recf, &tmcf->deleting,
                                           recf->deleting);
}


static nxt_int_t
nxt_router_engine_joints_create(nxt_task_t *task, nxt_mem_pool_t *mp,
    nxt_router_engine_conf_t *recf, nxt_queue_t *sockets, nxt_array_t *array,
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

        joint = nxt_mem_alloc(mp, sizeof(nxt_socket_conf_joint_t));
        if (nxt_slow_path(joint == NULL)) {
            return NXT_ERROR;
        }

        work->data = joint;

        joint->count = 1;
        joint->socket_conf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_router_engine_joints_delete(nxt_task_t *task,
    nxt_router_engine_conf_t *recf, nxt_queue_t *sockets, nxt_array_t *array)
{
    nxt_work_t        *work;
    nxt_queue_link_t  *qlk;

    for (qlk = nxt_queue_first(sockets);
         qlk != nxt_queue_tail(sockets);
         qlk = nxt_queue_next(qlk))
    {
        work = nxt_array_add(array);
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

    work = recf->creating->elts;

    for (n = recf->creating->nelts; n != 0; n--) {
        nxt_event_engine_post(recf->engine, work);
        work++;
    }
}


static void
nxt_router_thread_start(void *data)
{
    nxt_thread_t        *thread;
    nxt_thread_link_t   *link;
    nxt_event_engine_t  *engine;

    link = data;
    engine = link->engine;

    thread = nxt_thread();

    /* STUB */
    thread->runtime = engine->task.thread->runtime;

    engine->task.thread = thread;
    engine->task.log = thread->log;
    thread->engine = engine;
    thread->fiber = &engine->fibers->fiber;

    engine->mem_pool = nxt_mem_cache_pool_create(4096, 1024, 1024, 64);

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
    nxt_socket_t        socket;
    nxt_queue_link_t    *link;
    nxt_listen_event_t  *listen;

    socket = skcf->listen.socket;

    for (link = nxt_queue_first(listen_connections);
         link != nxt_queue_tail(listen_connections);
         link = nxt_queue_next(link))
    {
        listen = nxt_queue_link_data(link, nxt_listen_event_t, link);

        if (socket == listen->socket.fd) {
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
    nxt_free(listen);

    nxt_router_listen_socket_release(task, joint);
}


static void
nxt_router_listen_socket_release(nxt_task_t *task,
    nxt_socket_conf_joint_t *joint)
{
    nxt_socket_t           s;
    nxt_listen_socket_t    *ls;
    nxt_thread_spinlock_t  *lock;

    s = -1;
    ls = &joint->socket_conf->listen;
    lock = &joint->socket_conf->router_conf->router->lock;

    nxt_thread_spin_lock(lock);

    if (--ls->count == 0) {
        s = ls->socket;
        ls->socket = -1;
    }

    nxt_thread_spin_unlock(lock);

    if (s != -1) {
        nxt_socket_close(task, s);
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
        nxt_mem_pool_destroy(rtcf->mem_pool);
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

    nxt_mem_cache_pool_destroy(engine->mem_pool);

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
    .ready_handler = nxt_router_conn_close,
    .close_handler = nxt_router_conn_close,
    .error_handler = nxt_router_conn_error,
};


static void
nxt_router_conn_http_header_parse(nxt_task_t *task, void *obj, void *data)
{
    size_t                    size;
    nxt_int_t                 ret;
    nxt_buf_t                 *b;
    nxt_conn_t                *c;
    nxt_socket_conf_joint_t   *joint;
    nxt_http_request_parse_t  *rp;

    c = obj;
    rp = data;

    nxt_debug(task, "router conn http header parse");

    if (rp == NULL) {
        rp = nxt_mem_zalloc(c->mem_pool, sizeof(nxt_http_request_parse_t));
        if (nxt_slow_path(rp == NULL)) {
            nxt_router_conn_close(task, c, data);
            return;
        }

        c->socket.data = rp;

        ret = nxt_http_parse_request_init(rp, c->mem_pool);
        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_router_conn_close(task, c, data);
            return;
        }
    }

    ret = nxt_http_parse_request(rp, &c->read->mem);

    nxt_debug(task, "http parse request: %d", ret);

    switch (nxt_expect(NXT_DONE, ret)) {

    case NXT_DONE:
        break;

    case NXT_ERROR:
        nxt_router_conn_close(task, c, data);
        return;

    default:  /* NXT_AGAIN */

        if (c->read->mem.free == c->read->mem.end) {
            joint = c->listen->socket.data;
            size = joint->socket_conf->large_header_buffer_size,

            b = nxt_buf_mem_alloc(c->mem_pool, size, 0);
            if (nxt_slow_path(b == NULL)) {
                nxt_router_conn_close(task, c, data);
                return;
            }

            size = c->read->mem.free - c->read->mem.pos;
            nxt_memcpy(b->mem.pos, c->read->mem.pos, size);

            b->mem.free += size;
            c->read = b;
        }

        nxt_conn_read(task->thread->engine, c);
        return;
    }

    c->write = c->read;
    c->write->mem.pos = c->write->mem.start;
    c->write_state = &nxt_router_conn_write_state;

    nxt_conn_write(task->thread->engine, c);
}


static const nxt_conn_state_t  nxt_router_conn_close_state
    nxt_aligned(64) =
{
    .ready_handler = nxt_router_conn_free,
};


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
    nxt_socket_conf_joint_t  *joint;

    c = obj;

    nxt_debug(task, "router conn close done");

    joint = c->listen->socket.data;
    nxt_router_conf_release(task, joint);

    nxt_mem_pool_destroy(c->mem_pool);
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
