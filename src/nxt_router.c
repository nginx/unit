
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_conf.h>
#if (NXT_TLS)
#include <nxt_cert.h>
#endif
#include <nxt_http.h>
#include <nxt_port_memory_int.h>
#include <nxt_unit_request.h>
#include <nxt_unit_response.h>
#include <nxt_router_request.h>
#include <nxt_app_queue.h>
#include <nxt_port_queue.h>

typedef struct {
    nxt_str_t         type;
    uint32_t          processes;
    uint32_t          max_processes;
    uint32_t          spare_processes;
    nxt_msec_t        timeout;
    nxt_msec_t        idle_timeout;
    uint32_t          requests;
    nxt_conf_value_t  *limits_value;
    nxt_conf_value_t  *processes_value;
    nxt_conf_value_t  *targets_value;
} nxt_router_app_conf_t;


typedef struct {
    nxt_str_t         pass;
    nxt_str_t         application;
} nxt_router_listener_conf_t;


#if (NXT_TLS)

typedef struct {
    nxt_str_t          name;
    nxt_socket_conf_t  *conf;

    nxt_queue_link_t   link;  /* for nxt_socket_conf_t.tls */
} nxt_router_tlssock_t;

#endif


typedef struct {
    nxt_str_t               *name;
    nxt_socket_conf_t       *socket_conf;
    nxt_router_temp_conf_t  *temp_conf;
    nxt_bool_t              last;
} nxt_socket_rpc_t;


typedef struct {
    nxt_app_t               *app;
    nxt_router_temp_conf_t  *temp_conf;
} nxt_app_rpc_t;


static nxt_int_t nxt_router_prefork(nxt_task_t *task, nxt_process_t *process,
    nxt_mp_t *mp);
static nxt_int_t nxt_router_start(nxt_task_t *task, nxt_process_data_t *data);
static void nxt_router_greet_controller(nxt_task_t *task,
    nxt_port_t *controller_port);

static nxt_int_t nxt_router_start_app_process(nxt_task_t *task, nxt_app_t *app);

static void nxt_router_new_port_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_router_conf_data_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_router_remove_pid_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_router_access_log_reopen_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);

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
static nxt_int_t nxt_router_conf_process_static(nxt_task_t *task,
    nxt_router_conf_t *rtcf, nxt_conf_value_t *conf);

static nxt_app_t *nxt_router_app_find(nxt_queue_t *queue, nxt_str_t *name);
static nxt_int_t nxt_router_apps_hash_test(nxt_lvlhsh_query_t *lhq, void *data);
static nxt_int_t nxt_router_apps_hash_add(nxt_router_conf_t *rtcf,
    nxt_app_t *app);
static nxt_app_t *nxt_router_apps_hash_get(nxt_router_conf_t *rtcf,
    nxt_str_t *name);
static void nxt_router_apps_hash_use(nxt_task_t *task, nxt_router_conf_t *rtcf,
    int i);

static nxt_int_t nxt_router_app_queue_init(nxt_task_t *task,
    nxt_port_t *port);
static nxt_int_t nxt_router_port_queue_init(nxt_task_t *task,
    nxt_port_t *port);
static nxt_int_t nxt_router_port_queue_map(nxt_task_t *task,
    nxt_port_t *port, nxt_fd_t fd);
static void nxt_router_listen_socket_rpc_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_socket_conf_t *skcf);
static void nxt_router_listen_socket_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_listen_socket_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
#if (NXT_TLS)
static void nxt_router_tls_rpc_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_router_tlssock_t *tls, nxt_bool_t last);
static void nxt_router_tls_rpc_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static nxt_int_t nxt_router_conf_tls_insert(nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *value, nxt_socket_conf_t *skcf);
#endif
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
static void nxt_router_rt_add_port(nxt_task_t *task, void *obj,
    void *data);
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
static void nxt_router_req_headers_ack_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, nxt_request_rpc_data_t *req_rpc_data);
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
static nxt_int_t nxt_router_app_shared_port_send(nxt_task_t *task,
    nxt_port_t *app_port);
static void nxt_router_app_port_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);

static void nxt_router_app_use(nxt_task_t *task, nxt_app_t *app, int i);
static void nxt_router_app_unlink(nxt_task_t *task, nxt_app_t *app);

static void nxt_router_app_port_release(nxt_task_t *task, nxt_port_t *port,
    nxt_apr_action_t action);
static void nxt_router_app_port_get(nxt_task_t *task, nxt_app_t *app,
    nxt_request_rpc_data_t *req_rpc_data);
static void nxt_router_http_request_error(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_http_request_done(nxt_task_t *task, void *obj,
    void *data);

static void nxt_router_dummy_buf_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_app_prepare_request(nxt_task_t *task,
    nxt_request_rpc_data_t *req_rpc_data);
static nxt_buf_t *nxt_router_prepare_msg(nxt_task_t *task,
    nxt_http_request_t *r, nxt_app_t *app, const nxt_str_t *prefix);

static void nxt_router_app_timeout(nxt_task_t *task, void *obj, void *data);
static void nxt_router_adjust_idle_timer(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_app_idle_timeout(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_app_joint_release_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_free_app(nxt_task_t *task, void *obj, void *data);

static const nxt_http_request_state_t  nxt_http_request_send_state;
static void nxt_http_request_send_body(nxt_task_t *task, void *obj, void *data);

static void nxt_router_app_joint_use(nxt_task_t *task,
    nxt_app_joint_t *app_joint, int i);

static void nxt_router_http_request_release_post(nxt_task_t *task,
    nxt_http_request_t *r);
static void nxt_router_http_request_release(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_oosm_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
static void nxt_router_get_port_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_router_get_mmap_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);

extern const nxt_http_request_state_t  nxt_http_websocket;

static nxt_router_t  *nxt_router;

static const nxt_str_t http_prefix = nxt_string("HTTP_");
static const nxt_str_t empty_prefix = nxt_string("");

static const nxt_str_t  *nxt_app_msg_prefix[] = {
    &empty_prefix,
    &empty_prefix,
    &http_prefix,
    &http_prefix,
    &http_prefix,
    &empty_prefix,
};


static const nxt_port_handlers_t  nxt_router_process_port_handlers = {
    .quit         = nxt_signal_quit_handler,
    .new_port     = nxt_router_new_port_handler,
    .get_port     = nxt_router_get_port_handler,
    .change_file  = nxt_port_change_log_file_handler,
    .mmap         = nxt_port_mmap_handler,
    .get_mmap     = nxt_router_get_mmap_handler,
    .data         = nxt_router_conf_data_handler,
    .remove_pid   = nxt_router_remove_pid_handler,
    .access_log   = nxt_router_access_log_reopen_handler,
    .rpc_ready    = nxt_port_rpc_handler,
    .rpc_error    = nxt_port_rpc_handler,
    .oosm         = nxt_router_oosm_handler,
};


const nxt_process_init_t  nxt_router_process = {
    .name           = "router",
    .type           = NXT_PROCESS_ROUTER,
    .prefork        = nxt_router_prefork,
    .restart        = 1,
    .setup          = nxt_process_core_setup,
    .start          = nxt_router_start,
    .port_handlers  = &nxt_router_process_port_handlers,
    .signals        = nxt_process_signals,
};


/* Queues of nxt_socket_conf_t */
nxt_queue_t  creating_sockets;
nxt_queue_t  pending_sockets;
nxt_queue_t  updating_sockets;
nxt_queue_t  keeping_sockets;
nxt_queue_t  deleting_sockets;


static nxt_int_t
nxt_router_prefork(nxt_task_t *task, nxt_process_t *process, nxt_mp_t *mp)
{
    nxt_runtime_stop_app_processes(task, task->thread->runtime);

    return NXT_OK;
}


static nxt_int_t
nxt_router_start(nxt_task_t *task, nxt_process_data_t *data)
{
    nxt_int_t      ret;
    nxt_port_t     *controller_port;
    nxt_router_t   *router;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    nxt_log(task, NXT_LOG_INFO, "router started");

#if (NXT_TLS)
    rt->tls = nxt_service_get(rt->services, "SSL/TLS", "OpenSSL");
    if (nxt_slow_path(rt->tls == NULL)) {
        return NXT_ERROR;
    }

    ret = rt->tls->library_init(task);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }
#endif

    ret = nxt_http_init(task);
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

    nxt_router_app_joint_use(task, app->joint, 1);

    stream = nxt_port_rpc_register_handler(task, port,
                                           nxt_router_app_port_ready,
                                           nxt_router_app_port_error,
                                           -1, app->joint);

    if (nxt_slow_path(stream == 0)) {
        nxt_router_app_joint_use(task, app->joint, -1);

        goto failed;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_START_PROCESS,
                                -1, stream, port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, port, stream);

        nxt_router_app_joint_use(task, app->joint, -1);

        goto failed;
    }

    nxt_router_app_use(task, app, -1);

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


static void
nxt_router_app_joint_use(nxt_task_t *task, nxt_app_joint_t *app_joint, int i)
{
    app_joint->use_count += i;

    if (app_joint->use_count == 0) {
        nxt_assert(app_joint->app == NULL);

        nxt_free(app_joint);
    }
}


static nxt_int_t
nxt_router_start_app_process(nxt_task_t *task, nxt_app_t *app)
{
    nxt_int_t      res;
    nxt_port_t     *router_port;
    nxt_runtime_t  *rt;

    nxt_debug(task, "app '%V' start process", &app->name);

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


nxt_inline nxt_bool_t
nxt_router_msg_cancel(nxt_task_t *task, nxt_request_rpc_data_t *req_rpc_data)
{
    nxt_buf_t       *b, *next;
    nxt_bool_t      cancelled;
    nxt_msg_info_t  *msg_info;

    msg_info = &req_rpc_data->msg_info;

    if (msg_info->buf == NULL) {
        return 0;
    }

    cancelled = nxt_app_queue_cancel(req_rpc_data->app->shared_port->queue,
                                     msg_info->tracking_cookie,
                                     req_rpc_data->stream);

    if (cancelled) {
        nxt_debug(task, "stream #%uD: cancelled by router",
                  req_rpc_data->stream);
    }

    for (b = msg_info->buf; b != NULL; b = next) {
        next = b->next;
        b->next = NULL;

        if (b->is_port_mmap_sent) {
            b->is_port_mmap_sent = cancelled == 0;
        }

        b->completion_handler(task, b, b->parent);
    }

    msg_info->buf = NULL;

    return cancelled;
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
nxt_request_rpc_data_unlink(nxt_task_t *task,
    nxt_request_rpc_data_t *req_rpc_data)
{
    nxt_app_t           *app;
    nxt_bool_t          unlinked;
    nxt_http_request_t  *r;

    nxt_router_msg_cancel(task, req_rpc_data);

    if (req_rpc_data->app_port != NULL) {
        nxt_router_app_port_release(task, req_rpc_data->app_port,
                                    req_rpc_data->apr_action);

        req_rpc_data->app_port = NULL;
    }

    app = req_rpc_data->app;
    r = req_rpc_data->request;

    if (r != NULL) {
        r->timer_data = NULL;

        nxt_router_http_request_release_post(task, r);

        r->req_rpc_data = NULL;
        req_rpc_data->request = NULL;

        if (app != NULL) {
            unlinked = 0;

            nxt_thread_mutex_lock(&app->mutex);

            if (r->app_link.next != NULL) {
                nxt_queue_remove(&r->app_link);
                r->app_link.next = NULL;

                unlinked = 1;
            }

            nxt_thread_mutex_unlock(&app->mutex);

            if (unlinked) {
                nxt_mp_release(r->mem_pool);
            }
        }
    }

    if (app != NULL) {
        nxt_router_app_use(task, app, -1);

        req_rpc_data->app = NULL;
    }

    if (req_rpc_data->msg_info.body_fd != -1) {
        nxt_fd_close(req_rpc_data->msg_info.body_fd);

        req_rpc_data->msg_info.body_fd = -1;
    }

    if (req_rpc_data->rpc_cancel) {
        req_rpc_data->rpc_cancel = 0;

        nxt_port_rpc_cancel(task, task->thread->engine->port,
                            req_rpc_data->stream);
    }
}


static void
nxt_router_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_int_t      res;
    nxt_app_t      *app;
    nxt_port_t     *port, *main_app_port;
    nxt_runtime_t  *rt;

    nxt_port_new_port_handler(task, msg);

    port = msg->u.new_port;

    if (port != NULL && port->type == NXT_PROCESS_CONTROLLER) {
        nxt_router_greet_controller(task, msg->u.new_port);
    }

    if (port == NULL || port->type != NXT_PROCESS_APP) {

        if (msg->port_msg.stream == 0) {
            return;
        }

        msg->port_msg.type = _NXT_PORT_MSG_RPC_ERROR;

    } else {
        if (msg->fd[1] != -1) {
            res = nxt_router_port_queue_map(task, port, msg->fd[1]);
            if (nxt_slow_path(res != NXT_OK)) {
                return;
            }

            nxt_fd_close(msg->fd[1]);
            msg->fd[1] = -1;
        }
    }

    if (msg->port_msg.stream != 0) {
        nxt_port_rpc_handler(task, msg);
        return;
    }

    /*
     * Port with "id == 0" is application 'main' port and it always
     * should come with non-zero stream.
     */
    nxt_assert(port->id != 0);

    /* Find 'main' app port and get app reference. */
    rt = task->thread->runtime;

    /*
     * It is safe to access 'runtime->ports' hash because 'NEW_PORT'
     * sent to main port (with id == 0) and processed in main thread.
     */
    main_app_port = nxt_port_hash_find(&rt->ports, port->pid, 0);
    nxt_assert(main_app_port != NULL);

    app = main_app_port->app;
    nxt_assert(app != NULL);

    nxt_thread_mutex_lock(&app->mutex);

    /* TODO here should be find-and-add code because there can be
       port waiters in port_hash */
    nxt_port_hash_add(&app->port_hash, port);
    app->port_hash_count++;

    nxt_thread_mutex_unlock(&app->mutex);

    port->app = app;
    port->main_app_port = main_app_port;

    nxt_port_socket_write(task, port, NXT_PORT_MSG_PORT_ACK, -1, 0, 0, NULL);
}


static void
nxt_router_conf_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    void                    *p;
    size_t                  size;
    nxt_int_t               ret;
    nxt_port_t              *port;
    nxt_router_temp_conf_t  *tmcf;

    port = nxt_runtime_port_find(task->thread->runtime,
                                 msg->port_msg.pid,
                                 msg->port_msg.reply_port);
    if (nxt_slow_path(port == NULL)) {
        nxt_alert(task, "conf_data_handler: reply port not found");
        return;
    }

    p = MAP_FAILED;

    /*
     * Ancient compilers like gcc 4.8.5 on CentOS 7 wants 'size' to be
     * initialized in 'cleanup' section.
     */
    size = 0;

    tmcf = nxt_router_temp_conf(task);
    if (nxt_slow_path(tmcf == NULL)) {
        goto fail;
    }

    if (nxt_slow_path(msg->fd[0] == -1)) {
        nxt_alert(task, "conf_data_handler: invalid shm fd");
        goto fail;
    }

    if (nxt_buf_mem_used_size(&msg->buf->mem) != sizeof(size_t)) {
        nxt_alert(task, "conf_data_handler: unexpected buffer size (%d)",
                  (int) nxt_buf_mem_used_size(&msg->buf->mem));
        goto fail;
    }

    nxt_memcpy(&size, msg->buf->mem.pos, sizeof(size_t));

    p = nxt_mem_mmap(NULL, size, PROT_READ, MAP_SHARED, msg->fd[0], 0);

    nxt_fd_close(msg->fd[0]);
    msg->fd[0] = -1;

    if (nxt_slow_path(p == MAP_FAILED)) {
        goto fail;
    }

    nxt_debug(task, "conf_data_handler(%uz): %*s", size, size, p);

    tmcf->router_conf->router = nxt_router;
    tmcf->stream = msg->port_msg.stream;
    tmcf->port = port;

    nxt_port_use(task, tmcf->port, 1);

    ret = nxt_router_conf_create(task, tmcf, p, nxt_pointer_to(p, size));

    if (nxt_fast_path(ret == NXT_OK)) {
        nxt_router_conf_apply(task, tmcf, NULL);

    } else {
        nxt_router_conf_error(task, tmcf);
    }

    goto cleanup;

fail:

    nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_ERROR, -1,
                          msg->port_msg.stream, 0, NULL);

    if (tmcf != NULL) {
        nxt_mp_destroy(tmcf->mem_pool);
    }

cleanup:

    if (p != MAP_FAILED) {
        nxt_mem_munmap(p, size);
    }

    if (msg->fd[0] != -1) {
        nxt_fd_close(msg->fd[0]);
        msg->fd[0] = -1;
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


static void
nxt_router_remove_pid_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_event_engine_t  *engine;

    nxt_port_remove_pid_handler(task, msg);

    nxt_queue_each(engine, &nxt_router->engines, nxt_event_engine_t, link0)
    {
        if (nxt_fast_path(engine->port != NULL)) {
            nxt_port_post(task, engine->port, nxt_router_app_process_remove_pid,
                          msg->u.data);
        }
    }
    nxt_queue_loop;

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
    tmcf->router_conf = rtcf;
    tmcf->count = 1;
    tmcf->engine = task->thread->engine;

    tmcf->engines = nxt_array_create(tmcf->mem_pool, 4,
                                     sizeof(nxt_router_engine_conf_t));
    if (nxt_slow_path(tmcf->engines == NULL)) {
        goto temp_fail;
    }

    nxt_queue_init(&creating_sockets);
    nxt_queue_init(&pending_sockets);
    nxt_queue_init(&updating_sockets);
    nxt_queue_init(&keeping_sockets);
    nxt_queue_init(&deleting_sockets);

#if (NXT_TLS)
    nxt_queue_init(&tmcf->tls);
#endif

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
    return (app->active_requests
              > app->port_hash_count + app->pending_processes)
           || (app->spare_processes
                > app->idle_processes + app->pending_processes);
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
#if (NXT_TLS)
    nxt_router_tlssock_t         *tls;
#endif

    tmcf = obj;

    qlk = nxt_queue_first(&pending_sockets);

    if (qlk != nxt_queue_tail(&pending_sockets)) {
        nxt_queue_remove(qlk);
        nxt_queue_insert_tail(&creating_sockets, qlk);

        skcf = nxt_queue_link_data(qlk, nxt_socket_conf_t, link);

        nxt_router_listen_socket_rpc_create(task, tmcf, skcf);

        return;
    }

#if (NXT_TLS)
    qlk = nxt_queue_last(&tmcf->tls);

    if (qlk != nxt_queue_head(&tmcf->tls)) {
        nxt_queue_remove(qlk);

        tls = nxt_queue_link_data(qlk, nxt_router_tlssock_t, link);

        nxt_router_tls_rpc_create(task, tmcf, tls,
                                  nxt_queue_is_empty(&tmcf->tls));
        return;
    }
#endif

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

    nxt_router_apps_hash_use(task, rtcf, 1);

    nxt_router_engines_post(router, tmcf);

    nxt_queue_add(&router->sockets, &updating_sockets);
    nxt_queue_add(&router->sockets, &creating_sockets);

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
    uint32_t               count;
    nxt_router_conf_t      *rtcf;
    nxt_thread_spinlock_t  *lock;

    nxt_debug(task, "temp conf %p count: %D", tmcf, tmcf->count);

    if (--tmcf->count > 0) {
        return;
    }

    nxt_router_conf_send(task, tmcf, NXT_PORT_MSG_RPC_READY_LAST);

    rtcf = tmcf->router_conf;

    lock = &rtcf->router->lock;

    nxt_thread_spin_lock(lock);

    count = rtcf->count;

    nxt_thread_spin_unlock(lock);

    nxt_debug(task, "rtcf %p: %D", rtcf, count);

    if (count == 0) {
        nxt_router_apps_hash_use(task, rtcf, -1);

        nxt_router_access_log_release(task, lock, rtcf->access_log);

        nxt_mp_destroy(rtcf->mem_pool);
    }

    nxt_mp_destroy(tmcf->mem_pool);
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

    for (qlk = nxt_queue_first(&creating_sockets);
         qlk != nxt_queue_tail(&creating_sockets);
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
    nxt_queue_add(&new_socket_confs, &updating_sockets);
    nxt_queue_add(&new_socket_confs, &pending_sockets);
    nxt_queue_add(&new_socket_confs, &creating_sockets);

    rtcf = tmcf->router_conf;

    nxt_queue_each(app, &tmcf->apps, nxt_app_t, link) {

        nxt_router_app_unlink(task, app);

    } nxt_queue_loop;

    router = rtcf->router;

    nxt_queue_add(&router->sockets, &keeping_sockets);
    nxt_queue_add(&router->sockets, &deleting_sockets);

    nxt_queue_add(&router->apps, &tmcf->previous);

    // TODO: new engines and threads

    nxt_router_access_log_release(task, &router->lock, rtcf->access_log);

    nxt_mp_destroy(rtcf->mem_pool);

    nxt_router_conf_send(task, tmcf, NXT_PORT_MSG_RPC_ERROR);

    nxt_mp_destroy(tmcf->mem_pool);
}


static void
nxt_router_conf_send(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_port_msg_type_t type)
{
    nxt_port_socket_write(task, tmcf->port, type, -1, tmcf->stream, 0, NULL);

    nxt_port_use(task, tmcf->port, -1);

    tmcf->port = NULL;
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

    {
        nxt_string("targets"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_router_app_conf_t, targets_value),
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
        nxt_string("pass"),
        NXT_CONF_MAP_STR_COPY,
        offsetof(nxt_router_listener_conf_t, pass),
    },

    {
        nxt_string("application"),
        NXT_CONF_MAP_STR_COPY,
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

    {
        nxt_string("body_temp_path"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_socket_conf_t, body_temp_path),
    },

    {
        nxt_string("discard_unsafe_fields"),
        NXT_CONF_MAP_INT8,
        offsetof(nxt_socket_conf_t, discard_unsafe_fields),
    },
};


static nxt_conf_map_t  nxt_router_websocket_conf[] = {
    {
        nxt_string("max_frame_size"),
        NXT_CONF_MAP_SIZE,
        offsetof(nxt_websocket_conf_t, max_frame_size),
    },

    {
        nxt_string("read_timeout"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_websocket_conf_t, read_timeout),
    },

    {
        nxt_string("keepalive_interval"),
        NXT_CONF_MAP_MSEC,
        offsetof(nxt_websocket_conf_t, keepalive_interval),
    },

};


static nxt_int_t
nxt_router_conf_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    u_char *start, u_char *end)
{
    u_char                      *p;
    size_t                      size;
    nxt_mp_t                    *mp, *app_mp;
    uint32_t                    next, next_target;
    nxt_int_t                   ret;
    nxt_str_t                   name, path, target;
    nxt_app_t                   *app, *prev;
    nxt_str_t                   *t, *s, *targets;
    nxt_uint_t                  n, i;
    nxt_port_t                  *port;
    nxt_router_t                *router;
    nxt_app_joint_t             *app_joint;
#if (NXT_TLS)
    nxt_conf_value_t            *certificate;
#endif
    nxt_conf_value_t            *conf, *http, *value, *websocket;
    nxt_conf_value_t            *applications, *application;
    nxt_conf_value_t            *listeners, *listener;
    nxt_conf_value_t            *routes_conf, *static_conf;
    nxt_socket_conf_t           *skcf;
    nxt_http_routes_t           *routes;
    nxt_event_engine_t          *engine;
    nxt_app_lang_module_t       *lang;
    nxt_router_app_conf_t       apcf;
    nxt_router_access_log_t     *access_log;
    nxt_router_listener_conf_t  lscf;

    static nxt_str_t  http_path = nxt_string("/settings/http");
    static nxt_str_t  applications_path = nxt_string("/applications");
    static nxt_str_t  listeners_path = nxt_string("/listeners");
    static nxt_str_t  routes_path = nxt_string("/routes");
    static nxt_str_t  access_log_path = nxt_string("/access_log");
#if (NXT_TLS)
    static nxt_str_t  certificate_path = nxt_string("/tls/certificate");
#endif
    static nxt_str_t  static_path = nxt_string("/settings/http/static");
    static nxt_str_t  websocket_path = nxt_string("/settings/http/websocket");

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

    static_conf = nxt_conf_get_path(conf, &static_path);

    ret = nxt_router_conf_process_static(task, tmcf->router_conf, static_conf);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    router = tmcf->router_conf->router;

    applications = nxt_conf_get_path(conf, &applications_path);

    if (applications != NULL) {
        next = 0;

        for ( ;; ) {
            application = nxt_conf_next_object_member(applications,
                                                      &name, &next);
            if (application == NULL) {
                break;
            }

            nxt_debug(task, "application \"%V\"", &name);

            size = nxt_conf_json_length(application, NULL);

            app_mp = nxt_mp_create(4096, 128, 1024, 64);
            if (nxt_slow_path(app_mp == NULL)) {
                goto fail;
            }

            app = nxt_mp_get(app_mp, sizeof(nxt_app_t) + name.length + size);
            if (app == NULL) {
                goto app_fail;
            }

            nxt_memzero(app, sizeof(nxt_app_t));

            app->mem_pool = app_mp;

            app->name.start = nxt_pointer_to(app, sizeof(nxt_app_t));
            app->conf.start = nxt_pointer_to(app, sizeof(nxt_app_t)
                                                  + name.length);

            p = nxt_conf_json_print(app->conf.start, application, NULL);
            app->conf.length = p - app->conf.start;

            nxt_assert(app->conf.length <= size);

            nxt_debug(task, "application conf \"%V\"", &app->conf);

            prev = nxt_router_app_find(&router->apps, &name);

            if (prev != NULL && nxt_strstr_eq(&app->conf, &prev->conf)) {
                nxt_mp_destroy(app_mp);

                nxt_queue_remove(&prev->link);
                nxt_queue_insert_tail(&tmcf->previous, &prev->link);

                ret = nxt_router_apps_hash_add(tmcf->router_conf, prev);
                if (nxt_slow_path(ret != NXT_OK)) {
                    goto fail;
                }

                continue;
            }

            apcf.processes = 1;
            apcf.max_processes = 1;
            apcf.spare_processes = 0;
            apcf.timeout = 0;
            apcf.idle_timeout = 15000;
            apcf.requests = 0;
            apcf.limits_value = NULL;
            apcf.processes_value = NULL;
            apcf.targets_value = NULL;

            app_joint = nxt_malloc(sizeof(nxt_app_joint_t));
            if (nxt_slow_path(app_joint == NULL)) {
                goto app_fail;
            }

            nxt_memzero(app_joint, sizeof(nxt_app_joint_t));

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

            if (apcf.targets_value != NULL) {
                n = nxt_conf_object_members_count(apcf.targets_value);

                targets = nxt_mp_get(app_mp, sizeof(nxt_str_t) * n);
                if (nxt_slow_path(targets == NULL)) {
                    goto app_fail;
                }

                next_target = 0;

                for (i = 0; i < n; i++) {
                    (void) nxt_conf_next_object_member(apcf.targets_value,
                                                       &target, &next_target);

                    s = nxt_str_dup(app_mp, &targets[i], &target);
                    if (nxt_slow_path(s == NULL)) {
                        goto app_fail;
                    }
                }

            } else {
                targets = NULL;
            }

            nxt_debug(task, "application type: %V", &apcf.type);
            nxt_debug(task, "application processes: %D", apcf.processes);
            nxt_debug(task, "application request timeout: %M", apcf.timeout);
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
            nxt_queue_init(&app->ack_waiting_req);

            app->name.length = name.length;
            nxt_memcpy(app->name.start, name.start, name.length);

            app->type = lang->type;
            app->max_processes = apcf.max_processes;
            app->spare_processes = apcf.spare_processes;
            app->max_pending_processes = apcf.spare_processes
                                         ? apcf.spare_processes : 1;
            app->timeout = apcf.timeout;
            app->idle_timeout = apcf.idle_timeout;
            app->max_requests = apcf.requests;

            app->targets = targets;

            engine = task->thread->engine;

            app->engine = engine;

            app->adjust_idle_work.handler = nxt_router_adjust_idle_timer;
            app->adjust_idle_work.task = &engine->task;
            app->adjust_idle_work.obj = app;

            nxt_queue_insert_tail(&tmcf->apps, &app->link);

            ret = nxt_router_apps_hash_add(tmcf->router_conf, app);
            if (nxt_slow_path(ret != NXT_OK)) {
                goto app_fail;
            }

            nxt_router_app_use(task, app, 1);

            app->joint = app_joint;

            app_joint->use_count = 1;
            app_joint->app = app;

            app_joint->idle_timer.bias = NXT_TIMER_DEFAULT_BIAS;
            app_joint->idle_timer.work_queue = &engine->fast_work_queue;
            app_joint->idle_timer.handler = nxt_router_app_idle_timeout;
            app_joint->idle_timer.task = &engine->task;
            app_joint->idle_timer.log = app_joint->idle_timer.task->log;

            app_joint->free_app_work.handler = nxt_router_free_app;
            app_joint->free_app_work.task = &engine->task;
            app_joint->free_app_work.obj = app_joint;

            port = nxt_port_new(task, (nxt_port_id_t) -1, nxt_pid,
                                NXT_PROCESS_APP);
            if (nxt_slow_path(port == NULL)) {
                return NXT_ERROR;
            }

            ret = nxt_port_socket_init(task, port, 0);
            if (nxt_slow_path(ret != NXT_OK)) {
                nxt_port_use(task, port, -1);
                return NXT_ERROR;
            }

            ret = nxt_router_app_queue_init(task, port);
            if (nxt_slow_path(ret != NXT_OK)) {
                nxt_port_write_close(port);
                nxt_port_read_close(port);
                nxt_port_use(task, port, -1);
                return NXT_ERROR;
            }

            nxt_port_write_enable(task, port);
            port->app = app;

            app->shared_port = port;

            nxt_thread_mutex_create(&app->outgoing.mutex);
        }
    }

    routes_conf = nxt_conf_get_path(conf, &routes_path);
    if (nxt_fast_path(routes_conf != NULL)) {
        routes = nxt_http_routes_create(task, tmcf, routes_conf);
        if (nxt_slow_path(routes == NULL)) {
            return NXT_ERROR;
        }
        tmcf->router_conf->routes = routes;
    }

    ret = nxt_upstreams_create(task, tmcf, conf);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    http = nxt_conf_get_path(conf, &http_path);
#if 0
    if (http == NULL) {
        nxt_alert(task, "no \"http\" block");
        return NXT_ERROR;
    }
#endif

    websocket = nxt_conf_get_path(conf, &websocket_path);

    listeners = nxt_conf_get_path(conf, &listeners_path);

    if (listeners != NULL) {
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

            nxt_memzero(&lscf, sizeof(lscf));

            ret = nxt_conf_map_object(mp, listener, nxt_router_listener_conf,
                                      nxt_nitems(nxt_router_listener_conf),
                                      &lscf);
            if (ret != NXT_OK) {
                nxt_alert(task, "listener map error");
                goto fail;
            }

            nxt_debug(task, "application: %V", &lscf.application);

            // STUB, default values if http block is not defined.
            skcf->header_buffer_size = 2048;
            skcf->large_header_buffer_size = 8192;
            skcf->large_header_buffers = 4;
            skcf->discard_unsafe_fields = 1;
            skcf->body_buffer_size = 16 * 1024;
            skcf->max_body_size = 8 * 1024 * 1024;
            skcf->proxy_header_buffer_size = 64 * 1024;
            skcf->proxy_buffer_size = 4096;
            skcf->proxy_buffers = 256;
            skcf->idle_timeout = 180 * 1000;
            skcf->header_read_timeout = 30 * 1000;
            skcf->body_read_timeout = 30 * 1000;
            skcf->send_timeout = 30 * 1000;
            skcf->proxy_timeout = 60 * 1000;
            skcf->proxy_send_timeout = 30 * 1000;
            skcf->proxy_read_timeout = 30 * 1000;

            skcf->websocket_conf.max_frame_size = 1024 * 1024;
            skcf->websocket_conf.read_timeout = 60 * 1000;
            skcf->websocket_conf.keepalive_interval = 30 * 1000;

            nxt_str_null(&skcf->body_temp_path);

            if (http != NULL) {
                ret = nxt_conf_map_object(mp, http, nxt_router_http_conf,
                                          nxt_nitems(nxt_router_http_conf),
                                          skcf);
                if (ret != NXT_OK) {
                    nxt_alert(task, "http map error");
                    goto fail;
                }
            }

            if (websocket != NULL) {
                ret = nxt_conf_map_object(mp, websocket,
                                          nxt_router_websocket_conf,
                                          nxt_nitems(nxt_router_websocket_conf),
                                          &skcf->websocket_conf);
                if (ret != NXT_OK) {
                    nxt_alert(task, "websocket map error");
                    goto fail;
                }
            }

            t = &skcf->body_temp_path;

            if (t->length == 0) {
                t->start = (u_char *) task->thread->runtime->tmp;
                t->length = nxt_strlen(t->start);
            }

#if (NXT_TLS)
            certificate = nxt_conf_get_path(listener, &certificate_path);

            if (certificate != NULL) {
                if (nxt_conf_type(certificate) == NXT_CONF_ARRAY) {
                    n = nxt_conf_array_elements_count(certificate);

                    for (i = 0; i < n; i++) {
                        value = nxt_conf_get_array_element(certificate, i);

                        nxt_assert(value != NULL);

                        ret = nxt_router_conf_tls_insert(tmcf, value, skcf);
                        if (nxt_slow_path(ret != NXT_OK)) {
                            goto fail;
                        }
                    }

                } else {
                    /* NXT_CONF_STRING */
                    ret = nxt_router_conf_tls_insert(tmcf, certificate, skcf);
                    if (nxt_slow_path(ret != NXT_OK)) {
                        goto fail;
                    }
                }
            }
#endif

            skcf->listen->handler = nxt_http_conn_init;
            skcf->router_conf = tmcf->router_conf;
            skcf->router_conf->count++;

            if (lscf.pass.length != 0) {
                skcf->action = nxt_http_action_create(task, tmcf, &lscf.pass);

            /* COMPATIBILITY: listener application. */
            } else if (lscf.application.length > 0) {
                skcf->action = nxt_http_pass_application(task,
                                                         tmcf->router_conf,
                                                         &lscf.application);
            }

            if (nxt_slow_path(skcf->action == NULL)) {
                goto fail;
            }
        }
    }

    ret = nxt_http_routes_resolve(task, tmcf);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
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

    nxt_queue_add(&deleting_sockets, &router->sockets);
    nxt_queue_init(&router->sockets);

    return NXT_OK;

app_fail:

    nxt_mp_destroy(app_mp);

fail:

    nxt_queue_each(app, &tmcf->apps, nxt_app_t, link) {

        nxt_queue_remove(&app->link);
        nxt_thread_mutex_destroy(&app->mutex);
        nxt_mp_destroy(app->mem_pool);

    } nxt_queue_loop;

    return NXT_ERROR;
}


#if (NXT_TLS)

static nxt_int_t
nxt_router_conf_tls_insert(nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *value, nxt_socket_conf_t *skcf)
{
    nxt_mp_t              *mp;
    nxt_str_t             str;
    nxt_router_tlssock_t  *tls;

    mp = tmcf->router_conf->mem_pool;

    tls = nxt_mp_get(mp, sizeof(nxt_router_tlssock_t));
    if (nxt_slow_path(tls == NULL)) {
        return NXT_ERROR;
    }

    tls->conf = skcf;
    nxt_conf_get_string(value, &str);

    if (nxt_slow_path(nxt_str_dup(mp, &tls->name, &str) == NULL)) {
        return NXT_ERROR;
    }

    nxt_queue_insert_tail(&tmcf->tls, &tls->link);

    return NXT_OK;
}

#endif


static nxt_int_t
nxt_router_conf_process_static(nxt_task_t *task, nxt_router_conf_t *rtcf,
    nxt_conf_value_t *conf)
{
    uint32_t          next, i;
    nxt_mp_t          *mp;
    nxt_str_t         *type, extension, str;
    nxt_int_t         ret;
    nxt_uint_t        exts;
    nxt_conf_value_t  *mtypes_conf, *ext_conf, *value;

    static nxt_str_t  mtypes_path = nxt_string("/mime_types");

    mp = rtcf->mem_pool;

    ret = nxt_http_static_mtypes_init(mp, &rtcf->mtypes_hash);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    if (conf == NULL) {
        return NXT_OK;
    }

    mtypes_conf = nxt_conf_get_path(conf, &mtypes_path);

    if (mtypes_conf != NULL) {
        next = 0;

        for ( ;; ) {
            ext_conf = nxt_conf_next_object_member(mtypes_conf, &str, &next);

            if (ext_conf == NULL) {
                break;
            }

            type = nxt_str_dup(mp, NULL, &str);
            if (nxt_slow_path(type == NULL)) {
                return NXT_ERROR;
            }

            if (nxt_conf_type(ext_conf) == NXT_CONF_STRING) {
                nxt_conf_get_string(ext_conf, &str);

                if (nxt_slow_path(nxt_str_dup(mp, &extension, &str) == NULL)) {
                    return NXT_ERROR;
                }

                ret = nxt_http_static_mtypes_hash_add(mp, &rtcf->mtypes_hash,
                                                      &extension, type);
                if (nxt_slow_path(ret != NXT_OK)) {
                    return NXT_ERROR;
                }

                continue;
            }

            exts = nxt_conf_array_elements_count(ext_conf);

            for (i = 0; i < exts; i++) {
                value = nxt_conf_get_array_element(ext_conf, i);

                nxt_conf_get_string(value, &str);

                if (nxt_slow_path(nxt_str_dup(mp, &extension, &str) == NULL)) {
                    return NXT_ERROR;
                }

                ret = nxt_http_static_mtypes_hash_add(mp, &rtcf->mtypes_hash,
                                                      &extension, type);
                if (nxt_slow_path(ret != NXT_OK)) {
                    return NXT_ERROR;
                }
            }
        }
    }

    return NXT_OK;
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


static nxt_int_t
nxt_router_app_queue_init(nxt_task_t *task, nxt_port_t *port)
{
    void       *mem;
    nxt_int_t  fd;

    fd = nxt_shm_open(task, sizeof(nxt_app_queue_t));
    if (nxt_slow_path(fd == -1)) {
        return NXT_ERROR;
    }

    mem = nxt_mem_mmap(NULL, sizeof(nxt_app_queue_t),
                       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_fd_close(fd);

        return NXT_ERROR;
    }

    nxt_app_queue_init(mem);

    port->queue_fd = fd;
    port->queue = mem;

    return NXT_OK;
}


static nxt_int_t
nxt_router_port_queue_init(nxt_task_t *task, nxt_port_t *port)
{
    void       *mem;
    nxt_int_t  fd;

    fd = nxt_shm_open(task, sizeof(nxt_port_queue_t));
    if (nxt_slow_path(fd == -1)) {
        return NXT_ERROR;
    }

    mem = nxt_mem_mmap(NULL, sizeof(nxt_port_queue_t),
                       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_fd_close(fd);

        return NXT_ERROR;
    }

    nxt_port_queue_init(mem);

    port->queue_fd = fd;
    port->queue = mem;

    return NXT_OK;
}


static nxt_int_t
nxt_router_port_queue_map(nxt_task_t *task, nxt_port_t *port, nxt_fd_t fd)
{
    void  *mem;

    nxt_assert(fd != -1);

    mem = nxt_mem_mmap(NULL, sizeof(nxt_port_queue_t),
                       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (nxt_slow_path(mem == MAP_FAILED)) {

        return NXT_ERROR;
    }

    port->queue = mem;

    return NXT_OK;
}


static const nxt_lvlhsh_proto_t  nxt_router_apps_hash_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_router_apps_hash_test,
    nxt_mp_lvlhsh_alloc,
    nxt_mp_lvlhsh_free,
};


static nxt_int_t
nxt_router_apps_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_app_t  *app;

    app = data;

    return nxt_strstr_eq(&lhq->key, &app->name) ? NXT_OK : NXT_DECLINED;
}


static nxt_int_t
nxt_router_apps_hash_add(nxt_router_conf_t *rtcf, nxt_app_t *app)
{
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_djb_hash(app->name.start, app->name.length);
    lhq.replace = 0;
    lhq.key = app->name;
    lhq.value = app;
    lhq.proto = &nxt_router_apps_hash_proto;
    lhq.pool = rtcf->mem_pool;

    switch (nxt_lvlhsh_insert(&rtcf->apps_hash, &lhq)) {

    case NXT_OK:
        return NXT_OK;

    case NXT_DECLINED:
        nxt_thread_log_alert("router app hash adding failed: "
                             "\"%V\" is already in hash", &lhq.key);
        /* Fall through. */
    default:
        return NXT_ERROR;
    }
}


static nxt_app_t *
nxt_router_apps_hash_get(nxt_router_conf_t *rtcf, nxt_str_t *name)
{
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_djb_hash(name->start, name->length);
    lhq.key = *name;
    lhq.proto = &nxt_router_apps_hash_proto;

    if (nxt_lvlhsh_find(&rtcf->apps_hash, &lhq) != NXT_OK) {
        return NULL;
    }

    return lhq.value;
}


static void
nxt_router_apps_hash_use(nxt_task_t *task, nxt_router_conf_t *rtcf, int i)
{
    nxt_app_t          *app;
    nxt_lvlhsh_each_t  lhe;

    nxt_lvlhsh_each_init(&lhe, &nxt_router_apps_hash_proto);

    for ( ;; ) {
        app = nxt_lvlhsh_each(&rtcf->apps_hash, &lhe);

        if (app == NULL) {
            break;
        }

        nxt_router_app_use(task, app, i);
    }
}



nxt_int_t
nxt_router_listener_application(nxt_router_conf_t *rtcf, nxt_str_t *name,
    nxt_http_action_t *action)
{
    nxt_app_t  *app;

    app = nxt_router_apps_hash_get(rtcf, name);

    if (app == NULL) {
        return NXT_DECLINED;
    }

    action->u.application = app;
    action->handler = nxt_http_application_handler;

    return NXT_OK;
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
            nxt_queue_insert_tail(&keeping_sockets, qlk);

            nxt_queue_insert_tail(&updating_sockets, &nskcf->link);

            return NXT_OK;
        }
    }

    nxt_queue_insert_tail(&pending_sockets, &nskcf->link);

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

    b->completion_handler = nxt_router_dummy_buf_completion;

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

    s = msg->fd[0];

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
    nxt_socket_rpc_t        *rpc;
    nxt_router_temp_conf_t  *tmcf;

    rpc = data;
    tmcf = rpc->temp_conf;

#if 0
    u_char                  *p;
    size_t                  size;
    uint8_t                 error;
    nxt_buf_t               *in, *out;
    nxt_sockaddr_t          *sa;

    static nxt_str_t  socket_errors[] = {
        nxt_string("ListenerSystem"),
        nxt_string("ListenerNoIPv6"),
        nxt_string("ListenerPort"),
        nxt_string("ListenerInUse"),
        nxt_string("ListenerNoAddress"),
        nxt_string("ListenerNoAccess"),
        nxt_string("ListenerPath"),
    };

    sa = rpc->socket_conf->listen->sockaddr;

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
#endif

    nxt_router_conf_error(task, tmcf);
}


#if (NXT_TLS)

static void
nxt_router_tls_rpc_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_router_tlssock_t *tls, nxt_bool_t last)
{
    nxt_socket_rpc_t  *rpc;

    rpc = nxt_mp_alloc(tmcf->mem_pool, sizeof(nxt_socket_rpc_t));
    if (rpc == NULL) {
        nxt_router_conf_error(task, tmcf);
        return;
    }

    rpc->name = &tls->name;
    rpc->socket_conf = tls->conf;
    rpc->temp_conf = tmcf;
    rpc->last = last;

    nxt_cert_store_get(task, &tls->name, tmcf->mem_pool,
                       nxt_router_tls_rpc_handler, rpc);
}


static void
nxt_router_tls_rpc_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_mp_t                *mp;
    nxt_int_t               ret;
    nxt_tls_conf_t          *tlscf;
    nxt_socket_rpc_t        *rpc;
    nxt_tls_bundle_conf_t   *bundle;
    nxt_router_temp_conf_t  *tmcf;

    nxt_debug(task, "tls rpc handler");

    rpc = data;
    tmcf = rpc->temp_conf;

    if (msg == NULL || msg->port_msg.type == _NXT_PORT_MSG_RPC_ERROR) {
        goto fail;
    }

    mp = tmcf->router_conf->mem_pool;

    if (rpc->socket_conf->tls == NULL){
        tlscf = nxt_mp_zget(mp, sizeof(nxt_tls_conf_t));
        if (nxt_slow_path(tlscf == NULL)) {
            goto fail;
        }

        rpc->socket_conf->tls = tlscf;

    } else {
        tlscf = rpc->socket_conf->tls;
    }

    bundle = nxt_mp_get(mp, sizeof(nxt_tls_bundle_conf_t));
    if (nxt_slow_path(bundle == NULL)) {
        goto fail;
    }

    bundle->name = rpc->name;
    bundle->chain_file = msg->fd[0];
    bundle->next = tlscf->bundle;
    tlscf->bundle = bundle;

    ret = task->thread->runtime->tls->server_init(task, tlscf, mp, rpc->last);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                       nxt_router_conf_apply, task, tmcf, NULL);
    return;

fail:

    nxt_router_conf_error(task, tmcf);
}

#endif


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

    b->completion_handler = nxt_router_dummy_buf_completion;

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

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_START_PROCESS,
                                -1, stream, router_port->id, b);

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

    nxt_assert(port != NULL);
    nxt_assert(port->type == NXT_PROCESS_APP);
    nxt_assert(port->id == 0);

    port->app = app;
    port->main_app_port = port;

    app->pending_processes--;
    app->processes++;
    app->idle_processes++;

    engine = task->thread->engine;

    nxt_queue_insert_tail(&app->ports, &port->app_link);
    nxt_queue_insert_tail(&app->spare_ports, &port->idle_link);

    nxt_debug(task, "app '%V' move new port %PI:%d to spare_ports",
              &app->name, port->pid, port->id);

    nxt_port_hash_add(&app->port_hash, port);
    app->port_hash_count++;

    port->idle_start = 0;

    nxt_port_inc_use(port);

    nxt_router_app_shared_port_send(task, port);

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

    ret = nxt_router_engine_joints_create(tmcf, recf, &creating_sockets,
                                          nxt_router_listen_socket_create);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    ret = nxt_router_engine_joints_create(tmcf, recf, &updating_sockets,
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

    ret = nxt_router_engine_joints_create(tmcf, recf, &creating_sockets,
                                          nxt_router_listen_socket_create);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    ret = nxt_router_engine_joints_create(tmcf, recf, &updating_sockets,
                                          nxt_router_listen_socket_update);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    ret = nxt_router_engine_joints_delete(tmcf, recf, &deleting_sockets);
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

    ret = nxt_router_engine_joints_delete(tmcf, recf, &updating_sockets);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    return nxt_router_engine_joints_delete(tmcf, recf, &deleting_sockets);
}


static nxt_int_t
nxt_router_engine_joints_create(nxt_router_temp_conf_t *tmcf,
    nxt_router_engine_conf_t *recf, nxt_queue_t *sockets,
    nxt_work_handler_t handler)
{
    nxt_int_t                ret;
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

        ret = nxt_upstreams_joint_create(tmcf, &joint->upstreams);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

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

        nxt_router_app_unlink(task, app);

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
    .rpc_error       = nxt_port_rpc_handler,
    .mmap            = nxt_port_mmap_handler,
    .data            = nxt_port_rpc_handler,
    .oosm            = nxt_router_oosm_handler,
    .req_headers_ack = nxt_port_rpc_handler,
};


static void
nxt_router_thread_start(void *data)
{
    nxt_int_t           ret;
    nxt_port_t          *port;
    nxt_task_t          *task;
    nxt_work_t          *work;
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

    ret = nxt_router_port_queue_init(task, port);
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_use(task, port, -1);
        return;
    }

    engine->port = port;

    nxt_port_enable(task, port, &nxt_router_app_port_handlers);

    work = nxt_zalloc(sizeof(nxt_work_t));
    if (nxt_slow_path(work == NULL)) {
        return;
    }

    work->handler = nxt_router_rt_add_port;
    work->task = link->work.task;
    work->obj = work;
    work->data = port;

    nxt_event_engine_post(link->work.task->thread->engine, work);

    nxt_event_engine_start(engine);
}


static void
nxt_router_rt_add_port(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t      res;
    nxt_port_t     *port;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;
    port = data;

    nxt_free(obj);

    res = nxt_port_hash_add(&rt->ports, port);

    if (nxt_fast_path(res == NXT_OK)) {
        nxt_port_use(task, port, 1);
    }
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

    engine = task->thread->engine;

    if (--lev->count == 0) {
        if (lev->next != NULL) {
            nxt_sockaddr_cache_free(engine, lev->next);

            nxt_conn_free(task, lev->next);
        }

        nxt_free(lev);
    }

    if (joint != NULL) {
        nxt_router_conf_release(task, joint);
    }

    if (engine->shutdown && nxt_queue_is_empty(&engine->joints)) {
        nxt_thread_exit(task->thread);
    }
}


void
nxt_router_conf_release(nxt_task_t *task, nxt_socket_conf_joint_t *joint)
{
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
    rtcf = skcf->router_conf;
    lock = &rtcf->router->lock;

    nxt_thread_spin_lock(lock);

    nxt_debug(task, "conf skcf %p: %D, rtcf %p: %D", skcf, skcf->count,
              rtcf, rtcf->count);

    if (--skcf->count != 0) {
        skcf = NULL;
        rtcf = NULL;

    } else {
        nxt_queue_remove(&skcf->link);

        if (--rtcf->count != 0) {
            rtcf = NULL;
        }
    }

    nxt_thread_spin_unlock(lock);

#if (NXT_TLS)
    if (skcf != NULL && skcf->tls != NULL) {
        task->thread->runtime->tls->server_free(task, skcf->tls);
    }
#endif

    /* TODO remove engine->port */

    if (rtcf != NULL) {
        nxt_debug(task, "old router conf is destroyed");

        nxt_router_apps_hash_use(task, rtcf, -1);

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

    bytes = nxt_http_proto[r->protocol].body_bytes_sent(task, r->proto);

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

    b->completion_handler = nxt_router_dummy_buf_completion;

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

    access_log->fd = msg->fd[0];

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


static void
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

        if (nxt_slow_path(dup2(msg->fd[0], access_log->fd) == -1)) {
            nxt_alert(task, "dup2(%FD, %FD) failed %E",
                      msg->fd[0], access_log->fd, nxt_errno);
        }
    }

    nxt_fd_close(msg->fd[0]);
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

    handle = (nxt_thread_handle_t) (uintptr_t) obj;
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
    size_t                  b_size, count;
    nxt_int_t               ret;
    nxt_app_t               *app;
    nxt_buf_t               *b, *next;
    nxt_port_t              *app_port;
    nxt_unit_field_t        *f;
    nxt_http_field_t        *field;
    nxt_http_request_t      *r;
    nxt_unit_response_t     *resp;
    nxt_request_rpc_data_t  *req_rpc_data;

    req_rpc_data = data;

    r = req_rpc_data->request;
    if (nxt_slow_path(r == NULL)) {
        return;
    }

    if (r->error) {
        nxt_request_rpc_data_unlink(task, req_rpc_data);
        return;
    }

    app = req_rpc_data->app;
    nxt_assert(app != NULL);

    if (msg->port_msg.type == _NXT_PORT_MSG_REQ_HEADERS_ACK) {
        nxt_router_req_headers_ack_handler(task, msg, req_rpc_data);

        return;
    }

    b = (msg->size == 0) ? NULL : msg->buf;

    if (msg->port_msg.last != 0) {
        nxt_debug(task, "router data create last buf");

        nxt_buf_chain_add(&b, nxt_http_buf_last(r));

        req_rpc_data->rpc_cancel = 0;

        if (req_rpc_data->apr_action == NXT_APR_REQUEST_FAILED) {
            req_rpc_data->apr_action = NXT_APR_GOT_RESPONSE;
        }

        nxt_request_rpc_data_unlink(task, req_rpc_data);

    } else {
        if (app->timeout != 0) {
            r->timer.handler = nxt_router_app_timeout;
            r->timer_data = req_rpc_data;
            nxt_timer_add(task->thread->engine, &r->timer, app->timeout);
        }
    }

    if (b == NULL) {
        return;
    }

    if (msg->buf == b) {
        /* Disable instant buffer completion/re-using by port. */
        msg->buf = NULL;
    }

    if (r->header_sent) {
        nxt_buf_chain_add(&r->out, b);
        nxt_http_request_send_body(task, r, NULL);

    } else {
        b_size = nxt_buf_is_mem(b) ? nxt_buf_mem_used_size(&b->mem) : 0;

        if (nxt_slow_path(b_size < sizeof(nxt_unit_response_t))) {
            nxt_alert(task, "response buffer too small: %z", b_size);
            goto fail;
        }

        resp = (void *) b->mem.pos;
        count = (b_size - sizeof(nxt_unit_response_t))
                    / sizeof(nxt_unit_field_t);

        if (nxt_slow_path(count < resp->fields_count)) {
            nxt_alert(task, "response buffer too small for fields count: %D",
                      resp->fields_count);
            goto fail;
        }

        field = NULL;

        for (f = resp->fields; f < resp->fields + resp->fields_count; f++) {
            if (f->skip) {
                continue;
            }

            field = nxt_list_add(r->resp.fields);

            if (nxt_slow_path(field == NULL)) {
                goto fail;
            }

            field->hash = f->hash;
            field->skip = 0;
            field->hopbyhop = 0;

            field->name_length = f->name_length;
            field->value_length = f->value_length;
            field->name = nxt_unit_sptr_get(&f->name);
            field->value = nxt_unit_sptr_get(&f->value);

            ret = nxt_http_field_process(field, &nxt_response_fields_hash, r);
            if (nxt_slow_path(ret != NXT_OK)) {
                goto fail;
            }

            nxt_debug(task, "header%s: %*s: %*s",
                      (field->skip ? " skipped" : ""),
                      (size_t) field->name_length, field->name,
                      (size_t) field->value_length, field->value);

            if (field->skip) {
                r->resp.fields->last->nelts--;
            }
        }

        r->status = resp->status;

        if (resp->piggyback_content_length != 0) {
            b->mem.pos = nxt_unit_sptr_get(&resp->piggyback_content);
            b->mem.free = b->mem.pos + resp->piggyback_content_length;

        } else {
            b->mem.pos = b->mem.free;
        }

        if (nxt_buf_mem_used_size(&b->mem) == 0) {
            next = b->next;
            b->next = NULL;

            nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                               b->completion_handler, task, b, b->parent);

            b = next;
        }

        if (b != NULL) {
            nxt_buf_chain_add(&r->out, b);
        }

        nxt_http_request_header_send(task, r, nxt_http_request_send_body, NULL);

        if (r->websocket_handshake
            && r->status == NXT_HTTP_SWITCHING_PROTOCOLS)
        {
            app_port = req_rpc_data->app_port;
            if (nxt_slow_path(app_port == NULL)) {
                goto fail;
            }

            nxt_thread_mutex_lock(&app->mutex);

            app_port->main_app_port->active_websockets++;

            nxt_thread_mutex_unlock(&app->mutex);

            nxt_router_app_port_release(task, app_port, NXT_APR_UPGRADE);
            req_rpc_data->apr_action = NXT_APR_CLOSE;

            nxt_debug(task, "stream #%uD upgrade", req_rpc_data->stream);

            r->state = &nxt_http_websocket;

        } else {
            r->state = &nxt_http_request_send_state;
        }
    }

    return;

fail:

    nxt_http_request_error(task, r, NXT_HTTP_SERVICE_UNAVAILABLE);

    nxt_request_rpc_data_unlink(task, req_rpc_data);
}


static void
nxt_router_req_headers_ack_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, nxt_request_rpc_data_t *req_rpc_data)
{
    int                 res;
    nxt_app_t           *app;
    nxt_buf_t           *b;
    nxt_bool_t          start_process, unlinked;
    nxt_port_t          *app_port, *main_app_port, *idle_port;
    nxt_queue_link_t    *idle_lnk;
    nxt_http_request_t  *r;

    nxt_debug(task, "stream #%uD: got ack from %PI:%d",
              req_rpc_data->stream,
              msg->port_msg.pid, msg->port_msg.reply_port);

    nxt_port_rpc_ex_set_peer(task, msg->port, req_rpc_data,
                             msg->port_msg.pid);

    app = req_rpc_data->app;
    r = req_rpc_data->request;

    start_process = 0;
    unlinked = 0;

    nxt_thread_mutex_lock(&app->mutex);

    if (r->app_link.next != NULL) {
        nxt_queue_remove(&r->app_link);
        r->app_link.next = NULL;

        unlinked = 1;
    }

    app_port = nxt_port_hash_find(&app->port_hash, msg->port_msg.pid,
                                  msg->port_msg.reply_port);
    if (nxt_slow_path(app_port == NULL)) {
        nxt_thread_mutex_unlock(&app->mutex);

        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);

        if (unlinked) {
            nxt_mp_release(r->mem_pool);
        }

        return;
    }

    main_app_port = app_port->main_app_port;

    if (nxt_queue_chk_remove(&main_app_port->idle_link)) {
        app->idle_processes--;

        nxt_debug(task, "app '%V' move port %PI:%d out of %s (ack)",
                  &app->name, main_app_port->pid, main_app_port->id,
                  (main_app_port->idle_start ? "idle_ports" : "spare_ports"));

        /* Check port was in 'spare_ports' using idle_start field. */
        if (main_app_port->idle_start == 0
            && app->idle_processes >= app->spare_processes)
        {
            /*
             * If there is a vacant space in spare ports,
             * move the last idle to spare_ports.
             */
            nxt_assert(!nxt_queue_is_empty(&app->idle_ports));

            idle_lnk = nxt_queue_last(&app->idle_ports);
            idle_port = nxt_queue_link_data(idle_lnk, nxt_port_t, idle_link);
            nxt_queue_remove(idle_lnk);

            nxt_queue_insert_tail(&app->spare_ports, idle_lnk);

            idle_port->idle_start = 0;

            nxt_debug(task, "app '%V' move port %PI:%d from idle_ports "
                      "to spare_ports",
                      &app->name, idle_port->pid, idle_port->id);
        }

        if (nxt_router_app_can_start(app) && nxt_router_app_need_start(app)) {
            app->pending_processes++;
            start_process = 1;
        }
    }

    main_app_port->active_requests++;

    nxt_port_inc_use(app_port);

    nxt_thread_mutex_unlock(&app->mutex);

    if (unlinked) {
        nxt_mp_release(r->mem_pool);
    }

    if (start_process) {
        nxt_router_start_app_process(task, app);
    }

    nxt_port_use(task, req_rpc_data->app_port, -1);

    req_rpc_data->app_port = app_port;

    b = req_rpc_data->msg_info.buf;

    if (b != NULL) {
        /* First buffer is already sent.  Start from second. */
        b = b->next;

        req_rpc_data->msg_info.buf->next = NULL;
    }

    if (req_rpc_data->msg_info.body_fd != -1 || b != NULL) {
        nxt_debug(task, "stream #%uD: send body fd %d", req_rpc_data->stream,
                  req_rpc_data->msg_info.body_fd);

        if (req_rpc_data->msg_info.body_fd != -1) {
            lseek(req_rpc_data->msg_info.body_fd, 0, SEEK_SET);
        }

        res = nxt_port_socket_write(task, app_port, NXT_PORT_MSG_REQ_BODY,
                                    req_rpc_data->msg_info.body_fd,
                                    req_rpc_data->stream,
                                    task->thread->engine->port->id, b);

        if (nxt_slow_path(res != NXT_OK)) {
            nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    if (app->timeout != 0) {
        r->timer.handler = nxt_router_app_timeout;
        r->timer_data = req_rpc_data;
        nxt_timer_add(task->thread->engine, &r->timer, app->timeout);
    }
}


static const nxt_http_request_state_t  nxt_http_request_send_state
    nxt_aligned(64) =
{
    .error_handler = nxt_http_request_error_handler,
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
    nxt_request_rpc_data_t  *req_rpc_data;

    req_rpc_data = data;

    req_rpc_data->rpc_cancel = 0;

    /* TODO cancel message and return if cancelled. */
    // nxt_router_msg_cancel(task, &req_rpc_data->msg_info, req_rpc_data->stream);

    if (req_rpc_data->request != NULL) {
        nxt_http_request_error(task, req_rpc_data->request,
                               NXT_HTTP_SERVICE_UNAVAILABLE);
    }

    nxt_request_rpc_data_unlink(task, req_rpc_data);
}


static void
nxt_router_app_port_ready(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_app_t        *app;
    nxt_port_t       *port;
    nxt_app_joint_t  *app_joint;

    app_joint = data;
    port = msg->u.new_port;

    nxt_assert(app_joint != NULL);
    nxt_assert(port != NULL);
    nxt_assert(port->type == NXT_PROCESS_APP);
    nxt_assert(port->id == 0);

    app = app_joint->app;

    nxt_router_app_joint_use(task, app_joint, -1);

    if (nxt_slow_path(app == NULL)) {
        nxt_debug(task, "new port ready for released app, send QUIT");

        nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT, -1, 0, 0, NULL);

        return;
    }

    port->app = app;
    port->main_app_port = port;

    nxt_thread_mutex_lock(&app->mutex);

    nxt_assert(app->pending_processes != 0);

    app->pending_processes--;
    app->processes++;
    nxt_port_hash_add(&app->port_hash, port);
    app->port_hash_count++;

    nxt_thread_mutex_unlock(&app->mutex);

    nxt_debug(task, "app '%V' new port ready, pid %PI, %d/%d",
              &app->name, port->pid, app->processes, app->pending_processes);

    nxt_router_app_shared_port_send(task, port);

    nxt_router_app_port_release(task, port, NXT_APR_NEW_PORT);
}


static nxt_int_t
nxt_router_app_shared_port_send(nxt_task_t *task, nxt_port_t *app_port)
{
    nxt_buf_t                *b;
    nxt_port_t               *port;
    nxt_port_msg_new_port_t  *msg;

    b = nxt_buf_mem_ts_alloc(task, task->thread->engine->mem_pool,
                             sizeof(nxt_port_data_t));
    if (nxt_slow_path(b == NULL)) {
        return NXT_ERROR;
    }

    port = app_port->app->shared_port;

    nxt_debug(task, "send port %FD to process %PI",
              port->pair[0], app_port->pid);

    b->mem.free += sizeof(nxt_port_msg_new_port_t);
    msg = (nxt_port_msg_new_port_t *) b->mem.pos;

    msg->id = port->id;
    msg->pid = port->pid;
    msg->max_size = port->max_size;
    msg->max_share = port->max_share;
    msg->type = port->type;

    return nxt_port_socket_write2(task, app_port,
                                  NXT_PORT_MSG_NEW_PORT,
                                  port->pair[0], port->queue_fd,
                                  0, 0, b);
}


static void
nxt_router_app_port_error(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data)
{
    nxt_app_t           *app;
    nxt_app_joint_t     *app_joint;
    nxt_queue_link_t    *link;
    nxt_http_request_t  *r;

    app_joint = data;

    nxt_assert(app_joint != NULL);

    app = app_joint->app;

    nxt_router_app_joint_use(task, app_joint, -1);

    if (nxt_slow_path(app == NULL)) {
        nxt_debug(task, "start error for released app");

        return;
    }

    nxt_debug(task, "app '%V' %p start error", &app->name, app);

    link = NULL;

    nxt_thread_mutex_lock(&app->mutex);

    nxt_assert(app->pending_processes != 0);

    app->pending_processes--;

    if (app->processes == 0 && !nxt_queue_is_empty(&app->ack_waiting_req)) {
        link = nxt_queue_first(&app->ack_waiting_req);

        nxt_queue_remove(link);
        link->next = NULL;
    }

    nxt_thread_mutex_unlock(&app->mutex);

    while (link != NULL) {
        r = nxt_container_of(link, nxt_http_request_t, app_link);

        nxt_event_engine_post(r->engine, &r->err_work);

        link = NULL;

        nxt_thread_mutex_lock(&app->mutex);

        if (app->processes == 0 && app->pending_processes == 0
            && !nxt_queue_is_empty(&app->ack_waiting_req))
        {
            link = nxt_queue_first(&app->ack_waiting_req);

            nxt_queue_remove(link);
            link->next = NULL;
        }

        nxt_thread_mutex_unlock(&app->mutex);
    }
}



nxt_inline nxt_port_t *
nxt_router_app_get_port_for_quit(nxt_task_t *task, nxt_app_t *app)
{
    nxt_port_t  *port;

    port = NULL;

    nxt_thread_mutex_lock(&app->mutex);

    nxt_queue_each(port, &app->ports, nxt_port_t, app_link) {

        /* Caller is responsible to decrease port use count. */
        nxt_queue_chk_remove(&port->app_link);

        if (nxt_queue_chk_remove(&port->idle_link)) {
            app->idle_processes--;

            nxt_debug(task, "app '%V' move port %PI:%d out of %s for quit",
                      &app->name, port->pid, port->id,
                      (port->idle_start ? "idle_ports" : "spare_ports"));
        }

        nxt_port_hash_remove(&app->port_hash, port);
        app->port_hash_count--;

        port->app = NULL;
        app->processes--;

        break;

    } nxt_queue_loop;

    nxt_thread_mutex_unlock(&app->mutex);

    return port;
}


static void
nxt_router_app_use(nxt_task_t *task, nxt_app_t *app, int i)
{
    int  c;

    c = nxt_atomic_fetch_add(&app->use_count, i);

    if (i < 0 && c == -i) {

        if (task->thread->engine != app->engine) {
            nxt_event_engine_post(app->engine, &app->joint->free_app_work);

        } else {
            nxt_router_free_app(task, app->joint, NULL);
        }
    }
}


static void
nxt_router_app_unlink(nxt_task_t *task, nxt_app_t *app)
{
    nxt_debug(task, "app '%V' %p unlink", &app->name, app);

    nxt_queue_remove(&app->link);

    nxt_router_app_use(task, app, -1);
}


static void
nxt_router_app_port_release(nxt_task_t *task, nxt_port_t *port,
    nxt_apr_action_t action)
{
    int         inc_use;
    uint32_t    got_response, dec_requests;
    nxt_app_t   *app;
    nxt_bool_t  port_unchained, send_quit, adjust_idle_timer;
    nxt_port_t  *main_app_port;

    nxt_assert(port != NULL);
    nxt_assert(port->app != NULL);

    app = port->app;

    inc_use = 0;
    got_response = 0;
    dec_requests = 0;

    switch (action) {
    case NXT_APR_NEW_PORT:
        break;
    case NXT_APR_REQUEST_FAILED:
        dec_requests = 1;
        inc_use = -1;
        break;
    case NXT_APR_GOT_RESPONSE:
        got_response = 1;
        inc_use = -1;
        break;
    case NXT_APR_UPGRADE:
        got_response = 1;
        break;
    case NXT_APR_CLOSE:
        inc_use = -1;
        break;
    }

    nxt_debug(task, "app '%V' release port %PI:%d: %d %d", &app->name,
              port->pid, port->id,
              (int) inc_use, (int) got_response);

    if (port == app->shared_port) {
        nxt_thread_mutex_lock(&app->mutex);

        app->active_requests -= got_response + dec_requests;

        nxt_thread_mutex_unlock(&app->mutex);

        goto adjust_use;
    }

    main_app_port = port->main_app_port;

    nxt_thread_mutex_lock(&app->mutex);

    main_app_port->app_responses += got_response;
    main_app_port->active_requests -= got_response + dec_requests;
    app->active_requests -= got_response + dec_requests;

    if (main_app_port->pair[1] != -1
        && (app->max_requests == 0
            || main_app_port->app_responses < app->max_requests))
    {
        if (main_app_port->app_link.next == NULL) {
            nxt_queue_insert_tail(&app->ports, &main_app_port->app_link);

            nxt_port_inc_use(main_app_port);
        }
    }

    send_quit = (app->max_requests > 0
                 && main_app_port->app_responses >= app->max_requests);

    if (send_quit) {
        port_unchained = nxt_queue_chk_remove(&main_app_port->app_link);

        nxt_port_hash_remove(&app->port_hash, main_app_port);
        app->port_hash_count--;

        main_app_port->app = NULL;
        app->processes--;

    } else {
        port_unchained = 0;
    }

    adjust_idle_timer = 0;

    if (main_app_port->pair[1] != -1 && !send_quit
        && main_app_port->active_requests == 0
        && main_app_port->active_websockets == 0
        && main_app_port->idle_link.next == NULL)
    {
        if (app->idle_processes == app->spare_processes
            && app->adjust_idle_work.data == NULL)
        {
            adjust_idle_timer = 1;
            app->adjust_idle_work.data = app;
            app->adjust_idle_work.next = NULL;
        }

        if (app->idle_processes < app->spare_processes) {
            nxt_queue_insert_tail(&app->spare_ports, &main_app_port->idle_link);

            nxt_debug(task, "app '%V' move port %PI:%d to spare_ports",
                      &app->name, main_app_port->pid, main_app_port->id);
        } else {
            nxt_queue_insert_tail(&app->idle_ports, &main_app_port->idle_link);

            main_app_port->idle_start = task->thread->engine->timers.now;

            nxt_debug(task, "app '%V' move port %PI:%d to idle_ports",
                      &app->name, main_app_port->pid, main_app_port->id);
        }

        app->idle_processes++;
    }

    nxt_thread_mutex_unlock(&app->mutex);

    if (adjust_idle_timer) {
        nxt_router_app_use(task, app, 1);
        nxt_event_engine_post(app->engine, &app->adjust_idle_work);
    }

    /* ? */
    if (main_app_port->pair[1] == -1) {
        nxt_debug(task, "app '%V' %p port %p already closed (pid %PI dead?)",
                  &app->name, app, main_app_port, main_app_port->pid);

        goto adjust_use;
    }

    if (send_quit) {
        nxt_debug(task, "app '%V' %p send QUIT to port", &app->name, app);

        nxt_port_socket_write(task, main_app_port, NXT_PORT_MSG_QUIT, -1, 0, 0,
                              NULL);

        if (port_unchained) {
            nxt_port_use(task, main_app_port, -1);
        }

        goto adjust_use;
    }

    nxt_debug(task, "app '%V' %p requests queue is empty, keep the port",
              &app->name, app);

adjust_use:

    nxt_port_use(task, port, inc_use);
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

    nxt_port_hash_remove(&app->port_hash, port);
    app->port_hash_count--;

    if (port->id != 0) {
        nxt_thread_mutex_unlock(&app->mutex);

        nxt_debug(task, "app '%V' port (%PI, %d) closed", &app->name,
                  port->pid, port->id);

        return;
    }

    unchain = nxt_queue_chk_remove(&port->app_link);

    if (nxt_queue_chk_remove(&port->idle_link)) {
        app->idle_processes--;

        nxt_debug(task, "app '%V' move port %PI:%d out of %s before close",
                  &app->name, port->pid, port->id,
                  (port->idle_start ? "idle_ports" : "spare_ports"));

        if (port->idle_start == 0
            && app->idle_processes >= app->spare_processes)
        {
            nxt_assert(!nxt_queue_is_empty(&app->idle_ports));

            idle_lnk = nxt_queue_last(&app->idle_ports);
            idle_port = nxt_queue_link_data(idle_lnk, nxt_port_t, idle_link);
            nxt_queue_remove(idle_lnk);

            nxt_queue_insert_tail(&app->spare_ports, idle_lnk);

            idle_port->idle_start = 0;

            nxt_debug(task, "app '%V' move port %PI:%d from idle_ports "
                      "to spare_ports",
                      &app->name, idle_port->pid, idle_port->id);
        }
    }

    app->processes--;

    start_process = !task->thread->engine->shutdown
                    && nxt_router_app_can_start(app)
                    && nxt_router_app_need_start(app);

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

    threshold = engine->timers.now + app->joint->idle_timer.bias;
    timeout = 0;

    nxt_thread_mutex_lock(&app->mutex);

    if (queued) {
        app->adjust_idle_work.data = NULL;
    }

    nxt_debug(task, "app '%V' idle_processes %d, spare_processes %d",
              &app->name,
              (int) app->idle_processes, (int) app->spare_processes);

    while (app->idle_processes > app->spare_processes) {

        nxt_assert(!nxt_queue_is_empty(&app->idle_ports));

        lnk = nxt_queue_first(&app->idle_ports);
        port = nxt_queue_link_data(lnk, nxt_port_t, idle_link);

        timeout = port->idle_start + app->idle_timeout;

        nxt_debug(task, "app '%V' pid %PI, start %M, timeout %M, threshold %M",
                  &app->name, port->pid,
                  port->idle_start, timeout, threshold);

        if (timeout > threshold) {
            break;
        }

        nxt_queue_remove(lnk);
        lnk->next = NULL;

        nxt_debug(task, "app '%V' move port %PI:%d out of idle_ports (timeout)",
                  &app->name, port->pid, port->id);

        nxt_queue_chk_remove(&port->app_link);

        nxt_port_hash_remove(&app->port_hash, port);
        app->port_hash_count--;

        app->idle_processes--;
        app->processes--;
        port->app = NULL;

        nxt_thread_mutex_unlock(&app->mutex);

        nxt_debug(task, "app '%V' send QUIT to idle port %PI",
                  &app->name, port->pid);

        nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT, -1, 0, 0, NULL);

        nxt_port_use(task, port, -1);

        nxt_thread_mutex_lock(&app->mutex);
    }

    nxt_thread_mutex_unlock(&app->mutex);

    if (timeout > threshold) {
        nxt_timer_add(engine, &app->joint->idle_timer, timeout - threshold);

    } else {
        nxt_timer_disable(engine, &app->joint->idle_timer);
    }

    if (queued) {
        nxt_router_app_use(task, app, -1);
    }
}


static void
nxt_router_app_idle_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_timer_t      *timer;
    nxt_app_joint_t  *app_joint;

    timer = obj;
    app_joint = nxt_container_of(timer, nxt_app_joint_t, idle_timer);

    if (nxt_fast_path(app_joint->app != NULL)) {
        nxt_router_adjust_idle_timer(task, app_joint->app, NULL);
    }
}


static void
nxt_router_app_joint_release_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_timer_t      *timer;
    nxt_app_joint_t  *app_joint;

    timer = obj;
    app_joint = nxt_container_of(timer, nxt_app_joint_t, idle_timer);

    nxt_router_app_joint_use(task, app_joint, -1);
}


static void
nxt_router_free_app(nxt_task_t *task, void *obj, void *data)
{
    nxt_app_t        *app;
    nxt_port_t       *port;
    nxt_app_joint_t  *app_joint;

    app_joint = obj;
    app = app_joint->app;

    for ( ;; ) {
        port = nxt_router_app_get_port_for_quit(task, app);
        if (port == NULL) {
            break;
        }

        nxt_debug(task, "send QUIT to app '%V' pid %PI", &app->name, port->pid);

        nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT, -1, 0, 0, NULL);

        nxt_port_use(task, port, -1);
    }

    nxt_thread_mutex_lock(&app->mutex);

    for ( ;; ) {
        port = nxt_port_hash_retrieve(&app->port_hash);
        if (port == NULL) {
            break;
        }

        app->port_hash_count--;

        port->app = NULL;

        nxt_port_close(task, port);

        nxt_port_use(task, port, -1);
    }

    nxt_thread_mutex_unlock(&app->mutex);

    nxt_assert(app->processes == 0);
    nxt_assert(app->active_requests == 0);
    nxt_assert(app->port_hash_count == 0);
    nxt_assert(app->idle_processes == 0);
    nxt_assert(nxt_queue_is_empty(&app->ports));
    nxt_assert(nxt_queue_is_empty(&app->spare_ports));
    nxt_assert(nxt_queue_is_empty(&app->idle_ports));

    nxt_port_mmaps_destroy(&app->outgoing, 1);

    nxt_thread_mutex_destroy(&app->outgoing.mutex);

    if (app->shared_port != NULL) {
        app->shared_port->app = NULL;
        nxt_port_close(task, app->shared_port);
        nxt_port_use(task, app->shared_port, -1);
    }

    nxt_thread_mutex_destroy(&app->mutex);
    nxt_mp_destroy(app->mem_pool);

    app_joint->app = NULL;

    if (nxt_timer_delete(task->thread->engine, &app_joint->idle_timer)) {
        app_joint->idle_timer.handler = nxt_router_app_joint_release_handler;
        nxt_timer_add(task->thread->engine, &app_joint->idle_timer, 0);

    } else {
        nxt_router_app_joint_use(task, app_joint, -1);
    }
}


static void
nxt_router_app_port_get(nxt_task_t *task, nxt_app_t *app,
    nxt_request_rpc_data_t *req_rpc_data)
{
    nxt_bool_t          start_process;
    nxt_port_t          *port;
    nxt_http_request_t  *r;

    start_process = 0;

    nxt_thread_mutex_lock(&app->mutex);

    port = app->shared_port;
    nxt_port_inc_use(port);

    app->active_requests++;

    if (nxt_router_app_can_start(app) && nxt_router_app_need_start(app)) {
        app->pending_processes++;
        start_process = 1;
    }

    r = req_rpc_data->request;

    /*
     * Put request into application-wide list to be able to cancel request
     * if something goes wrong with application processes.
     */
    nxt_queue_insert_tail(&app->ack_waiting_req, &r->app_link);

    nxt_thread_mutex_unlock(&app->mutex);

    /*
     * Retain request memory pool while request is linked in ack_waiting_req
     * to guarantee request structure memory is accessble.
     */
    nxt_mp_retain(r->mem_pool);

    req_rpc_data->app_port = port;
    req_rpc_data->apr_action = NXT_APR_REQUEST_FAILED;

    if (start_process) {
        nxt_router_start_app_process(task, app);
    }
}


void
nxt_router_process_http_request(nxt_task_t *task, nxt_http_request_t *r,
    nxt_app_t *app)
{
    nxt_event_engine_t      *engine;
    nxt_request_rpc_data_t  *req_rpc_data;

    engine = task->thread->engine;

    req_rpc_data = nxt_port_rpc_register_handler_ex(task, engine->port,
                                          nxt_router_response_ready_handler,
                                          nxt_router_response_error_handler,
                                          sizeof(nxt_request_rpc_data_t));
    if (nxt_slow_path(req_rpc_data == NULL)) {
        nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /*
     * At this point we have request req_rpc_data allocated and registered
     * in port handlers.  Need to fixup request memory pool.  Counterpart
     * release will be called via following call chain:
     *    nxt_request_rpc_data_unlink() ->
     *        nxt_router_http_request_release_post() ->
     *            nxt_router_http_request_release()
     */
    nxt_mp_retain(r->mem_pool);

    r->timer.task = &engine->task;
    r->timer.work_queue = &engine->fast_work_queue;
    r->timer.log = engine->task.log;
    r->timer.bias = NXT_TIMER_DEFAULT_BIAS;

    r->engine = engine;
    r->err_work.handler = nxt_router_http_request_error;
    r->err_work.task = task;
    r->err_work.obj = r;

    req_rpc_data->stream = nxt_port_rpc_ex_stream(req_rpc_data);
    req_rpc_data->app = app;
    req_rpc_data->msg_info.body_fd = -1;
    req_rpc_data->rpc_cancel = 1;

    nxt_router_app_use(task, app, 1);

    req_rpc_data->request = r;
    r->req_rpc_data = req_rpc_data;

    if (r->last != NULL) {
        r->last->completion_handler = nxt_router_http_request_done;
    }

    nxt_router_app_port_get(task, app, req_rpc_data);
    nxt_router_app_prepare_request(task, req_rpc_data);
}


static void
nxt_router_http_request_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t  *r;

    r = obj;

    nxt_debug(task, "router http request error (rpc_data %p)", r->req_rpc_data);

    nxt_http_request_error(task, r, NXT_HTTP_SERVICE_UNAVAILABLE);

    if (r->req_rpc_data != NULL) {
        nxt_request_rpc_data_unlink(task, r->req_rpc_data);
    }

    nxt_mp_release(r->mem_pool);
}


static void
nxt_router_http_request_done(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t  *r;

    r = data;

    nxt_debug(task, "router http request done (rpc_data %p)", r->req_rpc_data);

    if (r->req_rpc_data != NULL) {
        nxt_request_rpc_data_unlink(task, r->req_rpc_data);
    }

    nxt_http_request_close_handler(task, r, r->proto.any);
}


static void
nxt_router_dummy_buf_completion(nxt_task_t *task, void *obj, void *data)
{
}


static void
nxt_router_app_prepare_request(nxt_task_t *task,
    nxt_request_rpc_data_t *req_rpc_data)
{
    nxt_app_t         *app;
    nxt_buf_t         *buf, *body;
    nxt_int_t         res;
    nxt_port_t        *port, *reply_port;

    int                   notify;
    struct {
        nxt_port_msg_t       pm;
        nxt_port_mmap_msg_t  mm;
    } msg;


    app = req_rpc_data->app;

    nxt_assert(app != NULL);

    port = req_rpc_data->app_port;

    nxt_assert(port != NULL);
    nxt_assert(port->queue != NULL);

    reply_port = task->thread->engine->port;

    buf = nxt_router_prepare_msg(task, req_rpc_data->request, app,
                                 nxt_app_msg_prefix[app->type]);
    if (nxt_slow_path(buf == NULL)) {
        nxt_alert(task, "stream #%uD, app '%V': failed to prepare app message",
                  req_rpc_data->stream, &app->name);

        nxt_http_request_error(task, req_rpc_data->request,
                               NXT_HTTP_INTERNAL_SERVER_ERROR);

        return;
    }

    nxt_debug(task, "about to send %O bytes buffer to app process port %d",
                    nxt_buf_used_size(buf),
                    port->socket.fd);

    req_rpc_data->msg_info.buf = buf;

    body = req_rpc_data->request->body;

    if (body != NULL && nxt_buf_is_file(body)) {
        req_rpc_data->msg_info.body_fd = body->file->fd;

        body->file->fd = -1;

    } else {
        req_rpc_data->msg_info.body_fd = -1;
    }

    msg.pm.stream = req_rpc_data->stream;
    msg.pm.pid = reply_port->pid;
    msg.pm.reply_port = reply_port->id;
    msg.pm.type = NXT_PORT_MSG_REQ_HEADERS;
    msg.pm.last = 0;
    msg.pm.mmap = 1;
    msg.pm.nf = 0;
    msg.pm.mf = 0;
    msg.pm.tracking = 0;

    nxt_port_mmap_handler_t *mmap_handler = buf->parent;
    nxt_port_mmap_header_t *hdr = mmap_handler->hdr;

    msg.mm.mmap_id = hdr->id;
    msg.mm.chunk_id = nxt_port_mmap_chunk_id(hdr, buf->mem.pos);
    msg.mm.size = nxt_buf_used_size(buf);

    res = nxt_app_queue_send(port->queue, &msg, sizeof(msg),
                             req_rpc_data->stream, &notify,
                             &req_rpc_data->msg_info.tracking_cookie);
    if (nxt_fast_path(res == NXT_OK)) {
        if (notify != 0) {
            (void) nxt_port_socket_write(task, port,
                                         NXT_PORT_MSG_READ_QUEUE,
                                         -1, req_rpc_data->stream,
                                         reply_port->id, NULL);

        } else {
            nxt_debug(task, "queue is not empty");
        }

        buf->is_port_mmap_sent = 1;
        buf->mem.pos = buf->mem.free;

    } else {
        nxt_alert(task, "stream #%uD, app '%V': failed to send app message",
                  req_rpc_data->stream, &app->name);

        nxt_http_request_error(task, req_rpc_data->request,
                               NXT_HTTP_INTERNAL_SERVER_ERROR);
    }
}


struct nxt_fields_iter_s {
    nxt_list_part_t   *part;
    nxt_http_field_t  *field;
};

typedef struct nxt_fields_iter_s  nxt_fields_iter_t;


static nxt_http_field_t *
nxt_fields_part_first(nxt_list_part_t *part, nxt_fields_iter_t *i)
{
    if (part == NULL) {
        return NULL;
    }

    while (part->nelts == 0) {
        part = part->next;
        if (part == NULL) {
            return NULL;
        }
    }

    i->part = part;
    i->field = nxt_list_data(i->part);

    return i->field;
}


static nxt_http_field_t *
nxt_fields_first(nxt_list_t *fields, nxt_fields_iter_t *i)
{
    return nxt_fields_part_first(nxt_list_part(fields), i);
}


static nxt_http_field_t *
nxt_fields_next(nxt_fields_iter_t *i)
{
    nxt_http_field_t  *end = nxt_list_data(i->part);

    end += i->part->nelts;
    i->field++;

    if (i->field < end) {
        return i->field;
    }

    return nxt_fields_part_first(i->part->next, i);
}


static nxt_buf_t *
nxt_router_prepare_msg(nxt_task_t *task, nxt_http_request_t *r,
    nxt_app_t *app, const nxt_str_t *prefix)
{
    void                *target_pos, *query_pos;
    u_char              *pos, *end, *p, c;
    size_t              fields_count, req_size, size, free_size;
    size_t              copy_size;
    nxt_off_t           content_length;
    nxt_buf_t           *b, *buf, *out, **tail;
    nxt_http_field_t    *field, *dup;
    nxt_unit_field_t    *dst_field;
    nxt_fields_iter_t   iter, dup_iter;
    nxt_unit_request_t  *req;

    req_size = sizeof(nxt_unit_request_t)
               + r->method->length + 1
               + r->version.length + 1
               + r->remote->length + 1
               + r->local->length + 1
               + r->server_name.length + 1
               + r->target.length + 1
               + (r->path->start != r->target.start ? r->path->length + 1 : 0);

    content_length = r->content_length_n < 0 ? 0 : r->content_length_n;
    fields_count = 0;

    nxt_list_each(field, r->fields) {
        fields_count++;

        req_size += field->name_length + prefix->length + 1
                    + field->value_length + 1;
    } nxt_list_loop;

    req_size += fields_count * sizeof(nxt_unit_field_t);

    if (nxt_slow_path(req_size > PORT_MMAP_DATA_SIZE)) {
        nxt_alert(task, "headers to big to fit in shared memory (%d)",
                  (int) req_size);

        return NULL;
    }

    out = nxt_port_mmap_get_buf(task, &app->outgoing,
              nxt_min(req_size + content_length, PORT_MMAP_DATA_SIZE));
    if (nxt_slow_path(out == NULL)) {
        return NULL;
    }

    req = (nxt_unit_request_t *) out->mem.free;
    out->mem.free += req_size;

    req->app_target = r->app_target;

    req->content_length = content_length;

    p = (u_char *) (req->fields + fields_count);

    nxt_debug(task, "fields_count=%d", (int) fields_count);

    req->method_length = r->method->length;
    nxt_unit_sptr_set(&req->method, p);
    p = nxt_cpymem(p, r->method->start, r->method->length);
    *p++ = '\0';

    req->version_length = r->version.length;
    nxt_unit_sptr_set(&req->version, p);
    p = nxt_cpymem(p, r->version.start, r->version.length);
    *p++ = '\0';

    req->remote_length = r->remote->address_length;
    nxt_unit_sptr_set(&req->remote, p);
    p = nxt_cpymem(p, nxt_sockaddr_address(r->remote),
                   r->remote->address_length);
    *p++ = '\0';

    req->local_length = r->local->address_length;
    nxt_unit_sptr_set(&req->local, p);
    p = nxt_cpymem(p, nxt_sockaddr_address(r->local), r->local->address_length);
    *p++ = '\0';

    req->tls = (r->tls != NULL);
    req->websocket_handshake = r->websocket_handshake;

    req->server_name_length = r->server_name.length;
    nxt_unit_sptr_set(&req->server_name, p);
    p = nxt_cpymem(p, r->server_name.start, r->server_name.length);
    *p++ = '\0';

    target_pos = p;
    req->target_length = (uint32_t) r->target.length;
    nxt_unit_sptr_set(&req->target, p);
    p = nxt_cpymem(p, r->target.start, r->target.length);
    *p++ = '\0';

    req->path_length = (uint32_t) r->path->length;
    if (r->path->start == r->target.start) {
        nxt_unit_sptr_set(&req->path, target_pos);

    } else {
        nxt_unit_sptr_set(&req->path, p);
        p = nxt_cpymem(p, r->path->start, r->path->length);
        *p++ = '\0';
    }

    req->query_length = r->args != NULL ? (uint32_t) r->args->length : 0;
    if (r->args != NULL && r->args->start != NULL) {
        query_pos = nxt_pointer_to(target_pos,
                                   r->args->start - r->target.start);

        nxt_unit_sptr_set(&req->query, query_pos);

    } else {
        req->query.offset = 0;
    }

    req->content_length_field = NXT_UNIT_NONE_FIELD;
    req->content_type_field   = NXT_UNIT_NONE_FIELD;
    req->cookie_field         = NXT_UNIT_NONE_FIELD;
    req->authorization_field  = NXT_UNIT_NONE_FIELD;

    dst_field = req->fields;

    for (field = nxt_fields_first(r->fields, &iter);
         field != NULL;
         field = nxt_fields_next(&iter))
    {
        if (field->skip) {
            continue;
        }

        dst_field->hash = field->hash;
        dst_field->skip = 0;
        dst_field->name_length = field->name_length + prefix->length;
        dst_field->value_length = field->value_length;

        if (field == r->content_length) {
            req->content_length_field = dst_field - req->fields;

        } else if (field == r->content_type) {
            req->content_type_field = dst_field - req->fields;

        } else if (field == r->cookie) {
            req->cookie_field = dst_field - req->fields;

        } else if (field == r->authorization) {
            req->authorization_field = dst_field - req->fields;
        }

        nxt_debug(task, "add field 0x%04Xd, %d, %d, %p : %d %p",
                  (int) field->hash, (int) field->skip,
                  (int) field->name_length, field->name,
                  (int) field->value_length, field->value);

        if (prefix->length != 0) {
            nxt_unit_sptr_set(&dst_field->name, p);
            p = nxt_cpymem(p, prefix->start, prefix->length);

            end = field->name + field->name_length;
            for (pos = field->name; pos < end; pos++) {
                c = *pos;

                if (c >= 'a' && c <= 'z') {
                    *p++ = (c & ~0x20);
                    continue;
                }

                if (c == '-') {
                    *p++ = '_';
                    continue;
                }

                *p++ = c;
            }

        } else {
            nxt_unit_sptr_set(&dst_field->name, p);
            p = nxt_cpymem(p, field->name, field->name_length);
        }

        *p++ = '\0';

        nxt_unit_sptr_set(&dst_field->value, p);
        p = nxt_cpymem(p, field->value, field->value_length);

        if (prefix->length != 0) {
            dup_iter = iter;

            for (dup = nxt_fields_next(&dup_iter);
                 dup != NULL;
                 dup = nxt_fields_next(&dup_iter))
            {
                if (dup->name_length != field->name_length
                    || dup->skip
                    || dup->hash != field->hash
                    || nxt_memcasecmp(dup->name, field->name, dup->name_length))
                {
                    continue;
                }

                p = nxt_cpymem(p, ", ", 2);
                p = nxt_cpymem(p, dup->value, dup->value_length);

                dst_field->value_length += 2 + dup->value_length;

                dup->skip = 1;
            }
        }

        *p++ = '\0';

        dst_field++;
    }

    req->fields_count = (uint32_t) (dst_field - req->fields);

    nxt_unit_sptr_set(&req->preread_content, out->mem.free);

    buf = out;
    tail = &buf->next;

    for (b = r->body; b != NULL; b = b->next) {
        size = nxt_buf_mem_used_size(&b->mem);
        pos = b->mem.pos;

        while (size > 0) {
            if (buf == NULL) {
                free_size = nxt_min(size, PORT_MMAP_DATA_SIZE);

                buf = nxt_port_mmap_get_buf(task, &app->outgoing, free_size);
                if (nxt_slow_path(buf == NULL)) {
                    while (out != NULL) {
                        buf = out->next;
                        out->next = NULL;
                        out->completion_handler(task, out, out->parent);
                        out = buf;
                    }
                    return NULL;
                }

                *tail = buf;
                tail = &buf->next;

            } else {
                free_size = nxt_buf_mem_free_size(&buf->mem);
                if (free_size < size
                    && nxt_port_mmap_increase_buf(task, buf, size, 1)
                       == NXT_OK)
                {
                    free_size = nxt_buf_mem_free_size(&buf->mem);
                }
            }

            if (free_size > 0) {
                copy_size = nxt_min(free_size, size);

                buf->mem.free = nxt_cpymem(buf->mem.free, pos, copy_size);

                size -= copy_size;
                pos += copy_size;

                if (size == 0) {
                    break;
                }
            }

            buf = NULL;
        }
    }

    return out;
}


static void
nxt_router_app_timeout(nxt_task_t *task, void *obj, void *data)
{
    nxt_timer_t              *timer;
    nxt_http_request_t       *r;
    nxt_request_rpc_data_t   *req_rpc_data;

    timer = obj;

    nxt_debug(task, "router app timeout");

    r = nxt_timer_data(timer, nxt_http_request_t, timer);
    req_rpc_data = r->timer_data;

    nxt_http_request_error(task, r, NXT_HTTP_SERVICE_UNAVAILABLE);

    nxt_request_rpc_data_unlink(task, req_rpc_data);
}


static void
nxt_router_http_request_release_post(nxt_task_t *task, nxt_http_request_t *r)
{
    r->timer.handler = nxt_router_http_request_release;
    nxt_timer_add(task->thread->engine, &r->timer, 0);
}


static void
nxt_router_http_request_release(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t  *r;

    nxt_debug(task, "http request pool release");

    r = nxt_timer_data(obj, nxt_http_request_t, timer);

    nxt_mp_release(r->mem_pool);
}


static void
nxt_router_oosm_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    size_t                   mi;
    uint32_t                 i;
    nxt_bool_t               ack;
    nxt_process_t            *process;
    nxt_free_map_t           *m;
    nxt_port_mmap_handler_t  *mmap_handler;

    nxt_debug(task, "oosm in %PI", msg->port_msg.pid);

    process = nxt_runtime_process_find(task->thread->runtime,
                                       msg->port_msg.pid);
    if (nxt_slow_path(process == NULL)) {
        return;
    }

    ack = 0;

    /*
     * To mitigate possible racing condition (when OOSM message received
     * after some of the memory was already freed), need to try to find
     * first free segment in shared memory and send ACK if found.
     */

    nxt_thread_mutex_lock(&process->incoming.mutex);

    for (i = 0; i < process->incoming.size; i++) {
        mmap_handler = process->incoming.elts[i].mmap_handler;

        if (nxt_slow_path(mmap_handler == NULL)) {
            continue;
        }

        m = mmap_handler->hdr->free_map;

        for (mi = 0; mi < MAX_FREE_IDX; mi++) {
            if (m[mi] != 0) {
                ack = 1;

                nxt_debug(task, "oosm: already free #%uD %uz = 0x%08xA",
                          i, mi, m[mi]);

                break;
            }
        }
    }

    nxt_thread_mutex_unlock(&process->incoming.mutex);

    if (ack) {
        nxt_process_broadcast_shm_ack(task, process);
    }
}


static void
nxt_router_get_mmap_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_fd_t                 fd;
    nxt_port_t               *port;
    nxt_runtime_t            *rt;
    nxt_port_mmaps_t         *mmaps;
    nxt_port_msg_get_mmap_t  *get_mmap_msg;
    nxt_port_mmap_handler_t  *mmap_handler;

    rt = task->thread->runtime;

    port = nxt_runtime_port_find(rt, msg->port_msg.pid,
                                 msg->port_msg.reply_port);
    if (nxt_slow_path(port == NULL)) {
        nxt_alert(task, "get_mmap_handler: reply_port %PI:%d not found",
                  msg->port_msg.pid, msg->port_msg.reply_port);

        return;
    }

    if (nxt_slow_path(nxt_buf_used_size(msg->buf)
                      < (int) sizeof(nxt_port_msg_get_mmap_t)))
    {
        nxt_alert(task, "get_mmap_handler: message buffer too small (%d)",
                  (int) nxt_buf_used_size(msg->buf));

        return;
    }

    get_mmap_msg = (nxt_port_msg_get_mmap_t *) msg->buf->mem.pos;

    nxt_assert(port->type == NXT_PROCESS_APP);

    if (nxt_slow_path(port->app == NULL)) {
        nxt_alert(task, "get_mmap_handler: app == NULL for reply port %PI:%d",
                  port->pid, port->id);

        // FIXME
        nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_ERROR,
                              -1, msg->port_msg.stream, 0, NULL);

        return;
    }

    mmaps = &port->app->outgoing;
    nxt_thread_mutex_lock(&mmaps->mutex);

    if (nxt_slow_path(get_mmap_msg->id >= mmaps->size)) {
        nxt_thread_mutex_unlock(&mmaps->mutex);

        nxt_alert(task, "get_mmap_handler: mmap id is too big (%d)",
                  (int) get_mmap_msg->id);

        // FIXME
        nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_ERROR,
                              -1, msg->port_msg.stream, 0, NULL);
        return;
    }

    mmap_handler = mmaps->elts[get_mmap_msg->id].mmap_handler;

    fd = mmap_handler->fd;

    nxt_thread_mutex_unlock(&mmaps->mutex);

    nxt_debug(task, "get mmap %PI:%d found",
              msg->port_msg.pid, (int) get_mmap_msg->id);

    (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_MMAP, fd, 0, 0, NULL);
}


static void
nxt_router_get_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_t               *port, *reply_port;
    nxt_runtime_t            *rt;
    nxt_port_msg_get_port_t  *get_port_msg;

    rt = task->thread->runtime;

    reply_port = nxt_runtime_port_find(rt, msg->port_msg.pid,
                                       msg->port_msg.reply_port);
    if (nxt_slow_path(reply_port == NULL)) {
        nxt_alert(task, "get_port_handler: reply_port %PI:%d not found",
                  msg->port_msg.pid, msg->port_msg.reply_port);

        return;
    }

    if (nxt_slow_path(nxt_buf_used_size(msg->buf)
                      < (int) sizeof(nxt_port_msg_get_port_t)))
    {
        nxt_alert(task, "get_port_handler: message buffer too small (%d)",
                  (int) nxt_buf_used_size(msg->buf));

        return;
    }

    get_port_msg = (nxt_port_msg_get_port_t *) msg->buf->mem.pos;

    port = nxt_runtime_port_find(rt, get_port_msg->pid, get_port_msg->id);
    if (nxt_slow_path(port == NULL)) {
        nxt_alert(task, "get_port_handler: port %PI:%d not found",
                  get_port_msg->pid, get_port_msg->id);

        return;
    }

    nxt_debug(task, "get port %PI:%d found", get_port_msg->pid,
              get_port_msg->id);

    (void) nxt_port_send_port(task, reply_port, port, msg->port_msg.stream);
}
