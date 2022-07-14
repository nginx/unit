
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_conf.h>
#include <nxt_http.h>


static void nxt_router_access_log_writer(nxt_task_t *task,
    nxt_http_request_t *r, nxt_router_access_log_t *access_log);
static u_char *nxt_router_access_log_date(u_char *buf, nxt_realtime_t *now,
    struct tm *tm, size_t size, const char *format);
static void nxt_router_access_log_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_access_log_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_access_log_reopen_completion(nxt_task_t *task, void *obj,
    void *data);
static void nxt_router_access_log_reopen_ready(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);
static void nxt_router_access_log_reopen_error(nxt_task_t *task,
    nxt_port_recv_msg_t *msg, void *data);


nxt_int_t
nxt_router_access_log_create(nxt_task_t *task, nxt_router_conf_t *rtcf,
    nxt_conf_value_t *value)
{
    nxt_str_t                path;
    nxt_router_t             *router;
    nxt_router_access_log_t  *access_log;

    router = nxt_router;

    nxt_conf_get_string(value, &path);

    access_log = router->access_log;

    if (access_log != NULL && nxt_strstr_eq(&path, &access_log->path)) {
        nxt_router_access_log_use(&router->lock, access_log);

    } else {
        access_log = nxt_malloc(sizeof(nxt_router_access_log_t)
                                + path.length);
        if (access_log == NULL) {
            nxt_alert(task, "failed to allocate access log structure");
            return NXT_ERROR;
        }

        access_log->fd = -1;
        access_log->handler = &nxt_router_access_log_writer;
        access_log->count = 1;

        access_log->path.length = path.length;
        access_log->path.start = (u_char *) access_log
                                 + sizeof(nxt_router_access_log_t);

        nxt_memcpy(access_log->path.start, path.start, path.length);
    }

    rtcf->access_log = access_log;

    return NXT_OK;
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


void
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

    b->completion_handler = nxt_buf_dummy_completion;

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


void
nxt_router_access_log_use(nxt_thread_spinlock_t *lock,
    nxt_router_access_log_t *access_log)
{
    if (access_log == NULL) {
        return;
    }

    nxt_thread_spin_lock(lock);

    access_log->count++;

    nxt_thread_spin_unlock(lock);
}


void
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
