
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_port.h>
#include <nxt_main_process.h>
#include <nxt_conf.h>
#include <nxt_router.h>
#include <nxt_port_queue.h>
#if (NXT_TLS)
#include <nxt_cert.h>
#endif
#if (NXT_HAVE_NJS)
#include <nxt_script.h>
#endif

#include <sys/mount.h>


typedef struct {
    nxt_socket_t        socket;
    nxt_socket_error_t  error;
    u_char              *start;
    u_char              *end;
} nxt_listening_socket_t;


typedef struct {
    nxt_uint_t          size;
    nxt_conf_map_t      *map;
} nxt_conf_app_map_t;


static nxt_int_t nxt_main_process_port_create(nxt_task_t *task,
    nxt_runtime_t *rt);
static void nxt_main_process_title(nxt_task_t *task);
static void nxt_main_process_sigterm_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_main_process_sigquit_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_main_process_sigusr1_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_main_process_sigchld_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_main_process_signal_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_main_process_cleanup(nxt_task_t *task, nxt_process_t *process);
static void nxt_main_port_socket_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_main_port_socket_unlink_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static nxt_int_t nxt_main_listening_socket(nxt_sockaddr_t *sa,
    nxt_listening_socket_t *ls);
static void nxt_main_port_modules_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static int nxt_cdecl nxt_app_lang_compare(const void *v1, const void *v2);
static void nxt_main_process_whoami_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_main_port_conf_store_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static nxt_int_t nxt_main_file_store(nxt_task_t *task, const char *tmp_name,
    const char *name, u_char *buf, size_t size);
static void nxt_main_port_access_log_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);

const nxt_sig_event_t  nxt_main_process_signals[] = {
    nxt_event_signal(SIGHUP,  nxt_main_process_signal_handler),
    nxt_event_signal(SIGINT,  nxt_main_process_sigterm_handler),
    nxt_event_signal(SIGQUIT, nxt_main_process_sigquit_handler),
    nxt_event_signal(SIGTERM, nxt_main_process_sigterm_handler),
    nxt_event_signal(SIGCHLD, nxt_main_process_sigchld_handler),
    nxt_event_signal(SIGUSR1, nxt_main_process_sigusr1_handler),
    nxt_event_signal_end,
};


nxt_uint_t  nxt_conf_ver;

static nxt_bool_t  nxt_exiting;


nxt_int_t
nxt_main_process_start(nxt_thread_t *thr, nxt_task_t *task,
    nxt_runtime_t *rt)
{
    rt->type = NXT_PROCESS_MAIN;

    if (nxt_main_process_port_create(task, rt) != NXT_OK) {
        return NXT_ERROR;
    }

    nxt_main_process_title(task);

    /*
     * The discovery process will send a message processed by
     * nxt_main_port_modules_handler() which starts the controller
     * and router processes.
     */
    return nxt_process_init_start(task, nxt_discovery_process);
}


static nxt_conf_map_t  nxt_common_app_conf[] = {
    {
        nxt_string("type"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_common_app_conf_t, type),
    },

    {
        nxt_string("user"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_common_app_conf_t, user),
    },

    {
        nxt_string("group"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_common_app_conf_t, group),
    },

    {
        nxt_string("stdout"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, stdout_log),
    },

    {
        nxt_string("stderr"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, stderr_log),
    },

    {
        nxt_string("working_directory"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, working_directory),
    },

    {
        nxt_string("environment"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, environment),
    },

    {
        nxt_string("isolation"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, isolation),
    },

    {
        nxt_string("limits"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, limits),
    },

};


static nxt_conf_map_t  nxt_common_app_limits_conf[] = {
    {
        nxt_string("shm"),
        NXT_CONF_MAP_SIZE,
        offsetof(nxt_common_app_conf_t, shm_limit),
    },

    {
        nxt_string("requests"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_common_app_conf_t, request_limit),
    },

};


static nxt_conf_map_t  nxt_external_app_conf[] = {
    {
        nxt_string("executable"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.external.executable),
    },

    {
        nxt_string("arguments"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, u.external.arguments),
    },

};


static nxt_conf_map_t  nxt_python_app_conf[] = {
    {
        nxt_string("home"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.python.home),
    },

    {
        nxt_string("path"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, u.python.path),
    },

    {
        nxt_string("protocol"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_common_app_conf_t, u.python.protocol),
    },

    {
        nxt_string("threads"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_common_app_conf_t, u.python.threads),
    },

    {
        nxt_string("targets"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, u.python.targets),
    },

    {
        nxt_string("thread_stack_size"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_common_app_conf_t, u.python.thread_stack_size),
    },
};


static nxt_conf_map_t  nxt_php_app_conf[] = {
    {
        nxt_string("targets"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, u.php.targets),
    },

    {
        nxt_string("options"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, u.php.options),
    },
};


static nxt_conf_map_t  nxt_perl_app_conf[] = {
    {
        nxt_string("script"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.perl.script),
    },

    {
        nxt_string("threads"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_common_app_conf_t, u.perl.threads),
    },

    {
        nxt_string("thread_stack_size"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_common_app_conf_t, u.perl.thread_stack_size),
    },
};


static nxt_conf_map_t  nxt_ruby_app_conf[] = {
    {
        nxt_string("script"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_common_app_conf_t, u.ruby.script),
    },
    {
        nxt_string("threads"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_common_app_conf_t, u.ruby.threads),
    },
    {
        nxt_string("hooks"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_common_app_conf_t, u.ruby.hooks),
    }
};


static nxt_conf_map_t  nxt_java_app_conf[] = {
    {
        nxt_string("classpath"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, u.java.classpath),
    },
    {
        nxt_string("webapp"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.java.webapp),
    },
    {
        nxt_string("options"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, u.java.options),
    },
    {
        nxt_string("unit_jars"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.java.unit_jars),
    },
    {
        nxt_string("threads"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_common_app_conf_t, u.java.threads),
    },
    {
        nxt_string("thread_stack_size"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_common_app_conf_t, u.java.thread_stack_size),
    },

};


static nxt_conf_map_t  nxt_wasm_app_conf[] = {
    {
        nxt_string("module"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.wasm.module),
    },
    {
        nxt_string("request_handler"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.wasm.request_handler),
    },
    {
        nxt_string("malloc_handler"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.wasm.malloc_handler),
    },
    {
        nxt_string("free_handler"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.wasm.free_handler),
    },
    {
        nxt_string("module_init_handler"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.wasm.module_init_handler),
    },
    {
        nxt_string("module_end_handler"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.wasm.module_end_handler),
    },
    {
        nxt_string("request_init_handler"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.wasm.request_init_handler),
    },
    {
        nxt_string("request_end_handler"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.wasm.request_end_handler),
    },
    {
        nxt_string("response_end_handler"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.wasm.response_end_handler),
    },
    {
        nxt_string("access"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, u.wasm.access),
    },
};


static nxt_conf_map_t  nxt_wasm_wc_app_conf[] = {
    {
        nxt_string("component"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_common_app_conf_t, u.wasm_wc.component),
    },
    {
        nxt_string("access"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_common_app_conf_t, u.wasm_wc.access),
    },
};


static nxt_conf_app_map_t  nxt_app_maps[] = {
    { nxt_nitems(nxt_external_app_conf),  nxt_external_app_conf },
    { nxt_nitems(nxt_python_app_conf),    nxt_python_app_conf },
    { nxt_nitems(nxt_php_app_conf),       nxt_php_app_conf },
    { nxt_nitems(nxt_perl_app_conf),      nxt_perl_app_conf },
    { nxt_nitems(nxt_ruby_app_conf),      nxt_ruby_app_conf },
    { nxt_nitems(nxt_java_app_conf),      nxt_java_app_conf },
    { nxt_nitems(nxt_wasm_app_conf),      nxt_wasm_app_conf },
    { nxt_nitems(nxt_wasm_wc_app_conf),   nxt_wasm_wc_app_conf },
};


static void
nxt_main_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_debug(task, "main data: %*s",
              nxt_buf_mem_used_size(&msg->buf->mem), msg->buf->mem.pos);
}


static void
nxt_main_new_port_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    void        *mem;
    nxt_port_t  *port;

    nxt_port_new_port_handler(task, msg);

    port = msg->u.new_port;

    if (port != NULL
        && port->type == NXT_PROCESS_APP
        && msg->fd[1] != -1)
    {
        mem = nxt_mem_mmap(NULL, sizeof(nxt_port_queue_t),
                           PROT_READ | PROT_WRITE, MAP_SHARED, msg->fd[1], 0);
        if (nxt_fast_path(mem != MAP_FAILED)) {
            port->queue = mem;
        }

        nxt_fd_close(msg->fd[1]);
        msg->fd[1] = -1;
    }
}


static void
nxt_main_start_process_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    u_char                 *start, *p, ch;
    size_t                 type_len;
    nxt_int_t              ret;
    nxt_buf_t              *b;
    nxt_port_t             *port;
    nxt_runtime_t          *rt;
    nxt_process_t          *process;
    nxt_app_type_t         idx;
    nxt_conf_value_t       *conf;
    nxt_process_init_t     *init;
    nxt_common_app_conf_t  *app_conf;

    rt = task->thread->runtime;

    port = rt->port_by_type[NXT_PROCESS_ROUTER];
    if (nxt_slow_path(port == NULL)) {
        nxt_alert(task, "router port not found");
        goto close_fds;
    }

    if (nxt_slow_path(port->pid != nxt_recv_msg_cmsg_pid(msg))) {
        nxt_alert(task, "process %PI cannot start processes",
                  nxt_recv_msg_cmsg_pid(msg));

        goto close_fds;
    }

    process = nxt_process_new(rt);
    if (nxt_slow_path(process == NULL)) {
        goto close_fds;
    }

    process->mem_pool = nxt_mp_create(1024, 128, 256, 32);
    if (process->mem_pool == NULL) {
        nxt_process_use(task, process, -1);
        goto close_fds;
    }

    process->parent_port = rt->port_by_type[NXT_PROCESS_MAIN];

    init = nxt_process_init(process);

    *init = nxt_proto_process;

    b = nxt_buf_chk_make_plain(process->mem_pool, msg->buf, msg->size);
    if (b == NULL) {
        goto failed;
    }

    nxt_debug(task, "main start prototype: %*s", b->mem.free - b->mem.pos,
              b->mem.pos);

    app_conf = nxt_mp_zalloc(process->mem_pool, sizeof(nxt_common_app_conf_t));
    if (nxt_slow_path(app_conf == NULL)) {
        goto failed;
    }

    app_conf->shared_port_fd = msg->fd[0];
    app_conf->shared_queue_fd = msg->fd[1];

    start = b->mem.pos;

    app_conf->name.start = start;
    app_conf->name.length = nxt_strlen(start);

    init->name = (const char *) start;

    process->name = nxt_mp_alloc(process->mem_pool, app_conf->name.length
                                 + sizeof("\"\" prototype") + 1);

    if (nxt_slow_path(process->name == NULL)) {
        goto failed;
    }

    p = (u_char *) process->name;
    *p++ = '"';
    p = nxt_cpymem(p, init->name, app_conf->name.length);
    p = nxt_cpymem(p, "\" prototype", 11);
    *p = '\0';

    app_conf->shm_limit = 100 * 1024 * 1024;
    app_conf->request_limit = 0;

    start += app_conf->name.length + 1;

    conf = nxt_conf_json_parse(process->mem_pool, start, b->mem.free, NULL);
    if (conf == NULL) {
        nxt_alert(task, "router app configuration parsing error");

        goto failed;
    }

    rt = task->thread->runtime;

    app_conf->user.start  = (u_char*)rt->user_cred.user;
    app_conf->user.length = nxt_strlen(rt->user_cred.user);

    ret = nxt_conf_map_object(process->mem_pool, conf, nxt_common_app_conf,
                              nxt_nitems(nxt_common_app_conf), app_conf);

    if (ret != NXT_OK) {
        nxt_alert(task, "failed to map common app conf received from router");
        goto failed;
    }

    for (type_len = 0; type_len != app_conf->type.length; type_len++) {
        ch = app_conf->type.start[type_len];

        if (ch == ' ' || nxt_isdigit(ch)) {
            break;
        }
    }

    idx = nxt_app_parse_type(app_conf->type.start, type_len);

    if (nxt_slow_path(idx >= nxt_nitems(nxt_app_maps))) {
        nxt_alert(task, "invalid app type %d received from router", (int) idx);
        goto failed;
    }

    ret = nxt_conf_map_object(process->mem_pool, conf, nxt_app_maps[idx].map,
                              nxt_app_maps[idx].size, app_conf);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_alert(task, "failed to map app conf received from router");
        goto failed;
    }

    if (app_conf->limits != NULL) {
        ret = nxt_conf_map_object(process->mem_pool, app_conf->limits,
                                  nxt_common_app_limits_conf,
                                  nxt_nitems(nxt_common_app_limits_conf),
                                  app_conf);

        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_alert(task, "failed to map app limits received from router");
            goto failed;
        }
    }

    app_conf->self = conf;

    process->stream = msg->port_msg.stream;
    process->data.app = app_conf;

    ret = nxt_process_start(task, process);
    if (nxt_fast_path(ret == NXT_OK || ret == NXT_AGAIN)) {

        /* Close shared port fds only in main process. */
        if (ret == NXT_OK) {
            nxt_fd_close(app_conf->shared_port_fd);
            nxt_fd_close(app_conf->shared_queue_fd);
        }

        /* Avoid fds close in caller. */
        msg->fd[0] = -1;
        msg->fd[1] = -1;

        return;
    }

failed:

    nxt_process_use(task, process, -1);

    port = nxt_runtime_port_find(rt, msg->port_msg.pid,
                                 msg->port_msg.reply_port);

    if (nxt_fast_path(port != NULL)) {
        nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_ERROR,
                              -1, msg->port_msg.stream, 0, NULL);
    }

close_fds:

    nxt_fd_close(msg->fd[0]);
    msg->fd[0] = -1;

    nxt_fd_close(msg->fd[1]);
    msg->fd[1] = -1;
}


static void
nxt_main_process_created_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_port_t     *port;
    nxt_process_t  *process;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    port = nxt_runtime_port_find(rt, msg->port_msg.pid,
                                 msg->port_msg.reply_port);
    if (nxt_slow_path(port == NULL)) {
        return;
    }

    process = port->process;

    nxt_assert(process != NULL);
    nxt_assert(process->state == NXT_PROCESS_STATE_CREATING);

#if (NXT_HAVE_LINUX_NS && NXT_HAVE_CLONE_NEWUSER)
    if (nxt_is_clone_flag_set(process->isolation.clone.flags, NEWUSER)) {
        if (nxt_slow_path(nxt_clone_credential_map(task, process->pid,
                                                   process->user_cred,
                                                   &process->isolation.clone)
                          != NXT_OK))
        {
            (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_ERROR,
                                         -1, msg->port_msg.stream, 0, NULL);
            return;
        }
    }

#endif

    process->state = NXT_PROCESS_STATE_CREATED;

    (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_READY_LAST,
                                 -1, msg->port_msg.stream, 0, NULL);
}


static nxt_port_handlers_t  nxt_main_process_port_handlers = {
    .data             = nxt_main_data_handler,
    .new_port         = nxt_main_new_port_handler,
    .process_created  = nxt_main_process_created_handler,
    .process_ready    = nxt_port_process_ready_handler,
    .whoami           = nxt_main_process_whoami_handler,
    .remove_pid       = nxt_port_remove_pid_handler,
    .start_process    = nxt_main_start_process_handler,
    .socket           = nxt_main_port_socket_handler,
    .socket_unlink    = nxt_main_port_socket_unlink_handler,
    .modules          = nxt_main_port_modules_handler,
    .conf_store       = nxt_main_port_conf_store_handler,
#if (NXT_TLS)
    .cert_get         = nxt_cert_store_get_handler,
    .cert_delete      = nxt_cert_store_delete_handler,
#endif
#if (NXT_HAVE_NJS)
    .script_get       = nxt_script_store_get_handler,
    .script_delete    = nxt_script_store_delete_handler,
#endif
    .access_log       = nxt_main_port_access_log_handler,
    .rpc_ready        = nxt_port_rpc_handler,
    .rpc_error        = nxt_port_rpc_handler,
};


static void
nxt_main_process_whoami_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_buf_t      *buf;
    nxt_pid_t      pid, ppid;
    nxt_port_t     *port;
    nxt_runtime_t  *rt;
    nxt_process_t  *pprocess;

    nxt_assert(msg->port_msg.reply_port == 0);

    if (nxt_slow_path(msg->buf == NULL
        || nxt_buf_used_size(msg->buf) != sizeof(nxt_pid_t)))
    {
        nxt_alert(task, "whoami: buffer is NULL or unexpected size");
        goto fail;
    }

    nxt_memcpy(&ppid, msg->buf->mem.pos, sizeof(nxt_pid_t));

    rt = task->thread->runtime;

    pprocess = nxt_runtime_process_find(rt, ppid);
    if (nxt_slow_path(pprocess == NULL)) {
        nxt_alert(task, "whoami: parent process %PI not found", ppid);
        goto fail;
    }

    pid = nxt_recv_msg_cmsg_pid(msg);

    nxt_debug(task, "whoami: from %PI, parent %PI, fd %d", pid, ppid,
              msg->fd[0]);

    if (msg->fd[0] != -1) {
        port = nxt_runtime_process_port_create(task, rt, pid, 0,
                                               NXT_PROCESS_APP);
        if (nxt_slow_path(port == NULL)) {
            goto fail;
        }

        nxt_fd_nonblocking(task, msg->fd[0]);

        port->pair[0] = -1;
        port->pair[1] = msg->fd[0];
        msg->fd[0] = -1;

        port->max_size = 16 * 1024;
        port->max_share = 64 * 1024;
        port->socket.task = task;

        nxt_port_write_enable(task, port);

    } else {
        port = nxt_runtime_port_find(rt, pid, 0);
        if (nxt_slow_path(port == NULL)) {
            goto fail;
        }
    }

    if (ppid != nxt_pid) {
        nxt_queue_insert_tail(&pprocess->children, &port->process->link);
    }

    buf = nxt_buf_mem_alloc(task->thread->engine->mem_pool,
                            sizeof(nxt_pid_t), 0);
    if (nxt_slow_path(buf == NULL)) {
        goto fail;
    }

    buf->mem.free = nxt_cpymem(buf->mem.free, &pid, sizeof(nxt_pid_t));

    (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_READY_LAST, -1,
                                 msg->port_msg.stream, 0, buf);

fail:

    if (msg->fd[0] != -1) {
        nxt_fd_close(msg->fd[0]);
    }
}


static nxt_int_t
nxt_main_process_port_create(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_int_t      ret;
    nxt_port_t     *port;
    nxt_process_t  *process;

    port = nxt_runtime_process_port_create(task, rt, nxt_pid, 0,
                                           NXT_PROCESS_MAIN);
    if (nxt_slow_path(port == NULL)) {
        return NXT_ERROR;
    }

    process = port->process;

    ret = nxt_port_socket_init(task, port, 0);
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_use(task, port, -1);
        return ret;
    }

    /*
     * A main process port.  A write port is not closed
     * since it should be inherited by processes.
     */
    nxt_port_enable(task, port, &nxt_main_process_port_handlers);

    process->state = NXT_PROCESS_STATE_READY;

    return NXT_OK;
}


static void
nxt_main_process_title(nxt_task_t *task)
{
    u_char      *p, *end;
    nxt_uint_t  i;
    u_char      title[2048];

    end = title + sizeof(title) - 1;

    p = nxt_sprintf(title, end, "unit: main v" NXT_VERSION " [%s",
                    nxt_process_argv[0]);

    for (i = 1; nxt_process_argv[i] != NULL; i++) {
        p = nxt_sprintf(p, end, " %s", nxt_process_argv[i]);
    }

    if (p < end) {
        *p++ = ']';
    }

    *p = '\0';

    nxt_process_title(task, "%s", title);
}


static void
nxt_main_process_sigterm_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_debug(task, "sigterm handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    /* TODO: fast exit. */

    nxt_exiting = 1;

    nxt_runtime_quit(task, 0);
}


static void
nxt_main_process_sigquit_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_debug(task, "sigquit handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    /* TODO: graceful exit. */

    nxt_exiting = 1;

    nxt_runtime_quit(task, 0);
}


static void
nxt_main_process_sigusr1_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t        *mp;
    nxt_int_t       ret;
    nxt_uint_t      n;
    nxt_port_t      *port;
    nxt_file_t      *file, *new_file;
    nxt_array_t     *new_files;
    nxt_runtime_t   *rt;

    nxt_log(task, NXT_LOG_NOTICE, "signal %d (%s) received, %s",
            (int) (uintptr_t) obj, data, "log files rotation");

    rt = task->thread->runtime;

    port = rt->port_by_type[NXT_PROCESS_ROUTER];

    if (nxt_fast_path(port != NULL)) {
        (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_ACCESS_LOG,
                                     -1, 0, 0, NULL);
    }

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        return;
    }

    n = nxt_list_nelts(rt->log_files);

    new_files = nxt_array_create(mp, n, sizeof(nxt_file_t));
    if (new_files == NULL) {
        nxt_mp_destroy(mp);
        return;
    }

    nxt_list_each(file, rt->log_files) {

        /* This allocation cannot fail. */
        new_file = nxt_array_add(new_files);

        new_file->name = file->name;
        new_file->fd = NXT_FILE_INVALID;
        new_file->log_level = NXT_LOG_ALERT;

        ret = nxt_file_open(task, new_file, O_WRONLY | O_APPEND, O_CREAT,
                            NXT_FILE_OWNER_ACCESS);

        if (ret != NXT_OK) {
            goto fail;
        }

    } nxt_list_loop;

    new_file = new_files->elts;

    ret = nxt_file_stderr(&new_file[0]);

    if (ret == NXT_OK) {
        n = 0;

        nxt_list_each(file, rt->log_files) {

            nxt_port_change_log_file(task, rt, n, new_file[n].fd);
            /*
             * The old log file descriptor must be closed at the moment
             * when no other threads use it.  dup2() allows to use the
             * old file descriptor for new log file.  This change is
             * performed atomically in the kernel.
             */
            (void) nxt_file_redirect(file, new_file[n].fd);

            n++;

        } nxt_list_loop;

        nxt_mp_destroy(mp);
        return;
    }

fail:

    new_file = new_files->elts;
    n = new_files->nelts;

    while (n != 0) {
        if (new_file->fd != NXT_FILE_INVALID) {
            nxt_file_close(task, new_file);
        }

        new_file++;
        n--;
    }

    nxt_mp_destroy(mp);
}


static void
nxt_main_process_sigchld_handler(nxt_task_t *task, void *obj, void *data)
{
    int                 status;
    nxt_int_t           ret;
    nxt_err_t           err;
    nxt_pid_t           pid;
    nxt_port_t          *port;
    nxt_queue_t         children;
    nxt_runtime_t       *rt;
    nxt_process_t       *process, *child;
    nxt_process_init_t  init;

    nxt_debug(task, "sigchld handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

    rt = task->thread->runtime;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == -1) {

            switch (err = nxt_errno) {

            case NXT_ECHILD:
                return;

            case NXT_EINTR:
                continue;

            default:
                nxt_alert(task, "waitpid() failed: %E", err);
                return;
            }
        }

        nxt_debug(task, "waitpid(): %PI", pid);

        if (pid == 0) {
            return;
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            nxt_alert(task, "process %PI exited on signal %d%s",
                      pid, WTERMSIG(status),
                      WCOREDUMP(status) ? " (core dumped)" : "");
#else
            nxt_alert(task, "process %PI exited on signal %d",
                      pid, WTERMSIG(status));
#endif

        } else {
            nxt_trace(task, "process %PI exited with code %d",
                      pid, WEXITSTATUS(status));
        }

        process = nxt_runtime_process_find(rt, pid);

        if (process != NULL) {
            nxt_main_process_cleanup(task, process);

            if (process->state == NXT_PROCESS_STATE_READY) {
                process->stream = 0;
            }

            nxt_queue_init(&children);

            if (!nxt_queue_is_empty(&process->children)) {
                nxt_queue_add(&children, &process->children);

                nxt_queue_init(&process->children);

                nxt_queue_each(child, &children, nxt_process_t, link) {
                    port = nxt_process_port_first(child);

                    (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT,
                                                 -1, 0, 0, NULL);
                } nxt_queue_loop;
            }

            if (nxt_exiting) {
                nxt_process_close_ports(task, process);

                nxt_queue_each(child, &children, nxt_process_t, link) {
                    nxt_queue_remove(&child->link);
                    child->link.next = NULL;

                    nxt_process_close_ports(task, child);
                } nxt_queue_loop;

                if (rt->nprocesses <= 1) {
                    nxt_runtime_quit(task, 0);

                    return;
                }

                continue;
            }

            nxt_port_remove_notify_others(task, process);

            nxt_queue_each(child, &children, nxt_process_t, link) {
                nxt_port_remove_notify_others(task, child);

                nxt_queue_remove(&child->link);
                child->link.next = NULL;

                nxt_process_close_ports(task, child);
            } nxt_queue_loop;

            init = *(nxt_process_init_t *) nxt_process_init(process);

            nxt_process_close_ports(task, process);

            if (init.restart) {
                ret = nxt_process_init_start(task, init);
                if (nxt_slow_path(ret == NXT_ERROR)) {
                    nxt_alert(task, "failed to restart %s", init.name);
                }
            }
        }
    }
}


static void
nxt_main_process_signal_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_trace(task, "signal signo:%d (%s) received, ignored",
              (int) (uintptr_t) obj, data);
}


static void
nxt_main_process_cleanup(nxt_task_t *task, nxt_process_t *process)
{
    if (process->isolation.cleanup != NULL) {
        process->isolation.cleanup(task, process);
    }

    if (process->isolation.cgroup_cleanup != NULL) {
        process->isolation.cgroup_cleanup(task, process);
    }
}


static void
nxt_main_port_socket_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    size_t                  size;
    nxt_int_t               ret;
    nxt_buf_t               *b, *out;
    nxt_port_t              *port;
    nxt_sockaddr_t          *sa;
    nxt_port_msg_type_t     type;
    nxt_listening_socket_t  ls;
    u_char                  message[2048];

    port = nxt_runtime_port_find(task->thread->runtime, msg->port_msg.pid,
                                 msg->port_msg.reply_port);
    if (nxt_slow_path(port == NULL)) {
        return;
    }

    if (nxt_slow_path(port->type != NXT_PROCESS_ROUTER)) {
        nxt_alert(task, "process %PI cannot create listener sockets",
                  msg->port_msg.pid);

        return;
    }

    b = msg->buf;
    sa = (nxt_sockaddr_t *) b->mem.pos;

    /* TODO check b size and make plain */

    ls.socket = -1;
    ls.error = NXT_SOCKET_ERROR_SYSTEM;
    ls.start = message;
    ls.end = message + sizeof(message);

    nxt_debug(task, "listening socket \"%*s\"",
              (size_t) sa->length, nxt_sockaddr_start(sa));

    ret = nxt_main_listening_socket(sa, &ls);

    if (ret == NXT_OK) {
        nxt_debug(task, "socket(\"%*s\"): %d",
                  (size_t) sa->length, nxt_sockaddr_start(sa), ls.socket);

        out = NULL;

        type = NXT_PORT_MSG_RPC_READY_LAST | NXT_PORT_MSG_CLOSE_FD;

    } else {
        size = ls.end - ls.start;

        nxt_alert(task, "%*s", size, ls.start);

        out = nxt_buf_mem_ts_alloc(task, task->thread->engine->mem_pool,
                                   size + 1);
        if (nxt_fast_path(out != NULL)) {
            *out->mem.free++ = (uint8_t) ls.error;

            out->mem.free = nxt_cpymem(out->mem.free, ls.start, size);
        }

        type = NXT_PORT_MSG_RPC_ERROR;
    }

    nxt_port_socket_write(task, port, type, ls.socket, msg->port_msg.stream,
                          0, out);
}


static nxt_int_t
nxt_main_listening_socket(nxt_sockaddr_t *sa, nxt_listening_socket_t *ls)
{
    nxt_err_t         err;
    nxt_socket_t      s;

    const socklen_t   length = sizeof(int);
    static const int  enable = 1;

    s = socket(sa->u.sockaddr.sa_family, sa->type, 0);

    if (nxt_slow_path(s == -1)) {
        err = nxt_errno;

#if (NXT_INET6)

        if (err == EAFNOSUPPORT && sa->u.sockaddr.sa_family == AF_INET6) {
            ls->error = NXT_SOCKET_ERROR_NOINET6;
        }

#endif

        ls->end = nxt_sprintf(ls->start, ls->end,
                              "socket(\\\"%*s\\\") failed %E",
                              (size_t) sa->length, nxt_sockaddr_start(sa), err);

        return NXT_ERROR;
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, length) != 0) {
        ls->end = nxt_sprintf(ls->start, ls->end,
                              "setsockopt(\\\"%*s\\\", SO_REUSEADDR) failed %E",
                              (size_t) sa->length, nxt_sockaddr_start(sa),
                              nxt_errno);
        goto fail;
    }

#if (NXT_INET6)

    if (sa->u.sockaddr.sa_family == AF_INET6) {

        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &enable, length) != 0) {
            ls->end = nxt_sprintf(ls->start, ls->end,
                               "setsockopt(\\\"%*s\\\", IPV6_V6ONLY) failed %E",
                               (size_t) sa->length, nxt_sockaddr_start(sa),
                               nxt_errno);
            goto fail;
        }
    }

#endif

    if (bind(s, &sa->u.sockaddr, sa->socklen) != 0) {
        err = nxt_errno;

#if (NXT_HAVE_UNIX_DOMAIN)

        if (sa->u.sockaddr.sa_family == AF_UNIX) {
            switch (err) {

            case EACCES:
                ls->error = NXT_SOCKET_ERROR_ACCESS;
                break;

            case ENOENT:
            case ENOTDIR:
                ls->error = NXT_SOCKET_ERROR_PATH;
                break;
            }

        } else
#endif
        {
            switch (err) {

            case EACCES:
                ls->error = NXT_SOCKET_ERROR_PORT;
                break;

            case EADDRINUSE:
                ls->error = NXT_SOCKET_ERROR_INUSE;
                break;

            case EADDRNOTAVAIL:
                ls->error = NXT_SOCKET_ERROR_NOADDR;
                break;
            }
        }

        ls->end = nxt_sprintf(ls->start, ls->end, "bind(\\\"%*s\\\") failed %E",
                              (size_t) sa->length, nxt_sockaddr_start(sa), err);
        goto fail;
    }

#if (NXT_HAVE_UNIX_DOMAIN)

    if (sa->u.sockaddr.sa_family == AF_UNIX
        && sa->u.sockaddr_un.sun_path[0] != '\0')
    {
        char          *filename;
        mode_t        access;
        nxt_thread_t  *thr;

        filename = sa->u.sockaddr_un.sun_path;
        access = (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

        if (chmod(filename, access) != 0) {
            ls->end = nxt_sprintf(ls->start, ls->end,
                                  "chmod(\\\"%s\\\") failed %E",
                                  filename, nxt_errno);
            goto fail;
        }

        thr = nxt_thread();
        nxt_runtime_listen_socket_add(thr->runtime, sa);
    }

#endif

    ls->socket = s;

    return NXT_OK;

fail:

    (void) close(s);

    return NXT_ERROR;
}


static void
nxt_main_port_socket_unlink_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
#if (NXT_HAVE_UNIX_DOMAIN)
    size_t               i;
    nxt_buf_t            *b;
    const char           *filename;
    nxt_runtime_t        *rt;
    nxt_sockaddr_t       *sa;
    nxt_listen_socket_t  *ls;

    b = msg->buf;
    sa = (nxt_sockaddr_t *) b->mem.pos;

    filename = sa->u.sockaddr_un.sun_path;
    unlink(filename);

    rt = task->thread->runtime;

    for (i = 0; i < rt->listen_sockets->nelts; i++) {
        const char  *name;

        ls = (nxt_listen_socket_t *) rt->listen_sockets->elts + i;
        sa = ls->sockaddr;

        if (sa->u.sockaddr.sa_family != AF_UNIX
            || sa->u.sockaddr_un.sun_path[0] == '\0')
        {
            continue;
        }

        name = sa->u.sockaddr_un.sun_path;
        if (strcmp(name, filename) != 0) {
            continue;
        }

        nxt_array_remove(rt->listen_sockets, ls);
        break;
    }
#endif
}


static nxt_conf_map_t  nxt_app_lang_module_map[] = {
    {
        nxt_string("type"),
        NXT_CONF_MAP_INT,
        offsetof(nxt_app_lang_module_t, type),
    },

    {
        nxt_string("version"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_app_lang_module_t, version),
    },

    {
        nxt_string("file"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_app_lang_module_t, file),
    },
};


static nxt_conf_map_t  nxt_app_lang_mounts_map[] = {
    {
        nxt_string("src"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_fs_mount_t, src),
    },
    {
        nxt_string("dst"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_fs_mount_t, dst),
    },
    {
        nxt_string("name"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_fs_mount_t, name),
    },
    {
        nxt_string("type"),
        NXT_CONF_MAP_INT,
        offsetof(nxt_fs_mount_t, type),
    },
    {
        nxt_string("flags"),
        NXT_CONF_MAP_INT,
        offsetof(nxt_fs_mount_t, flags),
    },
    {
        nxt_string("data"),
        NXT_CONF_MAP_CSTRZ,
        offsetof(nxt_fs_mount_t, data),
    },
};


static void
nxt_main_port_modules_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    uint32_t               index, jindex, nmounts;
    nxt_mp_t               *mp;
    nxt_int_t              ret;
    nxt_buf_t              *b;
    nxt_port_t             *port;
    nxt_runtime_t          *rt;
    nxt_fs_mount_t         *mnt;
    nxt_conf_value_t       *conf, *root, *value, *mounts;
    nxt_app_lang_module_t  *lang;

    static nxt_str_t root_path = nxt_string("/");
    static nxt_str_t mounts_name = nxt_string("mounts");

    rt = task->thread->runtime;

    if (msg->port_msg.pid != rt->port_by_type[NXT_PROCESS_DISCOVERY]->pid) {
        nxt_alert(task, "process %PI cannot send modules", msg->port_msg.pid);
        return;
    }

    if (nxt_exiting) {
        nxt_debug(task, "ignoring discovered modules, exiting");
        return;
    }

    port = nxt_runtime_port_find(task->thread->runtime, msg->port_msg.pid,
                                 msg->port_msg.reply_port);

    if (nxt_fast_path(port != NULL)) {
        (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_ERROR, -1,
                                     msg->port_msg.stream, 0, NULL);
    }

    b = msg->buf;

    if (b == NULL) {
        return;
    }

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        return;
    }

    b = nxt_buf_chk_make_plain(mp, b, msg->size);

    if (b == NULL) {
        return;
    }

    nxt_debug(task, "application languages: \"%*s\"",
              b->mem.free - b->mem.pos, b->mem.pos);

    conf = nxt_conf_json_parse(mp, b->mem.pos, b->mem.free, NULL);
    if (conf == NULL) {
        goto fail;
    }

    root = nxt_conf_get_path(conf, &root_path);
    if (root == NULL) {
        goto fail;
    }

    for (index = 0; /* void */ ; index++) {
        value = nxt_conf_get_array_element(root, index);
        if (value == NULL) {
            break;
        }

        lang = nxt_array_zero_add(rt->languages);
        if (lang == NULL) {
            goto fail;
        }

        lang->module = NULL;

        ret = nxt_conf_map_object(rt->mem_pool, value, nxt_app_lang_module_map,
                                  nxt_nitems(nxt_app_lang_module_map), lang);

        if (ret != NXT_OK) {
            goto fail;
        }

        mounts = nxt_conf_get_object_member(value, &mounts_name, NULL);
        if (mounts == NULL) {
            nxt_alert(task, "missing mounts from discovery message.");
            goto fail;
        }

        if (nxt_conf_type(mounts) != NXT_CONF_ARRAY) {
            nxt_alert(task, "invalid mounts type from discovery message.");
            goto fail;
        }

        nmounts = nxt_conf_array_elements_count(mounts);

        lang->mounts = nxt_array_create(rt->mem_pool, nmounts,
                                        sizeof(nxt_fs_mount_t));

        if (lang->mounts == NULL) {
            goto fail;
        }

        for (jindex = 0; /* */; jindex++) {
            value = nxt_conf_get_array_element(mounts, jindex);
            if (value == NULL) {
                break;
            }

            mnt = nxt_array_zero_add(lang->mounts);
            if (mnt == NULL) {
                goto fail;
            }

            mnt->builtin = 1;
            mnt->deps = 1;

            ret = nxt_conf_map_object(rt->mem_pool, value,
                                      nxt_app_lang_mounts_map,
                                      nxt_nitems(nxt_app_lang_mounts_map), mnt);

            if (ret != NXT_OK) {
                goto fail;
            }
        }

        nxt_debug(task, "lang %d %s \"%s\" (%d mounts)",
                  lang->type, lang->version, lang->file, lang->mounts->nelts);
    }

    qsort(rt->languages->elts, rt->languages->nelts,
          sizeof(nxt_app_lang_module_t), nxt_app_lang_compare);

fail:

    nxt_mp_destroy(mp);

    ret = nxt_process_init_start(task, nxt_controller_process);
    if (ret == NXT_OK) {
        ret = nxt_process_init_start(task, nxt_router_process);
    }

    if (nxt_slow_path(ret == NXT_ERROR)) {
        nxt_exiting = 1;

        nxt_runtime_quit(task, 1);
    }
}


static int nxt_cdecl
nxt_app_lang_compare(const void *v1, const void *v2)
{
    int                          n;
    const nxt_app_lang_module_t  *lang1, *lang2;

    lang1 = v1;
    lang2 = v2;

    n = lang1->type - lang2->type;

    if (n != 0) {
        return n;
    }

    n = nxt_strverscmp(lang1->version, lang2->version);

    /* Negate result to move higher versions to the beginning. */

    return -n;
}


static void
nxt_main_port_conf_store_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    void           *p;
    size_t         n, size;
    nxt_int_t      ret;
    nxt_port_t     *ctl_port;
    nxt_runtime_t  *rt;
    u_char         ver[NXT_INT_T_LEN];

    rt = task->thread->runtime;

    ctl_port = rt->port_by_type[NXT_PROCESS_CONTROLLER];

    if (nxt_slow_path(msg->port_msg.pid != ctl_port->pid)) {
        nxt_alert(task, "process %PI cannot store conf", msg->port_msg.pid);
        return;
    }

    p = MAP_FAILED;

    /*
     * Ancient compilers like gcc 4.8.5 on CentOS 7 wants 'size' to be
     * initialized in 'cleanup' section.
     */
    size = 0;

    if (nxt_slow_path(msg->fd[0] == -1)) {
        nxt_alert(task, "conf_store_handler: invalid shm fd");
        goto error;
    }

    if (nxt_buf_mem_used_size(&msg->buf->mem) != sizeof(size_t)) {
        nxt_alert(task, "conf_store_handler: unexpected buffer size (%d)",
                  (int) nxt_buf_mem_used_size(&msg->buf->mem));
        goto error;
    }

    nxt_memcpy(&size, msg->buf->mem.pos, sizeof(size_t));

    p = nxt_mem_mmap(NULL, size, PROT_READ, MAP_SHARED, msg->fd[0], 0);

    nxt_fd_close(msg->fd[0]);
    msg->fd[0] = -1;

    if (nxt_slow_path(p == MAP_FAILED)) {
        goto error;
    }

    nxt_debug(task, "conf_store_handler(%uz): %*s", size, size, p);

    if (nxt_conf_ver != NXT_VERNUM) {
        n = nxt_sprintf(ver, ver + NXT_INT_T_LEN, "%d", NXT_VERNUM) - ver;

        ret = nxt_main_file_store(task, rt->ver_tmp, rt->ver, ver, n);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto error;
        }

        nxt_conf_ver = NXT_VERNUM;
    }

    ret = nxt_main_file_store(task, rt->conf_tmp, rt->conf, p, size);

    if (nxt_fast_path(ret == NXT_OK)) {
        goto cleanup;
    }

error:

    nxt_alert(task, "failed to store current configuration");

cleanup:

    if (p != MAP_FAILED) {
        nxt_mem_munmap(p, size);
    }

    if (msg->fd[0] != -1) {
        nxt_fd_close(msg->fd[0]);
        msg->fd[0] = -1;
    }
}


static nxt_int_t
nxt_main_file_store(nxt_task_t *task, const char *tmp_name, const char *name,
    u_char *buf, size_t size)
{
    ssize_t     n;
    nxt_int_t   ret;
    nxt_file_t  file;

    nxt_memzero(&file, sizeof(nxt_file_t));

    file.name = (nxt_file_name_t *) name;

    ret = nxt_file_open(task, &file, NXT_FILE_WRONLY, NXT_FILE_TRUNCATE,
                        NXT_FILE_OWNER_ACCESS);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    n = nxt_file_write(&file, buf, size, 0);

    nxt_file_close(task, &file);

    if (nxt_slow_path(n != (ssize_t) size)) {
        (void) nxt_file_delete(file.name);
        return NXT_ERROR;
    }

    return nxt_file_rename(file.name, (nxt_file_name_t *) name);
}


static void
nxt_main_port_access_log_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    u_char               *path;
    nxt_int_t            ret;
    nxt_file_t           file;
    nxt_port_t           *port;
    nxt_port_msg_type_t  type;

    nxt_debug(task, "opening access log file");

    path = msg->buf->mem.pos;

    nxt_memzero(&file, sizeof(nxt_file_t));

    file.name = (nxt_file_name_t *) path;
    file.log_level = NXT_LOG_ERR;

    ret = nxt_file_open(task, &file, O_WRONLY | O_APPEND, O_CREAT,
                        NXT_FILE_OWNER_ACCESS);

    type = (ret == NXT_OK) ? NXT_PORT_MSG_RPC_READY_LAST | NXT_PORT_MSG_CLOSE_FD
                           : NXT_PORT_MSG_RPC_ERROR;

    port = nxt_runtime_port_find(task->thread->runtime, msg->port_msg.pid,
                                 msg->port_msg.reply_port);

    if (nxt_fast_path(port != NULL)) {
        (void) nxt_port_socket_write(task, port, type, file.fd,
                                     msg->port_msg.stream, 0, NULL);
    }
}
