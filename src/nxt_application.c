
/*
 * Copyright (C) Max Romanov
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_main_process.h>
#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_application.h>
#include <nxt_unit.h>
#include <nxt_port_memory_int.h>
#include <nxt_isolation.h>

#include <glob.h>

#if (NXT_HAVE_PR_SET_NO_NEW_PRIVS)
#include <sys/prctl.h>
#endif


#ifdef WCOREDUMP
#define NXT_WCOREDUMP(s) WCOREDUMP(s)
#else
#define NXT_WCOREDUMP(s) 0
#endif


typedef struct {
    nxt_app_type_t  type;
    nxt_str_t       version;
    nxt_str_t       file;
    nxt_array_t     *mounts;
} nxt_module_t;


static nxt_int_t nxt_discovery_start(nxt_task_t *task,
    nxt_process_data_t *data);
static nxt_buf_t *nxt_discovery_modules(nxt_task_t *task, const char *path);
static nxt_int_t nxt_discovery_module(nxt_task_t *task, nxt_mp_t *mp,
    nxt_array_t *modules, const char *name);
static void nxt_discovery_completion_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_discovery_quit(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data);
static nxt_app_module_t *nxt_app_module_load(nxt_task_t *task,
    const char *name);
static nxt_int_t nxt_proto_setup(nxt_task_t *task, nxt_process_t *process);
static nxt_int_t nxt_proto_start(nxt_task_t *task, nxt_process_data_t *data);
static nxt_int_t nxt_app_setup(nxt_task_t *task, nxt_process_t *process);
static nxt_int_t nxt_app_set_environment(nxt_conf_value_t *environment);
static void nxt_proto_start_process_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_proto_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
static void nxt_proto_process_created_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
static void nxt_proto_quit_children(nxt_task_t *task);
static nxt_process_t *nxt_proto_process_find(nxt_task_t *task, nxt_pid_t pid);
static void nxt_proto_process_add(nxt_task_t *task, nxt_process_t *process);
static nxt_process_t *nxt_proto_process_remove(nxt_task_t *task, nxt_pid_t pid);
static u_char *nxt_cstr_dup(nxt_mp_t *mp, u_char *dst, u_char *src);
static void nxt_proto_signal_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_proto_sigterm_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_proto_sigchld_handler(nxt_task_t *task, void *obj, void *data);


nxt_str_t  nxt_server = nxt_string(NXT_SERVER);


static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};


static nxt_lvlhsh_t           nxt_proto_processes;
static nxt_queue_t            nxt_proto_children;
static nxt_bool_t             nxt_proto_exiting;

static nxt_app_module_t       *nxt_app;
static nxt_common_app_conf_t  *nxt_app_conf;


static const nxt_port_handlers_t  nxt_discovery_process_port_handlers = {
    .quit         = nxt_signal_quit_handler,
    .new_port     = nxt_port_new_port_handler,
    .change_file  = nxt_port_change_log_file_handler,
    .mmap         = nxt_port_mmap_handler,
    .data         = nxt_port_data_handler,
    .remove_pid   = nxt_port_remove_pid_handler,
    .rpc_ready    = nxt_port_rpc_handler,
    .rpc_error    = nxt_port_rpc_handler,
};


const nxt_sig_event_t  nxt_prototype_signals[] = {
    nxt_event_signal(SIGHUP,  nxt_proto_signal_handler),
    nxt_event_signal(SIGINT,  nxt_proto_sigterm_handler),
    nxt_event_signal(SIGQUIT, nxt_proto_sigterm_handler),
    nxt_event_signal(SIGTERM, nxt_proto_sigterm_handler),
    nxt_event_signal(SIGCHLD, nxt_proto_sigchld_handler),
    nxt_event_signal_end,
};


static const nxt_port_handlers_t  nxt_proto_process_port_handlers = {
    .quit            = nxt_proto_quit_handler,
    .change_file     = nxt_port_change_log_file_handler,
    .new_port        = nxt_port_new_port_handler,
    .process_created = nxt_proto_process_created_handler,
    .process_ready   = nxt_port_process_ready_handler,
    .remove_pid      = nxt_port_remove_pid_handler,
    .start_process   = nxt_proto_start_process_handler,
    .rpc_ready       = nxt_port_rpc_handler,
    .rpc_error       = nxt_port_rpc_handler,
};


static const nxt_port_handlers_t  nxt_app_process_port_handlers = {
    .quit         = nxt_signal_quit_handler,
    .rpc_ready    = nxt_port_rpc_handler,
    .rpc_error    = nxt_port_rpc_handler,
};


const nxt_process_init_t  nxt_discovery_process = {
    .name           = "discovery",
    .type           = NXT_PROCESS_DISCOVERY,
    .prefork        = NULL,
    .restart        = 0,
    .setup          = nxt_process_core_setup,
    .start          = nxt_discovery_start,
    .port_handlers  = &nxt_discovery_process_port_handlers,
    .signals        = nxt_process_signals,
};


const nxt_process_init_t  nxt_proto_process = {
    .type           = NXT_PROCESS_PROTOTYPE,
    .prefork        = nxt_isolation_main_prefork,
    .restart        = 0,
    .setup          = nxt_proto_setup,
    .start          = nxt_proto_start,
    .port_handlers  = &nxt_proto_process_port_handlers,
    .signals        = nxt_prototype_signals,
};


const nxt_process_init_t  nxt_app_process = {
    .type           = NXT_PROCESS_APP,
    .setup          = nxt_app_setup,
    .start          = NULL,
    .prefork        = NULL,
    .restart        = 0,
    .port_handlers  = &nxt_app_process_port_handlers,
    .signals        = nxt_process_signals,
};


static nxt_int_t
nxt_discovery_start(nxt_task_t *task, nxt_process_data_t *data)
{
    uint32_t       stream;
    nxt_buf_t      *b;
    nxt_int_t      ret;
    nxt_port_t     *main_port, *discovery_port;
    nxt_runtime_t  *rt;

    nxt_log(task, NXT_LOG_INFO, "discovery started");

    rt = task->thread->runtime;

    b = nxt_discovery_modules(task, rt->modules);
    if (nxt_slow_path(b == NULL)) {
        return NXT_ERROR;
    }

    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    discovery_port = rt->port_by_type[NXT_PROCESS_DISCOVERY];

    stream = nxt_port_rpc_register_handler(task, discovery_port,
                                           nxt_discovery_quit,
                                           nxt_discovery_quit,
                                           main_port->pid, NULL);

    if (nxt_slow_path(stream == 0)) {
        return NXT_ERROR;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_MODULES, -1,
                                stream, discovery_port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, discovery_port, stream);
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_buf_t *
nxt_discovery_modules(nxt_task_t *task, const char *path)
{
    char            *name;
    u_char          *p, *end;
    size_t          size;
    glob_t          glb;
    nxt_mp_t        *mp;
    nxt_buf_t       *b;
    nxt_int_t       ret;
    nxt_uint_t      i, n, j;
    nxt_array_t     *modules, *mounts;
    nxt_module_t    *module;
    nxt_fs_mount_t  *mnt;

    b = NULL;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        return b;
    }

    ret = glob(path, 0, NULL, &glb);

    n = glb.gl_pathc;

    if (ret != 0) {
        nxt_log(task, NXT_LOG_NOTICE,
                "no modules matching: \"%s\" found", path);
        n = 0;
    }

    modules = nxt_array_create(mp, n, sizeof(nxt_module_t));
    if (modules == NULL) {
        goto fail;
    }

    for (i = 0; i < n; i++) {
        name = glb.gl_pathv[i];

        ret = nxt_discovery_module(task, mp, modules, name);
        if (ret != NXT_OK) {
            goto fail;
        }
    }

    size = nxt_length("[]");
    module = modules->elts;
    n = modules->nelts;

    for (i = 0; i < n; i++) {
        nxt_debug(task, "module: %d %V %V",
                  module[i].type, &module[i].version, &module[i].file);

        size += nxt_length("{\"type\": ,");
        size += nxt_length(" \"version\": \"\",");
        size += nxt_length(" \"file\": \"\",");
        size += nxt_length(" \"mounts\": []},");

        size += NXT_INT_T_LEN
                + module[i].version.length
                + module[i].file.length;

        mounts = module[i].mounts;

        size += mounts->nelts * nxt_length("{\"src\": \"\", \"dst\": \"\", "
                                            "\"type\": , \"name\": \"\", "
                                            "\"flags\": , \"data\": \"\"},");

        mnt = mounts->elts;

        for (j = 0; j < mounts->nelts; j++) {
            size += nxt_strlen(mnt[j].src) + nxt_strlen(mnt[j].dst)
                    + nxt_strlen(mnt[j].name) + (2 * NXT_INT_T_LEN)
                    + (mnt[j].data == NULL ? 0 : nxt_strlen(mnt[j].data));
        }
    }

    b = nxt_buf_mem_alloc(mp, size, 0);
    if (b == NULL) {
        goto fail;
    }

    b->completion_handler = nxt_discovery_completion_handler;

    p = b->mem.free;
    end = b->mem.end;
    *p++ = '[';

    for (i = 0; i < n; i++) {
        mounts = module[i].mounts;

        p = nxt_sprintf(p, end, "{\"type\": %d, \"version\": \"%V\", "
                        "\"file\": \"%V\", \"mounts\": [",
                        module[i].type, &module[i].version, &module[i].file);

        mnt = mounts->elts;
        for (j = 0; j < mounts->nelts; j++) {
            p = nxt_sprintf(p, end,
                            "{\"src\": \"%s\", \"dst\": \"%s\", "
                            "\"name\": \"%s\", \"type\": %d, \"flags\": %d, "
                            "\"data\": \"%s\"},",
                            mnt[j].src, mnt[j].dst, mnt[j].name, mnt[j].type,
                            mnt[j].flags,
                            mnt[j].data == NULL ? (u_char *) "" : mnt[j].data);
        }

        *p++ = ']';
        *p++ = '}';
        *p++ = ',';
    }

    *p++ = ']';

    if (nxt_slow_path(p > end)) {
        nxt_alert(task, "discovery write past the buffer");
        goto fail;
    }

    b->mem.free = p;

fail:

    globfree(&glb);

    return b;
}


static nxt_int_t
nxt_discovery_module(nxt_task_t *task, nxt_mp_t *mp, nxt_array_t *modules,
    const char *name)
{
    void                  *dl;
    nxt_str_t             version;
    nxt_int_t             ret;
    nxt_uint_t            i, j, n;
    nxt_array_t           *mounts;
    nxt_module_t          *module;
    nxt_app_type_t        type;
    nxt_fs_mount_t        *to;
    nxt_app_module_t      *app;
    const nxt_fs_mount_t  *from;

    /*
     * Only memory allocation failure should return NXT_ERROR.
     * Any module processing errors are ignored.
     */
    ret = NXT_ERROR;

    dl = dlopen(name, RTLD_GLOBAL | RTLD_NOW);

    if (dl == NULL) {
        nxt_alert(task, "dlopen(\"%s\"), failed: \"%s\"", name, dlerror());
        return NXT_OK;
    }

    app = dlsym(dl, "nxt_app_module");

    if (app != NULL) {
        nxt_log(task, NXT_LOG_NOTICE, "module: %V %s \"%s\"",
                &app->type, app->version, name);

        if (app->compat_length != sizeof(compat)
            || memcmp(app->compat, compat, sizeof(compat)) != 0)
        {
            nxt_log(task, NXT_LOG_NOTICE, "incompatible module %s", name);

            goto done;
        }

        type = nxt_app_parse_type(app->type.start, app->type.length);

        if (type == NXT_APP_UNKNOWN) {
            nxt_log(task, NXT_LOG_NOTICE, "unknown module type %V", &app->type);

            goto done;
        }

        module = modules->elts;
        n = modules->nelts;

        version.start = (u_char *) app->version;
        version.length = nxt_strlen(app->version);

        for (i = 0; i < n; i++) {
            if (type == module[i].type
                && nxt_strstr_eq(&module[i].version, &version))
            {
                nxt_log(task, NXT_LOG_NOTICE,
                        "ignoring %s module with the same "
                        "application language version %V %V as in %V",
                        name, &app->type, &version, &module[i].file);

                goto done;
            }
        }

        module = nxt_array_add(modules);
        if (module == NULL) {
            goto fail;
        }

        module->type = type;

        nxt_str_dup(mp, &module->version, &version);
        if (module->version.start == NULL) {
            goto fail;
        }

        module->file.length = nxt_strlen(name);

        module->file.start = nxt_mp_alloc(mp, module->file.length);
        if (module->file.start == NULL) {
            goto fail;
        }

        nxt_memcpy(module->file.start, name, module->file.length);

        module->mounts = nxt_array_create(mp, app->nmounts,
                                          sizeof(nxt_fs_mount_t));

        if (nxt_slow_path(module->mounts == NULL)) {
            goto fail;
        }

        mounts = module->mounts;

        for (j = 0; j < app->nmounts; j++) {
            from = &app->mounts[j];
            to = nxt_array_zero_add(mounts);
            if (nxt_slow_path(to == NULL)) {
                goto fail;
            }

            to->src = nxt_cstr_dup(mp, to->src, from->src);
            if (nxt_slow_path(to->src == NULL)) {
                goto fail;
            }

            to->dst = nxt_cstr_dup(mp, to->dst, from->dst);
            if (nxt_slow_path(to->dst == NULL)) {
                goto fail;
            }

            to->name = nxt_cstr_dup(mp, to->name, from->name);
            if (nxt_slow_path(to->name == NULL)) {
                goto fail;
            }

            to->type = from->type;

            if (from->data != NULL) {
                to->data = nxt_cstr_dup(mp, to->data, from->data);
                if (nxt_slow_path(to->data == NULL)) {
                    goto fail;
                }
            }

            to->flags = from->flags;
        }

    } else {
        nxt_alert(task, "dlsym(\"%s\"), failed: \"%s\"", name, dlerror());
    }

done:

    ret = NXT_OK;

fail:

    if (dlclose(dl) != 0) {
        nxt_alert(task, "dlclose(\"%s\"), failed: \"%s\"", name, dlerror());
    }

    return ret;
}


static void
nxt_discovery_completion_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t   *mp;
    nxt_buf_t  *b;

    b = obj;
    mp = b->data;

    nxt_mp_destroy(mp);
}


static void
nxt_discovery_quit(nxt_task_t *task, nxt_port_recv_msg_t *msg, void *data)
{
    nxt_signal_quit_handler(task, msg);
}


static nxt_int_t
nxt_proto_setup(nxt_task_t *task, nxt_process_t *process)
{
    nxt_int_t              ret;
    nxt_app_lang_module_t  *lang;
    nxt_common_app_conf_t  *app_conf;

    app_conf = process->data.app;

    nxt_queue_init(&nxt_proto_children);

    nxt_app_conf = app_conf;

    lang = nxt_app_lang_module(task->thread->runtime, &app_conf->type);
    if (nxt_slow_path(lang == NULL)) {
        nxt_alert(task, "unknown application type: \"%V\"", &app_conf->type);
        return NXT_ERROR;
    }

    nxt_app = lang->module;

    if (nxt_app == NULL) {
        nxt_debug(task, "application language module: %s \"%s\"",
                  lang->version, lang->file);

        nxt_app = nxt_app_module_load(task, lang->file);
        if (nxt_slow_path(nxt_app == NULL)) {
            return NXT_ERROR;
        }
    }

    if (nxt_slow_path(nxt_app_set_environment(app_conf->environment)
                      != NXT_OK))
    {
        nxt_alert(task, "failed to set environment");
        return NXT_ERROR;
    }

    if (nxt_app->setup != NULL) {
        ret = nxt_app->setup(task, process, app_conf);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }
    }

#if (NXT_HAVE_ISOLATION_ROOTFS)
    if (process->isolation.rootfs != NULL) {
        if (process->isolation.mounts != NULL) {
            ret = nxt_isolation_prepare_rootfs(task, process);
            if (nxt_slow_path(ret != NXT_OK)) {
                return ret;
            }
        }

        ret = nxt_isolation_change_root(task, process);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }
#endif

    if (app_conf->working_directory != NULL
        && app_conf->working_directory[0] != 0)
    {
        ret = chdir(app_conf->working_directory);

        if (nxt_slow_path(ret != 0)) {
            nxt_log(task, NXT_LOG_WARN, "chdir(%s) failed %E",
                    app_conf->working_directory, nxt_errno);

            return NXT_ERROR;
        }
    }

    process->state = NXT_PROCESS_STATE_CREATED;

    return NXT_OK;
}


static nxt_int_t
nxt_proto_start(nxt_task_t *task, nxt_process_data_t *data)
{
    nxt_debug(task, "prototype waiting for clone messages");

    return NXT_OK;
}


static void
nxt_proto_start_process_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    u_char              *p;
    nxt_int_t           ret;
    nxt_port_t          *port;
    nxt_runtime_t       *rt;
    nxt_process_t       *process;
    nxt_process_init_t  *init;

    rt = task->thread->runtime;

    process = nxt_process_new(rt);
    if (nxt_slow_path(process == NULL)) {
        goto failed;
    }

    process->mem_pool = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(process->mem_pool == NULL)) {
        nxt_process_use(task, process, -1);
        goto failed;
    }

    process->parent_port = rt->port_by_type[NXT_PROCESS_PROTOTYPE];

    init = nxt_process_init(process);
    *init = nxt_app_process;

    process->name = nxt_mp_alloc(process->mem_pool, nxt_app_conf->name.length
                                 + sizeof("\"\" application") + 1);

    if (nxt_slow_path(process->name == NULL)) {
        nxt_process_use(task, process, -1);

        goto failed;
    }

    init->start = nxt_app->start;

    init->name = (const char *) nxt_app_conf->name.start;

    p = (u_char *) process->name;
    *p++ = '"';
    p = nxt_cpymem(p, nxt_app_conf->name.start, nxt_app_conf->name.length);
    p = nxt_cpymem(p, "\" application", 13);
    *p = '\0';

    process->user_cred = &rt->user_cred;

    process->data.app = nxt_app_conf;
    process->stream = msg->port_msg.stream;

    init->siblings = &nxt_proto_children;

    ret = nxt_process_start(task, process);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        nxt_process_use(task, process, -1);

        goto failed;
    }

    nxt_proto_process_add(task, process);

    return;

failed:

    port = nxt_runtime_port_find(rt, msg->port_msg.pid,
                                 msg->port_msg.reply_port);

    if (nxt_fast_path(port != NULL)) {
        nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_ERROR,
                              -1, msg->port_msg.stream, 0, NULL);
    }
}


static void
nxt_proto_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_debug(task, "prototype quit handler");

    nxt_proto_quit_children(task);

    nxt_proto_exiting = 1;

    if (nxt_queue_is_empty(&nxt_proto_children)) {
        nxt_process_quit(task, 0);
    }
}


static void
nxt_proto_quit_children(nxt_task_t *task)
{
    nxt_port_t     *port;
    nxt_process_t  *process;

    nxt_queue_each(process, &nxt_proto_children, nxt_process_t, link) {
        port = nxt_process_port_first(process);

        (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_QUIT,
                                     -1, 0, 0, NULL);
    }
    nxt_queue_loop;
}


static void
nxt_proto_process_created_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_pid_t      isolated_pid, pid;
    nxt_process_t  *process;

    isolated_pid = nxt_recv_msg_cmsg_pid(msg);

    process = nxt_proto_process_find(task, isolated_pid);
    if (nxt_slow_path(process == NULL)) {
        return;
    }

    process->state = NXT_PROCESS_STATE_CREATED;

    pid = msg->port_msg.pid;

    if (process->pid != pid) {
        nxt_debug(task, "app process %PI (aka %PI) is created", isolated_pid,
                  pid);

        process->pid = pid;

    } else {
        nxt_debug(task, "app process %PI is created", isolated_pid);
    }

    if (!process->registered) {
        nxt_assert(!nxt_queue_is_empty(&process->ports));

        nxt_runtime_process_add(task, process);

        nxt_port_use(task, nxt_process_port_first(process), -1);
    }
}


static void
nxt_proto_signal_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_trace(task, "signal signo:%d (%s) received, ignored",
              (int) (uintptr_t) obj, data);
}


static void
nxt_proto_sigterm_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_trace(task, "signal signo:%d (%s) received",
              (int) (uintptr_t) obj, data);

    nxt_proto_quit_children(task);

    nxt_proto_exiting = 1;

    if (nxt_queue_is_empty(&nxt_proto_children)) {
        nxt_process_quit(task, 0);
    }
}


static void
nxt_proto_sigchld_handler(nxt_task_t *task, void *obj, void *data)
{
    int            status;
    nxt_err_t      err;
    nxt_pid_t      pid;
    nxt_port_t     *port;
    nxt_process_t  *process;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    nxt_debug(task, "proto sigchld handler signo:%d (%s)",
              (int) (uintptr_t) obj, data);

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

        process = nxt_proto_process_remove(task, pid);

        if (WTERMSIG(status)) {
            if (rt->is_pid_isolated) {
                nxt_alert(task, "app process %PI (isolated %PI) "
                                "exited on signal %d%s",
                          process != NULL ? process->pid : 0,
                          pid, WTERMSIG(status),
                          NXT_WCOREDUMP(status) ? " (core dumped)" : "");

            } else {
                nxt_alert(task, "app process %PI exited on signal %d%s",
                          pid, WTERMSIG(status),
                          NXT_WCOREDUMP(status) ? " (core dumped)" : "");
            }

        } else {
            if (rt->is_pid_isolated) {
                nxt_trace(task, "app process %PI (isolated %PI) "
                                "exited with code %d",
                          process != NULL ? process->pid : 0,
                          pid, WEXITSTATUS(status));

            } else {
                nxt_trace(task, "app process %PI exited with code %d",
                          pid, WEXITSTATUS(status));
            }
        }

        if (process == NULL) {
            continue;
        }

        if (process->registered) {
            port = NULL;

        } else {
            nxt_assert(!nxt_queue_is_empty(&process->ports));

            port = nxt_process_port_first(process);
        }

        if (process->state != NXT_PROCESS_STATE_CREATING) {
            nxt_port_remove_notify_others(task, process);
        }

        nxt_process_close_ports(task, process);

        if (port != NULL) {
            nxt_port_use(task, port, -1);
        }

        if (nxt_proto_exiting && nxt_queue_is_empty(&nxt_proto_children)) {
            nxt_process_quit(task, 0);
            return;
        }
    }
}


static nxt_app_module_t *
nxt_app_module_load(nxt_task_t *task, const char *name)
{
    char              *err;
    void              *dl;
    nxt_app_module_t  *app;

    dl = dlopen(name, RTLD_GLOBAL | RTLD_LAZY);

    if (nxt_slow_path(dl == NULL)) {
        err = dlerror();
        nxt_alert(task, "dlopen(\"%s\") failed: \"%s\"",
                  name, err != NULL ? err : "(null)");
        return NULL;
    }

    app = dlsym(dl, "nxt_app_module");

    if (nxt_slow_path(app == NULL)) {
        err = dlerror();
        nxt_alert(task, "dlsym(\"%s\", \"nxt_app_module\") failed: \"%s\"",
                  name, err != NULL ? err : "(null)");

        if (dlclose(dl) != 0) {
            err = dlerror();
            nxt_alert(task, "dlclose(\"%s\") failed: \"%s\"",
                      name, err != NULL ? err : "(null)");
        }
    }

    return app;
}


static nxt_int_t
nxt_app_set_environment(nxt_conf_value_t *environment)
{
    char              *env, *p;
    uint32_t          next;
    nxt_str_t         name, value;
    nxt_conf_value_t  *value_obj;

    if (environment != NULL) {
        next = 0;

        for ( ;; ) {
            value_obj = nxt_conf_next_object_member(environment, &name, &next);
            if (value_obj == NULL) {
                break;
            }

            nxt_conf_get_string(value_obj, &value);

            env = nxt_malloc(name.length + value.length + 2);
            if (nxt_slow_path(env == NULL)) {
                return NXT_ERROR;
            }

            p = nxt_cpymem(env, name.start, name.length);
            *p++ = '=';
            p = nxt_cpymem(p, value.start, value.length);
            *p = '\0';

            if (nxt_slow_path(putenv(env) != 0)) {
                return NXT_ERROR;
            }
        }
    }

    return NXT_OK;
}


nxt_int_t
nxt_app_set_logs(void)
{
    nxt_int_t              ret;
    nxt_file_t             file;
    nxt_task_t             *task;
    nxt_thread_t           *thr;
    nxt_process_t          *process;
    nxt_runtime_t          *rt;
    nxt_common_app_conf_t  *app_conf;

    thr = nxt_thread();

    task = thr->task;

    rt = task->thread->runtime;
    if (!rt->daemon) {
        return NXT_OK;
    }

    process = rt->port_by_type[NXT_PROCESS_PROTOTYPE]->process;
    app_conf = process->data.app;

    if (app_conf->stdout_log != NULL) {
        nxt_memzero(&file, sizeof(nxt_file_t));
        file.log_level = 1;
        file.name = (u_char *) app_conf->stdout_log;
        ret = nxt_file_open(task, &file, O_WRONLY | O_APPEND, O_CREAT, 0666);
        if (ret == NXT_ERROR) {
            return NXT_ERROR;
        }

        nxt_file_stdout(&file);
        nxt_file_close(task, &file);
    }

    if (app_conf->stderr_log != NULL) {
        nxt_memzero(&file, sizeof(nxt_file_t));
        file.log_level = 1;
        file.name = (u_char *) app_conf->stderr_log;
        ret = nxt_file_open(task, &file, O_WRONLY | O_APPEND, O_CREAT, 0666);
        if (ret == NXT_ERROR) {
            return NXT_ERROR;
        }

        nxt_file_stderr(&file);
        nxt_file_close(task, &file);
    }

    return NXT_OK;
}


static u_char *
nxt_cstr_dup(nxt_mp_t *mp, u_char *dst, u_char *src)
{
    u_char  *p;
    size_t  len;

    len = nxt_strlen(src);

    if (dst == NULL) {
        dst = nxt_mp_alloc(mp, len + 1);
        if (nxt_slow_path(dst == NULL)) {
            return NULL;
        }
    }

    p = nxt_cpymem(dst, src, len);
    *p = '\0';

    return dst;
}


static nxt_int_t
nxt_app_setup(nxt_task_t *task, nxt_process_t *process)
{
    nxt_process_init_t  *init;

    process->state = NXT_PROCESS_STATE_CREATED;

    init = nxt_process_init(process);

    return init->start(task, &process->data);
}


nxt_app_lang_module_t *
nxt_app_lang_module(nxt_runtime_t *rt, nxt_str_t *name)
{
    u_char                 *p, *end, *version;
    size_t                 version_length;
    nxt_uint_t             i, n;
    nxt_app_type_t         type;
    nxt_app_lang_module_t  *lang;

    end = name->start + name->length;
    version = end;

    for (p = name->start; p < end; p++) {
        if (*p == ' ') {
            version = p + 1;
            break;
        }

        if (*p >= '0' && *p <= '9') {
            version = p;
            break;
        }
    }

    type = nxt_app_parse_type(name->start, p - name->start);

    if (type == NXT_APP_UNKNOWN) {
        return NULL;
    }

    version_length = end - version;

    lang = rt->languages->elts;
    n = rt->languages->nelts;

    for (i = 0; i < n; i++) {

        /*
         * Versions are sorted in descending order
         * so first match chooses the highest version.
         */

        if (lang[i].type == type
            && nxt_strvers_match(lang[i].version, version, version_length))
        {
            return &lang[i];
        }
    }

    return NULL;
}


nxt_app_type_t
nxt_app_parse_type(u_char *p, size_t length)
{
    nxt_str_t str;

    str.length = length;
    str.start = p;

    if (nxt_str_eq(&str, "external", 8) || nxt_str_eq(&str, "go", 2)) {
        return NXT_APP_EXTERNAL;

    } else if (nxt_str_eq(&str, "python", 6)) {
        return NXT_APP_PYTHON;

    } else if (nxt_str_eq(&str, "php", 3)) {
        return NXT_APP_PHP;

    } else if (nxt_str_eq(&str, "perl", 4)) {
        return NXT_APP_PERL;

    } else if (nxt_str_eq(&str, "ruby", 4)) {
        return NXT_APP_RUBY;

    } else if (nxt_str_eq(&str, "java", 4)) {
        return NXT_APP_JAVA;

    } else if (nxt_str_eq(&str, "wasm-wasi-component", 19)) {
        return NXT_APP_WASM_WC;

    } else if (nxt_str_eq(&str, "wasm", 4)) {
        return NXT_APP_WASM;
    }

    return NXT_APP_UNKNOWN;
}


nxt_int_t
nxt_unit_default_init(nxt_task_t *task, nxt_unit_init_t *init,
    nxt_common_app_conf_t *conf)
{
    nxt_port_t     *my_port, *proto_port, *router_port;
    nxt_runtime_t  *rt;

    nxt_memzero(init, sizeof(nxt_unit_init_t));

    rt = task->thread->runtime;

    proto_port = rt->port_by_type[NXT_PROCESS_PROTOTYPE];
    if (nxt_slow_path(proto_port == NULL)) {
        return NXT_ERROR;
    }

    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];
    if (nxt_slow_path(router_port == NULL)) {
        return NXT_ERROR;
    }

    my_port = nxt_runtime_port_find(rt, nxt_pid, 0);
    if (nxt_slow_path(my_port == NULL)) {
        return NXT_ERROR;
    }

    init->ready_port.id.pid = proto_port->pid;
    init->ready_port.id.id = proto_port->id;
    init->ready_port.in_fd = -1;
    init->ready_port.out_fd = proto_port->pair[1];

    init->ready_stream = my_port->process->stream;

    init->router_port.id.pid = router_port->pid;
    init->router_port.id.id = router_port->id;
    init->router_port.in_fd = -1;
    init->router_port.out_fd = router_port->pair[1];

    init->read_port.id.pid = my_port->pid;
    init->read_port.id.id = my_port->id;
    init->read_port.in_fd = my_port->pair[0];
    init->read_port.out_fd = my_port->pair[1];

    init->shared_port_fd = conf->shared_port_fd;
    init->shared_queue_fd = conf->shared_queue_fd;

    init->log_fd = 2;

    init->shm_limit = conf->shm_limit;
    init->request_limit = conf->request_limit;

    return NXT_OK;
}


static nxt_int_t
nxt_proto_lvlhsh_isolated_pid_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_pid_t      *qpid;
    nxt_process_t  *process;

    process = data;
    qpid = (nxt_pid_t *) lhq->key.start;

    if (*qpid == process->isolated_pid) {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


static const nxt_lvlhsh_proto_t  lvlhsh_processes_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_proto_lvlhsh_isolated_pid_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


nxt_inline void
nxt_proto_process_lhq_pid(nxt_lvlhsh_query_t *lhq, nxt_pid_t *pid)
{
    lhq->key_hash = nxt_murmur_hash2(pid, sizeof(nxt_pid_t));
    lhq->key.length = sizeof(nxt_pid_t);
    lhq->key.start = (u_char *) pid;
    lhq->proto = &lvlhsh_processes_proto;
}


static void
nxt_proto_process_add(nxt_task_t *task, nxt_process_t *process)
{
    nxt_runtime_t       *rt;
    nxt_lvlhsh_query_t  lhq;

    rt = task->thread->runtime;

    nxt_proto_process_lhq_pid(&lhq, &process->isolated_pid);

    lhq.replace = 0;
    lhq.value = process;
    lhq.pool = rt->mem_pool;

    switch (nxt_lvlhsh_insert(&nxt_proto_processes, &lhq)) {

    case NXT_OK:
        nxt_debug(task, "process (isolated %PI) added", process->isolated_pid);

        nxt_queue_insert_tail(&nxt_proto_children, &process->link);
        break;

    default:
        nxt_alert(task, "process (isolated %PI) failed to add",
                  process->isolated_pid);
        break;
    }
}


static nxt_process_t *
nxt_proto_process_remove(nxt_task_t *task, nxt_pid_t pid)
{
    nxt_runtime_t       *rt;
    nxt_process_t       *process;
    nxt_lvlhsh_query_t  lhq;

    nxt_proto_process_lhq_pid(&lhq, &pid);

    rt = task->thread->runtime;

    lhq.pool = rt->mem_pool;

    switch (nxt_lvlhsh_delete(&nxt_proto_processes, &lhq)) {

    case NXT_OK:
        nxt_debug(task, "process (isolated %PI) removed", pid);

        process = lhq.value;

        nxt_queue_remove(&process->link);
        process->link.next = NULL;

        break;

    default:
        nxt_debug(task, "process (isolated %PI) remove failed", pid);
        process = NULL;
        break;
    }

    return process;
}


static nxt_process_t *
nxt_proto_process_find(nxt_task_t *task, nxt_pid_t pid)
{
    nxt_process_t       *process;
    nxt_lvlhsh_query_t  lhq;

    nxt_proto_process_lhq_pid(&lhq, &pid);

    if (nxt_lvlhsh_find(&nxt_proto_processes, &lhq) == NXT_OK) {
        process = lhq.value;

    } else {
        nxt_debug(task, "process (isolated %PI) not found", pid);

        process = NULL;
    }

    return process;
}
