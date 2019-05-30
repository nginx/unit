
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_port.h>
#include <nxt_main_process.h>
#include <nxt_router.h>


static nxt_int_t nxt_runtime_inherited_listen_sockets(nxt_task_t *task,
    nxt_runtime_t *rt);
static nxt_int_t nxt_runtime_systemd_listen_sockets(nxt_task_t *task,
    nxt_runtime_t *rt);
static nxt_int_t nxt_runtime_event_engines(nxt_task_t *task, nxt_runtime_t *rt);
static nxt_int_t nxt_runtime_thread_pools(nxt_thread_t *thr, nxt_runtime_t *rt);
static void nxt_runtime_start(nxt_task_t *task, void *obj, void *data);
static void nxt_runtime_initial_start(nxt_task_t *task, nxt_uint_t status);
static void nxt_runtime_close_idle_connections(nxt_event_engine_t *engine);
static void nxt_runtime_exit(nxt_task_t *task, void *obj, void *data);
static nxt_int_t nxt_runtime_event_engine_change(nxt_task_t *task,
    nxt_runtime_t *rt);
static nxt_int_t nxt_runtime_conf_init(nxt_task_t *task, nxt_runtime_t *rt);
static nxt_int_t nxt_runtime_conf_read_cmd(nxt_task_t *task, nxt_runtime_t *rt);
static nxt_int_t nxt_runtime_hostname(nxt_task_t *task, nxt_runtime_t *rt);
static nxt_int_t nxt_runtime_log_files_init(nxt_runtime_t *rt);
static nxt_int_t nxt_runtime_log_files_create(nxt_task_t *task,
    nxt_runtime_t *rt);
static nxt_int_t nxt_runtime_pid_file_create(nxt_task_t *task,
    nxt_file_name_t *pid_file);
static void nxt_runtime_thread_pool_destroy(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_runtime_cont_t cont);
static void nxt_runtime_thread_pool_init(void);
static void nxt_runtime_thread_pool_exit(nxt_task_t *task, void *obj,
    void *data);
static void nxt_runtime_process_destroy(nxt_runtime_t *rt,
    nxt_process_t *process);
static nxt_process_t *nxt_runtime_process_remove_pid(nxt_runtime_t *rt,
    nxt_pid_t pid);


nxt_int_t
nxt_runtime_create(nxt_task_t *task)
{
    nxt_mp_t               *mp;
    nxt_int_t              ret;
    nxt_array_t            *listen_sockets;
    nxt_runtime_t          *rt;
    nxt_app_lang_module_t  *lang;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(mp == NULL)) {
        return NXT_ERROR;
    }

    rt = nxt_mp_zget(mp, sizeof(nxt_runtime_t));
    if (nxt_slow_path(rt == NULL)) {
        goto fail;
    }

    task->thread->runtime = rt;
    rt->mem_pool = mp;

    nxt_thread_mutex_create(&rt->processes_mutex);

    rt->services = nxt_services_init(mp);
    if (nxt_slow_path(rt->services == NULL)) {
        goto fail;
    }

    rt->languages = nxt_array_create(mp, 1, sizeof(nxt_app_lang_module_t));
    if (nxt_slow_path(rt->languages == NULL)) {
        goto fail;
    }

    /* Should not fail. */
    lang = nxt_array_add(rt->languages);
    lang->type = NXT_APP_EXTERNAL;
    lang->version = (u_char *) "";
    lang->file = NULL;
    lang->module = &nxt_external_module;

    listen_sockets = nxt_array_create(mp, 1, sizeof(nxt_listen_socket_t));
    if (nxt_slow_path(listen_sockets == NULL)) {
        goto fail;
    }

    rt->listen_sockets = listen_sockets;

    ret = nxt_runtime_inherited_listen_sockets(task, rt);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    if (nxt_runtime_hostname(task, rt) != NXT_OK) {
        goto fail;
    }

    if (nxt_slow_path(nxt_runtime_log_files_init(rt) != NXT_OK)) {
        goto fail;
    }

    if (nxt_runtime_event_engines(task, rt) != NXT_OK) {
        goto fail;
    }

    if (nxt_slow_path(nxt_runtime_thread_pools(task->thread, rt) != NXT_OK)) {
        goto fail;
    }

    rt->start = nxt_runtime_initial_start;

    if (nxt_runtime_conf_init(task, rt) != NXT_OK) {
        goto fail;
    }

    nxt_work_queue_add(&task->thread->engine->fast_work_queue,
                       nxt_runtime_start, task, rt, NULL);

    return NXT_OK;

fail:

    nxt_mp_destroy(mp);

    return NXT_ERROR;
}


static nxt_int_t
nxt_runtime_inherited_listen_sockets(nxt_task_t *task, nxt_runtime_t *rt)
{
    u_char               *v, *p;
    nxt_int_t            type;
    nxt_array_t          *inherited_sockets;
    nxt_socket_t         s;
    nxt_listen_socket_t  *ls;

    v = (u_char *) getenv("NGINX");

    if (v == NULL) {
        return nxt_runtime_systemd_listen_sockets(task, rt);
    }

    nxt_alert(task, "using inherited listen sockets: %s", v);

    inherited_sockets = nxt_array_create(rt->mem_pool,
                                         1, sizeof(nxt_listen_socket_t));
    if (inherited_sockets == NULL) {
        return NXT_ERROR;
    }

    rt->inherited_sockets = inherited_sockets;

    for (p = v; *p != '\0'; p++) {

        if (*p == ';') {
            s = nxt_int_parse(v, p - v);

            if (nxt_slow_path(s < 0)) {
                nxt_alert(task, "invalid socket number \"%s\" "
                          "in NGINX environment variable, "
                          "ignoring the rest of the variable", v);
                return NXT_ERROR;
            }

            v = p + 1;

            ls = nxt_array_zero_add(inherited_sockets);
            if (nxt_slow_path(ls == NULL)) {
                return NXT_ERROR;
            }

            ls->socket = s;

            ls->sockaddr = nxt_getsockname(task, rt->mem_pool, s);
            if (nxt_slow_path(ls->sockaddr == NULL)) {
                return NXT_ERROR;
            }

            type = nxt_socket_getsockopt(task, s, SOL_SOCKET, SO_TYPE);
            if (nxt_slow_path(type == -1)) {
                return NXT_ERROR;
            }

            ls->sockaddr->type = (uint16_t) type;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_runtime_systemd_listen_sockets(nxt_task_t *task, nxt_runtime_t *rt)
{
    u_char               *nfd, *pid;
    nxt_int_t            n;
    nxt_array_t          *inherited_sockets;
    nxt_socket_t         s;
    nxt_listen_socket_t  *ls;

    /*
     * Number of listening sockets passed.  The socket
     * descriptors start from number 3 and are sequential.
     */
    nfd = (u_char *) getenv("LISTEN_FDS");
    if (nfd == NULL) {
        return NXT_OK;
    }

    /* The pid of the service process. */
    pid = (u_char *) getenv("LISTEN_PID");
    if (pid == NULL) {
        return NXT_OK;
    }

    n = nxt_int_parse(nfd, nxt_strlen(nfd));
    if (n < 0) {
        return NXT_OK;
    }

    if (nxt_pid != nxt_int_parse(pid, nxt_strlen(pid))) {
        return NXT_OK;
    }

    nxt_log(task, NXT_LOG_INFO, "using %i systemd listen sockets", n);

    inherited_sockets = nxt_array_create(rt->mem_pool,
                                         n, sizeof(nxt_listen_socket_t));
    if (inherited_sockets == NULL) {
        return NXT_ERROR;
    }

    rt->inherited_sockets = inherited_sockets;

    for (s = 3; s < n; s++) {
        ls = nxt_array_zero_add(inherited_sockets);
        if (nxt_slow_path(ls == NULL)) {
            return NXT_ERROR;
        }

        ls->socket = s;

        ls->sockaddr = nxt_getsockname(task, rt->mem_pool, s);
        if (nxt_slow_path(ls->sockaddr == NULL)) {
            return NXT_ERROR;
        }

        ls->sockaddr->type = SOCK_STREAM;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_runtime_event_engines(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_thread_t                 *thread;
    nxt_event_engine_t           *engine;
    const nxt_event_interface_t  *interface;

    interface = nxt_service_get(rt->services, "engine", NULL);

    if (nxt_slow_path(interface == NULL)) {
        /* TODO: log */
        return NXT_ERROR;
    }

    engine = nxt_event_engine_create(task, interface,
                                     nxt_main_process_signals, 0, 0);

    if (nxt_slow_path(engine == NULL)) {
        return NXT_ERROR;
    }

    thread = task->thread;
    thread->engine = engine;
#if 0
    thread->fiber = &engine->fibers->fiber;
#endif

    engine->id = rt->last_engine_id++;
    engine->mem_pool = nxt_mp_create(1024, 128, 256, 32);

    nxt_queue_init(&rt->engines);
    nxt_queue_insert_tail(&rt->engines, &engine->link);

    return NXT_OK;
}


static nxt_int_t
nxt_runtime_thread_pools(nxt_thread_t *thr, nxt_runtime_t *rt)
{
    nxt_int_t    ret;
    nxt_array_t  *thread_pools;

    thread_pools = nxt_array_create(rt->mem_pool, 1,
                                    sizeof(nxt_thread_pool_t *));

    if (nxt_slow_path(thread_pools == NULL)) {
        return NXT_ERROR;
    }

    rt->thread_pools = thread_pools;
    ret = nxt_runtime_thread_pool_create(thr, rt, 2, 60000 * 1000000LL);

    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static void
nxt_runtime_start(nxt_task_t *task, void *obj, void *data)
{
    nxt_runtime_t  *rt;

    rt = obj;

    nxt_debug(task, "rt conf done");

    task->thread->log->ctx_handler = NULL;
    task->thread->log->ctx = NULL;

    if (nxt_runtime_log_files_create(task, rt) != NXT_OK) {
        goto fail;
    }

    if (nxt_runtime_event_engine_change(task, rt) != NXT_OK) {
        goto fail;
    }

    /*
     * Thread pools should be destroyed before starting worker
     * processes, because thread pool semaphores will stick in
     * locked state in new processes after fork().
     */
    nxt_runtime_thread_pool_destroy(task, rt, rt->start);

    return;

fail:

    nxt_runtime_quit(task, 1);
}


static void
nxt_runtime_initial_start(nxt_task_t *task, nxt_uint_t status)
{
    nxt_int_t                    ret;
    nxt_thread_t                 *thr;
    nxt_runtime_t                *rt;
    const nxt_event_interface_t  *interface;

    thr = task->thread;
    rt = thr->runtime;

    if (rt->inherited_sockets == NULL && rt->daemon) {

        if (nxt_process_daemon(task) != NXT_OK) {
            goto fail;
        }

        /*
         * An event engine should be updated after fork()
         * even if an event facility was not changed because:
         * 1) inherited kqueue descriptor is invalid,
         * 2) the signal thread is not inherited.
         */
        interface = nxt_service_get(rt->services, "engine", rt->engine);
        if (interface == NULL) {
            goto fail;
        }

        ret = nxt_event_engine_change(task->thread->engine, interface,
                                      rt->batch);
        if (ret != NXT_OK) {
            goto fail;
        }
    }

    ret = nxt_runtime_pid_file_create(task, rt->pid_file);
    if (ret != NXT_OK) {
        goto fail;
    }

    if (nxt_runtime_event_engine_change(task, rt) != NXT_OK) {
        goto fail;
    }

    thr->engine->max_connections = rt->engine_connections;

    if (nxt_main_process_start(thr, task, rt) != NXT_ERROR) {
        return;
    }

fail:

    nxt_runtime_quit(task, 1);
}


void
nxt_runtime_quit(nxt_task_t *task, nxt_uint_t status)
{
    nxt_bool_t          done;
    nxt_runtime_t       *rt;
    nxt_event_engine_t  *engine;

    rt = task->thread->runtime;
    rt->status |= status;
    engine = task->thread->engine;

    nxt_debug(task, "exiting");

    done = 1;

    if (!engine->shutdown) {
        engine->shutdown = 1;

        if (!nxt_array_is_empty(rt->thread_pools)) {
            nxt_runtime_thread_pool_destroy(task, rt, nxt_runtime_quit);
            done = 0;
        }

        if (rt->type == NXT_PROCESS_MAIN) {
            nxt_main_stop_all_processes(task, rt);
            done = 0;
        }
    }

    nxt_runtime_close_idle_connections(engine);

    if (done) {
        nxt_work_queue_add(&engine->fast_work_queue, nxt_runtime_exit,
                           task, rt, engine);
    }
}


static void
nxt_runtime_close_idle_connections(nxt_event_engine_t *engine)
{
    nxt_conn_t        *c;
    nxt_queue_t       *idle;
    nxt_queue_link_t  *link, *next;

    nxt_debug(&engine->task, "close idle connections");

    idle = &engine->idle_connections;

    for (link = nxt_queue_head(idle);
         link != nxt_queue_tail(idle);
         link = next)
    {
        next = nxt_queue_next(link);
        c = nxt_queue_link_data(link, nxt_conn_t, link);

        if (!c->socket.read_ready) {
            nxt_queue_remove(link);
            nxt_conn_close(engine, c);
        }
    }
}


static void
nxt_runtime_exit(nxt_task_t *task, void *obj, void *data)
{
    int                 status;
    nxt_runtime_t       *rt;
    nxt_process_t       *process;
    nxt_event_engine_t  *engine;

    rt = obj;
    engine = data;

    nxt_debug(task, "thread pools: %d", rt->thread_pools->nelts);

    if (!nxt_array_is_empty(rt->thread_pools)) {
        return;
    }

    if (rt->type == NXT_PROCESS_MAIN) {
        if (rt->pid_file != NULL) {
            nxt_file_delete(rt->pid_file);
        }

#if (NXT_HAVE_UNIX_DOMAIN)
        {
            nxt_sockaddr_t   *sa;
            nxt_file_name_t  *name;

            sa = rt->controller_listen;

            if (sa->u.sockaddr.sa_family == AF_UNIX) {
                name = (nxt_file_name_t *) sa->u.sockaddr_un.sun_path;
                (void) nxt_file_delete(name);
            }
        }
#endif
    }

    if (!engine->event.signal_support) {
        nxt_event_engine_signals_stop(engine);
    }

    nxt_runtime_process_each(rt, process) {

        nxt_process_close_ports(task, process);

    } nxt_runtime_process_loop;

    nxt_thread_mutex_destroy(&rt->processes_mutex);

    status = rt->status;
    nxt_mp_destroy(rt->mem_pool);

    nxt_debug(task, "exit: %d", status);

    exit(status);
    nxt_unreachable();
}


static nxt_int_t
nxt_runtime_event_engine_change(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_event_engine_t           *engine;
    const nxt_event_interface_t  *interface;

    engine = task->thread->engine;

    if (engine->batch == rt->batch
        && nxt_strcmp(engine->event.name, rt->engine) == 0)
    {
        return NXT_OK;
    }

    interface = nxt_service_get(rt->services, "engine", rt->engine);

    if (interface != NULL) {
        return nxt_event_engine_change(engine, interface, rt->batch);
    }

    return NXT_ERROR;
}


void
nxt_runtime_event_engine_free(nxt_runtime_t *rt)
{
    nxt_queue_link_t    *link;
    nxt_event_engine_t  *engine;

    link = nxt_queue_first(&rt->engines);
    nxt_queue_remove(link);

    engine = nxt_queue_link_data(link, nxt_event_engine_t, link);
    nxt_event_engine_free(engine);
}


nxt_int_t
nxt_runtime_thread_pool_create(nxt_thread_t *thr, nxt_runtime_t *rt,
    nxt_uint_t max_threads, nxt_nsec_t timeout)
{
    nxt_thread_pool_t   *thread_pool, **tp;

    tp = nxt_array_add(rt->thread_pools);
    if (tp == NULL) {
        return NXT_ERROR;
    }

    thread_pool = nxt_thread_pool_create(max_threads, timeout,
                                         nxt_runtime_thread_pool_init,
                                         thr->engine,
                                         nxt_runtime_thread_pool_exit);

    if (nxt_fast_path(thread_pool != NULL)) {
        *tp = thread_pool;
    }

    return NXT_OK;
}


static void
nxt_runtime_thread_pool_destroy(nxt_task_t *task, nxt_runtime_t *rt,
    nxt_runtime_cont_t cont)
{
    nxt_uint_t         n;
    nxt_thread_pool_t  **tp;

    rt->continuation = cont;

    n = rt->thread_pools->nelts;

    if (n == 0) {
        cont(task, 0);
        return;
    }

    tp = rt->thread_pools->elts;

    do {
        nxt_thread_pool_destroy(*tp);

        tp++;
        n--;
    } while (n != 0);
}


static void
nxt_runtime_thread_pool_init(void)
{
#if (NXT_REGEX)
    nxt_regex_init(0);
#endif
}


static void
nxt_runtime_thread_pool_exit(nxt_task_t *task, void *obj, void *data)
{
    nxt_uint_t           i, n;
    nxt_runtime_t        *rt;
    nxt_thread_pool_t    *tp, **thread_pools;
    nxt_thread_handle_t  handle;

    tp = obj;

    if (data != NULL) {
        handle = (nxt_thread_handle_t) (uintptr_t) data;
        nxt_thread_wait(handle);
    }

    rt = task->thread->runtime;

    thread_pools = rt->thread_pools->elts;
    n = rt->thread_pools->nelts;

    nxt_debug(task, "thread pools: %ui", n);

    for (i = 0; i < n; i++) {

        if (tp == thread_pools[i]) {
            nxt_array_remove(rt->thread_pools, &thread_pools[i]);

            if (n == 1) {
                /* The last thread pool. */
                rt->continuation(task, 0);
            }

            return;
        }
    }
}


static nxt_int_t
nxt_runtime_conf_init(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_int_t                    ret;
    nxt_str_t                    control;
    nxt_uint_t                   n;
    nxt_file_t                   *file;
    const char                   *slash;
    nxt_sockaddr_t               *sa;
    nxt_file_name_str_t          file_name;
    const nxt_event_interface_t  *interface;

    rt->daemon = 1;
    rt->engine_connections = 256;
    rt->auxiliary_threads = 2;
    rt->user_cred.user = NXT_USER;
    rt->group = NXT_GROUP;
    rt->pid = NXT_PID;
    rt->log = NXT_LOG;
    rt->modules = NXT_MODULES;
    rt->state = NXT_STATE;
    rt->control = NXT_CONTROL_SOCK;

    if (nxt_runtime_conf_read_cmd(task, rt) != NXT_OK) {
        return NXT_ERROR;
    }

    if (nxt_user_cred_get(task, &rt->user_cred, rt->group) != NXT_OK) {
        return NXT_ERROR;
    }

    /* An engine's parameters. */

    interface = nxt_service_get(rt->services, "engine", rt->engine);
    if (interface == NULL) {
        return NXT_ERROR;
    }

    rt->engine = interface->name;

    ret = nxt_file_name_create(rt->mem_pool, &file_name, "%s%Z", rt->pid);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    rt->pid_file = file_name.start;

    ret = nxt_file_name_create(rt->mem_pool, &file_name, "%s%Z", rt->log);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    file = nxt_list_first(rt->log_files);
    file->name = file_name.start;

    slash = "";
    n = nxt_strlen(rt->modules);

    if (n > 1 && rt->modules[n - 1] != '/') {
        slash = "/";
    }

    ret = nxt_file_name_create(rt->mem_pool, &file_name, "%s%s*.unit.so%Z",
                               rt->modules, slash);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    rt->modules = (char *) file_name.start;

    slash = "";
    n = nxt_strlen(rt->state);

    if (n > 1 && rt->state[n - 1] != '/') {
        slash = "/";
    }

    ret = nxt_file_name_create(rt->mem_pool, &file_name, "%s%sconf.json%Z",
                               rt->state, slash);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    rt->conf = (char *) file_name.start;

    ret = nxt_file_name_create(rt->mem_pool, &file_name, "%s.tmp%Z", rt->conf);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    rt->conf_tmp = (char *) file_name.start;

    ret = nxt_file_name_create(rt->mem_pool, &file_name, "%s%scerts/%Z",
                               rt->state, slash);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    ret = mkdir((char *) file_name.start, S_IRWXU);

    if (nxt_fast_path(ret == 0 || nxt_errno == EEXIST)) {
        rt->certs.length = file_name.len;
        rt->certs.start = file_name.start;

    } else {
        nxt_alert(task, "Unable to create certificates storage directory: "
                  "mkdir(%s) failed %E", file_name.start, nxt_errno);
    }

    control.length = nxt_strlen(rt->control);
    control.start = (u_char *) rt->control;

    sa = nxt_sockaddr_parse(rt->mem_pool, &control);
    if (nxt_slow_path(sa == NULL)) {
        return NXT_ERROR;
    }

    sa->type = SOCK_STREAM;

    rt->controller_listen = sa;

    if (nxt_runtime_controller_socket(task, rt) != NXT_OK) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_runtime_conf_read_cmd(nxt_task_t *task, nxt_runtime_t *rt)
{
    char    *p, **argv;
    u_char  *end;
    u_char  buf[1024];

    static const char  version[] =
        "unit version: " NXT_VERSION "\n"
        "configured as ./configure" NXT_CONFIGURE_OPTIONS "\n";

    static const char  no_control[] =
                       "option \"--control\" requires socket address\n";
    static const char  no_user[] = "option \"--user\" requires username\n";
    static const char  no_group[] = "option \"--group\" requires group name\n";
    static const char  no_pid[] = "option \"--pid\" requires filename\n";
    static const char  no_log[] = "option \"--log\" requires filename\n";
    static const char  no_modules[] =
                       "option \"--modules\" requires directory\n";
    static const char  no_state[] = "option \"--state\" requires directory\n";

    static const char  help[] =
        "\n"
        "unit options:\n"
        "\n"
        "  --version            print unit version and configure options\n"
        "\n"
        "  --no-daemon          run unit in non-daemon mode\n"
        "\n"
        "  --control ADDRESS    set address of control API socket\n"
        "                       default: \"" NXT_CONTROL_SOCK "\"\n"
        "\n"
        "  --pid FILE           set pid filename\n"
        "                       default: \"" NXT_PID "\"\n"
        "\n"
        "  --log FILE           set log filename\n"
        "                       default: \"" NXT_LOG "\"\n"
        "\n"
        "  --modules DIRECTORY  set modules directory name\n"
        "                       default: \"" NXT_MODULES "\"\n"
        "\n"
        "  --state DIRECTORY    set state directory name\n"
        "                       default: \"" NXT_STATE "\"\n"
        "\n"
        "  --user USER          set non-privileged processes to run"
                                " as specified user\n"
        "                       default: \"" NXT_USER "\"\n"
        "\n"
        "  --group GROUP        set non-privileged processes to run"
                                " as specified group\n"
        "                       default: ";

    static const char  group[] = "\"" NXT_GROUP "\"\n\n";
    static const char  primary[] = "user's primary group\n\n";

    argv = &nxt_process_argv[1];

    while (*argv != NULL) {
        p = *argv++;

        if (nxt_strcmp(p, "--control") == 0) {
            if (*argv == NULL) {
                write(STDERR_FILENO, no_control, nxt_length(no_control));
                return NXT_ERROR;
            }

            p = *argv++;

            rt->control = p;

            continue;
        }

        if (nxt_strcmp(p, "--user") == 0) {
            if (*argv == NULL) {
                write(STDERR_FILENO, no_user, nxt_length(no_user));
                return NXT_ERROR;
            }

            p = *argv++;

            rt->user_cred.user = p;

            continue;
        }

        if (nxt_strcmp(p, "--group") == 0) {
            if (*argv == NULL) {
                write(STDERR_FILENO, no_group, nxt_length(no_group));
                return NXT_ERROR;
            }

            p = *argv++;

            rt->group = p;

            continue;
        }

        if (nxt_strcmp(p, "--pid") == 0) {
            if (*argv == NULL) {
                write(STDERR_FILENO, no_pid, nxt_length(no_pid));
                return NXT_ERROR;
            }

            p = *argv++;

            rt->pid = p;

            continue;
        }

        if (nxt_strcmp(p, "--log") == 0) {
            if (*argv == NULL) {
                write(STDERR_FILENO, no_log, nxt_length(no_log));
                return NXT_ERROR;
            }

            p = *argv++;

            rt->log = p;

            continue;
        }

        if (nxt_strcmp(p, "--modules") == 0) {
            if (*argv == NULL) {
                write(STDERR_FILENO, no_modules, nxt_length(no_modules));
                return NXT_ERROR;
            }

            p = *argv++;

            rt->modules = p;

            continue;
        }

        if (nxt_strcmp(p, "--state") == 0) {
            if (*argv == NULL) {
                write(STDERR_FILENO, no_state, nxt_length(no_state));
                return NXT_ERROR;
            }

            p = *argv++;

            rt->state = p;

            continue;
        }

        if (nxt_strcmp(p, "--no-daemon") == 0) {
            rt->daemon = 0;
            continue;
        }

        if (nxt_strcmp(p, "--version") == 0) {
            write(STDERR_FILENO, version, nxt_length(version));
            exit(0);
        }

        if (nxt_strcmp(p, "--help") == 0 || nxt_strcmp(p, "-h") == 0) {
            write(STDOUT_FILENO, help, nxt_length(help));

            if (sizeof(NXT_GROUP) == 1) {
                write(STDOUT_FILENO, primary, nxt_length(primary));

            } else {
                write(STDOUT_FILENO, group, nxt_length(group));
            }

            exit(0);
        }

        end = nxt_sprintf(buf, buf + sizeof(buf), "unknown option \"%s\", "
                          "try \"%s -h\" for available options\n",
                          p, nxt_process_argv[0]);

        write(STDERR_FILENO, buf, end - buf);

        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_listen_socket_t *
nxt_runtime_listen_socket_add(nxt_runtime_t *rt, nxt_sockaddr_t *sa)
{
    nxt_mp_t             *mp;
    nxt_listen_socket_t  *ls;

    ls = nxt_array_zero_add(rt->listen_sockets);
    if (ls == NULL) {
        return NULL;
    }

    mp = rt->mem_pool;

    ls->sockaddr = nxt_sockaddr_create(mp, &sa->u.sockaddr, sa->socklen,
                                       sa->length);
    if (ls->sockaddr == NULL) {
        return NULL;
    }

    ls->sockaddr->type = sa->type;

    nxt_sockaddr_text(ls->sockaddr);

    ls->socket = -1;
    ls->backlog = NXT_LISTEN_BACKLOG;

    return ls;
}


static nxt_int_t
nxt_runtime_hostname(nxt_task_t *task, nxt_runtime_t *rt)
{
    size_t  length;
    char    hostname[NXT_MAXHOSTNAMELEN + 1];

    if (gethostname(hostname, NXT_MAXHOSTNAMELEN) != 0) {
        nxt_alert(task, "gethostname() failed %E", nxt_errno);
        return NXT_ERROR;
    }

    /*
     * Linux gethostname(2):
     *
     *    If the null-terminated hostname is too large to fit,
     *    then the name is truncated, and no error is returned.
     *
     * For this reason an additional byte is reserved in the buffer.
     */
    hostname[NXT_MAXHOSTNAMELEN] = '\0';

    length = nxt_strlen(hostname);
    rt->hostname.length = length;

    rt->hostname.start = nxt_mp_nget(rt->mem_pool, length);

    if (rt->hostname.start != NULL) {
        nxt_memcpy_lowcase(rt->hostname.start, (u_char *) hostname, length);
        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_runtime_log_files_init(nxt_runtime_t *rt)
{
    nxt_file_t  *file;
    nxt_list_t  *log_files;

    log_files = nxt_list_create(rt->mem_pool, 1, sizeof(nxt_file_t));

    if (nxt_fast_path(log_files != NULL)) {
        rt->log_files = log_files;

        /* Preallocate the main log.  This allocation cannot fail. */
        file = nxt_list_zero_add(log_files);

        file->fd = NXT_FILE_INVALID;
        file->log_level = NXT_LOG_ALERT;

        return NXT_OK;
    }

    return NXT_ERROR;
}


nxt_file_t *
nxt_runtime_log_file_add(nxt_runtime_t *rt, nxt_str_t *name)
{
    nxt_int_t            ret;
    nxt_file_t           *file;
    nxt_file_name_str_t  file_name;

    ret = nxt_file_name_create(rt->mem_pool, &file_name, "V%Z", name);

    if (nxt_slow_path(ret != NXT_OK)) {
        return NULL;
    }

    nxt_list_each(file, rt->log_files) {

        /* STUB: hardecoded case sensitive/insensitive. */

        if (file->name != NULL
            && nxt_file_name_eq(file->name, file_name.start))
        {
            return file;
        }

    } nxt_list_loop;

    file = nxt_list_zero_add(rt->log_files);

    if (nxt_slow_path(file == NULL)) {
        return NULL;
    }

    file->fd = NXT_FILE_INVALID;
    file->log_level = NXT_LOG_ALERT;
    file->name = file_name.start;

    return file;
}


static nxt_int_t
nxt_runtime_log_files_create(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_int_t   ret;
    nxt_file_t  *file;

    nxt_list_each(file, rt->log_files) {

        ret = nxt_file_open(task, file, O_WRONLY | O_APPEND, O_CREAT,
                            NXT_FILE_OWNER_ACCESS);

        if (ret != NXT_OK) {
            return NXT_ERROR;
        }

    } nxt_list_loop;

    file = nxt_list_first(rt->log_files);

    return nxt_file_stderr(file);
}


nxt_int_t
nxt_runtime_listen_sockets_create(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_int_t            ret;
    nxt_uint_t           c, p, ncurr, nprev;
    nxt_listen_socket_t  *curr, *prev;

    curr = rt->listen_sockets->elts;
    ncurr = rt->listen_sockets->nelts;

    if (rt->inherited_sockets != NULL) {
        prev = rt->inherited_sockets->elts;
        nprev = rt->inherited_sockets->nelts;

    } else {
        prev = NULL;
        nprev = 0;
    }

    for (c = 0; c < ncurr; c++) {

        for (p = 0; p < nprev; p++) {

            if (nxt_sockaddr_cmp(curr[c].sockaddr, prev[p].sockaddr)) {

                ret = nxt_listen_socket_update(task, &curr[c], &prev[p]);
                if (ret != NXT_OK) {
                    return NXT_ERROR;
                }

                goto next;
            }
        }

        if (nxt_listen_socket_create(task, &curr[c], 0) != NXT_OK) {
            return NXT_ERROR;
        }

    next:

        continue;
    }

    return NXT_OK;
}


nxt_int_t
nxt_runtime_listen_sockets_enable(nxt_task_t *task, nxt_runtime_t *rt)
{
    nxt_uint_t           i, n;
    nxt_listen_socket_t  *ls;

    ls = rt->listen_sockets->elts;
    n = rt->listen_sockets->nelts;

    for (i = 0; i < n; i++) {
        if (ls[i].flags == NXT_NONBLOCK) {
            if (nxt_listen_event(task, &ls[i]) == NULL) {
                return NXT_ERROR;
            }
        }
    }

    return NXT_OK;
}


nxt_str_t *
nxt_current_directory(nxt_mp_t *mp)
{
    size_t     length;
    u_char     *p;
    nxt_str_t  *name;
    char       buf[NXT_MAX_PATH_LEN];

    length = nxt_dir_current(buf, NXT_MAX_PATH_LEN);

    if (nxt_fast_path(length != 0)) {
        name = nxt_str_alloc(mp, length + 1);

        if (nxt_fast_path(name != NULL)) {
            p = nxt_cpymem(name->start, buf, length);
            *p = '/';

            return name;
        }
    }

    return NULL;
}


static nxt_int_t
nxt_runtime_pid_file_create(nxt_task_t *task, nxt_file_name_t *pid_file)
{
    ssize_t     length;
    nxt_int_t   n;
    nxt_file_t  file;
    u_char      pid[NXT_INT64_T_LEN + nxt_length("\n")];

    nxt_memzero(&file, sizeof(nxt_file_t));

    file.name = pid_file;

    n = nxt_file_open(task, &file, O_WRONLY, O_CREAT | O_TRUNC,
                      NXT_FILE_DEFAULT_ACCESS);

    if (n != NXT_OK) {
        return NXT_ERROR;
    }

    length = nxt_sprintf(pid, pid + sizeof(pid), "%PI%n", nxt_pid) - pid;

    if (nxt_file_write(&file, pid, length, 0) != length) {
        return NXT_ERROR;
    }

    nxt_file_close(task, &file);

    return NXT_OK;
}


nxt_process_t *
nxt_runtime_process_new(nxt_runtime_t *rt)
{
    nxt_process_t  *process;

    /* TODO: memory failures. */

    process = nxt_mp_zalloc(rt->mem_pool, sizeof(nxt_process_t));
    if (nxt_slow_path(process == NULL)) {
        return NULL;
    }

    nxt_queue_init(&process->ports);

    nxt_thread_mutex_create(&process->incoming.mutex);
    nxt_thread_mutex_create(&process->outgoing.mutex);
    nxt_thread_mutex_create(&process->cp_mutex);

    process->use_count = 1;

    return process;
}


static void
nxt_runtime_process_destroy(nxt_runtime_t *rt, nxt_process_t *process)
{
    nxt_port_t  *port;

    nxt_assert(process->use_count == 0);
    nxt_assert(process->registered == 0);

    nxt_port_mmaps_destroy(&process->incoming, 1);
    nxt_port_mmaps_destroy(&process->outgoing, 1);

    do {
        port = nxt_port_hash_retrieve(&process->connected_ports);

    } while (port != NULL);

    nxt_thread_mutex_destroy(&process->incoming.mutex);
    nxt_thread_mutex_destroy(&process->outgoing.mutex);
    nxt_thread_mutex_destroy(&process->cp_mutex);

    nxt_mp_free(rt->mem_pool, process);
}


static nxt_int_t
nxt_runtime_lvlhsh_pid_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_process_t  *process;

    process = data;

    if (lhq->key.length == sizeof(nxt_pid_t)
        && *(nxt_pid_t *) lhq->key.start == process->pid)
    {
        return NXT_OK;
    }

    return NXT_DECLINED;
}

static const nxt_lvlhsh_proto_t  lvlhsh_processes_proto  nxt_aligned(64) = {
    NXT_LVLHSH_DEFAULT,
    nxt_runtime_lvlhsh_pid_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


nxt_inline void
nxt_runtime_process_lhq_pid(nxt_lvlhsh_query_t *lhq, nxt_pid_t *pid)
{
    lhq->key_hash = nxt_murmur_hash2(pid, sizeof(*pid));
    lhq->key.length = sizeof(*pid);
    lhq->key.start = (u_char *) pid;
    lhq->proto = &lvlhsh_processes_proto;
}


nxt_process_t *
nxt_runtime_process_find(nxt_runtime_t *rt, nxt_pid_t pid)
{
    nxt_process_t       *process;
    nxt_lvlhsh_query_t  lhq;

    process = NULL;

    nxt_runtime_process_lhq_pid(&lhq, &pid);

    nxt_thread_mutex_lock(&rt->processes_mutex);

    if (nxt_lvlhsh_find(&rt->processes, &lhq) == NXT_OK) {
        process = lhq.value;

    } else {
        nxt_thread_log_debug("process %PI not found", pid);
    }

    nxt_thread_mutex_unlock(&rt->processes_mutex);

    return process;
}


nxt_process_t *
nxt_runtime_process_get(nxt_runtime_t *rt, nxt_pid_t pid)
{
    nxt_process_t       *process;
    nxt_lvlhsh_query_t  lhq;

    nxt_runtime_process_lhq_pid(&lhq, &pid);

    nxt_thread_mutex_lock(&rt->processes_mutex);

    if (nxt_lvlhsh_find(&rt->processes, &lhq) == NXT_OK) {
        nxt_thread_log_debug("process %PI found", pid);

        nxt_thread_mutex_unlock(&rt->processes_mutex);

        process = lhq.value;
        process->use_count++;

        return process;
    }

    process = nxt_runtime_process_new(rt);
    if (nxt_slow_path(process == NULL)) {

        nxt_thread_mutex_unlock(&rt->processes_mutex);

        return NULL;
    }

    process->pid = pid;

    lhq.replace = 0;
    lhq.value = process;
    lhq.pool = rt->mem_pool;

    switch (nxt_lvlhsh_insert(&rt->processes, &lhq)) {

    case NXT_OK:
        if (rt->nprocesses == 0) {
            rt->mprocess = process;
        }

        rt->nprocesses++;

        process->registered = 1;

        nxt_thread_log_debug("process %PI insert", pid);
        break;

    default:
        nxt_thread_log_debug("process %PI insert failed", pid);
        break;
    }

    nxt_thread_mutex_unlock(&rt->processes_mutex);

    return process;
}


void
nxt_runtime_process_add(nxt_task_t *task, nxt_process_t *process)
{
    nxt_port_t          *port;
    nxt_runtime_t       *rt;
    nxt_lvlhsh_query_t  lhq;

    nxt_assert(process->registered == 0);

    rt = task->thread->runtime;

    nxt_runtime_process_lhq_pid(&lhq, &process->pid);

    lhq.replace = 0;
    lhq.value = process;
    lhq.pool = rt->mem_pool;

    nxt_thread_mutex_lock(&rt->processes_mutex);

    switch (nxt_lvlhsh_insert(&rt->processes, &lhq)) {

    case NXT_OK:
        if (rt->nprocesses == 0) {
            rt->mprocess = process;
        }

        rt->nprocesses++;

        nxt_process_port_each(process, port) {

            port->pid = process->pid;

            nxt_runtime_port_add(task, port);

        } nxt_process_port_loop;

        process->registered = 1;

        nxt_thread_log_debug("process %PI added", process->pid);
        break;

    default:
        nxt_thread_log_debug("process %PI failed to add", process->pid);
        break;
    }

    nxt_thread_mutex_unlock(&rt->processes_mutex);
}


static nxt_process_t *
nxt_runtime_process_remove_pid(nxt_runtime_t *rt, nxt_pid_t pid)
{
    nxt_process_t       *process;
    nxt_lvlhsh_query_t  lhq;

    process = NULL;

    nxt_runtime_process_lhq_pid(&lhq, &pid);

    lhq.pool = rt->mem_pool;

    nxt_thread_mutex_lock(&rt->processes_mutex);

    switch (nxt_lvlhsh_delete(&rt->processes, &lhq)) {

    case NXT_OK:
        rt->nprocesses--;

        process = lhq.value;

        process->registered = 0;

        nxt_thread_log_debug("process %PI removed", pid);
        break;

    default:
        nxt_thread_log_debug("process %PI remove failed", pid);
        break;
    }

    nxt_thread_mutex_unlock(&rt->processes_mutex);

    return process;
}


void
nxt_process_use(nxt_task_t *task, nxt_process_t *process, int i)
{
    nxt_runtime_t  *rt;

    process->use_count += i;

    if (process->use_count == 0) {
        rt = task->thread->runtime;

        if (process->registered == 1) {
            nxt_runtime_process_remove_pid(rt, process->pid);
        }

        nxt_runtime_process_destroy(rt, process);
    }
}


nxt_process_t *
nxt_runtime_process_first(nxt_runtime_t *rt, nxt_lvlhsh_each_t *lhe)
{
    nxt_lvlhsh_each_init(lhe, &lvlhsh_processes_proto);

    return nxt_runtime_process_next(rt, lhe);
}


void
nxt_runtime_port_add(nxt_task_t *task, nxt_port_t *port)
{
    nxt_int_t      res;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    res = nxt_port_hash_add(&rt->ports, port);

    if (res != NXT_OK) {
        return;
    }

    rt->port_by_type[port->type] = port;

    nxt_port_use(task, port, 1);
}


void
nxt_runtime_port_remove(nxt_task_t *task, nxt_port_t *port)
{
    nxt_int_t      res;
    nxt_runtime_t  *rt;

    rt = task->thread->runtime;

    res = nxt_port_hash_remove(&rt->ports, port);

    if (res != NXT_OK) {
        return;
    }

    if (rt->port_by_type[port->type] == port) {
        rt->port_by_type[port->type] = NULL;
    }

    nxt_port_use(task, port, -1);
}


nxt_port_t *
nxt_runtime_port_find(nxt_runtime_t *rt, nxt_pid_t pid,
    nxt_port_id_t port_id)
{
    return nxt_port_hash_find(&rt->ports, pid, port_id);
}
