
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_main_process.h>

#if (NXT_HAVE_CLONE)
#include <nxt_clone.h>
#endif

#include <signal.h>

static void nxt_process_start(nxt_task_t *task, nxt_process_t *process);
static nxt_int_t nxt_process_worker_setup(nxt_task_t *task,
    nxt_process_t *process, int parentfd);

/* A cached process pid. */
nxt_pid_t  nxt_pid;

/* An original parent process pid. */
nxt_pid_t  nxt_ppid;

/* A cached process effective uid */
nxt_uid_t  nxt_euid;

/* A cached process effective gid */
nxt_gid_t  nxt_egid;

nxt_bool_t  nxt_proc_conn_matrix[NXT_PROCESS_MAX][NXT_PROCESS_MAX] = {
    { 1, 1, 1, 1, 1 },
    { 1, 0, 0, 0, 0 },
    { 1, 0, 0, 1, 0 },
    { 1, 0, 1, 0, 1 },
    { 1, 0, 0, 0, 0 },
};

nxt_bool_t  nxt_proc_remove_notify_matrix[NXT_PROCESS_MAX][NXT_PROCESS_MAX] = {
    { 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0 },
    { 0, 0, 0, 1, 0 },
    { 0, 0, 1, 0, 1 },
    { 0, 0, 0, 1, 0 },
};


static nxt_int_t
nxt_process_worker_setup(nxt_task_t *task, nxt_process_t *process, int parentfd)
{
    pid_t               rpid, pid;
    ssize_t             n;
    nxt_int_t           parent_status;
    nxt_process_t       *p;
    nxt_runtime_t       *rt;
    nxt_process_init_t  *init;
    nxt_process_type_t  ptype;

    pid  = getpid();
    rpid = 0;
    rt   = task->thread->runtime;
    init = process->init;

    /* Setup the worker process. */

    n = read(parentfd, &rpid, sizeof(rpid));
    if (nxt_slow_path(n == -1 || n != sizeof(rpid))) {
        nxt_alert(task, "failed to read real pid");
        return NXT_ERROR;
    }

    if (nxt_slow_path(rpid == 0)) {
        nxt_alert(task, "failed to get real pid from parent");
        return NXT_ERROR;
    }

    nxt_pid = rpid;

    /* Clean inherited cached thread tid. */
    task->thread->tid = 0;

    process->pid = nxt_pid;

    if (nxt_pid != pid) {
        nxt_debug(task, "app \"%s\" real pid %d", init->name, nxt_pid);
        nxt_debug(task, "app \"%s\" isolated pid: %d", init->name, pid);
    }

    n = read(parentfd, &parent_status, sizeof(parent_status));
    if (nxt_slow_path(n == -1 || n != sizeof(parent_status))) {
        nxt_alert(task, "failed to read parent status");
        return NXT_ERROR;
    }

    if (nxt_slow_path(parent_status != NXT_OK)) {
        return parent_status;
    }

    ptype = init->type;

    nxt_port_reset_next_id();

    nxt_event_engine_thread_adopt(task->thread->engine);

    /* Remove not ready processes. */
    nxt_runtime_process_each(rt, p) {

        if (nxt_proc_conn_matrix[ptype][nxt_process_type(p)] == 0) {
            nxt_debug(task, "remove not required process %PI", p->pid);

            nxt_process_close_ports(task, p);

            continue;
        }

        if (!p->ready) {
            nxt_debug(task, "remove not ready process %PI", p->pid);

            nxt_process_close_ports(task, p);

            continue;
        }

        nxt_port_mmaps_destroy(&p->incoming, 0);
        nxt_port_mmaps_destroy(&p->outgoing, 0);

    } nxt_runtime_process_loop;

    nxt_runtime_process_add(task, process);

    nxt_process_start(task, process);

    process->ready = 1;

    return NXT_OK;
}


nxt_pid_t
nxt_process_create(nxt_task_t *task, nxt_process_t *process)
{
    int                 pipefd[2];
    nxt_int_t           ret;
    nxt_pid_t           pid;
    nxt_process_init_t  *init;

    if (nxt_slow_path(pipe(pipefd) == -1)) {
        nxt_alert(task, "failed to create process pipe for passing rpid");
        return -1;
    }

    init = process->init;

#if (NXT_HAVE_CLONE)
    pid = nxt_clone(SIGCHLD | init->isolation.clone.flags);
    if (nxt_slow_path(pid < 0)) {
        nxt_alert(task, "clone() failed while creating \"%s\" %E",
                  init->name, nxt_errno);
        goto cleanup;
    }
#else
    pid = fork();
    if (nxt_slow_path(pid < 0)) {
        nxt_alert(task, "fork() failed while creating \"%s\" %E",
                  init->name, nxt_errno);
        goto cleanup;
    }
#endif

    if (pid == 0) {
        /* Child. */

        if (nxt_slow_path(close(pipefd[1]) == -1)) {
            nxt_alert(task, "failed to close writer pipe fd");
        }

        ret = nxt_process_worker_setup(task, process, pipefd[0]);
        if (nxt_slow_path(ret != NXT_OK)) {
            exit(1);
        }

        if (nxt_slow_path(close(pipefd[0]) == -1)) {
            nxt_alert(task, "failed to close writer pipe fd");
        }

        /*
         * Explicitly return 0 to notice the caller function this is the child.
         * The caller must return to the event engine work queue loop.
         */
        return 0;
    }

    /* Parent. */

    /*
     * At this point, the child process is blocked reading the
     * pipe fd to get its real pid (rpid).
     *
     * If anything goes wrong now, we need to terminate the child
     * process by sending a NXT_ERROR in the pipe.
     */

#if (NXT_HAVE_CLONE)
    nxt_debug(task, "clone(\"%s\"): %PI", init->name, pid);
#else
    nxt_debug(task, "fork(\"%s\"): %PI", init->name, pid);
#endif

    if (nxt_slow_path(write(pipefd[1], &pid, sizeof(pid)) == -1)) {
        nxt_alert(task, "failed to write real pid");
        goto fail;
    }

#if (NXT_HAVE_CLONE && NXT_HAVE_CLONE_NEWUSER)
    if (NXT_CLONE_USER(init->isolation.clone.flags)) {
        ret = nxt_clone_credential_map(task, pid, init->user_cred,
                                       &init->isolation.clone);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }
    }
#endif

    ret = NXT_OK;

    if (nxt_slow_path(write(pipefd[1], &ret, sizeof(ret)) == -1)) {
        nxt_alert(task, "failed to write status");
        goto fail;
    }

    process->pid = pid;

    nxt_runtime_process_add(task, process);

    goto cleanup;

fail:

    ret = NXT_ERROR;

    if (nxt_slow_path(write(pipefd[1], &ret, sizeof(ret)) == -1)) {
        nxt_alert(task, "failed to write status");
    }

    waitpid(pid, NULL, 0);

    pid = -1;

cleanup:

    if (nxt_slow_path(close(pipefd[0]) != 0)) {
        nxt_alert(task, "failed to close pipe: %E", nxt_errno);
    }

    if (nxt_slow_path(close(pipefd[1]) != 0)) {
        nxt_alert(task, "failed to close pipe: %E", nxt_errno);
    }

    return pid;
}


static void
nxt_process_start(nxt_task_t *task, nxt_process_t *process)
{
    nxt_int_t                    ret, cap_setid;
    nxt_port_t                   *port, *main_port;
    nxt_thread_t                 *thread;
    nxt_runtime_t                *rt;
    nxt_process_init_t           *init;
    nxt_event_engine_t           *engine;
    const nxt_event_interface_t  *interface;

    init = process->init;

    nxt_log(task, NXT_LOG_INFO, "%s started", init->name);

    nxt_process_title(task, "unit: %s", init->name);

    thread = task->thread;
    rt     = thread->runtime;

    nxt_random_init(&thread->random);

    cap_setid = rt->capabilities.setid;

#if (NXT_HAVE_CLONE_NEWUSER)
    if (!cap_setid && NXT_CLONE_USER(init->isolation.clone.flags)) {
        cap_setid = 1;
    }
#endif

    if (cap_setid) {
        ret = nxt_credential_setgids(task, init->user_cred);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }

        ret = nxt_credential_setuid(task, init->user_cred);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto fail;
        }
    }

    rt->type = init->type;

    engine = thread->engine;

    /* Update inherited main process event engine and signals processing. */
    engine->signals->sigev = init->signals;

    interface = nxt_service_get(rt->services, "engine", rt->engine);
    if (nxt_slow_path(interface == NULL)) {
        goto fail;
    }

    if (nxt_event_engine_change(engine, interface, rt->batch) != NXT_OK) {
        goto fail;
    }

    ret = nxt_runtime_thread_pool_create(thread, rt, rt->auxiliary_threads,
                                         60000 * 1000000LL);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    main_port = rt->port_by_type[NXT_PROCESS_MAIN];

    nxt_port_read_close(main_port);
    nxt_port_write_enable(task, main_port);

    port = nxt_process_port_first(process);

    nxt_port_write_close(port);

    ret = init->start(task, init->data);

    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    nxt_port_enable(task, port, init->port_handlers);

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_PROCESS_READY,
                                -1, init->stream, 0, NULL);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_log(task, NXT_LOG_ERR, "failed to send READY message to main");

        goto fail;
    }

    return;

fail:

    exit(1);
}


#if (NXT_HAVE_POSIX_SPAWN)

/*
 * Linux glibc 2.2 posix_spawn() is implemented via fork()/execve().
 * Linux glibc 2.4 posix_spawn() without file actions and spawn
 * attributes uses vfork()/execve().
 *
 * On FreeBSD 8.0 posix_spawn() is implemented via vfork()/execve().
 *
 * Solaris 10:
 *   In the Solaris 10 OS, posix_spawn() is currently implemented using
 *   private-to-libc vfork(), execve(), and exit() functions.  They are
 *   identical to regular vfork(), execve(), and exit() in functionality,
 *   but they are not exported from libc and therefore don't cause the
 *   deadlock-in-the-dynamic-linker problem that any multithreaded code
 *   outside of libc that calls vfork() can cause.
 *
 * On MacOSX 10.5 (Leoprad) and NetBSD 6.0 posix_spawn() is implemented
 * as syscall.
 */

nxt_pid_t
nxt_process_execute(nxt_task_t *task, char *name, char **argv, char **envp)
{
    nxt_pid_t  pid;

    nxt_debug(task, "posix_spawn(\"%s\")", name);

    if (posix_spawn(&pid, name, NULL, NULL, argv, envp) != 0) {
        nxt_alert(task, "posix_spawn(\"%s\") failed %E", name, nxt_errno);
        return -1;
    }

    return pid;
}

#else

nxt_pid_t
nxt_process_execute(nxt_task_t *task, char *name, char **argv, char **envp)
{
    nxt_pid_t  pid;

    /*
     * vfork() is better than fork() because:
     *   it is faster several times;
     *   its execution time does not depend on private memory mapping size;
     *   it has lesser chances to fail due to the ENOMEM error.
     */

    pid = vfork();

    switch (pid) {

    case -1:
        nxt_alert(task, "vfork() failed while executing \"%s\" %E",
                  name, nxt_errno);
        break;

    case 0:
        /* A child. */
        nxt_debug(task, "execve(\"%s\")", name);

        (void) execve(name, argv, envp);

        nxt_alert(task, "execve(\"%s\") failed %E", name, nxt_errno);

        exit(1);
        nxt_unreachable();
        break;

    default:
        /* A parent. */
        nxt_debug(task, "vfork(): %PI", pid);
        break;
    }

    return pid;
}

#endif


nxt_int_t
nxt_process_daemon(nxt_task_t *task)
{
    nxt_fd_t      fd;
    nxt_pid_t     pid;
    const char    *msg;

    fd = -1;

    /*
     * fork() followed by a parent process's exit() detaches a child process
     * from an init script or terminal shell process which has started the
     * parent process and allows the child process to run in background.
     */

    pid = fork();

    switch (pid) {

    case -1:
        msg = "fork() failed %E";
        goto fail;

    case 0:
        /* A child. */
        break;

    default:
        /* A parent. */
        nxt_debug(task, "fork(): %PI", pid);
        exit(0);
        nxt_unreachable();
    }

    nxt_pid = getpid();

    /* Clean inherited cached thread tid. */
    task->thread->tid = 0;

    nxt_debug(task, "daemon");

    /* Detach from controlling terminal. */

    if (setsid() == -1) {
        nxt_alert(task, "setsid() failed %E", nxt_errno);
        return NXT_ERROR;
    }

    /*
     * Reset file mode creation mask: any access
     * rights can be set on file creation.
     */
    umask(0);

    /* Redirect STDIN and STDOUT to the "/dev/null". */

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        msg = "open(\"/dev/null\") failed %E";
        goto fail;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        msg = "dup2(\"/dev/null\", STDIN) failed %E";
        goto fail;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        msg = "dup2(\"/dev/null\", STDOUT) failed %E";
        goto fail;
    }

    if (fd > STDERR_FILENO) {
        nxt_fd_close(fd);
    }

    return NXT_OK;

fail:

    nxt_alert(task, msg, nxt_errno);

    if (fd != -1) {
        nxt_fd_close(fd);
    }

    return NXT_ERROR;
}


void
nxt_nanosleep(nxt_nsec_t ns)
{
    struct timespec  ts;

    ts.tv_sec = ns / 1000000000;
    ts.tv_nsec = ns % 1000000000;

    (void) nanosleep(&ts, NULL);
}


void
nxt_process_use(nxt_task_t *task, nxt_process_t *process, int i)
{
    process->use_count += i;

    if (process->use_count == 0) {
        nxt_runtime_process_release(task->thread->runtime, process);
    }
}


void
nxt_process_port_add(nxt_task_t *task, nxt_process_t *process, nxt_port_t *port)
{
    nxt_assert(port->process == NULL);

    port->process = process;
    nxt_queue_insert_tail(&process->ports, &port->link);

    nxt_process_use(task, process, 1);
}


nxt_process_type_t
nxt_process_type(nxt_process_t *process)
{
    return nxt_queue_is_empty(&process->ports) ? 0 :
        (nxt_process_port_first(process))->type;
}


void
nxt_process_close_ports(nxt_task_t *task, nxt_process_t *process)
{
    nxt_port_t  *port;

    nxt_process_port_each(process, port) {

        nxt_port_close(task, port);

        nxt_runtime_port_remove(task, port);

    } nxt_process_port_loop;
}


void
nxt_process_connected_port_add(nxt_process_t *process, nxt_port_t *port)
{
    nxt_thread_mutex_lock(&process->cp_mutex);

    nxt_port_hash_add(&process->connected_ports, port);

    nxt_thread_mutex_unlock(&process->cp_mutex);
}


void
nxt_process_connected_port_remove(nxt_process_t *process, nxt_port_t *port)
{
    nxt_thread_mutex_lock(&process->cp_mutex);

    nxt_port_hash_remove(&process->connected_ports, port);

    nxt_thread_mutex_unlock(&process->cp_mutex);
}


nxt_port_t *
nxt_process_connected_port_find(nxt_process_t *process, nxt_pid_t pid,
    nxt_port_id_t port_id)
{
    nxt_port_t  *res;

    nxt_thread_mutex_lock(&process->cp_mutex);

    res = nxt_port_hash_find(&process->connected_ports, pid, port_id);

    nxt_thread_mutex_unlock(&process->cp_mutex);

    return res;
}
