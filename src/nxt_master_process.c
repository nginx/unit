
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_cycle.h>
#include <nxt_process_chan.h>
#include <nxt_master_process.h>


static nxt_int_t nxt_master_process_chan_create(nxt_cycle_t *cycle);
static void nxt_master_process_title(void);
static nxt_int_t nxt_master_start_worker_processes(nxt_cycle_t *cycle);
static nxt_int_t nxt_master_create_worker_process(nxt_cycle_t *cycle);
static void nxt_master_stop_previous_worker_processes(nxt_thread_t *thr,
    void *obj, void *data);
static void nxt_master_process_sighup_handler(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_master_process_new_cycle(nxt_thread_t *thr, nxt_cycle_t *cycle);
static void nxt_master_process_sigterm_handler(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_master_process_sigquit_handler(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_master_process_sigusr1_handler(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_master_process_sigusr2_handler(nxt_thread_t *thr, void *obj,
    void *data);
static char **nxt_master_process_upgrade_environment(nxt_cycle_t *cycle);
static char **nxt_master_process_upgrade_environment_create(nxt_cycle_t *cycle);
static void nxt_master_process_sigchld_handler(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_master_cleanup_worker_process(nxt_thread_t *thr, nxt_pid_t pid);


const nxt_event_sig_t  nxt_master_process_signals[] = {
    nxt_event_signal(SIGHUP,  nxt_master_process_sighup_handler),
    nxt_event_signal(SIGINT,  nxt_master_process_sigterm_handler),
    nxt_event_signal(SIGQUIT, nxt_master_process_sigquit_handler),
    nxt_event_signal(SIGTERM, nxt_master_process_sigterm_handler),
    nxt_event_signal(SIGCHLD, nxt_master_process_sigchld_handler),
    nxt_event_signal(SIGUSR1, nxt_master_process_sigusr1_handler),
    nxt_event_signal(SIGUSR2, nxt_master_process_sigusr2_handler),
    nxt_event_signal_end,
};


static nxt_bool_t  nxt_exiting;


nxt_int_t
nxt_master_process_start(nxt_thread_t *thr, nxt_cycle_t *cycle)
{
    cycle->type = NXT_PROCESS_MASTER;

    if (nxt_master_process_chan_create(cycle) != NXT_OK) {
        return NXT_ERROR;
    }

    nxt_master_process_title();

    return nxt_master_start_worker_processes(cycle);
}


static nxt_int_t
nxt_master_process_chan_create(nxt_cycle_t *cycle)
{
    nxt_process_chan_t  *proc;

    proc = nxt_array_add(cycle->processes);
    if (nxt_slow_path(proc == NULL)) {
        return NXT_ERROR;
    }

    proc->pid = nxt_pid;
    proc->engine = 0;

    proc->chan = nxt_chan_create(0);
    if (nxt_slow_path(proc->chan == NULL)) {
        return NXT_ERROR;
    }

    /*
     * A master process chan.  A write chan is not closed
     * since it should be inherited by worker processes.
     */
    nxt_chan_read_enable(nxt_thread(), proc->chan);

    return NXT_OK;
}


static void
nxt_master_process_title(void)
{
    u_char      *p, *end;
    nxt_uint_t  i;
    u_char      title[2048];

    end = title + sizeof(title);

    p = nxt_sprintf(title, end, "nginman: master process %s",
                    nxt_process_argv[0]);

    for (i = 1; nxt_process_argv[i] != NULL; i++) {
        p = nxt_sprintf(p, end, " %s", nxt_process_argv[i]);
    }

    *p = '\0';

    nxt_process_title((char *) title);
}


static nxt_int_t
nxt_master_start_worker_processes(nxt_cycle_t *cycle)
{
    nxt_int_t   ret;
    nxt_uint_t  n;

    cycle->process_generation++;

    n = cycle->worker_processes;

    while (n-- != 0) {
        ret = nxt_master_create_worker_process(cycle);

        if (ret != NXT_OK) {
            return ret;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_master_create_worker_process(nxt_cycle_t *cycle)
{
    nxt_pid_t           pid;
    nxt_process_chan_t  *proc;

    proc = nxt_array_add(cycle->processes);
    if (nxt_slow_path(proc == NULL)) {
        return NXT_ERROR;
    }

    cycle->current_process = cycle->processes->nelts - 1;

    proc->engine = 0;
    proc->generation = cycle->process_generation;

    proc->chan = nxt_chan_create(0);
    if (nxt_slow_path(proc->chan == NULL)) {
        return NXT_ERROR;
    }

    pid = nxt_process_create(nxt_worker_process_start, cycle,
                             "start worker process");

    switch (pid) {

    case -1:
        return NXT_ERROR;

    case 0:
        /* A worker process, return to the event engine work queue loop. */
        return NXT_AGAIN;

    default:
        /* The master process created a new process. */
        proc->pid = pid;

        nxt_chan_read_close(proc->chan);
        nxt_chan_write_enable(nxt_thread(), proc->chan);

        nxt_process_new_chan(cycle, proc);
        return NXT_OK;
    }
}


static void
nxt_master_process_sighup_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_cycle_t  *cycle;

    cycle = nxt_thread_cycle();

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "signal %d (%s) recevied, %s",
                  (int) (uintptr_t) obj, data,
                  cycle->reconfiguring ? "ignored" : "reconfiguring");

    if (!cycle->reconfiguring) {
        (void) nxt_cycle_create(thr, cycle, nxt_master_process_new_cycle,
                                cycle->config_name, 0);
    }
}


static void
nxt_master_process_new_cycle(nxt_thread_t *thr, nxt_cycle_t *cycle)
{
    nxt_log_debug(thr->log, "new cycle");

    /* A safe place to free the previous cycle. */
    nxt_mem_pool_destroy(cycle->previous->mem_pool);

    switch (nxt_master_start_worker_processes(cycle)) {

    case NXT_OK:
        /*
         * The master process, allow old worker processes to accept new
         * connections yet 500ms in parallel with new worker processes.
         */
        cycle->timer.handler = nxt_master_stop_previous_worker_processes;
        cycle->timer.log = &nxt_main_log;
        nxt_event_timer_ident(&cycle->timer, -1);

        cycle->timer.work_queue = &thr->work_queue.main;

        nxt_event_timer_add(thr->engine, &cycle->timer, 500);

        return;

    case NXT_ERROR:
        /*
         * The master process, one or more new worker processes
         * could not be created, there is no fallback.
         */
        return;

    default:  /* NXT_AGAIN */
        /* A worker process, return to the event engine work queue loop. */
        return;
    }
}


static void
nxt_master_stop_previous_worker_processes(nxt_thread_t *thr, void *obj,
    void *data)
{
    uint32_t            generation;
    nxt_uint_t          i, n;
    nxt_cycle_t         *cycle;
    nxt_process_chan_t  *proc;

    cycle = nxt_thread_cycle();

    proc = cycle->processes->elts;
    n = cycle->processes->nelts;

    generation = cycle->process_generation - 1;

    /* The proc[0] is the master process. */

    for (i = 1; i < n; i++) {
        if (proc[i].generation == generation) {
            (void) nxt_chan_write(proc[i].chan, NXT_CHAN_MSG_QUIT, -1, 0, NULL);
        }
    }

    cycle->reconfiguring = 0;
}


void
nxt_master_stop_worker_processes(nxt_cycle_t *cycle)
{
    nxt_process_chan_write(cycle, NXT_CHAN_MSG_QUIT, -1, 0, NULL);
}



static void
nxt_master_process_sigterm_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_log_debug(thr->log, "sigterm handler signo:%d (%s)",
                  (int) (uintptr_t) obj, data);

    /* TODO: fast exit. */

    nxt_exiting = 1;

    nxt_cycle_quit(thr, NULL);
}


static void
nxt_master_process_sigquit_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_log_debug(thr->log, "sigquit handler signo:%d (%s)",
                  (int) (uintptr_t) obj, data);

    /* TODO: graceful exit. */

    nxt_exiting = 1;

    nxt_cycle_quit(thr, NULL);
}


static void
nxt_master_process_sigusr1_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_int_t       ret;
    nxt_uint_t      n;
    nxt_file_t      *file, *new_file;
    nxt_cycle_t     *cycle;
    nxt_array_t     *new_files;
    nxt_mem_pool_t  *mp;

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "signal %d (%s) recevied, %s",
                  (int) (uintptr_t) obj, data, "log files rotation");

    mp = nxt_mem_pool_create(1024);
    if (mp == NULL) {
        return;
    }

    cycle = nxt_thread_cycle();

    n = nxt_list_nelts(cycle->log_files);

    new_files = nxt_array_create(mp, n, sizeof(nxt_file_t));
    if (new_files == NULL) {
        nxt_mem_pool_destroy(mp);
        return;
    }

    nxt_list_each(file, cycle->log_files) {

        /* This allocation cannot fail. */
        new_file = nxt_array_add(new_files);

        new_file->name = file->name;
        new_file->fd = NXT_FILE_INVALID;
        new_file->log_level = NXT_LOG_CRIT;

        ret = nxt_file_open(new_file, NXT_FILE_APPEND, NXT_FILE_CREATE_OR_OPEN,
                            NXT_FILE_OWNER_ACCESS);

        if (ret != NXT_OK) {
            goto fail;
        }

    } nxt_list_loop;

    new_file = new_files->elts;

    ret = nxt_file_stderr(&new_file[0]);

    if (ret == NXT_OK) {
        n = 0;

        nxt_list_each(file, cycle->log_files) {

            nxt_process_chan_change_log_file(cycle, n, new_file[n].fd);
            /*
             * The old log file descriptor must be closed at the moment
             * when no other threads use it.  dup2() allows to use the
             * old file descriptor for new log file.  This change is
             * performed atomically in the kernel.
             */
            (void) nxt_file_redirect(file, new_file[n].fd);

            n++;

        } nxt_list_loop;

        nxt_mem_pool_destroy(mp);
        return;
   }

fail:

    new_file = new_files->elts;
    n = new_files->nelts;

    while (n != 0) {
        if (new_file->fd != NXT_FILE_INVALID) {
            nxt_file_close(new_file);
        }

        new_file++;
        n--;
    }

    nxt_mem_pool_destroy(mp);
}


static void
nxt_master_process_sigusr2_handler(nxt_thread_t *thr, void *obj, void *data)
{
    char         **env;
    nxt_int_t    ret;
    nxt_pid_t    pid, ppid;
    nxt_bool_t   ignore;
    nxt_cycle_t  *cycle;

    cycle = nxt_thread_cycle();

    /* Is upgrade or reconfiguring in progress? */
    ignore = (cycle->new_binary != 0) || cycle->reconfiguring;

    ppid = getppid();

    if (ppid == nxt_ppid && ppid != 1) {
        /*
         * Ignore the upgrade signal in a new master process if an old
         * master process is still running.  After the old process's exit
         * getppid() will return 1 (init process pid) or pid of zsched (zone
         * scheduler) if the processes run in Solaris zone.  There is little
         * race condition between the parent process exit and getting getppid()
         * for the very start of the new master process execution, so init or
         * zsched pid may be stored in nxt_ppid.  For this reason pid 1 is
         * tested explicitly.  There is no workaround for this race condition
         * in Solaris zons.  To eliminate this race condition in Solaris
         * zone the old master process should be quit only when both
         * "nginman.pid.oldbin" (created by the old master process) and
         * "nginman.pid" (created by the new master process) files exists.
         */
        ignore = 1;
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "signal %d (%s) recevied, %s, parent pid: %PI",
                  (int) (uintptr_t) obj, data,
                  ignore ? "ignored" : "online binary file upgrade", ppid);

    if (ignore) {
        return;
    }

    env = nxt_master_process_upgrade_environment(cycle);
    if (nxt_slow_path(env == NULL)) {
        return;
    }

    cycle->new_binary = -1;

    ret = nxt_cycle_pid_file_create(cycle->oldbin_file, 0);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    pid = nxt_process_execute(nxt_process_argv[0], nxt_process_argv, env);

    if (pid == -1) {
        cycle->new_binary = 0;
        (void) nxt_file_delete(cycle->oldbin_file);

    } else {
        cycle->new_binary = pid;
    }

fail:

    /* Zero slot is NGINX variable slot, all other slots must not be free()d. */
    nxt_free(env[0]);
    nxt_free(env);
}


static char **
nxt_master_process_upgrade_environment(nxt_cycle_t *cycle)
{
    size_t               len;
    char                 **env;
    u_char               *p, *end;
    nxt_uint_t           n;
    nxt_listen_socket_t  *ls;

    env = nxt_master_process_upgrade_environment_create(cycle);
    if (nxt_slow_path(env == NULL)) {
        return NULL;
    }

    ls = cycle->listen_sockets->elts;
    n = cycle->listen_sockets->nelts;

    len = sizeof("NGINX=") + n * (NXT_INT_T_LEN + 1);

    p = nxt_malloc(len);

    if (nxt_slow_path(p == NULL)) {
        nxt_free(env);
        return NULL;
    }

    env[0] = (char *) p;
    end = p + len;

    p = nxt_cpymem(p, "NGINX=", sizeof("NGINX=") - 1);

    do {
        p = nxt_sprintf(p, end, "%ud;", ls->socket);

        ls++;
        n--;
    } while (n != 0);

    *p = '\0';

    return env;
}


static char **
nxt_master_process_upgrade_environment_create(nxt_cycle_t *cycle)
{
    char        **env;
    nxt_uint_t  n;

    /* 2 is for "NGINX" variable and the last NULL slot. */
    n = 2;

#if (NXT_SETPROCTITLE_ARGV)
    n++;
#endif

    env = nxt_malloc(n * sizeof(char *));
    if (nxt_slow_path(env == NULL)) {
        return NULL;
    }

    /* Zero slot is reserved for "NGINX" variable. */
    n = 1;

    /* TODO: copy env values */

#if (NXT_SETPROCTITLE_ARGV)

    /* 300 spare bytes for new process title. */
    env[n++] = (char *)
               "SPARE=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
               "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";

#endif

    env[n] = NULL;

    return env;
}


static void
nxt_master_process_sigchld_handler(nxt_thread_t *thr, void *obj, void *data)
{
    int                    status;
    nxt_err_t              err;
    nxt_pid_t              pid;

    nxt_log_debug(thr->log, "sigchld handler signo:%d (%s)",
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
                nxt_log_alert(thr->log, "waitpid() failed: %E", err);
                return;
            }
        }

        nxt_log_debug(thr->log, "waitpid(): %PI", pid);

        if (pid == 0) {
            return;
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            nxt_log_alert(thr->log, "process %PI exited on signal %d%s",
                          pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");
#else
            nxt_log_alert(thr->log, "process %PI exited on signal %d",
                          pid, WTERMSIG(status));
#endif

        } else {
            nxt_log_error(NXT_LOG_NOTICE, thr->log,
                          "process %PI exited with code %d",
                          pid, WEXITSTATUS(status));
        }

        nxt_master_cleanup_worker_process(thr, pid);
    }
}


static void
nxt_master_cleanup_worker_process(nxt_thread_t *thr, nxt_pid_t pid)
{
    nxt_uint_t          i, n, generation;
    nxt_cycle_t         *cycle;
    nxt_process_chan_t  *proc;

    cycle = nxt_thread_cycle();

    if (cycle->new_binary == pid) {
        cycle->new_binary = 0;

        (void) nxt_file_rename(cycle->oldbin_file, cycle->pid_file);
        return;
    }

    proc = cycle->processes->elts;
    n = cycle->processes->nelts;

    for (i = 0; i < n; i++) {

        if (pid == proc[i].pid) {
            generation = proc[i].generation;

            nxt_array_remove(cycle->processes, &proc[i]);

            if (nxt_exiting) {
                nxt_log_debug(thr->log, "processes %d", n);

                if (n == 2) {
                    nxt_cycle_quit(thr, cycle);
                }

            } else if (generation == cycle->process_generation) {
                (void) nxt_master_create_worker_process(cycle);
            }

            return;
        }
    }
}
