
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_user_groups_get(nxt_user_cred_t *uc);


/* A cached process pid. */
nxt_pid_t  nxt_pid;

/* An original parent process pid. */
nxt_pid_t  nxt_ppid;


nxt_pid_t
nxt_process_create(nxt_process_start_t start, void *data, const char *name)
{
    nxt_pid_t     pid;
    nxt_thread_t  *thr;

    thr = nxt_thread();

    pid = fork();

    switch (pid) {

    case -1:
        nxt_log_alert(thr->log, "fork() failed while creating \"%s\" %E",
                      name, nxt_errno);
        break;

    case 0:
        /* A child. */
        nxt_pid = getpid();

        /* Clean inherited cached thread tid. */
        thr->tid = 0;

        start(data);
        break;

    default:
        /* A parent. */
        nxt_log_debug(thr->log, "fork(): %PI", pid);
        break;
    }

    return pid;
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
nxt_process_execute(char *name, char **argv, char **envp)
{
    nxt_pid_t  pid;

    nxt_thread_log_debug("posix_spawn(\"%s\")", name);

    if (posix_spawn(&pid, name, NULL, NULL, argv, envp) != 0) {
        nxt_thread_log_alert("posix_spawn(\"%s\") failed %E", name, nxt_errno);
        return -1;
    }

    return pid;
}

#else

nxt_pid_t
nxt_process_execute(char *name, char **argv, char **envp)
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
        nxt_thread_log_alert("vfork() failed while executing \"%s\" %E",
                             name, nxt_errno);
        break;

    case 0:
        /* A child. */
        nxt_thread_log_debug("execve(\"%s\")", name);

        (void) execve(name, argv, envp);

        nxt_thread_log_alert("execve(\"%s\") failed %E", name, nxt_errno);

        exit(1);
        break;

    default:
        /* A parent. */
        nxt_thread_log_debug("vfork(): %PI", pid);
        break;
    }

    return pid;
}

#endif


nxt_int_t
nxt_process_daemon(void)
{
    nxt_fd_t      fd;
    nxt_pid_t     pid;
    const char    *msg;
    nxt_thread_t  *thr;

    thr = nxt_thread();

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
        nxt_log_debug(thr->log, "fork(): %PI", pid);
        exit(0);
        nxt_unreachable();
    }

    nxt_pid = getpid();

    /* Clean inherited cached thread tid. */
    thr->tid = 0;

    nxt_log_debug(thr->log, "daemon");

    /* Detach from controlling terminal. */

    if (setsid() == -1) {
        nxt_log_emerg(thr->log, "setsid() failed %E", nxt_errno);
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

    nxt_log_emerg(thr->log, msg, nxt_errno);

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


nxt_int_t
nxt_user_cred_get(nxt_user_cred_t *uc, const char *group)
{
    struct group   *grp;
    struct passwd  *pwd;

    pwd = getpwnam(uc->user);

    if (nxt_slow_path(pwd == NULL)) {
        nxt_thread_log_emerg("getpwnam(%s) failed %E", uc->user, nxt_errno);
        return NXT_ERROR;
    }

    uc->uid = pwd->pw_uid;
    uc->base_gid = pwd->pw_gid;

    if (group != NULL) {
        grp = getgrnam(group);

        if (nxt_slow_path(grp == NULL)) {
            nxt_thread_log_emerg("getgrnam(%s) failed %E", group, nxt_errno);
            return NXT_ERROR;
        }

        uc->base_gid = grp->gr_gid;
    }

    if (getuid() == 0) {
        return nxt_user_groups_get(uc);
    }

    return NXT_OK;
}


/*
 * nxt_user_groups_get() stores an array of groups IDs which should be
 * set by the initgroups() function for a given user.  The initgroups()
 * may block a just forked worker process for some time if LDAP or NDIS+
 * is used, so nxt_user_groups_get() allows to get worker user groups in
 * master process.  In a nutshell the initgroups() calls getgrouplist()
 * followed by setgroups().  However Solaris lacks the getgrouplist().
 * Besides getgrouplist() does not allow to query the exact number of
 * groups while NGROUPS_MAX can be quite large (e.g. 65536 on Linux).
 * So nxt_user_groups_get() emulates getgrouplist(): at first the function
 * saves the super-user groups IDs, then calls initgroups() and saves the
 * specified user groups IDs, and then restores the super-user groups IDs.
 * This works at least on Linux, FreeBSD, and Solaris, but does not work
 * on MacOSX, getgroups(2):
 *
 *   To provide compatibility with applications that use getgroups() in
 *   environments where users may be in more than {NGROUPS_MAX} groups,
 *   a variant of getgroups(), obtained when compiling with either the
 *   macros _DARWIN_UNLIMITED_GETGROUPS or _DARWIN_C_SOURCE defined, can
 *   be used that is not limited to {NGROUPS_MAX} groups.  However, this
 *   variant only returns the user's default group access list and not
 *   the group list modified by a call to setgroups(2).
 *
 * For such cases initgroups() is used in worker process as fallback.
 */

static nxt_int_t
nxt_user_groups_get(nxt_user_cred_t *uc)
{
    int        nsaved, ngroups;
    nxt_int_t  ret;
    nxt_gid_t  *saved;

    nsaved = getgroups(0, NULL);

    if (nsaved == -1) {
        nxt_thread_log_emerg("getgroups(0, NULL) failed %E", nxt_errno);
        return NXT_ERROR;
    }

    nxt_thread_log_debug("getgroups(0, NULL): %d", nsaved);

    if (nsaved > NGROUPS_MAX) {
        /* MacOSX case. */
        return NXT_OK;
    }

    saved = nxt_malloc(nsaved * sizeof(nxt_gid_t));

    if (saved == NULL) {
        return NXT_ERROR;
    }

    ret = NXT_ERROR;

    nsaved = getgroups(nsaved, saved);

    if (nsaved == -1) {
        nxt_thread_log_emerg("getgroups(%d) failed %E", nsaved, nxt_errno);
        goto fail;
    }

    nxt_thread_log_debug("getgroups(): %d", nsaved);

    if (initgroups(uc->user, uc->base_gid) != 0) {
        nxt_thread_log_emerg("initgroups(%s, %d) failed",
                             uc->user, uc->base_gid);
        goto restore;
    }

    ngroups = getgroups(0, NULL);

    if (ngroups == -1) {
        nxt_thread_log_emerg("getgroups(0, NULL) failed %E", nxt_errno);
        goto restore;
    }

    nxt_thread_log_debug("getgroups(0, NULL): %d", ngroups);

    uc->gids = nxt_malloc(ngroups * sizeof(nxt_gid_t));

    if (uc->gids == NULL) {
        goto restore;
    }

    ngroups = getgroups(ngroups, uc->gids);

    if (ngroups == -1) {
        nxt_thread_log_emerg("getgroups(%d) failed %E", ngroups, nxt_errno);
        goto restore;
    }

    uc->ngroups = ngroups;

#if (NXT_DEBUG)
    {
        u_char      *p, *end;
        nxt_uint_t  i;
        u_char      msg[NXT_MAX_ERROR_STR];

        p = msg;
        end = msg + NXT_MAX_ERROR_STR;

        for (i = 0; i < uc->ngroups; i++) {
            p = nxt_sprintf(p, end, "%uL:", (uint64_t) uc->gids[i]);
        }

        nxt_thread_log_debug("user \"%s\" cred: uid:%uL base gid:%uL, gids:%*s",
                             uc->user, (uint64_t) uc->uid,
                             (uint64_t) uc->base_gid, p - msg, msg);
    }
#endif

    ret = NXT_OK;

restore:

    if (setgroups(nsaved, saved) != 0) {
        nxt_thread_log_emerg("setgroups(%d) failed %E", nsaved, nxt_errno);
        ret = NXT_ERROR;
    }

fail:

    nxt_free(saved);

    return ret;
}


nxt_int_t
nxt_user_cred_set(nxt_user_cred_t *uc)
{
    nxt_thread_log_debug("user cred set: \"%s\" uid:%uL base gid:%uL",
                         uc->user, (uint64_t) uc->uid, uc->base_gid);

    if (setgid(uc->base_gid) != 0) {
        nxt_thread_log_emerg("setgid(%d) failed %E", uc->base_gid, nxt_errno);
        return NXT_ERROR;
    }

    if (uc->gids != NULL) {
        if (setgroups(uc->ngroups, uc->gids) != 0) {
            nxt_thread_log_emerg("setgroups(%i) failed %E",
                                 uc->ngroups, nxt_errno);
            return NXT_ERROR;
        }

    } else {
        /* MacOSX fallback. */
        if (initgroups(uc->user, uc->base_gid) != 0) {
            nxt_thread_log_emerg("initgroups(%s, %d) failed",
                                 uc->user, uc->base_gid);
            return NXT_ERROR;
        }
    }

    if (setuid(uc->uid) != 0) {
        nxt_thread_log_emerg("setuid(%d) failed %E", uc->uid, nxt_errno);
        return NXT_ERROR;
    }

    return NXT_OK;
}
