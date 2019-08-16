/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */
#include <nxt_main.h>
#include <sys/types.h>
#include <nxt_clone.h>

#if (NXT_HAVE_CLONE)

pid_t 
nxt_clone(nxt_int_t flags)
{
#if defined(__s390x__) || defined(__s390__) || defined(__CRIS__)
    return syscall(__NR_clone, NULL, flags);
#else
    return syscall(__NR_clone, flags, NULL);
#endif
}

#endif

#if (NXT_HAVE_CLONE_NEWUSER)

nxt_int_t
nxt_clone_proc_setgroups(nxt_task_t *task, pid_t child_pid, const char *str)
{
    u_char path[PATH_MAX];
    u_char *p, *end;
    int    fd;
    int    n;

    end = path + PATH_MAX;
    p = nxt_sprintf(path, end, "/proc/%d/setgroups", child_pid);
    *p = '\0';

    if (nxt_slow_path(p == end)) {
        nxt_alert(task, "error write past the buffer: %s", path);
        return NXT_ERROR;
    }

    fd = open((char *)path, O_RDWR);
    if (fd == -1) {
        /**
         * If the /proc/pid/setgroups doesn't exists, we are
         * safe to set uid/gid maps. But if the error is anything
         * other than ENOENT, then we should abort and let user know.
         */
        if (errno != ENOENT) {
            nxt_alert(task, "open(%s): %E", path, nxt_errno);
            return NXT_ERROR;
        }

        return NXT_OK;
    }

    n = write(fd, str, strlen(str));
    close(fd);

    if (nxt_slow_path(n == -1)) {
        nxt_alert(task, "write(%s): %E", path, nxt_errno);
        return NXT_ERROR;
    }

    return NXT_OK;
}

nxt_int_t 
nxt_clone_proc_map_set(nxt_task_t *task, const char *mapfile, 
        pid_t pid, const char *mapinfo)
{
    u_char buf[256];
    u_char *end; 
    u_char *p;
    int    mapfd;
    int    len;

    end = buf + sizeof(buf);
    p = nxt_sprintf(buf, end, "/proc/%d/%s", pid, mapfile);
    if (nxt_slow_path(p == end)) {
        nxt_alert(task, "writing past the buffer");
        return NXT_ERROR;
    }

    *p = '\0';

    mapfd = open((char*)buf, O_RDWR);
    if (nxt_slow_path(mapfd == -1)) {
        nxt_alert(task, "failed to open proc map (%s): (%s)", buf, 
            strerror(nxt_errno));
        return NXT_ERROR;
    }

    len = nxt_strlen(mapinfo);
    if (nxt_slow_path(write(mapfd, mapinfo, len) != len)) {
        nxt_alert(task, "failed to write proc map (%s): %s", buf,
            strerror(nxt_errno));
        return NXT_ERROR;
    }

    return NXT_OK;
}

nxt_int_t 
nxt_clone_proc_map(nxt_task_t *task, pid_t pid)
{
    nxt_int_t ret;

    /**
     * TODO(i4k): For now, just map the uid 1000 from host to 0 (root)
     * inside the namespace. Soon I'll add a config for that.
     * 
     * The process in the new namespace has the full set of capabilities 
     * on the namespace but none in the parent. Also, inside the namespace
     * it has root powers.
     */
    ret = nxt_clone_proc_map_set(task, "uid_map", pid, "0 1000 1");
    if (nxt_slow_path(ret != NXT_OK)) {
           nxt_alert(task, "failed to set uid map");
           return NXT_ERROR;
    }

    ret = nxt_clone_proc_setgroups(task, pid, "deny");
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_alert(task, "failed to write /proc/%d/setgroups", pid);
        return NXT_ERROR;
    }

    ret = nxt_clone_proc_map_set(task, "gid_map", pid, "0 1000 1");
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_alert(task, "failed to set gid map");
        return NXT_ERROR;
    }

    return NXT_OK;
}

#endif
