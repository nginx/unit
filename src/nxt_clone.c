/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <sys/types.h>
#include <nxt_conf.h>
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

/* map uid 65534 to unit pid */
#define NXT_DEFAULT_UNPRIV_MAP "65534 %d 1"

nxt_int_t nxt_clone_proc_setgroups(nxt_task_t *task,
        pid_t child_pid, const char *str);
nxt_int_t nxt_clone_proc_map_set(nxt_task_t *task, const char* mapfile,
        pid_t pid, nxt_int_t defval, nxt_conf_value_t *mapobj);
nxt_int_t nxt_clone_proc_map_write(nxt_task_t *task, const char *mapfile,
        pid_t pid, u_char *mapinfo);

typedef struct {
    nxt_int_t containerID;
    nxt_int_t hostID;
    nxt_int_t size;
} nxt_clone_procmap_t;

nxt_int_t
nxt_clone_proc_setgroups(nxt_task_t *task, pid_t child_pid, const char *str)
{
    int     fd, n;
    u_char  *p, *end;
    u_char  path[PATH_MAX];

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
nxt_clone_proc_map_write(nxt_task_t *task, const char *mapfile,
        pid_t pid, u_char *mapinfo)
{
    int     len, mapfd;
    u_char  *p, *end;
    u_char  buf[256];

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
    if (nxt_slow_path(write(mapfd, (char *)mapinfo, len) != len)) {
        nxt_alert(task, "failed to write proc map (%s): %s", buf,
            strerror(nxt_errno));
        return NXT_ERROR;
    }

    return NXT_OK;
}

nxt_int_t
nxt_clone_proc_map_set(nxt_task_t *task, const char* mapfile,
        pid_t pid, nxt_int_t defval, nxt_conf_value_t *mapobj)
{
    u_char            *p, *end, *mapinfo;
    nxt_int_t         contID, hostID, size;
    nxt_int_t         ret, len, count, i;
    nxt_conf_value_t  *obj;
    nxt_conf_value_t  *value;
    nxt_str_t         str_contID = nxt_string("containerID");
    nxt_str_t         str_hostID = nxt_string("hostID");
    nxt_str_t         str_size   = nxt_string("size");

    /**
     * uid_map one-entry size:
     *   alloc space for 3 numbers (32bit) plus 2 spaces and \n
     */
    len = sizeof(u_char) * (10+10+10+2+1);

    if (mapobj != NULL) {
        count = nxt_conf_array_elements_count(mapobj);
        if (count > NXT_CLONE_MAX_UID_LINES) {
            nxt_alert(task, "too many uidmap entries: (%d > %d)",
                count, NXT_CLONE_MAX_UID_LINES);
            return NXT_ERROR;
        }

        if (count == 0) {
            goto default_map;
        }

        len = len * count + 1;
        mapinfo = nxt_malloc(len);
        if (nxt_slow_path(mapinfo == NULL)) {
            nxt_alert(task, "failed to allocate uid_map buffer");
            return NXT_ERROR;
        }

        p = mapinfo;
        end = mapinfo + len;

        for (i = 0; i < count; i++) {
            obj = nxt_conf_get_array_element(mapobj, i);

            value = nxt_conf_get_object_member(obj, &str_contID, NULL);
            contID = nxt_conf_get_integer(value);

            value = nxt_conf_get_object_member(obj, &str_hostID, NULL);
            hostID = nxt_conf_get_integer(value);

            value = nxt_conf_get_object_member(obj, &str_size, NULL);
            size = nxt_conf_get_integer(value);

            p = nxt_sprintf(p, end, "%d %d %d", contID, hostID, size);
            if (nxt_slow_path(p == end)) {
                nxt_alert(task, "write past the uid_map buffer");
                nxt_free(mapinfo);
                return NXT_ERROR;
            }

            if (i+1 < count) {
                *p++ = '\n';
            } else {
                *p = '\0';
            }
        }
    } else {
default_map:
        mapinfo = nxt_malloc(len);
        if (nxt_slow_path(mapinfo == NULL)) {
            nxt_alert(task, "failed to allocate uid_map buffer");
            return NXT_ERROR;
        }

        end = mapinfo + len;
        p = nxt_sprintf(mapinfo, end, NXT_DEFAULT_UNPRIV_MAP, defval);
        *p = '\0';

        if (nxt_slow_path(p == end)) {
            nxt_alert(task, "write past the %s buffer", mapfile);
            nxt_free(mapinfo);
            return NXT_ERROR;
        }
    }

    ret = nxt_clone_proc_map_write(task, mapfile, pid, mapinfo);

    nxt_free(mapinfo);

    return ret;
}

nxt_int_t
nxt_clone_proc_map(nxt_task_t *task, pid_t pid, nxt_process_clone_t *clone)
{
    nxt_int_t      ret;
    nxt_int_t      uid, gid;
    const char     *rule;
    nxt_runtime_t  *rt;

    rt  = task->thread->runtime;
    uid = rt->user_cred.uid;
    gid = rt->user_cred.base_gid;

    if (rt->capabilities.setid) {
        rule = "allow";
    } else {
        rule = "deny";
    }

    ret = nxt_clone_proc_map_set(task, "uid_map", pid, uid, clone->uidmap);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    ret = nxt_clone_proc_setgroups(task, pid, rule);
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_alert(task, "failed to write /proc/%d/setgroups", pid);
        return NXT_ERROR;
    }

    ret = nxt_clone_proc_map_set(task, "gid_map", pid, gid, clone->gidmap);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}

#endif
