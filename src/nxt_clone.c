/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <sys/types.h>
#include <nxt_conf.h>
#include <nxt_clone.h>


#if (NXT_HAVE_CLONE_NEWUSER)

static inline id_t nxt_id_map_host2container(nxt_task_t *task, id_t host_id,
    const nxt_clone_map_entry_t *map);
static inline nxt_bool_t nxt_idmap_includes_host_id(id_t host_id,
    const nxt_clone_map_entry_t *map);

nxt_int_t nxt_clone_credential_setgroups(nxt_task_t *task, pid_t child_pid,
    const char *str);
nxt_int_t nxt_clone_credential_map_set(nxt_task_t *task, const char* mapfile,
    pid_t pid, nxt_int_t default_container, nxt_int_t default_host,
    nxt_clone_credential_map_t *map);
nxt_int_t nxt_clone_credential_map_write(nxt_task_t *task, const char *mapfile,
    pid_t pid, u_char *mapinfo);


nxt_int_t
nxt_clone_credential_setgroups(nxt_task_t *task, pid_t child_pid,
    const char *str)
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
        /*
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
nxt_clone_credential_map_write(nxt_task_t *task, const char *mapfile,
    pid_t pid, u_char *mapinfo)
{
    int      len, mapfd;
    u_char   *p, *end;
    ssize_t  n;
    u_char   buf[256];

    end = buf + sizeof(buf);

    p = nxt_sprintf(buf, end, "/proc/%d/%s", pid, mapfile);
    if (nxt_slow_path(p == end)) {
        nxt_alert(task, "writing past the buffer");
        return NXT_ERROR;
    }

    *p = '\0';

    mapfd = open((char*)buf, O_RDWR);
    if (nxt_slow_path(mapfd == -1)) {
        nxt_alert(task, "failed to open proc map (%s) %E", buf, nxt_errno);
        return NXT_ERROR;
    }

    len = nxt_strlen(mapinfo);

    n = write(mapfd, (char *)mapinfo, len);
    if (nxt_slow_path(n != len)) {

        if (n == -1 && nxt_errno == EINVAL) {
            nxt_alert(task, "failed to write %s: Check kernel maximum " \
                      "allowed lines %E", buf, nxt_errno);

        } else {
            nxt_alert(task, "failed to write proc map (%s) %E", buf,
                      nxt_errno);
        }

        close(mapfd);

        return NXT_ERROR;
    }

    close(mapfd);

    return NXT_OK;
}


nxt_int_t
nxt_clone_credential_map_set(nxt_task_t *task, const char* mapfile, pid_t pid,
    nxt_int_t default_container, nxt_int_t default_host,
    nxt_clone_credential_map_t *map)
{
    u_char      *p, *end, *mapinfo;
    nxt_int_t   ret, len;
    nxt_uint_t  i;

    /*
     * uid_map one-entry size:
     *   alloc space for 3 numbers (32bit) plus 2 spaces and \n.
     */
    len = sizeof(u_char) * (10 + 10 + 10 + 2 + 1);

    if (map->size > 0) {
        len = len * map->size + 1;

        mapinfo = nxt_malloc(len);
        if (nxt_slow_path(mapinfo == NULL)) {
            return NXT_ERROR;
        }

        p = mapinfo;
        end = mapinfo + len;

        for (i = 0; i < map->size; i++) {
            p = nxt_sprintf(p, end, "%d %d %d", map->map[i].container,
                            map->map[i].host, map->map[i].size);

            if (nxt_slow_path(p == end)) {
                nxt_alert(task, "write past the mapinfo buffer");
                nxt_free(mapinfo);
                return NXT_ERROR;
            }

            if (i+1 < map->size) {
                *p++ = '\n';

            } else {
                *p = '\0';
            }
        }

    } else {
        mapinfo = nxt_malloc(len);
        if (nxt_slow_path(mapinfo == NULL)) {
            return NXT_ERROR;
        }

        end = mapinfo + len;
        p = nxt_sprintf(mapinfo, end, "%d %d 1",
                        default_container, default_host);
        *p = '\0';

        if (nxt_slow_path(p == end)) {
            nxt_alert(task, "write past mapinfo buffer");
            nxt_free(mapinfo);
            return NXT_ERROR;
        }
    }

    ret = nxt_clone_credential_map_write(task, mapfile, pid, mapinfo);

    nxt_free(mapinfo);

    return ret;
}


nxt_int_t
nxt_clone_credential_map(nxt_task_t *task, pid_t pid,
    nxt_credential_t *app_creds, nxt_clone_t *clone)
{
    nxt_int_t      ret;
    nxt_int_t      default_host_uid;
    nxt_int_t      default_host_gid;
    const char     *rule;
    nxt_runtime_t  *rt;

    rt  = task->thread->runtime;

    if (rt->capabilities.setid) {
        rule = "allow";

        /*
         * By default we don't map a privileged user
         */
        default_host_uid = app_creds->uid;
        default_host_gid = app_creds->base_gid;
    } else {
        rule = "deny";

        default_host_uid = nxt_euid;
        default_host_gid = nxt_egid;
    }

    ret = nxt_clone_credential_map_set(task, "uid_map", pid, app_creds->uid,
                                       default_host_uid,
                                       &clone->uidmap);

    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    ret = nxt_clone_credential_setgroups(task, pid, rule);
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_alert(task, "failed to write /proc/%d/setgroups", pid);
        return NXT_ERROR;
    }

    ret = nxt_clone_credential_map_set(task, "gid_map", pid, app_creds->base_gid,
                                       default_host_gid,
                                       &clone->gidmap);

    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_int_t
nxt_clone_vldt_credential_uidmap(nxt_task_t *task,
    nxt_clone_credential_map_t *map, nxt_credential_t *creds)
{
    nxt_uint_t                   i;
    const nxt_clone_map_entry_t  *m;

    if (map->size == 0) {
        return NXT_OK;
    }

    for (i = 0; i < map->size; i++) {
        m = &map->map[i];

        if (nxt_idmap_includes_host_id(creds->uid, m)) {
            creds->uid = nxt_id_map_host2container(task, creds->uid, m);
            return NXT_OK;
        }
    }

    nxt_log(task, NXT_LOG_NOTICE,
            "\"uidmap\" field has no \"host\" entry for user \"%s\" (uid %d)",
            creds->user, creds->uid);

    return NXT_ERROR;
}


nxt_int_t
nxt_clone_vldt_credential_gidmap(nxt_task_t *task,
    nxt_clone_credential_map_t *map, nxt_credential_t *creds)
{
    nxt_uint_t                   base_ok, gid_ok, gids_ok;
    nxt_uint_t                   i, j;
    nxt_runtime_t                *rt;
    const nxt_clone_map_entry_t  *m;

    rt = task->thread->runtime;

    if (map->size == 0) {
        if (!rt->capabilities.setid) {
            return NXT_OK;
        }

        if (creds->ngroups == 0
            || (creds->ngroups == 1 && creds->gids[0] == creds->base_gid))
        {
            return NXT_OK;
        }

        nxt_log(task, NXT_LOG_ERR, "\"gidmap\" field has no entries but user "
                "\"%s\" has %d suplementary group%s.",
                creds->user, creds->ngroups, creds->ngroups > 1 ? "s" : "");

        return NXT_ERROR;
    }

    base_ok = 0;
    for (i = 0; i < map->size; i++) {
        m = &map->map[i];

        if (nxt_idmap_includes_host_id(creds->base_gid, m)) {
            creds->base_gid = nxt_id_map_host2container(task, creds->base_gid,
                                                        m);
            base_ok = 1;
            break;
        }
    }

    if (nxt_slow_path(!base_ok)) {
        nxt_log(task, NXT_LOG_ERR,
                "\"gidmap\" field has no \"host\" entry for gid %d.",
                creds->base_gid);

        return NXT_ERROR;
    }

    if (!rt->capabilities.setid) {
        return NXT_OK;
    }

    gids_ok = 0;
    for (i = 0; i < creds->ngroups; i++) {
        gid_ok = 0;

        for (j = 0; j < map->size; j++) {
            m = &map->map[j];

            if (nxt_idmap_includes_host_id(creds->gids[i], m)) {
                creds->gids[i] = nxt_id_map_host2container(task, creds->gids[i],
                                                           m);
                gid_ok = 1;
                break;
            }
        }

        if (nxt_fast_path(gid_ok)) {
            gids_ok++;
        }
    }

    if (nxt_slow_path(gids_ok < creds->ngroups)) {
        nxt_log(task, NXT_LOG_ERR,
                "\"gidmap\" field has missing suplementary gid mappings (found"
                " %d out of %d).", gids_ok, creds->ngroups);

        return NXT_ERROR;
    }

    return NXT_OK;
}


static inline id_t
nxt_id_map_host2container(nxt_task_t *task, id_t host_id,
    const nxt_clone_map_entry_t *map)
{
    id_t  host_start, container_start, container_id;

    host_start = map->host;
    container_start = map->container;

    container_id = host_id - host_start + container_start;

    nxt_log(task, NXT_LOG_DEBUG, "mapped host id %d to container id %d.",
            (int) host_id, (int) container_id);

    return container_id;
}


static inline nxt_bool_t
nxt_idmap_includes_host_id(id_t host_id, const nxt_clone_map_entry_t *map)
{
    id_t  host_start, map_size;

    host_start = map->host;
    map_size = map->size;

    return (host_id >= host_start && host_id < host_start + map_size);
}

#endif
