/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>

#if (NXT_HAVE_FREEBSD_NMOUNT)
#include <sys/param.h>
#include <sys/uio.h>
#endif


static nxt_int_t nxt_fs_mkdir(const u_char *dir, mode_t mode);


#if (NXT_HAVE_LINUX_MOUNT)

nxt_int_t
nxt_fs_mount(nxt_task_t *task, nxt_fs_mount_t *mnt)
{
    int  rc;

    rc = mount((const char *) mnt->src, (const char *) mnt->dst,
               (const char *) mnt->fstype, mnt->flags, mnt->data);

    if (nxt_slow_path(rc < 0)) {
        nxt_alert(task, "mount(\"%s\", \"%s\", \"%s\", %d, \"%s\") %E",
                  mnt->src, mnt->dst, mnt->fstype, mnt->flags, mnt->data,
                  nxt_errno);

        return NXT_ERROR;
    }

    return NXT_OK;
}


#elif (NXT_HAVE_FREEBSD_NMOUNT)

nxt_int_t
nxt_fs_mount(nxt_task_t *task, nxt_fs_mount_t *mnt)
{
    u_char        *data, *p, *end;
    size_t        iovlen;
    nxt_int_t     ret;
    const char    *fstype;
    struct iovec  iov[128];
    char          errmsg[256];

    if (nxt_strncmp(mnt->fstype, "bind", 4) == 0) {
        fstype = "nullfs";

    } else if (nxt_strncmp(mnt->fstype, "proc", 4) == 0) {
        fstype = "procfs";

    } else if (nxt_strncmp(mnt->fstype, "tmpfs", 5) == 0) {
        fstype = "tmpfs";

    } else {
        nxt_alert(task, "mount type \"%s\" not implemented.", mnt->fstype);
        return NXT_ERROR;
    }

    iov[0].iov_base = (void *) "fstype";
    iov[0].iov_len = 7;
    iov[1].iov_base = (void *) fstype;
    iov[1].iov_len = nxt_strlen(fstype) + 1;
    iov[2].iov_base = (void *) "fspath";
    iov[2].iov_len = 7;
    iov[3].iov_base = (void *) mnt->dst;
    iov[3].iov_len = nxt_strlen(mnt->dst) + 1;
    iov[4].iov_base = (void *) "target";
    iov[4].iov_len = 7;
    iov[5].iov_base = (void *) mnt->src;
    iov[5].iov_len = nxt_strlen(mnt->src) + 1;
    iov[6].iov_base = (void *) "errmsg";
    iov[6].iov_len = 7;
    iov[7].iov_base = (void *) errmsg;
    iov[7].iov_len = sizeof(errmsg);

    iovlen = 8;

    data = NULL;

    if (mnt->data != NULL) {
        data = (u_char *) nxt_strdup(mnt->data);
        if (nxt_slow_path(data == NULL)) {
            return NXT_ERROR;
        }

        end = data - 1;

        do {
            p = end + 1;
            end = nxt_strchr(p, '=');
            if (end == NULL) {
                break;
            }

            *end = '\0';

            iov[iovlen++].iov_base = (void *) p;
            iov[iovlen++].iov_len = (end - p) + 1;

            p = end + 1;

            end = nxt_strchr(p, ',');
            if (end != NULL) {
                *end = '\0';
            }

            iov[iovlen++].iov_base = (void *) p;
            iov[iovlen++].iov_len = nxt_strlen(p) + 1;

        } while (end != NULL && nxt_nitems(iov) > (iovlen + 2));
    }

    ret = NXT_OK;

    if (nxt_slow_path(nmount(iov, iovlen, 0) < 0)) {
        nxt_alert(task, "nmount(%p, %d, 0) %s", iov, iovlen, errmsg);
        ret = NXT_ERROR;
    }

    if (data != NULL) {
        free(data);
    }

    return ret;
}

#endif


#if (NXT_HAVE_LINUX_UMOUNT2)

void
nxt_fs_unmount(const u_char *path)
{
    if (nxt_slow_path(umount2((const char *) path, MNT_DETACH) < 0)) {
        nxt_thread_log_error(NXT_LOG_WARN, "umount2(%s, MNT_DETACH) %E",
                             path, nxt_errno);
    }
}

#elif (NXT_HAVE_UNMOUNT)

void
nxt_fs_unmount(const u_char *path)
{
    if (nxt_slow_path(unmount((const char *) path, MNT_FORCE) < 0)) {
        nxt_thread_log_error(NXT_LOG_WARN, "unmount(%s) %E", path, nxt_errno);
    }
}

#endif


nxt_int_t
nxt_fs_mkdir_all(const u_char *dir, mode_t mode)
{
    char    *start, *end, *dst;
    size_t  dirlen;
    char    path[PATH_MAX];

    dirlen = nxt_strlen(dir);

    nxt_assert(dirlen < PATH_MAX && dirlen > 1 && dir[0] == '/');

    dst = path;
    start = end = (char *) dir;

    while (*start != '\0') {
        if (*start == '/') {
            *dst++ = *start++;
        }

        end = strchr(start, '/');
        if (end == NULL) {
            end = ((char *)dir + dirlen);
        }

        dst = nxt_cpymem(dst, start, end - start);
        *dst = '\0';

        if (nxt_slow_path(nxt_fs_mkdir((u_char *) path, mode) != NXT_OK
                          && nxt_errno != EEXIST))
        {
            return NXT_ERROR;
        }

        start = end;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_fs_mkdir(const u_char *dir, mode_t mode)
{
    if (nxt_fast_path(mkdir((const char *) dir, mode) == 0)) {
        return NXT_OK;
    }

    return NXT_ERROR;
}
