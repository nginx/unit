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
    const char    *fstype;
    uint8_t       is_bind, is_proc;
    struct iovec  iov[8];
    char          errmsg[256];

    is_bind = nxt_strncmp(mnt->fstype, "bind", 4) == 0;
    is_proc = nxt_strncmp(mnt->fstype, "proc", 4) == 0;

    if (nxt_slow_path(!is_bind && !is_proc)) {
        nxt_alert(task, "mount type \"%s\" not implemented.", mnt->fstype);
        return NXT_ERROR;
    }

    if (is_bind) {
        fstype = "nullfs";

    } else {
        fstype = "procfs";
    }

    iov[0].iov_base = (void *) "fstype";
    iov[0].iov_len = 7;
    iov[1].iov_base = (void *) fstype;
    iov[1].iov_len = strlen(fstype) + 1;
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

    if (nxt_slow_path(nmount(iov, 8, 0) < 0)) {
        nxt_alert(task, "nmount(%p, 8, 0) %s", errmsg);
        return NXT_ERROR;
    }

    return NXT_OK;
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
