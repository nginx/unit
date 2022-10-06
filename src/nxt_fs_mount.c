/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>

#if (NXT_HAVE_FREEBSD_NMOUNT)
#include <sys/param.h>
#include <sys/uio.h>
#endif


#if (NXT_HAVE_LINUX_MOUNT)

nxt_int_t
nxt_fs_mount(nxt_task_t *task, nxt_fs_mount_t *mnt)
{
    int            rc;
    const char     *fsname;
    unsigned long  flags;

    flags = 0;

    switch (mnt->type) {
    case NXT_FS_BIND:
        if (nxt_slow_path(mnt->flags != 0)) {
            nxt_log(task, NXT_LOG_WARN,
                    "bind mount ignores additional flags");
        }

        fsname = "bind";
        flags = MS_BIND | MS_REC;
        break;

    case NXT_FS_PROC:
        fsname = "proc";
        goto getflags;

    case NXT_FS_TMP:
        fsname = "tmpfs";
        goto getflags;

    default:
        fsname = (const char *) mnt->name;

    getflags:

        if (mnt->flags & NXT_FS_FLAGS_NODEV) {
            flags |= MS_NODEV;
        }

        if (mnt->flags & NXT_FS_FLAGS_NOEXEC) {
            flags |= MS_NOEXEC;
        }

        if (mnt->flags & NXT_FS_FLAGS_NOSUID) {
            flags |= MS_NOSUID;
        }

        if (!(mnt->flags & NXT_FS_FLAGS_NOTIME)) {
            flags |= MS_RELATIME;
        }
    }

    rc = mount((const char *) mnt->src, (const char *) mnt->dst, fsname, flags,
               mnt->data);

    if (nxt_slow_path(rc < 0)) {
        nxt_alert(task, "mount(\"%s\", \"%s\", \"%s\", %ul, \"%s\") %E",
                  mnt->src, mnt->dst, fsname, flags, mnt->data, nxt_errno);

        return NXT_ERROR;
    }

    return NXT_OK;
}

#elif (NXT_HAVE_FREEBSD_NMOUNT)

nxt_int_t
nxt_fs_mount(nxt_task_t *task, nxt_fs_mount_t *mnt)
{
    int           flags;
    u_char        *data, *p, *end;
    size_t        iovlen;
    nxt_int_t     ret;
    const char    *fsname;
    struct iovec  iov[128];
    char          errmsg[256];

    if (nxt_slow_path((mnt->flags & NXT_FS_FLAGS_NODEV) && !mnt->builtin)) {
        nxt_alert(task, "nmount(2) doesn't support \"nodev\" option");

        return NXT_ERROR;
    }

    flags = 0;

    switch (mnt->type) {
    case NXT_FS_BIND:
        fsname = "nullfs";
        break;

    case NXT_FS_PROC:
        fsname = "procfs";
        goto getflags;

    case NXT_FS_TMP:
        fsname = "tmpfs";
        goto getflags;

    default:
        fsname = (const char *) mnt->name;

    getflags:

        if (mnt->flags & NXT_FS_FLAGS_NOEXEC) {
            flags |= MNT_NOEXEC;
        }

        if (mnt->flags & NXT_FS_FLAGS_NOSUID) {
            flags |= MNT_NOSUID;
        }

        if (mnt->flags & NXT_FS_FLAGS_NOTIME) {
            flags |= MNT_NOATIME;
        }

        if (mnt->flags & NXT_FS_FLAGS_RDONLY) {
            flags |= MNT_RDONLY;
        }
    }

    iov[0].iov_base = (void *) "fstype";
    iov[0].iov_len = 7;
    iov[1].iov_base = (void *) fsname;
    iov[1].iov_len = nxt_strlen(fsname) + 1;
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

            iov[iovlen].iov_base = (void *) p;
            iov[iovlen].iov_len = (end - p) + 1;

            iovlen++;

            p = end + 1;

            end = nxt_strchr(p, ',');
            if (end != NULL) {
                *end = '\0';
            }

            iov[iovlen].iov_base = (void *) p;
            iov[iovlen].iov_len = nxt_strlen(p) + 1;

            iovlen++;

        } while (end != NULL && nxt_nitems(iov) > (iovlen + 2));
    }

    ret = NXT_OK;

    if (nxt_slow_path(nmount(iov, iovlen, flags) < 0)) {
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
