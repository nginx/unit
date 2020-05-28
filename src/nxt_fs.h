/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_FS_H_INCLUDED_
#define _NXT_FS_H_INCLUDED_


#ifdef MS_BIND
#define NXT_MS_BIND MS_BIND
#else
#define NXT_MS_BIND 0
#endif

#ifdef MS_REC
#define NXT_MS_REC MS_BIND
#else
#define NXT_MS_REC 0
#endif


typedef struct {
    u_char     *src;
    u_char     *dst;
    u_char     *fstype;
    nxt_int_t  flags;
    u_char     *data;
} nxt_fs_mount_t;


nxt_int_t nxt_fs_mkdir_all(const u_char *dir, mode_t mode);
nxt_int_t nxt_fs_mount(nxt_task_t *task, nxt_fs_mount_t *mnt);
void nxt_fs_unmount(const u_char *path);


#endif  /* _NXT_FS_H_INCLUDED_ */
