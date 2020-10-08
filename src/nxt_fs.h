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

#ifdef MS_NOSUID
#define NXT_MS_NOSUID MS_NOSUID
#else
#define NXT_MS_NOSUID 0
#endif

#ifdef MS_NOEXEC
#define NXT_MS_NOEXEC MS_NOEXEC
#else
#define NXT_MS_NOEXEC 0
#endif

#ifdef MS_RELATIME
#define NXT_MS_RELATIME MS_RELATIME
#else
#define NXT_MS_RELATIME 0
#endif

#ifdef MS_NODEV
#define NXT_MS_NODEV MS_NODEV
#else
#define NXT_MS_NODEV 0
#endif


typedef struct {
    u_char      *src;
    u_char      *dst;
    u_char      *fstype;
    nxt_int_t   flags;
    u_char      *data;
    nxt_uint_t  builtin;  /* 1-bit */
} nxt_fs_mount_t;


nxt_int_t nxt_fs_mkdir_all(const u_char *dir, mode_t mode);
nxt_int_t nxt_fs_mount(nxt_task_t *task, nxt_fs_mount_t *mnt);
void nxt_fs_unmount(const u_char *path);


#endif  /* _NXT_FS_H_INCLUDED_ */
