/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_FS_MOUNT_H_INCLUDED_
#define _NXT_FS_MOUNT_H_INCLUDED_


typedef enum nxt_fs_type_s     nxt_fs_type_t;
typedef enum nxt_fs_flags_s    nxt_fs_flags_t;
typedef struct nxt_fs_mount_s  nxt_fs_mount_t;


enum nxt_fs_type_s {
    NXT_FS_UNKNOWN = 0,
    NXT_FS_BIND,
    NXT_FS_TMP,
    NXT_FS_PROC,
    NXT_FS_LAST,
};


enum nxt_fs_flags_s {
    NXT_FS_FLAGS_NOSUID   = 1 << 0,
    NXT_FS_FLAGS_NOEXEC   = 1 << 1,
    NXT_FS_FLAGS_NOTIME   = 1 << 2,
    NXT_FS_FLAGS_NODEV    = 1 << 3,
    NXT_FS_FLAGS_RDONLY   = 1 << 4,
};


struct nxt_fs_mount_s {
    u_char          *src;
    u_char          *dst;
    nxt_fs_type_t   type;
    u_char          *name;
    nxt_fs_flags_t  flags;
    u_char          *data;
    nxt_uint_t      builtin;  /* 1-bit */
    nxt_uint_t      deps;     /* 1-bit */
};


nxt_int_t nxt_fs_mount(nxt_task_t *task, nxt_fs_mount_t *mnt);
void nxt_fs_unmount(const u_char *path);


#endif  /* _NXT_FS_MOUNT_H_INCLUDED_ */
