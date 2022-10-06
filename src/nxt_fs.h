/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_FS_H_INCLUDED_
#define _NXT_FS_H_INCLUDED_


nxt_int_t nxt_fs_mkdir_parent(const u_char *path, mode_t mode);
nxt_int_t nxt_fs_mkdir_all(const u_char *dir, mode_t mode);


#endif  /* _NXT_FS_H_INCLUDED_ */
