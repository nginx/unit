/*
 * Copyright (C) NGINX, Inc.
 * Copyright 2024, Alejandro Colomar <alx@kernel.org>
 */

#include <nxt_main.h>


static nxt_int_t
nxt_fs_mkdir(const u_char *dir, mode_t mode);

nxt_int_t
nxt_fs_mkdir_p(const u_char *dir, mode_t mode)
{
    char     *start, *end, *dst;
    size_t    dirlen;
    nxt_int_t ret;
    char      path[PATH_MAX];

    dirlen = nxt_strlen(dir);

    nxt_assert(dirlen < PATH_MAX && dirlen > 0);

    dst   = path;
    start = (char *) dir;

    while (*start != '\0') {
        end = strchr(start + 1, '/');
        if (end == NULL) {
            end = ((char *) dir + dirlen);
        }

        dst  = nxt_cpymem(dst, start, end - start);
        *dst = '\0';

        ret  = nxt_fs_mkdir((u_char *) path, mode);
        if (nxt_slow_path(ret != NXT_OK && nxt_errno != EEXIST)) {
            return NXT_ERROR;
        }

        start = end;
    }

    return NXT_OK;
}

nxt_int_t
nxt_fs_mkdir_p_dirname(const u_char *path, mode_t mode)
{
    char     *ptr, *dir;
    nxt_int_t ret;

    dir = nxt_strdup(path);
    if (nxt_slow_path(dir == NULL)) {
        return NXT_ERROR;
    }

    ret = NXT_OK;

    ptr = strrchr(dir, '/');
    if (ptr == dir || nxt_slow_path(ptr == NULL)) {
        goto out_free;
    }

    *ptr = '\0';
    ret  = nxt_fs_mkdir_p((const u_char *) dir, mode);

out_free:
    nxt_free(dir);

    return ret;
}

static nxt_int_t
nxt_fs_mkdir(const u_char *dir, mode_t mode)
{
    if (nxt_fast_path(mkdir((const char *) dir, mode) == 0)) {
        return NXT_OK;
    }

    return NXT_ERROR;
}
