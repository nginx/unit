/*
 * Copyright (C) NGINX, Inc.
 * Copyright 2024, Alejandro Colomar <alx@kernel.org>
 */

#include <nxt_main.h>

#include <errno.h>


static nxt_int_t nxt_fs_mkdir(const u_char *dir, mode_t mode);


nxt_int_t
nxt_fs_mkdir_all(const u_char *dir, mode_t mode)
{
    char    *start, *end, *dst;
    size_t  dirlen;
    char    path[PATH_MAX];

    dirlen = nxt_strlen(dir);

    nxt_assert(dirlen < PATH_MAX && dirlen > 1 && dir[0] == '/');

    dst = path;
    start = (char *) dir;

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


nxt_int_t
nxt_fs_mkdir_parents_dirname(const u_char *path, mode_t mode)
{
    char       *ptr, *dir;
    nxt_int_t  ret;

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
    if (strcmp(dir, (const char *) path) != 0)
    {
        ret = nxt_fs_mkdir_parents_dirname((const u_char *) dir, mode);
        if (nxt_slow_path(ret == NXT_ERROR)) {
            goto out_free;
        }
    }

    ret = nxt_fs_mkdir((const u_char *) dir, mode);
    if (ret == NXT_ERROR && errno == EEXIST) {
        ret = NXT_OK;
    }

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
