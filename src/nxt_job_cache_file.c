
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


#include <nxt_main.h>


nxt_job_cache_file_t *
nxt_job_cache_file_create(nxt_mp_t *mp)
{
    nxt_job_cache_file_t  *jbc;

    jbc = nxt_job_create(mp, sizeof(nxt_job_cache_file_t));

    if (nxt_fast_path(jbc != NULL)) {
        jbc->file.fd = NXT_FILE_INVALID;
        jbc->read_required = nxt_job_file_read_required;
    }

    return jbc;
}
