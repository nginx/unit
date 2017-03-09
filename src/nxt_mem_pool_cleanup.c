
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_mem_pool_file_cleanup_handler(nxt_task_t *task, void *data);


nxt_mem_pool_cleanup_t *
nxt_mem_pool_file_cleanup(nxt_mem_pool_t *mp, nxt_file_t *file)
{
    nxt_mem_pool_cleanup_t  *mpcl;

    mpcl = nxt_mem_pool_cleanup(mp, 0);

    if (nxt_fast_path(mpcl != NULL)) {
        mpcl->handler = nxt_mem_pool_file_cleanup_handler;
        mpcl->data = file;
    }

    return mpcl;
}


static void
nxt_mem_pool_file_cleanup_handler(nxt_task_t *task, void *data)
{
    nxt_file_t  *file;

    file = data;

    if (file->fd != NXT_FILE_INVALID) {
        nxt_file_close(task, file);
    }
}
