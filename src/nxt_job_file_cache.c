
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


#include <nxt_main.h>


typedef struct {
    nxt_cache_node_t   node;
    nxt_file_t         file;
} nxt_file_cache_t;


void
nxt_job_file_cache_read(nxt_cache_t *cache, nxt_job_file_t *jbf)
{
    nxt_file_cache_node_t  *node;

    node = nxt_cache_find(cache);

    if (node != NULL) {

        if (node->fd != -1) {
            nxt_job_return(&jbf->job, jbf->ready_handler);
            return;
        }

        if (node->error != 0) {
            nxt_job_return(&jbf->job, jbf->error_handler);
            return;
        }

        if (node->accessed + 60 > nxt_thread_time()) {
            jbf->job.thread_pool = NULL;
        }
    }

    nxt_job_file_read(jbf);
}
