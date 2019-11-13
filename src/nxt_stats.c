
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static void nxt_stats_buf_completion(nxt_task_t *task, void *obj,
    void *data);


nxt_buf_t *
nxt_stats_buf_alloc(nxt_mp_t *mp)
{
    size_t                  size;
    nxt_buf_t               *b;
    nxt_conf_value_t        *value;
    nxt_conf_json_pretty_t  pretty;

    static nxt_str_t  accepted_str = nxt_string("accepted");
    static nxt_str_t  active_str = nxt_string("active");
    static nxt_str_t  requests_str = nxt_string("requests");
    static nxt_str_t  reading_str = nxt_string("reading");
    static nxt_str_t  writing_str = nxt_string("writing");

    value = nxt_conf_create_object(mp, 5);
    if (nxt_slow_path(value == NULL)) {
        return NULL;
    }

    nxt_conf_set_member_integer(value, &accepted_str, nxt_stats.accepted, 0);
    nxt_conf_set_member_integer(value, &active_str, nxt_stats.active, 1);
    nxt_conf_set_member_integer(value, &requests_str, nxt_stats.requests, 2);
    nxt_conf_set_member_integer(value, &reading_str, nxt_stats.reading, 3);
    nxt_conf_set_member_integer(value, &writing_str, nxt_stats.writing, 4);

    nxt_memzero(&pretty, sizeof(nxt_conf_json_pretty_t));

    size = nxt_conf_json_length(value, &pretty);

    b = nxt_buf_mem_alloc(mp, size, 0);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->completion_handler = nxt_stats_buf_completion;

    nxt_memzero(&pretty, sizeof(nxt_conf_json_pretty_t));

    b->mem.free = nxt_conf_json_print(b->mem.free, value, &pretty);

    return b;
}


static void
nxt_stats_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t   *mp;
    nxt_buf_t  *b;

    b = obj;
    mp = b->data;

    nxt_mp_release(mp);
}
