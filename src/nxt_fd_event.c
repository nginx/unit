
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_fd_event_hash_test(nxt_lvlhsh_query_t *lhq, void *data);
static void nxt_fd_event_hash_error(nxt_task_t *task, nxt_fd_t fd);


static const nxt_lvlhsh_proto_t  nxt_event_set_fd_hash_proto  nxt_aligned(64) =
{
    NXT_LVLHSH_LARGE_MEMALIGN,
    0,
    nxt_fd_event_hash_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


/* nxt_murmur_hash2() is unique for 4 bytes. */

static nxt_int_t
nxt_fd_event_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    return NXT_OK;
}


nxt_int_t
nxt_fd_event_hash_add(nxt_lvlhsh_t *lvlhsh, nxt_fd_t fd, nxt_fd_event_t *ev)
{
    nxt_int_t           ret;
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_murmur_hash2(&fd, sizeof(nxt_fd_t));
    lhq.replace = 0;
    lhq.value = ev;
    lhq.proto = &nxt_event_set_fd_hash_proto;

    ret = nxt_lvlhsh_insert(lvlhsh, &lhq);

    if (nxt_fast_path(ret == NXT_OK)) {
        return NXT_OK;
    }

    nxt_log(ev->task, NXT_LOG_CRIT, "fd event %d is already in hash", ev->fd);

    return NXT_ERROR;
}


void *
nxt_fd_event_hash_get(nxt_task_t *task, nxt_lvlhsh_t *lvlhsh, nxt_fd_t fd)
{
    nxt_int_t           ret;
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_murmur_hash2(&fd, sizeof(nxt_fd_t));
    lhq.proto = &nxt_event_set_fd_hash_proto;

    ret = nxt_lvlhsh_find(lvlhsh, &lhq);

    if (nxt_fast_path(ret == NXT_OK)) {
        return lhq.value;
    }

    nxt_fd_event_hash_error(task, fd);

    return NULL;
}


void
nxt_fd_event_hash_delete(nxt_task_t *task, nxt_lvlhsh_t *lvlhsh, nxt_fd_t fd,
    nxt_bool_t ignore)
{
    nxt_int_t           ret;
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_murmur_hash2(&fd, sizeof(nxt_fd_t));
    lhq.proto = &nxt_event_set_fd_hash_proto;

    ret = nxt_lvlhsh_delete(lvlhsh, &lhq);

    if (nxt_slow_path(ret != NXT_OK)) {
        if (!ignore) {
            nxt_fd_event_hash_error(task, fd);
        }
    }
}


void
nxt_fd_event_hash_destroy(nxt_lvlhsh_t *lvlhsh)
{
    nxt_int_t           ret;
    nxt_fd_event_t      *ev;
    nxt_lvlhsh_each_t   lhe;
    nxt_lvlhsh_query_t  lhq;

    nxt_memzero(&lhe, sizeof(nxt_lvlhsh_each_t));
    lhe.proto = &nxt_event_set_fd_hash_proto;
    lhq.proto = &nxt_event_set_fd_hash_proto;

    for ( ;; ) {
        ev = nxt_lvlhsh_each(lvlhsh, &lhe);

        if (ev == NULL) {
            return;
        }

        lhq.key_hash = nxt_murmur_hash2(&ev->fd, sizeof(nxt_fd_t));

        ret = nxt_lvlhsh_delete(lvlhsh, &lhq);

        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_fd_event_hash_error(ev->task, ev->fd);
        }
    }
}


static void
nxt_fd_event_hash_error(nxt_task_t *task, nxt_fd_t fd)
{
    nxt_log(task, NXT_LOG_CRIT, "fd event %d not found in hash", fd);
}
