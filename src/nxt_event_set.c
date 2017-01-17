
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_event_set_fd_hash_test(nxt_lvlhsh_query_t *lhq,
    void *data);


static const nxt_lvlhsh_proto_t  nxt_event_set_fd_hash_proto  nxt_aligned(64) =
{
    NXT_LVLHSH_LARGE_MEMALIGN,
    0,
    nxt_event_set_fd_hash_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


/* nxt_murmur_hash2() is unique for 4 bytes. */

static nxt_int_t
nxt_event_set_fd_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    return NXT_OK;
}


nxt_int_t
nxt_event_set_fd_hash_add(nxt_lvlhsh_t *lh, nxt_fd_t fd, nxt_event_fd_t *ev)
{
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_murmur_hash2(&fd, sizeof(nxt_fd_t));
    lhq.replace = 0;
    lhq.value = ev;
    lhq.proto = &nxt_event_set_fd_hash_proto;

    if (nxt_lvlhsh_insert(lh, &lhq) == NXT_OK) {
        return NXT_OK;
    }

    nxt_log_alert(ev->log, "event fd %d is already in hash", ev->fd);
    return NXT_ERROR;
}


void *
nxt_event_set_fd_hash_get(nxt_lvlhsh_t *lh, nxt_fd_t fd)
{
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_murmur_hash2(&fd, sizeof(nxt_fd_t));
    lhq.proto = &nxt_event_set_fd_hash_proto;

    if (nxt_lvlhsh_find(lh, &lhq) == NXT_OK) {
        return lhq.value;
    }

    nxt_thread_log_alert("event fd %d not found in hash", fd);
    return NULL;
}


void
nxt_event_set_fd_hash_delete(nxt_lvlhsh_t *lh, nxt_fd_t fd, nxt_bool_t ignore)
{
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_murmur_hash2(&fd, sizeof(nxt_fd_t));
    lhq.proto = &nxt_event_set_fd_hash_proto;

    if (nxt_lvlhsh_delete(lh, &lhq) != NXT_OK && !ignore) {
        nxt_thread_log_alert("event fd %d not found in hash", fd);
    }
}


void
nxt_event_set_fd_hash_destroy(nxt_lvlhsh_t *lh)
{
    nxt_event_fd_t      *ev;
    nxt_lvlhsh_each_t   lhe;
    nxt_lvlhsh_query_t  lhq;

    nxt_memzero(&lhe, sizeof(nxt_lvlhsh_each_t));
    lhe.proto = &nxt_event_set_fd_hash_proto;
    lhq.proto = &nxt_event_set_fd_hash_proto;

    for ( ;; ) {
        ev = nxt_lvlhsh_each(lh, &lhe);

        if (ev == NULL) {
            return;
        }

        lhq.key_hash = nxt_murmur_hash2(&ev->fd, sizeof(nxt_fd_t));

        if (nxt_lvlhsh_delete(lh, &lhq) != NXT_OK) {
            nxt_thread_log_alert("event fd %d not found in hash", ev->fd);
        }
    }
}
