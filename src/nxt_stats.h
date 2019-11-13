
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_STATS_H_INCLUDED_
#define _NXT_STATS_H_INCLUDED_


typedef struct {
    nxt_atomic_t  accepted;
    nxt_atomic_t  active;
    nxt_atomic_t  requests;
    nxt_atomic_t  reading;
    nxt_atomic_t  writing;
} nxt_stats_t;


nxt_buf_t *nxt_stats_buf_alloc(nxt_mp_t *mp);


#define nxt_stats_accepted_add(n)                                     \
     nxt_atomic_fetch_add(&nxt_stats.accepted, n)

#define nxt_stats_active_add(n)                                       \
     nxt_atomic_fetch_add(&nxt_stats.active, n)

#define nxt_stats_requests_add(n)                                     \
     nxt_atomic_fetch_add(&nxt_stats.requests, n)

#define nxt_stats_reading_add(n)                                      \
     nxt_atomic_fetch_add(&nxt_stats.reading, n)

#define nxt_stats_writing_add(n)                                      \
     nxt_atomic_fetch_add(&nxt_stats.writing, n)


#endif /* _NXT_STATS_H_INCLUDED_ */
