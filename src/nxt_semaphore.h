
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_SEMAPHORE_H_INCLUDED_
#define _NXT_UNIX_SEMAPHORE_H_INCLUDED_


#if (NXT_HAVE_SEM_TIMEDWAIT)

typedef sem_t           nxt_sem_t;

#else

typedef struct {
    nxt_atomic_t        count;
    nxt_thread_mutex_t  mutex;
    nxt_thread_cond_t   cond;
} nxt_sem_t;

#endif


NXT_EXPORT nxt_int_t nxt_sem_init(nxt_sem_t *sem, nxt_uint_t count);
NXT_EXPORT void nxt_sem_destroy(nxt_sem_t *sem);
NXT_EXPORT nxt_int_t nxt_sem_post(nxt_sem_t *sem);
NXT_EXPORT nxt_err_t nxt_sem_wait(nxt_sem_t *sem, nxt_nsec_t timeout);


#endif /* _NXT_UNIX_SEMAPHORE_H_INCLUDED_ */
