
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_GO_MUTEX_H_INCLUDED_
#define _NXT_GO_MUTEX_H_INCLUDED_


#include <pthread.h>

typedef pthread_mutex_t  nxt_go_mutex_t;

#define nxt_go_mutex_create(mutex)   pthread_mutex_init(mutex, NULL)
#define nxt_go_mutex_destroy(mutex)  pthread_mutex_destroy(mutex)
#define nxt_go_mutex_lock(mutex)     pthread_mutex_lock(mutex)
#define nxt_go_mutex_unlock(mutex)   pthread_mutex_unlock(mutex)


#endif /* _NXT_GO_MUTEX_H_INCLUDED_ */
