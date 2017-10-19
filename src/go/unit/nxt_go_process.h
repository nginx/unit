
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_GO_PROCESS_H_INCLUDED_
#define _NXT_GO_PROCESS_H_INCLUDED_


#include <nxt_main.h>
#include "nxt_go_mutex.h"

#ifndef _NXT_GO_PROCESS_T_DEFINED_
#define _NXT_GO_PROCESS_T_DEFINED_
typedef struct nxt_go_process_s nxt_go_process_t;
#endif

struct nxt_go_process_s {
    nxt_pid_t       pid;
    nxt_go_mutex_t  incoming_mutex;
    nxt_array_t     incoming;  /* of nxt_go_port_mmap_t */
    nxt_go_mutex_t  outgoing_mutex;
    nxt_array_t     outgoing;  /* of nxt_go_port_mmap_t */
};

nxt_go_process_t *nxt_go_get_process(nxt_pid_t pid);

void nxt_go_new_incoming_mmap(nxt_pid_t pid, nxt_fd_t fd);


#endif /* _NXT_GO_PROCESS_H_INCLUDED_ */

