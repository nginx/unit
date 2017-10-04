
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PORT_HASH_H_INCLUDED_
#define _NXT_PORT_HASH_H_INCLUDED_


#include <nxt_main.h>


nxt_int_t nxt_port_hash_add(nxt_lvlhsh_t *port_hash, nxt_port_t *port);

nxt_int_t nxt_port_hash_remove(nxt_lvlhsh_t *port_hash, nxt_port_t *port);

nxt_port_t *nxt_port_hash_find(nxt_lvlhsh_t *port_hash, nxt_pid_t pid,
    nxt_port_id_t port_id);

nxt_port_t *nxt_port_hash_first(nxt_lvlhsh_t *port_hash,
    nxt_lvlhsh_each_t *lhe);

#define nxt_port_hash_next(port_hash, lhe)                                    \
    nxt_lvlhsh_each((port_hash), (lhe))

#define nxt_port_hash_each(port_hash, port)                                   \
    do {                                                                      \
        nxt_lvlhsh_each_t  _lhe;                                              \
                                                                              \
        for (port = nxt_port_hash_first((port_hash), &_lhe);                  \
             port != NULL;                                                    \
             port = nxt_port_hash_next((port_hash), &_lhe)) {                 \

#define nxt_port_hash_loop                                                    \
        }                                                                     \
    } while(0)


#endif /* _NXT_PORT_HASH_H_INCLIDED_ */
