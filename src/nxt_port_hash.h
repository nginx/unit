
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

nxt_port_t *nxt_port_hash_retrieve(nxt_lvlhsh_t *port_hash);


#endif /* _NXT_PORT_HASH_H_INCLIDED_ */
