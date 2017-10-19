
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_GO_PORT_MEMORY_H_INCLUDED_
#define _NXT_GO_PORT_MEMORY_H_INCLUDED_


#include <nxt_main.h>
#include <nxt_port_memory_int.h>

#ifndef _NXT_GO_PROCESS_T_DEFINED_
#define _NXT_GO_PROCESS_T_DEFINED_
typedef struct nxt_go_process_s nxt_go_process_t;
#endif

typedef struct nxt_go_port_mmap_s nxt_go_port_mmap_t;

struct nxt_go_port_mmap_s {
    nxt_port_mmap_header_t  *hdr;
};

struct nxt_port_mmap_header_s *
nxt_go_port_mmap_get(nxt_go_process_t *process, nxt_port_id_t port_id,
    nxt_chunk_id_t *c);


#endif /* _NXT_GO_PORT_MEMORY_H_INCLUDED_ */
