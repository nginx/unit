
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_JOB_RESOLVE_H_INCLUDED_
#define _NXT_JOB_RESOLVE_H_INCLUDED_


typedef struct {
    nxt_job_t           job;
    nxt_str_t           name;

    uint32_t            log_level;  /* 4 bits */
    in_port_t           port;
    uint16_t            count;

    nxt_sockaddr_t      **sockaddrs;

    nxt_work_handler_t  ready_handler;
    nxt_work_handler_t  error_handler;
} nxt_job_resolve_t;


void nxt_job_resolve(nxt_job_resolve_t *jbr);


#endif /* _NXT_JOB_RESOLVE_H_INCLUDED_ */
