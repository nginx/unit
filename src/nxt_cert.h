
/*
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CERT_INCLUDED_
#define _NXT_CERT_INCLUDED_


typedef struct nxt_cert_s  nxt_cert_t;

nxt_cert_t *nxt_cert_mem(nxt_task_t *task, nxt_buf_mem_t *mbuf);
void nxt_cert_destroy(nxt_cert_t *cert);

void nxt_cert_info_init(nxt_task_t *task, nxt_array_t *certs);
nxt_int_t nxt_cert_info_save(nxt_str_t *name, nxt_cert_t *cert);
nxt_conf_value_t *nxt_cert_info_get(nxt_str_t *name);
nxt_conf_value_t *nxt_cert_info_get_all(nxt_mp_t *mp);
nxt_int_t nxt_cert_info_delete(nxt_str_t *name);

nxt_array_t *nxt_cert_store_load(nxt_task_t *task, nxt_mp_t *mem_pool);
void nxt_cert_store_release(nxt_array_t *certs);

void nxt_cert_store_get(nxt_task_t *task, nxt_str_t *name, nxt_mp_t *mp,
    nxt_port_rpc_handler_t handler, void *ctx);
void nxt_cert_store_delete(nxt_task_t *task, nxt_str_t *name, nxt_mp_t *mp);

void nxt_cert_store_get_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_cert_store_delete_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);

#endif /* _NXT_CERT_INCLUDED_ */
