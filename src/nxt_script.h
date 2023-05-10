
/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Zhidao HONG
 */

#ifndef _NXT_SCRIPT_INCLUDED_
#define _NXT_SCRIPT_INCLUDED_


typedef struct nxt_script_s  nxt_script_t;

nxt_script_t *nxt_script_new(nxt_task_t *task, nxt_str_t *name, u_char *data,
    size_t size, u_char *error);
void nxt_script_destroy(nxt_script_t *script);

void nxt_script_info_init(nxt_task_t *task, nxt_array_t *scripts);
nxt_int_t nxt_script_info_save(nxt_str_t *name, nxt_script_t *script);
nxt_conf_value_t *nxt_script_info_get(nxt_str_t *name);
nxt_conf_value_t *nxt_script_info_get_all(nxt_mp_t *mp);
nxt_int_t nxt_script_info_delete(nxt_str_t *name);

nxt_array_t *nxt_script_store_load(nxt_task_t *task, nxt_mp_t *mem_pool);
void nxt_script_store_release(nxt_array_t *scripts);

void nxt_script_store_get(nxt_task_t *task, nxt_str_t *name, nxt_mp_t *mp,
    nxt_port_rpc_handler_t handler, void *ctx);
void nxt_script_store_delete(nxt_task_t *task, nxt_str_t *name, nxt_mp_t *mp);

void nxt_script_store_get_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_script_store_delete_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);

nxt_int_t nxt_script_file_read(nxt_fd_t fd, nxt_str_t *str);


#endif /* _NXT_SCRIPT_INCLUDED_ */
