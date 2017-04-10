
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CONF_INCLUDED_
#define _NXT_CONF_INCLUDED_


typedef struct nxt_conf_json_value_s  nxt_conf_json_value_t;


nxt_conf_json_value_t *nxt_conf_json_parse(nxt_buf_mem_t *b,
    nxt_mem_pool_t *pool);


#endif /* _NXT_CONF_INCLUDED_ */
