
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_SERVICE_H_INCLUDED_
#define _NXT_SERVICE_H_INCLUDED_


typedef struct {
    const char  *type;
    const char  *name;
    const void  *service;
} nxt_service_t;


#define nxt_service_is_module(s)                                              \
    ((s)->type == NULL)


NXT_EXPORT nxt_array_t *nxt_services_init(nxt_mp_t *mp);
NXT_EXPORT nxt_int_t nxt_service_add(nxt_array_t *services,
    const nxt_service_t *service);
NXT_EXPORT const void *nxt_service_get(nxt_array_t *services, const char *type,
    const char *name);


#endif /* _NXT_SERVICE_H_INCLUDED_ */
