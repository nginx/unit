/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CREDENTIAL_H_INCLUDED_
#define _NXT_CREDENTIAL_H_INCLUDED_


typedef uid_t   nxt_uid_t;
typedef gid_t   nxt_gid_t;

typedef struct {
    const char  *user;
    nxt_uid_t   uid;
    nxt_gid_t   base_gid;
    nxt_uint_t  ngroups;
    nxt_gid_t   *gids;
} nxt_credential_t;


NXT_EXPORT nxt_int_t nxt_credential_get(nxt_task_t *task, nxt_mp_t *mp,
    nxt_credential_t *uc, const char *group);
NXT_EXPORT nxt_int_t nxt_credential_setuid(nxt_task_t *task,
    nxt_credential_t *uc);
NXT_EXPORT nxt_int_t nxt_credential_setgids(nxt_task_t *task,
    nxt_credential_t *uc);


#endif /* _NXT_CREDENTIAL_H_INCLUDED_ */
