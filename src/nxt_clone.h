/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_CLONE_H_INCLUDED_
#define _NXT_CLONE_H_INCLUDED_


#if (NXT_HAVE_CLONE_NEWUSER)

typedef int64_t                 nxt_cred_t;

typedef struct {
    nxt_cred_t                  container;
    nxt_cred_t                  host;
    nxt_cred_t                  size;
} nxt_clone_map_entry_t;

typedef struct {
    nxt_uint_t                  size;
    nxt_clone_map_entry_t       *map;
} nxt_clone_credential_map_t;

#endif

typedef struct {
    nxt_int_t                   flags;

#if (NXT_HAVE_CLONE_NEWUSER)
    nxt_clone_credential_map_t  uidmap;
    nxt_clone_credential_map_t  gidmap;
#endif

} nxt_clone_t;


#define nxt_is_clone_flag_set(flags, test)                                    \
    ((flags & CLONE_##test) == CLONE_##test)


#if (NXT_HAVE_CLONE_NEWUSER)

NXT_EXPORT nxt_int_t nxt_clone_credential_map(nxt_task_t *task, pid_t pid,
    nxt_credential_t *creds, nxt_clone_t *clone);
NXT_EXPORT nxt_int_t nxt_clone_vldt_credential_uidmap(nxt_task_t *task,
    nxt_clone_credential_map_t *map, nxt_credential_t *creds);
NXT_EXPORT nxt_int_t nxt_clone_vldt_credential_gidmap(nxt_task_t *task,
    nxt_clone_credential_map_t *map, nxt_credential_t *creds);

#endif


#endif /* _NXT_CLONE_H_INCLUDED_ */
