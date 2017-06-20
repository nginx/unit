
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_FILE_NAME_H_INCLUDED_
#define _NXT_FILE_NAME_H_INCLUDED_


NXT_EXPORT nxt_int_t nxt_file_name_create(nxt_mp_t *mp,
    nxt_file_name_str_t *fn, const char *format, ...);


#endif /* _NXT_FILE_NAME_H_INCLUDED_ */
