
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PARSE_H_INCLUDED_
#define _NXT_PARSE_H_INCLUDED_


NXT_EXPORT nxt_int_t nxt_int_parse(const u_char *p, size_t len);
NXT_EXPORT ssize_t nxt_size_t_parse(const u_char *p, size_t len);
NXT_EXPORT ssize_t nxt_size_parse(const u_char *p, size_t len);
NXT_EXPORT nxt_off_t nxt_off_t_parse(const u_char *p, size_t len);

NXT_EXPORT nxt_int_t nxt_str_int_parse(nxt_str_t *s);

NXT_EXPORT double nxt_number_parse(const u_char **start, const u_char *end);

NXT_EXPORT nxt_time_t nxt_time_parse(const u_char *p, size_t len);
NXT_EXPORT nxt_int_t nxt_term_parse(const u_char *p, size_t len,
    nxt_bool_t seconds);


#endif /* _NXT_PARSE_H_INCLUDED_ */
