
/*
 * Copyright (C) Axel Duch
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_REGEX_H_INCLUDED_
#define _NXT_REGEX_H_INCLUDED_

#if (NXT_HAVE_REGEX)

typedef struct nxt_regex_s        nxt_regex_t;

 #if (NXT_HAVE_PCRE2)
typedef void                      nxt_regex_match_t;
#else
typedef struct nxt_regex_match_s  nxt_regex_match_t;
#endif

typedef struct {
    size_t      offset;

#if (NXT_HAVE_PCRE2)
#define ERR_BUF_SIZE  256
    u_char      msg[ERR_BUF_SIZE];
#else
    const char  *msg;
#endif
} nxt_regex_err_t;


NXT_EXPORT void nxt_regex_init(void);
NXT_EXPORT nxt_regex_t *nxt_regex_compile(nxt_mp_t *mp, nxt_str_t *source,
    nxt_regex_err_t *err);
NXT_EXPORT nxt_regex_match_t *nxt_regex_match_create(nxt_mp_t *mp, size_t size);
NXT_EXPORT nxt_int_t nxt_regex_match(nxt_regex_t *re, u_char *subject,
    size_t length, nxt_regex_match_t *match);

#endif /* NXT_HAVE_REGEX */

#endif /* _NXT_REGEX_H_INCLUDED_ */
