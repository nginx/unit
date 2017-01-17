
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_SPRINTF_H_INCLUDED_
#define _NXT_SPRINTF_H_INCLUDED_


/* STUB */
#define NXT_DOUBLE_LEN  (1 + DBL_MAX_10_EXP)


NXT_EXPORT u_char *nxt_cdecl nxt_sprintf(u_char *buf, u_char *end,
    const char *fmt, ...);
NXT_EXPORT u_char *nxt_vsprintf(u_char *buf, u_char *end,
    const char *fmt, va_list args);


#endif /* _NXT_SPRINTF_H_INCLUDED_ */
