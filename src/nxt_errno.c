
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * The strerror() messages are copied because:
 *
 * 1) strerror() and strerror_r() functions are not Async-Signal-Safe,
 *    therefore, they can not be used in signal handlers;
 *
 * 2) a direct sys_errlist[] array may be used instead of these functions,
 *    but Linux linker warns about this usage:
 *
 * warning: `sys_errlist' is deprecated; use `strerror' or `strerror_r' instead
 * warning: `sys_nerr' is deprecated; use `strerror' or `strerror_r' instead
 *
 *    causing false bug reports.
 */

static u_char *nxt_bootstrap_strerror(nxt_err_t err, u_char *errstr,
    size_t size);
static u_char *nxt_runtime_strerror(nxt_err_t err, u_char *errstr, size_t size);


nxt_strerror_t     nxt_strerror = nxt_bootstrap_strerror;
static nxt_str_t   *nxt_sys_errlist;
static nxt_uint_t  nxt_sys_nerr;


nxt_int_t
nxt_strerror_start(void)
{
    char        *msg;
    u_char      *p;
    size_t      size, length, n;
    nxt_uint_t  err, invalid;

    /* The last entry. */
    size = nxt_length("Unknown error");

    /*
     * Linux has holes for error codes 41 and 58, so the loop
     * stops only after 100 invalid codes in succession.
     */

    for (invalid = 0; invalid < 100 && nxt_sys_nerr < 65536; nxt_sys_nerr++) {

        nxt_set_errno(0);
        msg = strerror((int) nxt_sys_nerr);

        /*
         * strerror() behaviour on passing invalid error code depends
         * on OS and version:
         *   Linux returns "Unknown error NN";
         *   FreeBSD, NetBSD and OpenBSD return "Unknown error: NN"
         *     and set errno to EINVAL;
         *   Solaris 10 returns "Unknown error" and sets errno to EINVAL;
         *   Solaris 9 returns "Unknown error";
         *   Solaris 2 returns NULL;
         *   MacOSX returns "Unknown error: NN";
         *   AIX returns "Error NNN occurred.";
         *   HP-UX returns "Unknown error" for invalid codes lesser than 250
         *     or empty string for larger codes.
         */

        if (msg == NULL) {
            invalid++;
            continue;
        }

        length = nxt_strlen(msg);
        size += length;

        if (length == 0  /* HP-UX empty strings. */
            || nxt_errno == NXT_EINVAL
            || memcmp(msg, "Unknown error", 13) == 0)
        {
            invalid++;
            continue;
        }

#if (NXT_AIX)

        if (memcmp(msg, "Error ", 6) == 0
            && memcmp(msg + length - 10, " occurred.", 9) == 0)
        {
            invalid++;
            continue;
        }

#endif
    }

    nxt_sys_nerr -= invalid;

    nxt_main_log_debug("sys_nerr: %d", nxt_sys_nerr);

    n = (nxt_sys_nerr + 1) * sizeof(nxt_str_t);

    nxt_sys_errlist = nxt_malloc(n + size);
    if (nxt_sys_errlist == NULL) {
        return NXT_ERROR;
    }

    p = nxt_pointer_to(nxt_sys_errlist, n);

    for (err = 0; err < nxt_sys_nerr; err++) {
        msg = strerror((int) err);
        length = nxt_strlen(msg);

        nxt_sys_errlist[err].length = length;
        nxt_sys_errlist[err].start = p;

        p = nxt_cpymem(p, msg, length);
    }

    nxt_sys_errlist[err].length = 13;
    nxt_sys_errlist[err].start = p;
    nxt_memcpy(p, "Unknown error", 13);

    nxt_strerror = nxt_runtime_strerror;

    return NXT_OK;
}


static u_char *
nxt_bootstrap_strerror(nxt_err_t err, u_char *errstr, size_t size)
{
    return nxt_cpystrn(errstr, (u_char *) strerror(err), size);
}


static u_char *
nxt_runtime_strerror(nxt_err_t err, u_char *errstr, size_t size)
{
    nxt_str_t   *msg;
    nxt_uint_t  n;

    n = nxt_min((nxt_uint_t) err, nxt_sys_nerr);

    msg = &nxt_sys_errlist[n];

    size = nxt_min(size, msg->length);

    return nxt_cpymem(errstr, msg->start, size);
}
