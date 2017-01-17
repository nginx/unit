
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * nxt_int_parse() returns size_t value >= 0 on success,
 * -1 on failure, and -2 on overflow.
 */

nxt_int_t
nxt_int_parse(const u_char *p, size_t len)
{
    u_char      c;
    nxt_uint_t  val;

    if (nxt_fast_path(len != 0)) {

        val = 0;

        do {
            c = *p++;

            /* Values below '0' become >= 208. */
            c = c - '0';

            if (nxt_slow_path(c > 9)) {
                return -1;
            }

            val = val * 10 + c;

            if (nxt_slow_path((nxt_int_t) val < 0)) {
                /* An overflow. */
                return -2;
            }

            len--;

        } while (len != 0);

        return val;
    }

    return -1;
}


/*
 * nxt_size_t_parse() returns size_t value >= 0 on success,
 * -1 on failure, and -2 on overflow.
 */

ssize_t
nxt_size_t_parse(const u_char *p, size_t len)
{
    u_char  c;
    size_t  val;

    if (nxt_fast_path(len != 0)) {

        val = 0;

        do {
            c = *p++;

            /* Values below '0' become >= 208. */
            c = c - '0';

            if (nxt_slow_path(c > 9)) {
                return -1;
            }

            val = val * 10 + c;

            if (nxt_slow_path((ssize_t) val < 0)) {
                /* An overflow. */
                return -2;
            }

            len--;

        } while (len != 0);

        return val;
    }

    return -1;
}


/*
 * nxt_size_parse() parses size string with optional K or M units and
 * returns size_t value >= 0 on success, -1 on failure, and -2 on overflow.
 */

ssize_t
nxt_size_parse(const u_char *p, size_t len)
{
    u_char      c, unit;
    size_t      val, max;
    nxt_uint_t  shift;

    if (nxt_fast_path(len != 0)) {

        len--;

        /* Upper case. */
        unit = p[len] & ~0x20;

        switch (unit) {

        case 'G':
            max = NXT_SIZE_T_MAX >> 30;
            shift = 30;
            break;

        case 'M':
            max = NXT_SIZE_T_MAX >> 20;
            shift = 20;
            break;

        case 'K':
            max = NXT_SIZE_T_MAX >> 10;
            shift = 10;
            break;

        default:
            max = NXT_SIZE_T_MAX;
            shift = 0;
            len++;
            break;
        }

        if (nxt_fast_path(len != 0)) {

            val = 0;

            do {
                c = *p++;

                /* Values below '0' become >= 208. */
                c = c - '0';

                if (nxt_slow_path(c > 9)) {
                    return -1;
                }

                val = val * 10 + c;

                if (nxt_slow_path(val > max)) {
                    /* An overflow. */
                    return -2;
                }

                len--;

            } while (len != 0);

            return val << shift;
        }
    }

    return -1;
}


/*
 * nxt_off_t_parse() returns nxt_off_t value >= 0 on success,
 * -1 on failure, and -2 on overflow.
 */

nxt_off_t
nxt_off_t_parse(const u_char *p, size_t len)
{
    u_char      c;
    nxt_uoff_t  val;

    if (nxt_fast_path(len != 0)) {

        val = 0;

        do {
            c = *p++;

            /* Values below '0' become >= 208. */
            c = c - '0';

            if (nxt_slow_path(c > 9)) {
                return -1;
            }

            val = val * 10 + c;

            if (nxt_slow_path((nxt_off_t) val < 0)) {
                /* An overflow. */
                return -2;
            }

            len--;

        } while (len != 0);

        return val;
    }

    return -1;
}


/*
 * nxt_str_int_parse() returns nxt_int_t value >= 0 on success,
 * -1 on failure, and -2 on overflow and also updates the 's' argument.
 */

nxt_int_t
nxt_str_int_parse(nxt_str_t *s)
{
    u_char      c, *p;
    size_t      len;
    nxt_uint_t  val;

    len = s->len;

    if (nxt_slow_path(len == 0)) {
        return -1;
    }

    p = s->data;
    val = 0;

    do {
        c = *p;

        /* Values below '0' become >= 208. */
        c = c - '0';

        if (c > 9) {
            break;
        }

        val = val * 10 + c;

        if (nxt_slow_path((nxt_int_t) val < 0)) {
            /* An overflow. */
            return -2;
        }

        p++;
        len--;

    } while (len != 0);

    s->len = len;
    s->data = p;

    return val;
}


/*
 * nxt_number_parse() returns a double value >= 0 and updates the start
 * argument on success, or returns -1 on failure or -2 on overflow.
 */

double
nxt_number_parse(const u_char **start, const u_char *end)
{
    u_char        c;
    nxt_uint_t    integral, frac, power;
    const u_char  *p;

    p = *start;
    integral = 0;

    while (p < end) {
        c = *p;

        if (c == '.') {
            goto dot;
        }

        /* Values below '0' become >= 208. */
        c = c - '0';

        if (c > 9) {
            break;
        }

        integral = integral * 10 + c;

        if (nxt_slow_path((nxt_int_t) integral < 0)) {
            /* An overflow. */
            return -2;
        }

        p++;
    }

    if (nxt_fast_path(p != *start)) {
        *start = p;
        return integral;
    }

    /* No value. */
    return -1;

dot:

    if (nxt_slow_path(p == *start)) {
        /* No leading digit before dot. */
        return -1;
    }

    frac = 0;
    power = 1;

    for (p++; p < end; p++) {
        c = *p;

        /* Values below '0' become >= 208. */
        c = c - '0';

        if (c > 9) {
            break;
        }

        frac = frac * 10 + c;
        power *= 10;

        if (nxt_slow_path((nxt_int_t) frac < 0 || (nxt_int_t) power < 0)) {
            /* An overflow. */
            return -2;
        }
    }

    *start = p;

    return integral + (double) frac / power;
}
