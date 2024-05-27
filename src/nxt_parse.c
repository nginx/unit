
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
nxt_int_parse(const u_char *p, size_t length)
{
    u_char      c;
    nxt_uint_t  val;

    static const nxt_uint_t cutoff = NXT_INT_T_MAX / 10;
    static const nxt_uint_t cutlim = NXT_INT_T_MAX % 10;

    if (nxt_fast_path(length != 0)) {

        val = 0;

        do {
            c = *p++;

            /* Values below '0' become >= 208. */
            c = c - '0';

            if (nxt_slow_path(c > 9)) {
                return -1;
            }

            if (nxt_slow_path(val >= cutoff && (val > cutoff || c > cutlim))) {
                /* An overflow. */
                return -2;
            }

            val = val * 10 + c;

            length--;

        } while (length != 0);

        return val;
    }

    return -1;
}


/*
 * nxt_size_t_parse() returns size_t value >= 0 on success,
 * -1 on failure, and -2 on overflow.
 */

ssize_t
nxt_size_t_parse(const u_char *p, size_t length)
{
    u_char  c;
    size_t  val;

    static const size_t cutoff = NXT_SIZE_T_MAX / 10;
    static const size_t cutlim = NXT_SIZE_T_MAX % 10;

    if (nxt_fast_path(length != 0)) {

        val = 0;

        do {
            c = *p++;

            /* Values below '0' become >= 208. */
            c = c - '0';

            if (nxt_slow_path(c > 9)) {
                return -1;
            }

            if (nxt_slow_path(val >= cutoff && (val > cutoff || c > cutlim))) {
                /* An overflow. */
                return -2;
            }

            val = val * 10 + c;

            length--;

        } while (length != 0);

        return val;
    }

    return -1;
}


/*
 * nxt_size_parse() parses size string with optional K or M units and
 * returns size_t value >= 0 on success, -1 on failure, and -2 on overflow.
 */

ssize_t
nxt_size_parse(const u_char *p, size_t length)
{
    u_char      unit;
    ssize_t     val, max;
    nxt_uint_t  shift;

    if (nxt_fast_path(length != 0)) {

        length--;

        /* Upper case. */
        unit = p[length] & ~0x20;

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
            return nxt_size_t_parse(p, length + 1);
        }

        val = nxt_size_t_parse(p, length);

        if (nxt_fast_path(val >= 0)) {

            if (nxt_slow_path(val > max)) {
                /* An overflow. */
                return -2;
            }

            val <<= shift;
        }

        return val;
    }

    return -1;
}


/*
 * nxt_off_t_parse() returns nxt_off_t value >= 0 on success,
 * -1 on failure, and -2 on overflow.
 */

nxt_off_t
nxt_off_t_parse(const u_char *p, size_t length)
{
    u_char      c;
    nxt_uoff_t  val;

    static const nxt_uoff_t cutoff = NXT_OFF_T_MAX / 10;
    static const nxt_uoff_t cutlim = NXT_OFF_T_MAX % 10;

    if (nxt_fast_path(length != 0)) {

        val = 0;

        do {
            c = *p++;

            /* Values below '0' become >= 208. */
            c = c - '0';

            if (nxt_slow_path(c > 9)) {
                return -1;
            }

            if (nxt_slow_path(val >= cutoff && (val > cutoff || c > cutlim))) {
                /* An overflow. */
                return -2;
            }

            val = val * 10 + c;

            length--;

        } while (length != 0);

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
    size_t      length;
    nxt_uint_t  val;

    static const nxt_uint_t cutoff = NXT_INT_T_MAX / 10;
    static const nxt_uint_t cutlim = NXT_INT_T_MAX % 10;

    length = s->length;

    if (nxt_slow_path(length == 0)) {
        return -1;
    }

    p = s->start;
    val = 0;

    do {
        c = *p;

        /* Values below '0' become >= 208. */
        c = c - '0';

        if (c > 9) {
            break;
        }

        if (nxt_slow_path(val >= cutoff && (val > cutoff || c > cutlim))) {
            /* An overflow. */
            return -2;
        }

        val = val * 10 + c;

        p++;
        length--;

    } while (length != 0);

    s->length = length;
    s->start = p;

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
    nxt_bool_t    overflow;
    nxt_uint_t    integral, frac, power;
    const u_char  *p;

    static const nxt_uint_t cutoff = NXT_INT_T_MAX / 10;
    static const nxt_uint_t cutlim = NXT_INT_T_MAX % 10;

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

        overflow = nxt_expect(0, (integral >= cutoff
                                  && (integral > cutoff || c > cutlim)));

        if (overflow) {
            return -2;
        }

        integral = integral * 10 + c;

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

        overflow = nxt_expect(0, (frac >= cutoff && (frac > cutoff
                                                     || c > cutlim))
                                 || power > cutoff);

        if (overflow) {
            return -2;
        }

        frac = frac * 10 + c;
        power *= 10;
    }

    *start = p;

    return integral + (double) frac / power;
}
