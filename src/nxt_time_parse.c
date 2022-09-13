
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * nxt_time_parse() parses a time string given in RFC822, RFC850, or ISOC
 * formats and returns nxt_time_t value >= 0 on success or -1 on failure.
 */

nxt_time_t
nxt_time_parse(const u_char *p, size_t len)
{
    size_t            n;
    u_char            c;
    uint64_t          s;
    nxt_int_t         yr, month, day, hour, min, sec;
    nxt_uint_t        year, days;
    const u_char      *end;

    static const nxt_int_t  mday[12] = {
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };

    enum {
        RFC822 = 0,   /* "Mon, 28 Sep 1970 12:00:00"  */
        RFC850,       /* "Monday, 28-Sep-70 12:00:00" */
        ISOC,         /* "Mon Sep 28 12:00:00 1970"   */
    } fmt;

    fmt = RFC822;
    end = p + len;

    while (p < end) {
        c = *p++;

        if (c == ',') {
            break;
        }

        if (c == ' ') {
            fmt = ISOC;
            break;
        }
    }

    while (p < end) {
        if (*p != ' ') {
            break;
        }

        p++;
    }

    if (nxt_slow_path(p + 18 > end)) {
        /* Lesser than RFC850 "28-Sep-70 12:00:00" length. */
        return -1;
    }

    day = 0;

    if (fmt != ISOC) {
        day = nxt_int_parse(p, 2);
        if (nxt_slow_path(day <= 0)) {
            return -1;
        }
        p += 2;

        if (*p == ' ') {
            if (nxt_slow_path(p + 18 > end)) {
                /* Lesser than RFC822 " Sep 1970 12:00:00" length. */
                return -1;
            }

            /* RFC822 */

        } else if (*p == '-') {
            fmt = RFC850;

        } else {
            return -1;
        }

        p++;
    }

    switch (*p) {

    case 'J':
        month = p[1] == 'a' ? 0 : p[2] == 'n' ? 5 : 6;
        break;

    case 'F':
        month = 1;
        break;

    case 'M':
        month = p[2] == 'r' ? 2 : 4;
        break;

    case 'A':
        month = p[1] == 'p' ? 3 : 7;
        break;

    case 'S':
        month = 8;
        break;

    case 'O':
        month = 9;
        break;

    case 'N':
        month = 10;
        break;

    case 'D':
        month = 11;
        break;

    default:
        return -1;
    }

    p += 3;
    yr = 0;

    switch (fmt) {

    case RFC822:
        if (nxt_slow_path(*p++ != ' ')) {
            return -1;
        }

        yr = nxt_int_parse(p, 4);
        if (nxt_slow_path(yr <= 0)) {
            return -1;
        }
        p += 4;

        break;

    case RFC850:
        if (nxt_slow_path(*p++ != '-')) {
            return -1;
        }

        yr = nxt_int_parse(p, 2);
        if (nxt_slow_path(yr <= 0)) {
            return -1;
        }
        p += 2;

        yr += (yr < 70) ? 2000 : 1900;

        break;

    default: /* ISOC */
        if (nxt_slow_path(*p++ != ' ')) {
            return -1;
        }

        if (p[0] != ' ') {
            n = 2;

            if (p[1] == ' ') {
                n = 1;
            }

        } else {
            p++;
            n = 1;
        }

        day = nxt_int_parse(p, n);
        if (nxt_slow_path(day <= 0)) {
            return -1;
        }
        p += n;

        if (nxt_slow_path(p + 14 > end)) {
            /* Lesser than ISOC " 12:00:00 1970" length. */
            return -1;
        }

        break;
    }

    if (nxt_slow_path(*p++ != ' ')) {
        return -1;
    }

    hour = nxt_int_parse(p, 2);
    if (nxt_slow_path(hour < 0)) {
        return -1;
    }
    p += 2;

    if (nxt_slow_path(*p++ != ':')) {
        return -1;
    }

    min = nxt_int_parse(p, 2);
    if (nxt_slow_path(min < 0)) {
        return -1;
    }
    p += 2;

    if (nxt_slow_path(*p++ != ':')) {
        return -1;
    }

    sec = nxt_int_parse(p, 2);
    if (nxt_slow_path(sec < 0)) {
        return -1;
    }

    if (fmt == ISOC) {
        p += 2;

        if (nxt_slow_path(*p++ != ' ')) {
            return -1;
        }

        yr = nxt_int_parse(p, 4);
        if (nxt_slow_path(yr < 0)) {
            return -1;
        }
    }

    if (nxt_slow_path(hour > 23 || min > 59 || sec > 59)) {
        return -1;
    }

    year = yr;

    if (day == 29 && month == 1) {

        if (nxt_slow_path((year & 3) != 0)) {
            /* Not a leap year. */
            return -1;
        }

        if (nxt_slow_path((year % 100 == 0) && (year % 400) != 0)) {
            /* Not a leap year. */
            return -1;
        }

    } else if (nxt_slow_path(day > mday[(nxt_uint_t) month])) {
        return -1;
    }

    /*
     * Shift new year to March 1 and start months
     * from 1 (not 0), as required for Gauss' formula.
     */

    if (--month <= 0) {
        month += 12;
        year -= 1;
    }

    /* Gauss' formula for Gregorian days since March 1, 1 BCE. */

           /* Days in years including leap years since March 1, 1 BCE. */
    days = 365 * year + year / 4 - year / 100 + year / 400

           /* Days before the month. */
           + 367 * (nxt_uint_t) month / 12 - 30

           /* Days before the day. */
           + (nxt_uint_t) day - 1;

    /*
     * 719527 days were between March 1, 1 BCE and March 1, 1970,
     * 31 and 28 days were in January and February 1970.
     */
    days = days - 719527 + 31 + 28;

    s = (uint64_t) days * 86400
        + (nxt_uint_t) hour * 3600
        + (nxt_uint_t) min * 60
        + (nxt_uint_t) sec;

#if (NXT_TIME_T_SIZE <= 4)

    /* Y2038 */

    if (nxt_slow_path(s > 0x7FFFFFFF)) {
        return -1;
    }

#endif

    return (nxt_time_t) s;
}


/*
 * nxt_term_parse() parses term string given in format "200", "10m",
 * or "1d 1h" and returns nxt_int_t value >= 0 on success, -1 on failure,
 * and -2 on overflow.  The maximum valid value is 2^31 - 1 or about
 * 68 years in seconds or about 24 days in milliseconds.
 */

nxt_int_t
nxt_term_parse(const u_char *p, size_t len, nxt_bool_t seconds)
{
    u_char        c, ch;
    nxt_uint_t    val, term, scale, max;
    const u_char  *end;

    enum {
        st_first_digit = 0,
        st_digit,
        st_letter,
        st_space,
    } state;

    enum {
        st_start = 0,
        st_year,
        st_month,
        st_week,
        st_day,
        st_hour,
        st_min,
        st_sec,
        st_msec,
        st_last,
    } step;

    val = 0;
    term = 0;
    state = st_first_digit;
    step = seconds ? st_start : st_month;

    end = p + len;

    while (p < end) {

        ch = *p++;

        if (state == st_space) {

            if (ch == ' ') {
                continue;
            }

            state = st_first_digit;
        }

        if (state != st_letter) {

            /* Values below '0' become >= 208. */
            c = ch - '0';

            if (c <= 9) {
                val = val * 10 + c;
                state = st_digit;
                continue;
            }

            if (state == st_first_digit) {
                return -1;
            }

            state = st_letter;
        }

        switch (ch) {

        case 'y':
            if (step > st_start) {
                return -1;
            }
            step = st_year;
            max = NXT_INT32_T_MAX / (365 * 24 * 60 * 60);
            scale = 365 * 24 * 60 * 60;
            break;

        case 'M':
            if (step >= st_month) {
                return -1;
            }
            step = st_month;
            max = NXT_INT32_T_MAX / (30 * 24 * 60 * 60);
            scale = 30 * 24 * 60 * 60;
            break;

        case 'w':
            if (step >= st_week) {
                return -1;
            }
            step = st_week;
            max = NXT_INT32_T_MAX / (7 * 24 * 60 * 60);
            scale = 7 * 24 * 60 * 60;
            break;

        case 'd':
            if (step >= st_day) {
                return -1;
            }
            step = st_day;
            max = NXT_INT32_T_MAX / (24 * 60 * 60);
            scale = 24 * 60 * 60;
            break;

        case 'h':
            if (step >= st_hour) {
                return -1;
            }
            step = st_hour;
            max = NXT_INT32_T_MAX / (60 * 60);
            scale = 60 * 60;
            break;

        case 'm':
            if (p < end && *p == 's') {
                if (seconds || step >= st_msec) {
                    return -1;
                }
                p++;
                step = st_msec;
                max = NXT_INT32_T_MAX;
                scale = 1;
                break;
            }

            if (step >= st_min) {
                return -1;
            }
            step = st_min;
            max = NXT_INT32_T_MAX / 60;
            scale = 60;
            break;

        case 's':
            if (step >= st_sec) {
                return -1;
            }
            step = st_sec;
            max = NXT_INT32_T_MAX;
            scale = 1;
            break;

        case ' ':
            if (step >= st_sec) {
                return -1;
            }
            step = st_last;
            max = NXT_INT32_T_MAX;
            scale = 1;
            break;

        default:
            return -1;
        }

        if (!seconds && step != st_msec) {
            scale *= 1000;
            max /= 1000;
        }

        if (val > max) {
            return -2;
        }

        term += val * scale;

        if (term > NXT_INT32_T_MAX) {
            return -2;
        }

        val = 0;

        state = st_space;
    }

    if (!seconds) {
        val *= 1000;
    }

    return term + val;
}
