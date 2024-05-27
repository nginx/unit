
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/* The function is valid for positive nxt_time_t only. */

void
nxt_gmtime(nxt_time_t s, struct tm *tm)
{
    nxt_int_t   yday;
    nxt_uint_t  daytime, mday, mon, year, days, leap;

    days = (nxt_uint_t) (s / 86400);
    daytime = (nxt_uint_t) (s % 86400);

    /* January 1, 1970 was Thursday. */
    tm->tm_wday = (4 + days) % 7;

    /* The algorithm based on Gauss' formula. */

    /* Days since March 1, 1 BCE. */
    days = days - (31 + 28) + 719527;

    /*
     * The "days" should be adjusted by 1 only, however some March 1st's
     * go to previous year, so "days" are adjusted by 2.  This also shifts
     * the last February days to the next year, but this is catched by
     * negative "yday".
     */
    year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);

    yday = days - (365 * year + year / 4 - year / 100 + year / 400);

    leap = (year % 4 == 0) && (year % 100 || (year % 400 == 0));

    if (yday < 0) {
        yday = 365 + leap + yday;
        year--;
    }

    /*
     * An empirical formula that maps "yday" to month.
     * There are at least 10 variants, some of them are:
     *     mon = (yday + 31) * 15 / 459
     *     mon = (yday + 31) * 17 / 520
     *     mon = (yday + 31) * 20 / 612
     */

    mon = (yday + 31) * 10 / 306;

    /* The Gauss' formula that evaluates days before month. */

    mday = yday - (367 * mon / 12 - 30) + 1;

    if (yday >= 306) {
        year++;
        mon -= 11;
        yday -= 306;

    } else {
        mon++;
        yday += 31 + 28 + leap;
    }

    tm->tm_mday = mday;
    tm->tm_mon = mon;
    tm->tm_year = year - 1900;
    tm->tm_yday = yday;

    tm->tm_hour = daytime / 3600;
    daytime %= 3600;
    tm->tm_min = daytime / 60;
    tm->tm_sec = daytime % 60;
}
