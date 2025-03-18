
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <math.h>
#include <float.h>


/*
 * Supported formats:
 *
 *    %[0][width][x|X]O         nxt_off_t
 *    %[0][width][x|X]T         nxt_time_t
 *    %[0][width][u][x|X]z      ssize_t/size_t
 *    %[0][width][u][x|X]d      int/u_int
 *    %[0][width][u][x|X]l      long
 *    %[0][width|m][u][x|X]i    nxt_int_t/nxt_uint_t
 *    %[0][width][u][x|X]D      int32_t/uint32_t
 *    %[0][width][u][x|X]L      int64_t/uint64_t
 *    %[0][width|m][u][x|X]A    nxt_atomic_int_t/nxt_atomic_uint_t
 *    %[0][width][.width]f      double, max valid number fits to %18.15f
 *
 *    %FD                       nxt_fd_t, int / HANDLE
 *    %d                        nxt_socket_t, int
 *
 *    %PI                       nxt_pid_t, process id
 *    %PT                       nxt_tid_t, thread id
 *    %PF                       nxt_fid_t, fiber id
 *    %PH                       pthread_t handle returned by pthread_self()
 *
 *    %s                        null-terminated string
 *    %*s                       length and string
 *    %FN                       nxt_file_name_t *
 *
 *    %M                        nxt_msec_t
 *    %N                        nxt_nsec_t
 *    %r                        rlim_t
 *    %p                        void *
 *    %b                        nxt_bool_t
 *    %E                        nxt_err_t
 *    %V                        nxt_str_t *
 *    %Z                        '\0'
 *    %n                        '\n'
 *    %c                        char
 *    %%                        %
 *
 *  Reserved:
 *    %t                        ptrdiff_t
 *    %S                        null-terminated wchar string
 *    %C                        wchar
 *    %[0][width][u][x|X]Q      int128_t/uint128_t
 */


u_char * nxt_cdecl
nxt_sprintf(u_char *buf, u_char *end, const char *fmt, ...)
{
    u_char   *p;
    va_list  args;

    va_start(args, fmt);
    p = nxt_vsprintf(buf, end, fmt, args);
    va_end(args);

    return p;
}


/*
 * nxt_sprintf_t is used:
 *    to pass several parameters of nxt_integer() via single pointer
 *    and to store little used variables of nxt_vsprintf().
 */

typedef struct {
    u_char        *end;
    const u_char  *hex;
    uint32_t      width;
    int32_t       frac_width;
    uint8_t       max_width;
    u_char        padding;
} nxt_sprintf_t;


static u_char *nxt_integer(nxt_sprintf_t *spf, u_char *buf, uint64_t ui64);
static u_char *nxt_number(nxt_sprintf_t *spf, u_char *buf, double n);


/* A right way of "f == 0.0". */
#define nxt_double_is_zero(f)                                                 \
    (fabs(f) <= FLT_EPSILON)


u_char *
nxt_vsprintf(u_char *buf, u_char *end, const char *fmt, va_list args)
{
    int                  d;
    double               f, i;
    size_t               length;
    int64_t              i64;
    uint64_t             ui64, frac;
    nxt_str_t            *v;
    nxt_err_t            err;
    nxt_uint_t           scale, n;
    nxt_msec_t           ms;
    nxt_nsec_t           ns;
    nxt_bool_t           sign;
    const u_char         *p;
    nxt_sprintf_t        spf;
    nxt_file_name_t      *fn;

    static const u_char  hexadecimal[16] NXT_NONSTRING = "0123456789abcdef";
    static const u_char  HEXADECIMAL[16] NXT_NONSTRING = "0123456789ABCDEF";
    static const u_char  nan[] = "[nan]";
    static const u_char  null[] = "[null]";
    static const u_char  infinity[] = "[infinity]";

    spf.end = end;

    while (*fmt != '\0' && buf < end) {

        /*
         * "buf < end" means that we could copy at least one character:
         * a plain character, "%%", "%c", or a minus without test.
         */

        if (*fmt != '%') {
            *buf++ = *fmt++;
            continue;
        }

        fmt++;

        /* Test some often used text formats first. */

        switch (*fmt) {

        case 'V':
            fmt++;
            v = va_arg(args, nxt_str_t *);

            if (nxt_fast_path(v != NULL)) {
                length = v->length;
                p = v->start;
                goto copy;
            }

            continue;

        case 's':
            fmt++;

            p = va_arg(args, const u_char *);

            if (nxt_slow_path(p == NULL)) {
                buf = nxt_cpymem(buf, null, nxt_length(null));
                continue;
            }

            while (*p != '\0' && buf < end) {
                *buf++ = *p++;
            }

            continue;

        case '*':
            length = va_arg(args, size_t);

            fmt++;

            if (*fmt == 's') {
                fmt++;
                p = va_arg(args, const u_char *);

                if (nxt_slow_path(p == NULL)) {
                    buf = nxt_cpymem(buf, null, nxt_length(null));
                    continue;
                }

                goto copy;
            }

            continue;

        default:
            break;
        }

        spf.hex = NULL;
        spf.width = 0;
        spf.frac_width = -1;
        spf.max_width = 0;
        spf.padding = (*fmt == '0') ? '0' : ' ';

        sign = 1;

        i64 = 0;
        ui64 = 0;

        while (*fmt >= '0' && *fmt <= '9') {
            spf.width = spf.width * 10 + (*fmt++ - '0');
        }


        for ( ;; ) {
            switch (*fmt) {

            case 'u':
                sign = 0;
                fmt++;
                continue;

            case 'm':
                spf.max_width = 1;
                fmt++;
                continue;

            case 'X':
                spf.hex = HEXADECIMAL;
                sign = 0;
                fmt++;
                continue;

            case 'x':
                spf.hex = hexadecimal;
                sign = 0;
                fmt++;
                continue;

            case '.':
                fmt++;
                spf.frac_width = 0;

                while (*fmt >= '0' && *fmt <= '9') {
                    spf.frac_width = spf.frac_width * 10 + *fmt++ - '0';
                }

                break;

            default:
                break;
            }

            break;
        }


        switch (*fmt) {

        case 'E':
            err = va_arg(args, nxt_err_t);

            *buf++ = '(';
            spf.hex = NULL;
            spf.width = 0;
            buf = nxt_integer(&spf, buf, err);

            if (buf < end - 1) {
                *buf++ = ':';
                *buf++ = ' ';
            }

            buf = nxt_strerror(err, buf, end - buf);

            if (buf < end) {
                *buf++ = ')';
            }

            fmt++;
            continue;

        case 'O':
            i64 = (int64_t) va_arg(args, nxt_off_t);
            sign = 1;
            goto number;

        case 'T':
            i64 = (int64_t) va_arg(args, nxt_time_t);
            sign = 1;
            goto number;

        case 'M':
            ms = (nxt_msec_t) va_arg(args, nxt_msec_t);
            if ((nxt_msec_int_t) ms == -1 && spf.hex == NULL) {
                i64 = -1;
                sign = 1;
            } else {
                ui64 = (uint64_t) ms;
                sign = 0;
            }
            goto number;

        case 'N':
            ns = (nxt_nsec_t) va_arg(args, nxt_nsec_t);
            if ((nxt_nsec_int_t) ns == -1) {
                i64 = -1;
                sign = 1;
            } else {
                ui64 = (uint64_t) ns;
                sign = 0;
            }
            goto number;

        case 'z':
            if (sign) {
                i64 = (int64_t) va_arg(args, ssize_t);
            } else {
                ui64 = (uint64_t) va_arg(args, size_t);
            }
            goto number;

        case 'i':
            if (sign) {
                i64 = (int64_t) va_arg(args, nxt_int_t);
            } else {
                ui64 = (uint64_t) va_arg(args, nxt_uint_t);
            }

            if (spf.max_width != 0) {
                spf.width = NXT_INT_T_LEN;
            }

            goto number;

        case 'd':
            if (sign) {
                i64 = (int64_t) va_arg(args, int);
            } else {
                ui64 = (uint64_t) va_arg(args, u_int);
            }
            goto number;

        case 'l':
            if (sign) {
                i64 = (int64_t) va_arg(args, long);
            } else {
                ui64 = (uint64_t) va_arg(args, u_long);
            }
            goto number;

        case 'D':
            if (sign) {
                i64 = (int64_t) va_arg(args, int32_t);
            } else {
                ui64 = (uint64_t) va_arg(args, uint32_t);
            }
            goto number;

        case 'L':
            if (sign) {
                i64 = va_arg(args, int64_t);
            } else {
                ui64 = va_arg(args, uint64_t);
            }
            goto number;

        case 'A':
            if (sign) {
                i64 = (int64_t) va_arg(args, nxt_atomic_int_t);
            } else {
                ui64 = (uint64_t) va_arg(args, nxt_atomic_uint_t);
            }

            if (spf.max_width != 0) {
                spf.width = NXT_ATOMIC_T_LEN;
            }

            goto number;

        case 'b':
            ui64 = (uint64_t) va_arg(args, nxt_bool_t);
            sign = 0;
            goto number;

        case 'f':
            fmt++;

            f = va_arg(args, double);

            if (f < 0) {
                *buf++ = '-';
                f = -f;
            }

            if (nxt_slow_path(isnan(f))) {
                p = nan;
                length = nxt_length(nan);

                goto copy;

            } else if (nxt_slow_path(isinf(f))) {
                p = infinity;
                length = nxt_length(infinity);

                goto copy;
            }

            (void) modf(f, &i);
            frac = 0;

            if (spf.frac_width > 0) {

                scale = 1;
                for (n = spf.frac_width; n != 0; n--) {
                    scale *= 10;
                }

                frac = (uint64_t) ((f - i) * scale + 0.5);

                if (frac == scale) {
                    i += 1;
                    frac = 0;
                }
            }

            buf = nxt_number(&spf, buf, i);

            if (spf.frac_width > 0) {

                if (buf < end) {
                    *buf++ = '.';

                    spf.hex = NULL;
                    spf.padding = '0';
                    spf.width = spf.frac_width;
                    buf = nxt_integer(&spf, buf, frac);
                }

            } else if (spf.frac_width < 0) {
                f = modf(f, &i);

                if (!nxt_double_is_zero(f) && buf < end) {
                    *buf++ = '.';

                    while (!nxt_double_is_zero(f) && buf < end) {
                        f *= 10;
                        f = modf(f, &i);
                        *buf++ = (u_char) i + '0';
                    }
                }
            }

            continue;

        case 'r':
            i64 = (int64_t) va_arg(args, rlim_t);
            sign = 1;
            break;

        case 'p':
            ui64 = (uintptr_t) va_arg(args, void *);
            sign = 0;
            spf.hex = HEXADECIMAL;
            /*
             * spf.width = NXT_PTR_SIZE * 2;
             * spf.padding = '0';
             */
            goto number;

        case 'c':
            d = va_arg(args, int);
            *buf++ = (u_char) (d & 0xFF);
            fmt++;

            continue;

        case 'F':
            fmt++;

            switch (*fmt) {

            case 'D':
                i64 = (int64_t) va_arg(args, nxt_fd_t);
                sign = 1;

                goto number;

            case 'N':
                fn = va_arg(args, nxt_file_name_t *);
                p = fn;

                while (*p != '\0' && buf < end) {
                    *buf++ = *p++;
                }

                fmt++;
                continue;

            default:
                continue;
            }

        case 'P':
            fmt++;

            switch (*fmt) {

            case 'I':
                i64 = (int64_t) va_arg(args, nxt_pid_t);
                sign = 1;
                goto number;

            case 'T':
                ui64 = (uint64_t) (uintptr_t) va_arg(args, nxt_tid_t);
                sign = 0;
                goto number;
#if 0
            case 'F':
                ui64 = (uint64_t) va_arg(args, nxt_fid_t);
                sign = 0;
                goto number;
#endif
            case 'H':
                ui64 = (uint64_t) (uintptr_t) va_arg(args, pthread_t);
                spf.hex = HEXADECIMAL;
                sign = 0;
                goto number;

            default:
                continue;
            }

        case 'Z':
            *buf++ = '\0';
            fmt++;
            continue;

        case 'n':
            *buf++ = '\n';
            fmt++;
            continue;

        case '%':
            *buf++ = '%';
            fmt++;
            continue;

        default:
            *buf++ = *fmt++;
            continue;
        }

    number:

        if (sign) {
            if (i64 < 0) {
                *buf++ = '-';
                ui64 = (uint64_t) -i64;

            } else {
                ui64 = (uint64_t) i64;
            }
        }

        buf = nxt_integer(&spf, buf, ui64);

        fmt++;
        continue;

    copy:

        length = nxt_min((size_t) (end - buf), length);
        buf = nxt_cpymem(buf, p, length);
        continue;
    }

    return buf;
}


static u_char *
nxt_integer(nxt_sprintf_t *spf, u_char *buf, uint64_t ui64)
{
    u_char  *p, *end;
    size_t  length;
    u_char  temp[NXT_INT64_T_LEN];

    p = temp + NXT_INT64_T_LEN;

    if (spf->hex == NULL) {

#if (NXT_32BIT)

        for ( ;; ) {
            u_char    *start;
            uint32_t  ui32;

            /*
             * 32-bit platforms usually lack hardware support of 64-bit
             * division and remainder operations.  For this reason C compiler
             * adds calls to the runtime library functions which provides
             * these operations.  These functions usually have about hundred
             * lines of code.
             *
             * For 32-bit numbers and some constant divisors GCC, Clang and
             * other compilers can use inlined multiplications and shifts
             * which are faster than division or remainder operations.
             * For example, unsigned "ui32 / 10" is compiled to
             *
             *     ((uint64_t) ui32 * 0xCCCCCCCD) >> 35
             *
             * So a 64-bit number is split to parts by 10^9.  The parts fit
             * to 32 bits and are processed separately as 32-bit numbers.  A
             * number of 64-bit division/remainder operations is significantly
             * decreased depending on the 64-bit number's value, it is
             *   0 if the 64-bit value is less than 4294967296,
             *   1 if the 64-bit value is greater than 4294967295
             *                           and less than 4294967296000000000,
             *   2 otherwise.
             */

            if (ui64 <= 0xFFFFFFFF) {
                ui32 = (uint32_t) ui64;
                start = NULL;

            } else {
                ui32 = (uint32_t) (ui64 % 1000000000);
                start = p - 9;
            }

            do {
                *(--p) = (u_char) (ui32 % 10 + '0');
                ui32 /= 10;
            } while (ui32 != 0);

            if (start == NULL) {
                break;
            }

            /* Add leading zeros of part. */

            while (p > start) {
                *(--p) = '0';
            }

            ui64 /= 1000000000;
        }

#else  /* NXT_64BIT */

        do {
            *(--p) = (u_char) (ui64 % 10 + '0');
            ui64 /= 10;
        } while (ui64 != 0);

#endif

    } else {

        do {
            *(--p) = spf->hex[ui64 & 0xF];
            ui64 >>= 4;
        } while (ui64 != 0);
    }

    /* Zero or space padding. */

    if (spf->width != 0) {

        length = (temp + NXT_INT64_T_LEN) - p;
        end = buf + (spf->width - length);
        end = nxt_min(end, spf->end);

        while (buf < end) {
            *buf++ = spf->padding;
        }
    }

    /* Number copying. */

    length = (temp + NXT_INT64_T_LEN) - p;
    end = buf + length;
    end = nxt_min(end, spf->end);

    while (buf < end) {
        *buf++ = *p++;
    }

    return buf;
}


static u_char *
nxt_number(nxt_sprintf_t *spf, u_char *buf, double n)
{
    u_char  *p, *end;
    size_t  length;
    u_char  temp[NXT_DOUBLE_LEN];

    p = temp + NXT_DOUBLE_LEN;

    do {
        *(--p) = (u_char) (fmod(n, 10) + '0');
        n = trunc(n / 10);
    } while (!nxt_double_is_zero(n));

    /* Zero or space padding. */

    if (spf->width != 0) {
        length = (temp + NXT_DOUBLE_LEN) - p;
        end = buf + (spf->width - length);
        end = nxt_min(end, spf->end);

        while (buf < end) {
            *buf++ = spf->padding;
        }
    }

    /* Number copying. */

    length = (temp + NXT_DOUBLE_LEN) - p;

    end = buf + length;
    end = nxt_min(end, spf->end);

    while (buf < end) {
        *buf++ = *p++;
    }

    return buf;
}
