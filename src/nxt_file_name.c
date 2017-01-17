
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * Supported formats:
 *    %s     null-terminated string
 *    %*s    length and string
 *    %FN    nxt_file_name_t *
 *    %V     nxt_str_t *
 *    %Z     '\0', this null is not counted in file name lenght.
 */

nxt_int_t
nxt_file_name_create(nxt_mem_pool_t *mp, nxt_file_name_str_t *file_name,
    const char *format, ...)
{
    u_char           ch, *p;
    size_t           len;
    va_list          args;
    nxt_str_t        *v;
    nxt_bool_t       zero;
    const char       *fmt;
    nxt_file_name_t  *dst, *fn;

    va_start(args, format);
    fmt = format;
    zero = 0;
    len = 0;

    for ( ;; ) {
        ch = *fmt++;

        if (ch != '%') {

            if (ch != '\0') {
                len++;
                continue;
            }

            break;
        }

        ch = *fmt++;

        switch (ch) {

        case 'V':
            v = va_arg(args, nxt_str_t *);

            if (nxt_fast_path(v != NULL)) {
                len += v->len;
            }

            continue;

        case 's':
            p = va_arg(args, u_char *);

            if (nxt_fast_path(p != NULL)) {
                while (*p != '\0') {
                    p++;
                    len++;
                }
            }

            continue;

        case '*':
            len += va_arg(args, u_int);
            fmt++;

            continue;

        case 'F':
            ch = *fmt++;

            if (nxt_fast_path(ch == 'N')) {
                fn = va_arg(args, nxt_file_name_t *);

                if (nxt_fast_path(fn != NULL)) {
                    while (*fn != '\0') {
                        fn++;
                        len += sizeof(nxt_file_name_t);
                    }
                }
            }

            continue;

        case 'Z':
            zero = 1;
            len++;
            continue;

        default:
            continue;
        }
    }

    va_end(args);

    if (len == 0) {
        return NXT_ERROR;
    }

    file_name->len = len - zero;

    fn = nxt_file_name_alloc(mp, len);
    if (nxt_slow_path(fn == NULL)) {
        return NXT_ERROR;
    }

    file_name->start = fn;
    dst = fn;

    va_start(args, format);
    fmt = format;

    for ( ;; ) {
        ch = *fmt++;

        if (ch != '%') {

            if (ch != '\0') {
                *dst++ = (nxt_file_name_t) ch;
                continue;
            }

            break;
        }

        ch = *fmt++;

        switch (ch) {

        case 'V':
            v = va_arg(args, nxt_str_t *);

            if (nxt_fast_path(v != NULL)) {
                dst = nxt_file_name_add(dst, v->data, v->len);
            }

            continue;

        case 's':
            p = va_arg(args, u_char *);

            if (nxt_fast_path(p != NULL)) {
                while (*p != '\0') {
                    *dst++ = (nxt_file_name_t) (*p++);
                }
            }

            continue;

        case '*':
            len += va_arg(args, u_int);

            ch = *fmt++;

            if (nxt_fast_path(ch == 's')) {
                p = va_arg(args, u_char *);
                dst = nxt_file_name_add(dst, p, len);
            }

            continue;

        case 'F':
            ch = *fmt++;

            if (nxt_fast_path(ch == 'N')) {
                fn = va_arg(args, nxt_file_name_t *);

                if (nxt_fast_path(fn != NULL)) {
                    while (*fn != '\0') {
                        *dst++ = *fn++;
                    }
                }
            }

            continue;

        case 'Z':
            *dst++ = '\0';
            continue;

        default:
            continue;
        }
    }

    va_end(args);

    return NXT_OK;
}
