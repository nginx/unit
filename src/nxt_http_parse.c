
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_http_split_header_part(nxt_http_split_header_parse_t *shp,
    u_char *start, u_char *end);
static nxt_int_t nxt_http_split_header_join(nxt_http_split_header_parse_t *shp);


nxt_int_t
nxt_http_status_parse(nxt_http_status_parse_t *sp, nxt_buf_mem_t *b)
{
    u_char  ch, *p;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_major_digit,
        sw_dot,
        sw_minor_digit,
        sw_space_after_version,
        sw_status_start,
        sw_status_code,
        sw_status_text,
        sw_end,
    } state;

    state = sp->state;

    for (p = b->pos; p < b->free; p++) {

        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            if (nxt_fast_path(ch == 'H')) {
                state = sw_H;
                continue;
            }

            return NXT_ERROR;

        case sw_H:
            if (nxt_fast_path(ch == 'T')) {
                state = sw_HT;
                continue;
            }

            return NXT_ERROR;

        case sw_HT:
            if (nxt_fast_path(ch == 'T')) {
                state = sw_HTT;
                continue;
            }

            return NXT_ERROR;

        case sw_HTT:
            if (nxt_fast_path(ch == 'P')) {
                state = sw_HTTP;
                continue;
            }

            return NXT_ERROR;

        case sw_HTTP:
            if (nxt_fast_path(ch == '/')) {
                state = sw_major_digit;
                continue;
            }

            return NXT_ERROR;

        /*
         * Only HTTP/x.x format is tested because it
         * is unlikely that other formats will appear.
         */
        case sw_major_digit:
            if (nxt_fast_path(ch >= '1' && ch <= '9')) {
                sp->http_version = 10 * (ch - '0');
                state = sw_dot;
                continue;
            }

            return NXT_ERROR;

        case sw_dot:
            if (nxt_fast_path(ch == '.')) {
                state = sw_minor_digit;
                continue;
            }

            return NXT_ERROR;

        case sw_minor_digit:
            if (nxt_fast_path(ch >= '0' && ch <= '9')) {
                sp->http_version += ch - '0';
                state = sw_space_after_version;
                continue;
            }

            return NXT_ERROR;

        case sw_space_after_version:
            if (nxt_fast_path(ch == ' ')) {
                state = sw_status_start;
                continue;
            }

            return NXT_ERROR;

        case sw_status_start:
            if (nxt_slow_path(ch == ' ')) {
                continue;
            }

            sp->start = p;
            state = sw_status_code;

            /* Fall through. */

        /* HTTP status code. */
        case sw_status_code:
            if (nxt_fast_path(ch >= '0' && ch <= '9')) {
                sp->code = sp->code * 10 + (ch - '0');
                continue;
            }

            switch (ch) {
            case ' ':
                state = sw_status_text;
                continue;
            case '.':                    /* IIS may send 403.1, 403.2, etc. */
                state = sw_status_text;
                continue;
            case NXT_CR:
                sp->end = p;
                state = sw_end;
                continue;
            case NXT_LF:
                sp->end = p;
                goto done;
            default:
                return NXT_ERROR;
            }

        /* Any text until end of line. */
        case sw_status_text:
            switch (ch) {
            case NXT_CR:
                sp->end = p;
                state = sw_end;
                continue;
            case NXT_LF:
                sp->end = p;
                goto done;
            }
            continue;

        /* End of status line. */
        case sw_end:
            if (nxt_fast_path(ch == NXT_LF)) {
                goto done;
            }

            return NXT_ERROR;
        }
    }

    b->pos = p;
    sp->state = state;

    return NXT_AGAIN;

done:

    b->pos = p + 1;

    return NXT_OK;
}


nxt_int_t
nxt_http_header_parse(nxt_http_header_parse_t *hp, nxt_buf_mem_t *b)
{
    u_char    c, ch, *p;
    uint32_t  hash;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_ignore_line,
        sw_almost_done,
        sw_header_almost_done,
    } state;

    static const u_char  normal[256]  nxt_aligned(64) =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"

        /* These 64 bytes should reside in one cache line */
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"

        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    nxt_prefetch(&normal[0]);
    nxt_prefetch(&normal[64]);

    state = hp->state;
    hash = hp->header_hash;

    for (p = b->pos; p < b->free; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:
            hp->header_name_start = p;
            hp->invalid_header = 0;

            switch (ch) {
            case NXT_CR:
                hp->header_end = p;
                state = sw_header_almost_done;
                break;
            case NXT_LF:
                hp->header_end = p;
                goto header_done;
            default:
                state = sw_name;

                c = normal[ch];

                if (c) {
                    hash = nxt_djb_hash_add(NXT_DJB_HASH_INIT, c);
                    break;
                }

                if (ch == '_') {
                    hash = nxt_djb_hash_add(NXT_DJB_HASH_INIT, ch);
                    hp->underscore = 1;
                    break;
                }

                hp->invalid_header = 1;
                break;
            }
            break;

        /* header name */
        case sw_name:
            c = normal[ch];

            if (c) {
                hash = nxt_djb_hash_add(hash, c);
                break;
            }

            if (ch == ':') {
                hp->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == NXT_CR) {
                hp->header_name_end = p;
                hp->header_start = p;
                hp->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == NXT_LF) {
                hp->header_name_end = p;
                hp->header_start = p;
                hp->header_end = p;
                goto done;
            }

            if (ch == '_') {
                hash = nxt_djb_hash_add(hash, ch);
                hp->underscore = 1;
                break;
            }

            /* IIS may send the duplicate "HTTP/1.1 ..." lines */
            if (ch == '/'
                && hp->upstream
                && p - hp->header_name_start == 4
                && nxt_memcmp(hp->header_name_start, "HTTP", 4) == 0)
            {
                state = sw_ignore_line;
                break;
            }

            hp->invalid_header = 1;
            break;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case NXT_CR:
                hp->header_start = p;
                hp->header_end = p;
                state = sw_almost_done;
                break;
            case NXT_LF:
                hp->header_start = p;
                hp->header_end = p;
                goto done;
            case '\0':
                hp->invalid_header = 1;
                /* Fall through. */
            default:
                hp->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                hp->header_end = p;
                state = sw_space_after_value;
                break;
            case NXT_CR:
                hp->header_end = p;
                state = sw_almost_done;
                break;
            case NXT_LF:
                hp->header_end = p;
                goto done;
            case '\0':
                hp->invalid_header = 1;
                break;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case NXT_CR:
                state = sw_almost_done;
                break;
            case NXT_LF:
                goto done;
            case '\0':
                hp->invalid_header = 1;
                /* Fall through. */
            default:
                state = sw_value;
                break;
            }
            break;

        /* ignore header line */
        case sw_ignore_line:
            switch (ch) {
            case NXT_LF:
                state = sw_start;
                break;
            default:
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case NXT_LF:
                goto done;
            case NXT_CR:
                break;
            default:
                return NXT_DECLINED;
            }
            break;

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case NXT_LF:
                goto header_done;
            default:
                return NXT_DECLINED;
            }
        }
    }

    b->pos = p;
    hp->state = state;
    hp->header_hash = hash;

    return NXT_AGAIN;

done:

    b->pos = p + 1;
    hp->state = sw_start;
    hp->header_hash = hash;

    return NXT_OK;

header_done:

    b->pos = p + 1;
    hp->state = sw_start;

    return NXT_DONE;
}


nxt_int_t
nxt_http_split_header_parse(nxt_http_split_header_parse_t *shp,
    nxt_buf_mem_t *b)
{
    u_char     *end;
    nxt_int_t  ret;

    if (shp->parts == NULL || nxt_array_is_empty(shp->parts)) {

        ret = nxt_http_header_parse(&shp->parse, b);

        if (nxt_fast_path(ret == NXT_OK)) {
            return ret;
        }

        if (nxt_fast_path(ret == NXT_AGAIN)) {
            /* A buffer is over. */

            if (shp->parse.state == 0) {
                /*
                 * A previous parsed header line is
                 * over right on the end of the buffer.
                 */
                return ret;
            }
            /*
             * Add the first header line part and return NXT_AGAIN on success.
             */
            return nxt_http_split_header_part(shp, shp->parse.header_name_start,
                                              b->pos);
        }

        return ret;
    }

    /* A header line is split in buffers. */

    end = nxt_memchr(b->pos, NXT_LF, b->free - b->pos);

    if (end != NULL) {

        /* The last header line part found. */
        end++;

        ret = nxt_http_split_header_part(shp, b->pos, end);

        if (nxt_fast_path(ret != NXT_ERROR)) {
            /* ret == NXT_AGAIN: success, mark the part if it were parsed. */
            b->pos = end;

            return nxt_http_split_header_join(shp);
        }

        return ret;
    }

    /* Add another header line part and return NXT_AGAIN on success. */

    return nxt_http_split_header_part(shp, b->pos, b->free);
}


static nxt_int_t
nxt_http_split_header_part(nxt_http_split_header_parse_t *shp, u_char *start,
    u_char *end)
{
    nxt_http_header_part_t  *part;

    nxt_thread_log_debug("http source header part: \"%*s\"",
                         end - start, start);

    if (shp->parts == NULL) {
        shp->parts = nxt_array_create(shp->mem_pool, 2,
                                     sizeof(nxt_http_header_part_t));
        if (nxt_slow_path(shp->parts == NULL)) {
            return NXT_ERROR;
        }
    }

    if (!nxt_array_is_empty(shp->parts)) {

        part = nxt_array_last(shp->parts);

        if (part->end == end) {
            part->end = end;
            return NXT_AGAIN;
        }
    }

    part = nxt_array_add(shp->parts);

    if (nxt_fast_path(part != NULL)) {
        part->start = start;
        part->end = end;
        return NXT_AGAIN;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_http_split_header_join(nxt_http_split_header_parse_t *shp)
{
    u_char                  *p;
    size_t                  size;
    nxt_uint_t              n;
    nxt_buf_mem_t           b;
    nxt_http_header_part_t  *part;

    part = shp->parts->elts;
    n = shp->parts->nelts;

    if (n == 1) {
        /*
         * A header line was read by parts, but resides continuously in a
         * stream source buffer, so use disposition in the original buffer.
         */
        b.pos = part->start;
        b.free = part->end;

    } else {
        /* Join header line parts to store the header line and ot parse it. */

        size = 0;

        do {
            size += part->end - part->start;
            part++;
            n--;
        } while (n != 0);

        p = nxt_mem_alloc(shp->mem_pool, size);
        if (nxt_slow_path(p == NULL)) {
            return NXT_ERROR;
        }

        b.pos = p;

        part = shp->parts->elts;
        n = shp->parts->nelts;

        do {
            p = nxt_cpymem(p, part->start, part->end - part->start);
            part++;
            n--;
        } while (n != 0);

        b.free = p;
    }

    /* b.start and b.end are not required for parsing. */

    nxt_array_reset(shp->parts);

    /* Reset a header parse state to the sw_start. */
    shp->parse.state = 0;

    return nxt_http_header_parse(&shp->parse, &b);
}
