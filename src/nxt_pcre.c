/*
 * Copyright (C) Axel Duch
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_regex.h>
#include <pcre.h>


struct nxt_regex_s {
    pcre        *code;
    pcre_extra  *extra;
    nxt_str_t   pattern;
};

struct nxt_regex_match_s {
    int  ovecsize;
    int  ovec[];
};


static void *nxt_pcre_malloc(size_t size);
static void nxt_pcre_free(void *p);

static nxt_mp_t  *nxt_pcre_mp;


nxt_regex_t *
nxt_regex_compile(nxt_mp_t *mp, nxt_str_t *source, nxt_regex_err_t *err)
{
    int          erroffset;
    char         *pattern;
    void         *saved_malloc, *saved_free;
    nxt_regex_t  *re;

    err->offset = source->length;

    re = nxt_mp_get(mp, sizeof(nxt_regex_t) + source->length + 1);
    if (nxt_slow_path(re == NULL)) {
        err->msg = "memory allocation failed";
        return NULL;
    }

    pattern = nxt_pointer_to(re, sizeof(nxt_regex_t));

    nxt_memcpy(pattern, source->start, source->length);
    pattern[source->length] = '\0';

    re->pattern.length = source->length;
    re->pattern.start = (u_char *) pattern;

    saved_malloc = pcre_malloc;
    saved_free = pcre_free;

    pcre_malloc = nxt_pcre_malloc;
    pcre_free = nxt_pcre_free;
    nxt_pcre_mp = mp;

    re->code = pcre_compile(pattern, 0, &err->msg, &erroffset, NULL);
    if (nxt_fast_path(re->code != NULL)) {
#if 0
        re->extra = pcre_study(re->code, PCRE_STUDY_JIT_COMPILE, &err->msg);
        if (nxt_slow_path(re->extra == NULL && err->msg != NULL)) {
            nxt_log_warn(thr->log, "pcre_study(%V) failed: %s", source, err->msg);
        }
#else
        re->extra = NULL;
#endif

    } else {
        err->offset = erroffset;
        re = NULL;
    }

    pcre_malloc = saved_malloc;
    pcre_free = saved_free;

    return re;
}


static void*
nxt_pcre_malloc(size_t size)
{
    if (nxt_slow_path(nxt_pcre_mp == NULL)) {
        nxt_thread_log_alert("pcre_malloc(%uz) called without memory pool",
                             size);
        return NULL;
    }

    nxt_thread_log_debug("pcre_malloc(%uz), pool %p", size, nxt_pcre_mp);

    return nxt_mp_get(nxt_pcre_mp, size);
}


static void
nxt_pcre_free(void *p)
{
}


nxt_regex_match_t *
nxt_regex_match_create(nxt_mp_t *mp, size_t size)
{
    nxt_regex_match_t  *match;

    match = nxt_mp_get(mp, sizeof(nxt_regex_match_t) + sizeof(int) * size);
    if (nxt_fast_path(match != NULL)) {
        match->ovecsize = size;
    }

    return match;
}


nxt_int_t
nxt_regex_match(nxt_regex_t *re, u_char *subject, size_t length,
    nxt_regex_match_t *match)
{
    int  ret;

    ret = pcre_exec(re->code, re->extra, (const char *) subject, length, 0, 0,
                    match->ovec, match->ovecsize);
    if (nxt_slow_path(ret < PCRE_ERROR_NOMATCH)) {
        nxt_thread_log_error(NXT_LOG_ERR,
                             "pcre_exec() failed: %d on \"%*s\" using \"%V\"",
                             ret, length, subject, &re->pattern);

        return NXT_ERROR;
    }

    return (ret != PCRE_ERROR_NOMATCH);
}
