/*
 * Copyright (C) Axel Duch
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_regex.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>


static void *nxt_pcre2_malloc(PCRE2_SIZE size, void *memory_data);
static void nxt_pcre2_free(void *p, void *memory_data);


struct nxt_regex_s {
    pcre2_code  *code;
    nxt_str_t   pattern;
};


nxt_regex_t *
nxt_regex_compile(nxt_mp_t *mp, nxt_str_t *source, nxt_regex_err_t *err)
{
    int                    errcode;
    nxt_int_t              ret;
    PCRE2_SIZE             erroffset;
    nxt_regex_t            *re;
    pcre2_general_context  *general_ctx;
    pcre2_compile_context  *compile_ctx;

    static const u_char    alloc_error[] = "memory allocation failed";

    general_ctx = pcre2_general_context_create(nxt_pcre2_malloc,
                                               nxt_pcre2_free, mp);
    if (nxt_slow_path(general_ctx == NULL)) {
        goto alloc_fail;
    }

    compile_ctx = pcre2_compile_context_create(general_ctx);
    if (nxt_slow_path(compile_ctx == NULL)) {
        goto alloc_fail;
    }

    re = nxt_mp_get(mp, sizeof(nxt_regex_t));
    if (nxt_slow_path(re == NULL)) {
        goto alloc_fail;
    }

    if (nxt_slow_path(nxt_str_dup(mp, &re->pattern, source) == NULL)) {
        goto alloc_fail;
    }

    re->code = pcre2_compile((PCRE2_SPTR) source->start, source->length, 0,
                             &errcode, &erroffset, compile_ctx);
    if (nxt_slow_path(re->code == NULL)) {
        err->offset = erroffset;

        ret = pcre2_get_error_message(errcode, (PCRE2_UCHAR *) err->msg,
                                      ERR_BUF_SIZE);
        if (ret < 0) {
            (void) nxt_sprintf(err->msg, err->msg + ERR_BUF_SIZE,
                               "compilation failed with unknown "
                               "error code: %d%Z", errcode);
        }

        return NULL;
    }

#if 0
    errcode = pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);
    if (nxt_slow_path(errcode != 0 && errcode != PCRE2_ERROR_JIT_BADOPTION)) {
        ret = pcre2_get_error_message(errcode, (PCRE2_UCHAR *) err->msg,
                                      ERR_BUF_SIZE);
        if (ret < 0) {
            (void) nxt_sprintf(err->msg, err->msg + ERR_BUF_SIZE,
                               "JIT compilation failed with unknown "
                               "error code: %d%Z", errcode);
        }

        return NULL;
    }
#endif

    return re;

alloc_fail:

    err->offset = source->length;
    nxt_memcpy(err->msg, alloc_error, sizeof(alloc_error));

    return NULL;
}


static void *
nxt_pcre2_malloc(PCRE2_SIZE size, void *mp)
{
    return nxt_mp_get(mp, size);
}


static void
nxt_pcre2_free(void *p, void *mp)
{
}


nxt_regex_match_t *
nxt_regex_match_create(nxt_mp_t *mp, size_t size)
{
    nxt_regex_match_t      *match;
    pcre2_general_context  *ctx;

    ctx = pcre2_general_context_create(nxt_pcre2_malloc, nxt_pcre2_free, mp);
    if (nxt_slow_path(ctx == NULL)) {
        nxt_thread_log_alert("pcre2_general_context_create() failed");
        return NULL;
    }

    match = pcre2_match_data_create(size, ctx);
    if (nxt_slow_path(match == NULL)) {
        nxt_thread_log_alert("pcre2_match_data_create(%uz) failed", size);
        return NULL;
    }

    return match;
}


nxt_int_t
nxt_regex_match(nxt_regex_t *re, u_char *subject, size_t length,
    nxt_regex_match_t *match)
{
    nxt_int_t    ret;
    PCRE2_UCHAR  errptr[ERR_BUF_SIZE];

    ret = pcre2_match(re->code, (PCRE2_SPTR) subject, length, 0, 0, match,
                      NULL);

    if (nxt_slow_path(ret < PCRE2_ERROR_NOMATCH)) {

        if (pcre2_get_error_message(ret, errptr, ERR_BUF_SIZE) < 0) {
            nxt_thread_log_error(NXT_LOG_ERR,
                                 "pcre2_match() failed: %d on \"%*s\" "
                                 "using \"%V\"", ret, length, subject,
                                 &re->pattern);

        } else {
            nxt_thread_log_error(NXT_LOG_ERR,
                                 "pcre2_match() failed: %s (%d) on \"%*s\" "
                                 "using \"%V\"", errptr, ret, length, subject,
                                 &re->pattern);
        }

        return NXT_ERROR;
    }

    return (ret != PCRE2_ERROR_NOMATCH);
}
