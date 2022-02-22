
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_log_moderation_t  nxt_malloc_log_moderation = {
    NXT_LOG_ALERT, 2, "memory allocation failed", NXT_LOG_MODERATION
};


static nxt_log_t *
nxt_malloc_log(void)
{
    nxt_thread_t  *thr;

    thr = nxt_thread();

    if (thr != NULL && thr->log != NULL) {
        return thr->log;
    }

    return &nxt_main_log;
}


void *
nxt_malloc(size_t size)
{
    void  *p;

    p = malloc(size);

    if (nxt_fast_path(p != NULL)) {
        nxt_log_debug(nxt_malloc_log(), "malloc(%uz): %p", size, p);

    } else {
        nxt_log_alert_moderate(&nxt_malloc_log_moderation, nxt_malloc_log(),
                               "malloc(%uz) failed %E", size, nxt_errno);
    }

    return p;
}


void *
nxt_zalloc(size_t size)
{
    void  *p;

    p = nxt_malloc(size);

    if (nxt_fast_path(p != NULL)) {
        nxt_memzero(p, size);
    }

    return p;
}


void *
nxt_realloc(void *p, size_t size)
{
    void       *n;
    uintptr_t  ptr;

    /*
     * Workaround for a warning on GCC 12 about using "p" pointer in debug log
     * after realloc().
     */
    ptr = (uintptr_t) p;

    n = realloc(p, size);

    if (nxt_fast_path(n != NULL)) {
        nxt_log_debug(nxt_malloc_log(), "realloc(%p, %uz): %p", ptr, size, n);

    } else {
        nxt_log_alert_moderate(&nxt_malloc_log_moderation, nxt_malloc_log(),
                               "realloc(%p, %uz) failed %E",
                               ptr, size, nxt_errno);
    }

    return n;
}


/* nxt_lvlhsh_* functions moved here to avoid references from nxt_lvlhsh.c. */

void *
nxt_lvlhsh_alloc(void *data, size_t size)
{
    return nxt_memalign(size, size);
}


void
nxt_lvlhsh_free(void *data, void *p)
{
    nxt_free(p);
}


#if (NXT_DEBUG)

void
nxt_free(void *p)
{
    nxt_log_debug(nxt_malloc_log(), "free(%p)", p);

    free(p);
}


#endif


#if (NXT_HAVE_POSIX_MEMALIGN)

/*
 * posix_memalign() presents in Linux glibc 2.1.91, FreeBSD 7.0,
 * Solaris 11, MacOSX 10.6 (Snow Leopard), NetBSD 5.0.
 */

void *
nxt_memalign(size_t alignment, size_t size)
{
    void        *p;
    nxt_err_t   err;

    err = posix_memalign(&p, alignment, size);

    if (nxt_fast_path(err == 0)) {
        nxt_thread_log_debug("posix_memalign(%uz, %uz): %p",
                             alignment, size, p);
        return p;
    }

    nxt_log_alert_moderate(&nxt_malloc_log_moderation, nxt_malloc_log(),
                           "posix_memalign(%uz, %uz) failed %E",
                           alignment, size, err);
    return NULL;
}

#elif (NXT_HAVE_MEMALIGN)

/* memalign() presents in Solaris, HP-UX. */

void *
nxt_memalign(size_t alignment, size_t size)
{
    void  *p;

    p = memalign(alignment, size);

    if (nxt_fast_path(p != NULL)) {
        nxt_thread_log_debug("memalign(%uz, %uz): %p",
                             alignment, size, p);
        return p;
    }

    nxt_log_alert_moderate(&nxt_malloc_log_moderation, nxt_malloc_log(),
                           "memalign(%uz, %uz) failed %E",
                           alignment, size, nxt_errno);
    return NULL;
}

#elif (NXT_FREEBSD)

/*
 * FreeBSD prior to 7.0 lacks posix_memalign(), but if a requested size
 * is lesser than or equal to 4K, then phkmalloc aligns the size to the
 * next highest power of 2 and allocates memory with the same alignment.
 * Allocations larger than 2K are always aligned to 4K.
 */

void *
nxt_memalign(size_t alignment, size_t size)
{
    size_t     aligned_size;
    u_char     *p;
    nxt_err_t  err;

    if (nxt_slow_path((alignment - 1) & alignment) != 0) {
        /* Alignment must be a power of 2. */
        err = NXT_EINVAL;
        goto fail;
    }

    if (nxt_slow_path(alignment > 4096)) {
        err = NXT_EOPNOTSUPP;
        goto fail;
    }

    if (nxt_fast_path(size <= 2048)) {
        aligned_size = nxt_max(size, alignment);

    } else {
        /* Align to 4096. */
        aligned_size = size;
    }

    p = malloc(aligned_size);

    if (nxt_fast_path(p != NULL)) {
        nxt_thread_log_debug("nxt_memalign(%uz, %uz): %p", alignment, size, p);

    } else {
        nxt_log_alert_moderate(&nxt_malloc_log_moderation, nxt_malloc_log(),
                               "malloc(%uz) failed %E", size, nxt_errno);
    }

    return p;

fail:

    nxt_thread_log_alert("nxt_memalign(%uz, %uz) failed %E",
                         alignment, size, err);
    return NULL;
}

#else

#error no memalign() implementation.

#endif
