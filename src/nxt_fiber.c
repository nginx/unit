
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static char *nxt_fiber_create_stack(nxt_fiber_t *fib);
static void nxt_fiber_switch_stack(nxt_fiber_t *fib, jmp_buf *parent);
static void nxt_fiber_switch_handler(nxt_thread_t *thr, void *obj,
    void *data);
static void nxt_fiber_switch(nxt_thread_t *thr, nxt_fiber_t *fib);
static void nxt_fiber_timer_handler(nxt_thread_t *thr, void *obj,
    void *data);


#define                                                                       \
nxt_fiber_enqueue(thr, fib)                                                   \
    nxt_thread_work_queue_add(thr, &(thr)->work_queue.main,                   \
                              nxt_fiber_switch_handler, fib, NULL, thr->log)


nxt_fiber_main_t *
nxt_fiber_main_create(nxt_event_engine_t *engine)
{
    nxt_fiber_main_t  *fm;

    fm = nxt_zalloc(sizeof(nxt_fiber_main_t));
    if (nxt_slow_path(fm == NULL)) {
        return NULL;
    }

    fm->stack_size = 512 * 1024 - nxt_pagesize;
    fm->idle = NULL;

    return fm;
}


nxt_int_t
nxt_fiber_create(nxt_fiber_start_t start, void *data, size_t stack)
{
    int                  ret;
    jmp_buf              parent;
    nxt_fid_t            fid;
    nxt_fiber_t          *fib;
    nxt_thread_t         *thr;
    nxt_fiber_main_t     *fm;

    thr = nxt_thread();
    fm = thr->engine->fibers;

    fid = ++fm->fid;

    if (fid == 0) {
        fid = ++fm->fid;
    }

    fib = fm->idle;

    if (fib != NULL) {
        fm->idle = fib->next;
        fib->fid = fid;
        fib->start = start;
        fib->data = data;
        fib->main = fm;

        nxt_log_debug(thr->log, "fiber create cached: %PF", fib->fid);
        nxt_fiber_enqueue(thr, fib);
        return NXT_OK;
    }

    nxt_log_debug(thr->log, "fiber create");

    fib = nxt_malloc(sizeof(nxt_fiber_t));
    if (nxt_slow_path(fib == NULL)) {
        return NXT_ERROR;
    }

    fib->fid = fid;
    fib->start = start;
    fib->data = data;
    fib->stack_size = fm->stack_size;
    fib->main = fm;

    fib->stack = nxt_fiber_create_stack(fib);

    if (nxt_fast_path(fib->stack != NULL)) {

        if (_setjmp(parent) != 0) {
            nxt_log_debug(thr->log, "fiber create: %PF", fib->fid);
            return NXT_OK;
        }

        nxt_fiber_switch_stack(fib, &parent);
        /* It does not return if the switch was successful. */
    }

    ret = munmap(fib->stack - nxt_pagesize, fib->stack_size + nxt_pagesize);

    if (nxt_slow_path(ret != 0)) {
        nxt_log_alert(thr->log, "munmap() failed %E", nxt_errno);
    }

    nxt_free(fib);

    return NXT_ERROR;
}


#if (NXT_LINUX)

static char *
nxt_fiber_create_stack(nxt_fiber_t *fib)
{
    char    *s;
    size_t  size;

    size = fib->stack_size + nxt_pagesize;

    s = mmap(NULL, size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANON | MAP_GROWSDOWN, -1, 0);

    if (nxt_slow_path(s == MAP_FAILED)) {
        nxt_thread_log_alert("fiber stack "
                   "mmap(%uz, MAP_PRIVATE|MAP_ANON|MAP_GROWSDOWN) failed %E",
                   size, nxt_errno);
        return NULL;
    }

    if (nxt_slow_path(mprotect(s, nxt_pagesize, PROT_NONE) != 0)) {
        nxt_thread_log_alert("fiber stack mprotect(%uz, PROT_NONE) failed %E",
                             size, nxt_errno);
        return NULL;
    }

    s += nxt_pagesize;

    nxt_thread_log_debug("fiber stack mmap: %p", s);

    return s;
}

#else /* Generic version. */

static char *
nxt_fiber_create_stack(nxt_fiber_t *fib)
{
    char    *s;
    size_t   size;

    size = fib->stack_size + nxt_pagesize;

    s = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    if (nxt_slow_path(s == MAP_FAILED)) {
        nxt_thread_log_alert("fiber stack "
                             "mmap(%uz, MAP_PRIVATE|MAP_ANON) failed %E",
                             size, nxt_errno);
        return NULL;
    }

    if (nxt_slow_path(mprotect(s, nxt_pagesize, PROT_NONE) != 0)) {
        nxt_thread_log_alert("fiber stack mprotect(%uz, PROT_NONE) failed %E",
                              size, nxt_errno);
        return NULL;
    }

    s += nxt_pagesize;

    nxt_thread_log_debug("fiber stack mmap: %p", s);

    return s;
}

#endif


#if (NXT_LINUX && NXT_64BIT)

/*
 * Linux 64-bit ucontext version.  64-bit glibc makecontext() passes
 * pointers as signed int's. The bug has been fixed in glibc 2.8.
 */

static void nxt_fiber_trampoline(uint32_t fh, uint32_t fl, uint32_t ph,
    uint32_t pl);


static void
nxt_fiber_switch_stack(nxt_fiber_t *fib, jmp_buf *parent)
{
    ucontext_t  uc;

    nxt_thread_log_debug("fiber switch to stack: %p", fib->stack);

    if (nxt_slow_path(getcontext(&uc) != 0)) {
        nxt_thread_log_alert("getcontext() failed");
        return;
    }

    uc.uc_link = NULL;
    uc.uc_stack.ss_sp = fib->stack;
    uc.uc_stack.ss_size = fib->stack_size;

    makecontext(&uc, (void (*)(void)) nxt_fiber_trampoline, 4,
                (uint32_t) ((uintptr_t) fib >> 32),
                (uint32_t) ((uintptr_t) fib & 0xffffffff),
                (uint32_t) ((uintptr_t) parent >> 32),
                (uint32_t) ((uintptr_t) parent & 0xffffffff));

    setcontext(&uc);

    nxt_thread_log_alert("setcontext() failed");
}


static void
nxt_fiber_trampoline(uint32_t fh, uint32_t fl, uint32_t ph, uint32_t pl)
{
    jmp_buf       *parent;
    nxt_fiber_t   *fib;
    nxt_thread_t  *thr;

    fib = (nxt_fiber_t *) (((uintptr_t) fh << 32) + fl);
    parent = (jmp_buf *) (((uintptr_t) ph << 32) + pl);

    thr = nxt_thread();

    if (_setjmp(fib->jmp) == 0) {
        nxt_log_debug(thr->log, "fiber return to parent stack");

        nxt_fiber_enqueue(thr, fib);
        _longjmp(*parent, 1);
        nxt_unreachable();
    }

    nxt_log_debug(thr->log, "fiber start");

    fib->start(fib->data);

    nxt_fiber_exit(&fib->main->fiber, NULL);
    nxt_unreachable();
}

#elif (NXT_HAVE_UCONTEXT)

/* Generic ucontext version. */

static void nxt_fiber_trampoline(nxt_fiber_t *fib, jmp_buf *parent);


static void
nxt_fiber_switch_stack(nxt_fiber_t *fib, jmp_buf *parent)
{
    ucontext_t  uc;

    nxt_thread_log_debug("fiber switch to stack: %p", fib->stack);

    if (nxt_slow_path(getcontext(&uc) != 0)) {
        nxt_thread_log_alert("getcontext() failed");
        return;
    }

    uc.uc_link = NULL;
    uc.uc_stack.ss_sp = fib->stack;
    uc.uc_stack.ss_size = fib->stack_size;

    makecontext(&uc, (void (*)(void)) nxt_fiber_trampoline, 2, fib, parent);

    setcontext(&uc);

#if !(NXT_SOLARIS)
    /* Solaris declares setcontext() as __NORETURN. */

    nxt_thread_log_alert("setcontext() failed");
#endif
}


static void
nxt_fiber_trampoline(nxt_fiber_t *fib, jmp_buf *parent)
{
    nxt_thread_t  *thr;

    thr = nxt_thread();

    if (_setjmp(fib->jmp) == 0) {
        nxt_log_debug(thr->log, "fiber return to parent stack");

        nxt_fiber_enqueue(thr, fib);
        _longjmp(*parent, 1);
        nxt_unreachable();
    }

    nxt_log_debug(thr->log, "fiber start");

    fib->start(fib->data);

    nxt_fiber_exit(&fib->main->fiber, NULL);
    nxt_unreachable();
}

#else

#error No ucontext(3) interface.

#endif


static void
nxt_fiber_switch_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_fiber_t  *fib;

    fib = obj;

    nxt_fiber_switch(thr, fib);
    nxt_unreachable();
}


static void
nxt_fiber_switch(nxt_thread_t *thr, nxt_fiber_t *fib)
{
    nxt_log_debug(thr->log, "fiber switch: %PF", fib->fid);

    thr->fiber = fib;
    _longjmp(fib->jmp, 1);
    nxt_unreachable();
}


nxt_fiber_t *
nxt_fiber_self(nxt_thread_t *thr)
{
    return (nxt_fast_path(thr != NULL)) ? thr->fiber : NULL;
}


void
nxt_fiber_yield(void)
{
    nxt_fiber_t   *fib;
    nxt_thread_t  *thr;

    thr = nxt_thread();
    fib = thr->fiber;

    if (_setjmp(fib->jmp) == 0) {

        nxt_log_debug(thr->log, "fiber yield");

        nxt_fiber_enqueue(thr, fib);
        nxt_fiber_switch(thr, &fib->main->fiber);
        nxt_unreachable();
    }

    nxt_log_debug(thr->log, "fiber yield return");
}


void
nxt_fiber_sleep(nxt_msec_t timeout)
{
    nxt_fiber_t   *fib;
    nxt_thread_t  *thr;

    thr = nxt_thread();
    fib = thr->fiber;

    fib->timer.work_queue = &thr->work_queue.main;
    fib->timer.handler = nxt_fiber_timer_handler;
    fib->timer.log = &nxt_main_log;

    nxt_event_timer_add(thr->engine, &fib->timer, timeout);

    if (_setjmp(fib->jmp) == 0) {

        nxt_log_debug(thr->log, "fiber sleep: %T", timeout);

        nxt_fiber_switch(thr, &fib->main->fiber);
        nxt_unreachable();
    }

    nxt_log_debug(thr->log, "fiber sleep return");
}


static void
nxt_fiber_timer_handler(nxt_thread_t *thr, void *obj, void *data)
{
    nxt_fiber_t        *fib;
    nxt_event_timer_t  *ev;

    ev = obj;

    nxt_log_debug(thr->log, "fiber timer handler");

    fib = nxt_event_timer_data(ev, nxt_fiber_t, timer);

    nxt_fiber_switch(thr, fib);
    nxt_unreachable();
}


void
nxt_fiber_wait(void)
{
    nxt_fiber_t   *fib;
    nxt_thread_t  *thr;

    thr = nxt_thread();
    fib = thr->fiber;

    if (_setjmp(fib->jmp) == 0) {
        nxt_log_debug(thr->log, "fiber wait");

        nxt_fiber_switch(thr, &fib->main->fiber);
        nxt_unreachable();
    }

    nxt_log_debug(thr->log, "fiber wait return");
}


void
nxt_fiber_exit(nxt_fiber_t *next, void *data)
{
    nxt_fiber_t   *fib;
    nxt_thread_t  *thr;

    thr = nxt_thread();
    fib = thr->fiber;

    nxt_log_debug(thr->log, "fiber exit");

    /* TODO: limit idle fibers. */
    fib->next = fib->main->idle;
    fib->main->idle = fib;

    nxt_fiber_switch(thr, next);
    nxt_unreachable();
}
