
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static char *nxt_fiber_create_stack(nxt_task_t *task, nxt_fiber_t *fib);
static void nxt_fiber_switch_stack(nxt_fiber_t *fib, jmp_buf *parent);
static void nxt_fiber_switch_handler(nxt_task_t *task, void *obj, void *data);
static void nxt_fiber_switch(nxt_task_t *task, nxt_fiber_t *fib);
static void nxt_fiber_timer_handler(nxt_task_t *task, void *obj, void *data);


#define nxt_fiber_enqueue(thr, task, fib)                                     \
    nxt_work_queue_add(&(thr)->engine->fast_work_queue,                       \
                              nxt_fiber_switch_handler, task, fib, NULL)


nxt_fiber_main_t *
nxt_fiber_main_create(nxt_event_engine_t *engine)
{
    nxt_fiber_main_t  *fm;

    fm = nxt_zalloc(sizeof(nxt_fiber_main_t));
    if (nxt_slow_path(fm == NULL)) {
        return NULL;
    }

    fm->engine = engine;
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

        fib->task.thread = thr;
        fib->task.log = thr->log;
        fib->task.ident = nxt_task_next_ident();

        nxt_debug(&fib->task, "fiber create cached: %PF", fib->fid);

        nxt_fiber_enqueue(thr, &fm->engine->task, fib);

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

    fib->task.thread = thr;
    fib->task.log = thr->log;
    fib->task.ident = nxt_task_next_ident();

    fib->stack = nxt_fiber_create_stack(&fib->task, fib);

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
nxt_fiber_create_stack(nxt_task_t *task, nxt_fiber_t *fib)
{
    char    *s;
    size_t  size;

    size = fib->stack_size + nxt_pagesize;

    s = mmap(NULL, size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANON | MAP_GROWSDOWN, -1, 0);

    if (nxt_slow_path(s == MAP_FAILED)) {
        nxt_alert(task, "fiber stack "
                  "mmap(%uz, MAP_PRIVATE|MAP_ANON|MAP_GROWSDOWN) failed %E",
                  size, nxt_errno);

        return NULL;
    }

    if (nxt_slow_path(mprotect(s, nxt_pagesize, PROT_NONE) != 0)) {
        nxt_alert(task, "fiber stack mprotect(%uz, PROT_NONE) failed %E",
                  size, nxt_errno);

        return NULL;
    }

    s += nxt_pagesize;

    nxt_debug(task, "fiber stack mmap: %p", s);

    return s;
}

#else /* Generic version. */

static char *
nxt_fiber_create_stack(nxt_task_t *task, nxt_fiber_t *fib)
{
    char    *s;
    size_t   size;

    size = fib->stack_size + nxt_pagesize;

    s = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

    if (nxt_slow_path(s == MAP_FAILED)) {
        nxt_alert(task, "fiber stack mmap(%uz, MAP_PRIVATE|MAP_ANON) failed %E",
                  size, nxt_errno);

        return NULL;
    }

    if (nxt_slow_path(mprotect(s, nxt_pagesize, PROT_NONE) != 0)) {
        nxt_alert(task, "fiber stack mprotect(%uz, PROT_NONE) failed %E",
                  size, nxt_errno);

        return NULL;
    }

    s += nxt_pagesize;

    nxt_debug(task, "fiber stack mmap: %p", s);

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

    nxt_debug(&fib->task, "fiber switch to stack: %p", fib->stack);

    if (nxt_slow_path(getcontext(&uc) != 0)) {
        nxt_alert(&fib->task, "getcontext() failed");
        return;
    }

    uc.uc_link = NULL;
    uc.uc_stack.ss_sp = fib->stack;
    uc.uc_stack.ss_size = fib->stack_size;

    makecontext(&uc, (void (*)(void)) nxt_fiber_trampoline, 4,
                (uint32_t) ((uintptr_t) fib >> 32),
                (uint32_t) ((uintptr_t) fib & 0xFFFFFFFF),
                (uint32_t) ((uintptr_t) parent >> 32),
                (uint32_t) ((uintptr_t) parent & 0xFFFFFFFF));

    setcontext(&uc);

    nxt_alert(&fib->task, "setcontext() failed");
}


static void
nxt_fiber_trampoline(uint32_t fh, uint32_t fl, uint32_t ph, uint32_t pl)
{
    jmp_buf      *parent;
    nxt_task_t   *task;
    nxt_fiber_t  *fib;

    fib = (nxt_fiber_t *) (((uintptr_t) fh << 32) + fl);
    parent = (jmp_buf *) (((uintptr_t) ph << 32) + pl);

    task = &fib->task;

    if (_setjmp(fib->jmp) == 0) {
        nxt_debug(task, "fiber return to parent stack");

        nxt_fiber_enqueue(task->thread, task, fib);

        _longjmp(*parent, 1);

        nxt_unreachable();
    }

    nxt_debug(task, "fiber start");

    fib->start(fib->data);

    nxt_fiber_exit(task, &fib->main->fiber, NULL);

    nxt_unreachable();
}

#elif (NXT_HAVE_UCONTEXT)

/* Generic ucontext version. */

static void nxt_fiber_trampoline(nxt_fiber_t *fib, jmp_buf *parent);


static void
nxt_fiber_switch_stack(nxt_fiber_t *fib, jmp_buf *parent)
{
    ucontext_t  uc;

    nxt_debug(&fib->task, "fiber switch to stack: %p", fib->stack);

    if (nxt_slow_path(getcontext(&uc) != 0)) {
        nxt_alert(&fib->task, "getcontext() failed");
        return;
    }

    uc.uc_link = NULL;
    uc.uc_stack.ss_sp = fib->stack;
    uc.uc_stack.ss_size = fib->stack_size;

    makecontext(&uc, (void (*)(void)) nxt_fiber_trampoline, 2, fib, parent);

    setcontext(&uc);

#if !(NXT_SOLARIS)
    /* Solaris declares setcontext() as __NORETURN. */

    nxt_alert(&fib->task, "setcontext() failed");
#endif
}


static void
nxt_fiber_trampoline(nxt_fiber_t *fib, jmp_buf *parent)
{
    nxt_task_t  *task;

    task = &fib->task;

    if (_setjmp(fib->jmp) == 0) {
        nxt_debug(task, "fiber return to parent stack");

        nxt_fiber_enqueue(task->thread, task, fib);

        _longjmp(*parent, 1);

        nxt_unreachable();
    }

    nxt_debug(task, "fiber start");

    fib->start(fib->data);

    nxt_fiber_exit(task, &fib->main->fiber, NULL);

    nxt_unreachable();
}

#else

#error No ucontext(3) interface.

#endif


static void
nxt_fiber_switch_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_fiber_t  *fib;

    fib = obj;

    nxt_fiber_switch(task, fib);
    nxt_unreachable();
}


static void
nxt_fiber_switch(nxt_task_t *task, nxt_fiber_t *fib)
{
    nxt_debug(task, "fiber switch: %PF", fib->fid);

    task->thread->fiber = fib;

    _longjmp(fib->jmp, 1);

    nxt_unreachable();
}


nxt_fiber_t *
nxt_fiber_self(nxt_thread_t *thr)
{
    return (nxt_fast_path(thr != NULL)) ? thr->fiber : NULL;
}


void
nxt_fiber_yield(nxt_task_t *task)
{
    nxt_fiber_t  *fib;

    fib = task->thread->fiber;

    if (_setjmp(fib->jmp) == 0) {

        nxt_debug(task, "fiber yield");

        nxt_fiber_enqueue(task->thread, &fib->main->engine->task, fib);

        nxt_fiber_switch(task, &fib->main->fiber);

        nxt_unreachable();
    }

    nxt_debug(task, "fiber yield return");
}


void
nxt_fiber_sleep(nxt_task_t *task, nxt_msec_t timeout)
{
    nxt_fiber_t  *fib;

    fib = task->thread->fiber;

    fib->timer.work_queue = &task->thread->engine->fast_work_queue;
    fib->timer.handler = nxt_fiber_timer_handler;
    fib->timer.log = &nxt_main_log;

    task = &fib->task;

    nxt_timer_add(task->thread->engine, &fib->timer, timeout);

    if (_setjmp(fib->jmp) == 0) {

        nxt_debug(task, "fiber sleep: %T", timeout);

        nxt_fiber_switch(task, &fib->main->fiber);

        nxt_unreachable();
    }

    nxt_debug(task, "fiber sleep return");
}


static void
nxt_fiber_timer_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_fiber_t  *fib;
    nxt_timer_t  *ev;

    ev = obj;

    nxt_debug(task, "fiber timer handler");

    fib = nxt_timer_data(ev, nxt_fiber_t, timer);

    nxt_fiber_switch(task, fib);

    nxt_unreachable();
}


void
nxt_fiber_wait(nxt_task_t *task)
{
    nxt_fiber_t  *fib;

    fib = task->thread->fiber;

    if (_setjmp(fib->jmp) == 0) {
        nxt_debug(task, "fiber wait");

        nxt_fiber_switch(task, &fib->main->fiber);

        nxt_unreachable();
    }

    nxt_debug(task, "fiber wait return");
}


void
nxt_fiber_exit(nxt_task_t *task, nxt_fiber_t *next, void *data)
{
    nxt_fiber_t  *fib;

    fib = task->thread->fiber;

    nxt_debug(task, "fiber exit");

    /* TODO: limit idle fibers. */
    fib->next = fib->main->idle;
    fib->main->idle = fib;

    nxt_fiber_switch(task, next);

    nxt_unreachable();
}
