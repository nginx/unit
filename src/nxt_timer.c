
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * Timer operations are batched to improve instruction and data
 * cache locality of rbtree operations.
 *
 * nxt_timer_add() adds a timer to the changes array to add or to
 * modify the timer.  The changes are processed by nxt_timer_find().
 *
 * nxt_timer_disable() disables a timer.  The disabled timer may
 * however present in rbtree for a long time and may be eventually removed
 * by nxt_timer_find() or nxt_timer_expire().
 *
 * nxt_timer_delete() removes a timer at once from both the rbtree and
 * the changes array and should be used only if the timer memory must be freed.
 */

static intptr_t nxt_timer_rbtree_compare(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2);
static void nxt_timer_change(nxt_timers_t *timers, nxt_timer_t *timer,
    nxt_msec_t time);
static void nxt_commit_timer_changes(nxt_timers_t *timers);
static void nxt_timer_drop_changes(nxt_timers_t *timers, nxt_timer_t *timer);


nxt_int_t
nxt_timers_init(nxt_timers_t *timers, nxt_uint_t mchanges)
{
    nxt_rbtree_init(&timers->tree, nxt_timer_rbtree_compare);

    timers->mchanges = mchanges;

    timers->changes = nxt_malloc(sizeof(nxt_timer_change_t) * mchanges);

    if (nxt_fast_path(timers->changes != NULL)) {
        return NXT_OK;
    }

    return NXT_ERROR;
}


static intptr_t
nxt_timer_rbtree_compare(nxt_rbtree_node_t *node1, nxt_rbtree_node_t *node2)
{
    nxt_timer_t  *timer1, *timer2;

    timer1 = (nxt_timer_t *) node1;
    timer2 = (nxt_timer_t *) node2;

    /*
     * Timer values are distributed in small range, usually several minutes
     * and overflow every 49 days if nxt_msec_t is stored in 32 bits.
     * This signed comparison takes into account that overflow.
     */
                      /* timer1->time < timer2->time */
    return nxt_msec_diff(timer1->time, timer2->time);
}


void
nxt_timer_add(nxt_event_engine_t *engine, nxt_timer_t *timer,
    nxt_msec_t timeout)
{
    int32_t   diff;
    uint32_t  time;

    time = engine->timers.now + timeout;

    if (nxt_timer_is_in_tree(timer)) {

        diff = nxt_msec_diff(time, timer->time);

        /*
         * Use the previous timer if difference between it and the
         * new timer is less than required precision milliseconds:
         * this decreases rbtree operations for fast connections.
         */

        if (nxt_abs(diff) < timer->precision) {
            nxt_log_debug(timer->log, "timer previous: %D: %d:%M",
                          timer->ident, timer->state, time);

            if (timer->state == NXT_TIMER_DISABLED) {
                timer->state = NXT_TIMER_ACTIVE;
            }

            return;
        }

        nxt_log_debug(timer->log, "timer change: %D: %d:%M",
                      timer->ident, timer->state, timer->time);

    } else {
        /*
         * The timer's time is updated here just to log a correct
         * value by debug logging in nxt_timer_disable().
         * It could be updated only in nxt_commit_timer_changes()
         * just before nxt_rbtree_insert().
         */
        timer->time = time;

        nxt_log_debug(timer->log, "timer add: %D: %M:%M",
                      timer->ident, timeout, time);
    }

    nxt_timer_change(&engine->timers, timer, time);
}


static void
nxt_timer_change(nxt_timers_t *timers, nxt_timer_t *timer, nxt_msec_t time)
{
    nxt_timer_change_t  *ch;

    if (timers->nchanges >= timers->mchanges) {
        nxt_commit_timer_changes(timers);
    }

    timer->state = NXT_TIMER_ACTIVE;

    ch = &timers->changes[timers->nchanges];
    ch->time = time;
    ch->timer = timer;
    timers->nchanges++;
}


#if (NXT_DEBUG)

void
nxt_timer_disable(nxt_timer_t *timer)
{
    nxt_debug(timer->task, "timer disable: %D: %d:%M",
              timer->ident, timer->state, timer->time);

    timer->state = NXT_TIMER_DISABLED;
}

#endif


void
nxt_timer_delete(nxt_event_engine_t *engine, nxt_timer_t *timer)
{
    if (nxt_timer_is_in_tree(timer)) {
        nxt_log_debug(timer->log, "timer delete: %D: %d:%M",
                      timer->ident, timer->state, timer->time);

        nxt_rbtree_delete(&engine->timers.tree, &timer->node);
        nxt_timer_in_tree_clear(timer);
        timer->state = NXT_TIMER_DISABLED;
    }

    nxt_timer_drop_changes(&engine->timers, timer);
}


static void
nxt_timer_drop_changes(nxt_timers_t *timers, nxt_timer_t *timer)
{
    nxt_timer_change_t  *dst, *src, *end;

    dst = timers->changes;
    end = dst + timers->nchanges;

    for (src = dst; src < end; src++) {

        if (src->timer == timer) {
            continue;
        }

        if (dst != src) {
            *dst = *src;
        }

        dst++;
    }

    timers->nchanges -= end - dst;
}


static void
nxt_commit_timer_changes(nxt_timers_t *timers)
{
    nxt_timer_t         *timer;
    nxt_timer_change_t  *ch, *end;

    nxt_thread_log_debug("timers changes: %ui", timers->nchanges);

    ch = timers->changes;
    end = ch + timers->nchanges;

    while (ch < end) {
        timer = ch->timer;

        if (timer->state != NXT_TIMER_DISABLED) {

            if (nxt_timer_is_in_tree(timer)) {
                nxt_log_debug(timer->log, "timer delete: %D: %d:%M",
                              timer->ident, timer->state, timer->time);

                nxt_rbtree_delete(&timers->tree, &timer->node);

                timer->time = ch->time;
            }

            nxt_log_debug(timer->log, "timer add: %D: %M",
                          timer->ident, timer->time);

            nxt_rbtree_insert(&timers->tree, &timer->node);
            nxt_timer_in_tree_set(timer);
        }

        ch++;
    }

    timers->nchanges = 0;
}


nxt_msec_t
nxt_timer_find(nxt_event_engine_t *engine)
{
    int32_t            time;
    nxt_timer_t        *timer;
    nxt_rbtree_node_t  *node, *next;

    if (engine->timers.nchanges != 0) {
        nxt_commit_timer_changes(&engine->timers);
    }

    for (node = nxt_rbtree_min(&engine->timers.tree);
         nxt_rbtree_is_there_successor(&engine->timers.tree, node);
         node = next)
    {
        next = nxt_rbtree_node_successor(&engine->timers.tree, node);

        timer = (nxt_timer_t *) node;

        if (timer->state != NXT_TIMER_DISABLED) {

            if (timer->state == NXT_TIMER_BLOCKED) {
                nxt_log_debug(timer->log, "timer blocked: %D: %M",
                              timer->ident, timer->time);
                continue;
            }

            time = nxt_msec_diff(timer->time, engine->timers.now);

            return (nxt_msec_t) nxt_max(time, 0);
        }

        /* Delete disabled timer. */

        nxt_log_debug(timer->log, "timer delete: %D: 0:%M",
                      timer->ident, timer->time);

        nxt_rbtree_delete(&engine->timers.tree, &timer->node);
        nxt_timer_in_tree_clear(timer);
    }

    return NXT_INFINITE_MSEC;
}


void
nxt_timer_expire(nxt_thread_t *thr, nxt_msec_t now)
{
    nxt_timer_t        *timer;
    nxt_rbtree_t       *tree;
    nxt_rbtree_node_t  *node, *next;

    thr->engine->timers.now = now;
    tree = &thr->engine->timers.tree;

    for (node = nxt_rbtree_min(tree);
         nxt_rbtree_is_there_successor(tree, node);
         node = next)
    {
        timer = (nxt_timer_t *) node;

                       /* timer->time > now */
        if (nxt_msec_diff(timer->time, now) > 0) {
            return;
        }

        next = nxt_rbtree_node_successor(tree, node);

        if (timer->state == NXT_TIMER_BLOCKED) {
            nxt_log_debug(timer->log, "timer blocked: %D: %M",
                          timer->ident, timer->time);
            continue;
        }

        nxt_log_debug(timer->log, "timer delete: %D: %d:%M",
                      timer->ident, timer->state, timer->time);

        nxt_rbtree_delete(tree, &timer->node);
        nxt_timer_in_tree_clear(timer);

        if (timer->state != NXT_TIMER_DISABLED) {
            timer->state = NXT_TIMER_DISABLED;

            nxt_work_queue_add(timer->work_queue, timer->handler, timer->task,
                               timer, NULL);
        }
    }
}
