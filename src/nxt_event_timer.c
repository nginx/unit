
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * Timer operations are batched to improve instruction and data
 * cache locality of rbtree operations.
 *
 * nxt_event_timer_add() adds a timer to the changes array to add or to
 * modify the timer.  The changes are processed by nxt_event_timer_find().
 *
 * nxt_event_timer_disable() disables a timer.  The disabled timer may
 * however present in rbtree for a long time and may be eventually removed
 * by nxt_event_timer_find() or nxt_event_timer_expire().
 *
 * nxt_event_timer_delete() removes a timer at once from both the rbtree and
 * the changes array and should be used only if the timer memory must be freed.
 */

static nxt_int_t nxt_event_timer_rbtree_compare(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2);
static void nxt_event_timer_change(nxt_event_timers_t *timers,
    nxt_event_timer_t *ev, nxt_msec_t time);
static void nxt_event_commit_timer_changes(nxt_event_timers_t *timers);
static void nxt_event_timer_drop_changes(nxt_event_timers_t *timers,
    nxt_event_timer_t *ev);


nxt_int_t
nxt_event_timers_init(nxt_event_timers_t *timers, nxt_uint_t mchanges)
{
    nxt_rbtree_init(&timers->tree, nxt_event_timer_rbtree_compare, NULL);

    timers->mchanges = mchanges;

    timers->changes = nxt_malloc(sizeof(nxt_event_timer_change_t) * mchanges);

    if (nxt_fast_path(timers->changes != NULL)) {
        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_event_timer_rbtree_compare(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2)
{
    nxt_event_timer_t  *ev1, *ev2;

    ev1 = (nxt_event_timer_t *) node1;
    ev2 = (nxt_event_timer_t *) node2;

    /*
     * Timer values are distributed in small range, usually several minutes
     * and overflow every 49 days if nxt_msec_t is stored in 32 bits.
     * This signed comparison takes into account that overflow.
     */
                      /* ev1->time < ev2->time */
    return nxt_msec_diff(ev1->time, ev2->time);
}


void
nxt_event_timer_add(nxt_event_engine_t *engine, nxt_event_timer_t *ev,
    nxt_msec_t timer)
{
    int32_t   diff;
    uint32_t  time;

    time = engine->timers.now + timer;

    if (nxt_event_timer_is_in_tree(ev)) {

        diff = nxt_msec_diff(time, ev->time);

        /*
         * Use the previous timer if difference between it and the
         * new timer is less than required precision milliseconds:
         * this decreases rbtree operations for fast connections.
         */

        if (nxt_abs(diff) < ev->precision) {
            nxt_log_debug(ev->log, "event timer previous: %D: %d:%M",
                          ev->ident, ev->state, time);

            if (ev->state == NXT_EVENT_TIMER_DISABLED) {
                ev->state = NXT_EVENT_TIMER_ACTIVE;
            }

            return;
        }

        nxt_log_debug(ev->log, "event timer change: %D: %d:%M",
                      ev->ident, ev->state, ev->time);

    } else {
        /*
         * The timer's time is updated here just to log a correct
         * value by debug logging in nxt_event_timer_disable().
         * It could be updated only in nxt_event_commit_timer_changes()
         * just before nxt_rbtree_insert().
         */
        ev->time = time;

        nxt_log_debug(ev->log, "event timer add: %D: %M:%M",
                      ev->ident, timer, time);
    }

    nxt_event_timer_change(&engine->timers, ev, time);
}


static void
nxt_event_timer_change(nxt_event_timers_t *timers, nxt_event_timer_t *ev,
    nxt_msec_t time)
{
    nxt_event_timer_change_t  *ch;

    if (timers->nchanges >= timers->mchanges) {
        nxt_event_commit_timer_changes(timers);
    }

    ev->state = NXT_EVENT_TIMER_ACTIVE;

    ch = &timers->changes[timers->nchanges];
    ch->time = time;
    ch->event = ev;
    timers->nchanges++;
}


#if (NXT_DEBUG)

void
nxt_event_timer_disable(nxt_event_timer_t *ev)
{
    nxt_debug(ev->task, "event timer disable: %D: %d:%M",
              ev->ident, ev->state, ev->time);

    ev->state = NXT_EVENT_TIMER_DISABLED;
}

#endif


void
nxt_event_timer_delete(nxt_event_engine_t *engine, nxt_event_timer_t *ev)
{
    if (nxt_event_timer_is_in_tree(ev)) {
        nxt_log_debug(ev->log, "event timer delete: %D: %d:%M",
                      ev->ident, ev->state, ev->time);

        nxt_rbtree_delete(&engine->timers.tree, &ev->node);
        nxt_event_timer_in_tree_clear(ev);
        ev->state = NXT_EVENT_TIMER_DISABLED;
    }

    nxt_event_timer_drop_changes(&engine->timers, ev);
}


static void
nxt_event_timer_drop_changes(nxt_event_timers_t *timers, nxt_event_timer_t *ev)
{
    nxt_event_timer_change_t  *dst, *src, *end;

    dst = timers->changes;
    end = dst + timers->nchanges;

    for (src = dst; src < end; src++) {

        if (src->event == ev) {
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
nxt_event_commit_timer_changes(nxt_event_timers_t *timers)
{
    nxt_event_timer_t         *ev;
    nxt_event_timer_change_t  *ch, *end;

    nxt_thread_log_debug("event timers changes: %ui", timers->nchanges);

    ch = timers->changes;
    end = ch + timers->nchanges;

    while (ch < end) {
        ev = ch->event;

        if (ev->state != NXT_EVENT_TIMER_DISABLED) {

            if (nxt_event_timer_is_in_tree(ev)) {
                nxt_log_debug(ev->log, "event timer delete: %D: %d:%M",
                              ev->ident, ev->state, ev->time);

                nxt_rbtree_delete(&timers->tree, &ev->node);

                ev->time = ch->time;
            }

            nxt_log_debug(ev->log, "event timer add: %D: %M",
                          ev->ident, ev->time);

            nxt_rbtree_insert(&timers->tree, &ev->node);
            nxt_event_timer_in_tree_set(ev);
        }

        ch++;
    }

    timers->nchanges = 0;
}


nxt_msec_t
nxt_event_timer_find(nxt_event_engine_t *engine)
{
    int32_t            time;
    nxt_rbtree_node_t  *node, *next;
    nxt_event_timer_t  *ev;

    if (engine->timers.nchanges != 0) {
        nxt_event_commit_timer_changes(&engine->timers);
    }

    for (node = nxt_rbtree_min(&engine->timers.tree);
         nxt_rbtree_is_there_successor(&engine->timers.tree, node);
         node = next)
    {
        next = nxt_rbtree_node_successor(&engine->timers.tree, node);

        ev = (nxt_event_timer_t *) node;

        if (ev->state != NXT_EVENT_TIMER_DISABLED) {

            if (ev->state == NXT_EVENT_TIMER_BLOCKED) {
                nxt_log_debug(ev->log, "event timer blocked: %D: %M",
                              ev->ident, ev->time);
                continue;
            }

            time = nxt_msec_diff(ev->time, engine->timers.now);

            return (nxt_msec_t) nxt_max(time, 0);
        }

        /* Delete disabled timer. */

        nxt_log_debug(ev->log, "event timer delete: %D: 0:%M",
                      ev->ident, ev->time);

        nxt_rbtree_delete(&engine->timers.tree, &ev->node);
        nxt_event_timer_in_tree_clear(ev);
    }

    return NXT_INFINITE_MSEC;
}


void
nxt_event_timer_expire(nxt_thread_t *thr, nxt_msec_t now)
{
    nxt_rbtree_t       *tree;
    nxt_rbtree_node_t  *node, *next;
    nxt_event_timer_t  *ev;

    thr->engine->timers.now = now;
    tree = &thr->engine->timers.tree;

    for (node = nxt_rbtree_min(tree);
         nxt_rbtree_is_there_successor(tree, node);
         node = next)
    {
        ev = (nxt_event_timer_t *) node;

                       /* ev->time > now */
        if (nxt_msec_diff(ev->time, now) > 0) {
            return;
        }

        next = nxt_rbtree_node_successor(tree, node);

        if (ev->state == NXT_EVENT_TIMER_BLOCKED) {
            nxt_log_debug(ev->log, "event timer blocked: %D: %M",
                          ev->ident, ev->time);
            continue;
        }

        nxt_log_debug(ev->log, "event timer delete: %D: %d:%M",
                      ev->ident, ev->state, ev->time);

        nxt_rbtree_delete(tree, &ev->node);
        nxt_event_timer_in_tree_clear(ev);

        if (ev->state != NXT_EVENT_TIMER_DISABLED) {
            ev->state = NXT_EVENT_TIMER_DISABLED;

            nxt_work_queue_add(ev->work_queue, ev->handler, ev->task, ev, NULL);
        }
    }
}
