
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/*
 * Timer operations are batched in the changes array to improve instruction
 * and data cache locality of rbtree operations.
 *
 * nxt_timer_add() adds or modify a timer.
 *
 * nxt_timer_disable() disables a timer.
 *
 * nxt_timer_delete() deletes a timer.  It returns 1 if there are pending
 * changes in the changes array or 0 otherwise.
 */

static intptr_t nxt_timer_rbtree_compare(nxt_rbtree_node_t *node1,
    nxt_rbtree_node_t *node2);
static void nxt_timer_change(nxt_event_engine_t *engine, nxt_timer_t *timer,
    nxt_timer_operation_t change, nxt_msec_t time);
static void nxt_timer_changes_commit(nxt_event_engine_t *engine);
static void nxt_timer_handler(nxt_task_t *task, void *obj, void *data);


nxt_int_t
nxt_timers_init(nxt_timers_t *timers, nxt_uint_t mchanges)
{
    nxt_rbtree_init(&timers->tree, nxt_timer_rbtree_compare);

    if (mchanges > NXT_TIMER_MAX_CHANGES) {
        mchanges = NXT_TIMER_MAX_CHANGES;
    }

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
    return nxt_msec_diff(timer1->time , timer2->time);
}


void
nxt_timer_add(nxt_event_engine_t *engine, nxt_timer_t *timer,
    nxt_msec_t timeout)
{
    int32_t   diff;
    uint32_t  time;

    time = engine->timers.now + timeout;

    nxt_debug(timer->task, "timer add: %M±%d %M:%M",
              timer->time, timer->bias, timeout, time);

    timer->enabled = 1;

    if (nxt_timer_is_in_tree(timer)) {

        diff = nxt_msec_diff(time, timer->time);
        /*
         * Use the previous timer if difference between it and the
         * new timer is within bias: this decreases number of rbtree
         * operations for fast connections.
         */
        if (nxt_abs(diff) <= timer->bias) {
            nxt_debug(timer->task, "timer previous: %M±%d",
                      time, timer->bias);

            nxt_timer_change(engine, timer, NXT_TIMER_NOPE, 0);
            return;
        }
    }

    nxt_timer_change(engine, timer, NXT_TIMER_ADD, time);
}


nxt_bool_t
nxt_timer_delete(nxt_event_engine_t *engine, nxt_timer_t *timer)
{
    nxt_debug(timer->task, "timer delete: %M±%d",
              timer->time, timer->bias);

    timer->enabled = 0;

    if (nxt_timer_is_in_tree(timer)) {

        nxt_timer_change(engine, timer, NXT_TIMER_DELETE, 0);

        return 1;
    }

    nxt_timer_change(engine, timer, NXT_TIMER_NOPE, 0);

    return (timer->queued || timer->change != NXT_TIMER_NO_CHANGE);
}


static void
nxt_timer_change(nxt_event_engine_t *engine, nxt_timer_t *timer,
    nxt_timer_operation_t change, nxt_msec_t time)
{
    nxt_timers_t        *timers;
    nxt_timer_change_t  *ch;

    timers = &engine->timers;

    if (timer->change == NXT_TIMER_NO_CHANGE) {

        if (change == NXT_TIMER_NOPE) {
            return;
        }

        if (timers->nchanges >= timers->mchanges) {
            nxt_timer_changes_commit(engine);
        }

        timers->nchanges++;
        timer->change = timers->nchanges;
    }

    nxt_debug(timer->task, "timer change: %M±%d:%d",
              time, timer->bias, change);

    ch = &timers->changes[timer->change - 1];

    ch->change = change;
    ch->time = time;
    ch->timer = timer;
}


static void
nxt_timer_changes_commit(nxt_event_engine_t *engine)
{
    nxt_timer_t         *timer;
    nxt_timers_t        *timers;
    nxt_timer_change_t  *ch, *end, *add, *add_end;

    timers = &engine->timers;

    nxt_debug(&engine->task, "timers changes: %ui", timers->nchanges);

    ch = timers->changes;
    end = ch + timers->nchanges;

    add = ch;
    add_end = add;

    while (ch < end) {
        timer = ch->timer;

        switch (ch->change) {

        case NXT_TIMER_NOPE:
            break;

        case NXT_TIMER_ADD:

            timer->time = ch->time;

            add_end->timer = timer;
            add_end++;

            if (!nxt_timer_is_in_tree(timer)) {
                break;
            }

            /* Fall through. */

        case NXT_TIMER_DELETE:
            nxt_debug(timer->task, "timer rbtree delete: %M±%d",
                      timer->time, timer->bias);

            nxt_rbtree_delete(&timers->tree, &timer->node);
            nxt_timer_in_tree_clear(timer);

            break;
        }

        timer->change = NXT_TIMER_NO_CHANGE;

        ch++;
    }

    while (add < add_end) {
        timer = add->timer;

        nxt_debug(timer->task, "timer rbtree insert: %M±%d",
                  timer->time, timer->bias);

        nxt_rbtree_insert(&timers->tree, &timer->node);
        nxt_timer_in_tree_set(timer);

        add++;
    }

    timers->nchanges = 0;
}


nxt_msec_t
nxt_timer_find(nxt_event_engine_t *engine)
{
    int32_t            delta;
    nxt_msec_t         time;
    nxt_timer_t        *timer;
    nxt_timers_t       *timers;
    nxt_rbtree_t       *tree;
    nxt_rbtree_node_t  *node, *next;

    timers = &engine->timers;

    if (timers->nchanges != 0) {
        nxt_timer_changes_commit(engine);
    }

    tree = &timers->tree;

    for (node = nxt_rbtree_min(tree);
         nxt_rbtree_is_there_successor(tree, node);
         node = next)
    {
        next = nxt_rbtree_node_successor(tree, node);

        timer = (nxt_timer_t *) node;

        /*
         * Disabled timers are not deleted here since the minimum active
         * timer may be larger than a disabled timer, but event poll may
         * return much earlier and the disabled timer can be reactivated.
         */

        if (timer->enabled) {
            time = timer->time;
            timers->minimum = time - timer->bias;

            nxt_debug(timer->task, "timer found minimum: %M±%d:%M",
                      time, timer->bias, timers->now);

            delta = nxt_msec_diff(time, timers->now);

            return (nxt_msec_t) nxt_max(delta, 0);
        }
    }

    /* Set minimum time one day ahead. */
    timers->minimum = timers->now + 24 * 60 * 60 * 1000;

    return NXT_INFINITE_MSEC;
}


void
nxt_timer_expire(nxt_event_engine_t *engine, nxt_msec_t now)
{
    nxt_timer_t        *timer;
    nxt_timers_t       *timers;
    nxt_rbtree_t       *tree;
    nxt_rbtree_node_t  *node, *next;

    timers = &engine->timers;
    timers->now = now;

    nxt_debug(&engine->task, "timer expire minimum: %M:%M",
              timers->minimum, now);

                   /* timers->minimum > now */
    if (nxt_msec_diff(timers->minimum , now) > 0) {
        return;
    }

    tree = &timers->tree;

    for (node = nxt_rbtree_min(tree);
         nxt_rbtree_is_there_successor(tree, node);
         node = next)
    {
        timer = (nxt_timer_t *) node;

                       /* timer->time > now + timer->bias */
        if (nxt_msec_diff(timer->time , now) > (int32_t) timer->bias) {
            return;
        }

        next = nxt_rbtree_node_successor(tree, node);

        nxt_debug(timer->task, "timer expire delete: %M±%d",
                  timer->time, timer->bias);

        nxt_rbtree_delete(tree, &timer->node);
        nxt_timer_in_tree_clear(timer);

        if (timer->enabled) {
            timer->queued = 1;

            nxt_work_queue_add(timer->work_queue, nxt_timer_handler,
                               timer->task, timer, NULL);
        }
    }
}


static void
nxt_timer_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_timer_t  *timer;

    timer = obj;

    timer->queued = 0;

    if (timer->enabled && timer->change == NXT_TIMER_NO_CHANGE) {
        timer->enabled = 0;

        timer->handler(task, timer, NULL);
    }
}
