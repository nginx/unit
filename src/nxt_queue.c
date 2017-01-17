
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


#include <nxt_main.h>


/*
 * Find the middle queue element if the queue has odd number of elements,
 * or the first element of the queue's second part otherwise.
 */

nxt_queue_link_t *
nxt_queue_middle(nxt_queue_t *queue)
{
    nxt_queue_link_t  *middle, *next;

    middle = nxt_queue_first(queue);

    if (middle == nxt_queue_last(queue)) {
        return middle;
    }

    next = middle;

    for ( ;; ) {
        middle = nxt_queue_next(middle);

        next = nxt_queue_next(next);

        if (next == nxt_queue_last(queue)) {
            return middle;
        }

        next = nxt_queue_next(next);

        if (next == nxt_queue_last(queue)) {
            return middle;
        }
    }
}


/*
 * nxt_queue_sort() provides a stable sort because it uses the insertion
 * sort algorithm.  Its worst and average computational complexity is O^2.
 */

void
nxt_queue_sort(nxt_queue_t *queue,
    nxt_int_t (*cmp)(const void *data, const nxt_queue_link_t *,
    const nxt_queue_link_t *), const void *data)
{
    nxt_queue_link_t  *link, *prev, *next;

    link = nxt_queue_first(queue);

    if (link == nxt_queue_last(queue)) {
        return;
    }

    for (link = nxt_queue_next(link);
         link != nxt_queue_tail(queue);
         link = next)
    {
        prev = nxt_queue_prev(link);
        next = nxt_queue_next(link);

        nxt_queue_remove(link);

        do {
            if (cmp(data, prev, link) <= 0) {
                break;
            }

            prev = nxt_queue_prev(prev);

        } while (prev != nxt_queue_head(queue));

        nxt_queue_insert_after(prev, link);
    }
}
