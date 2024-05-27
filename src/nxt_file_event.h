/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_FILE_EVENT_H_INCLUDED_
#define _NXT_FILE_EVENT_H_INCLUDED_


typedef struct {
    void                *data;
    nxt_file_t          *file;
    nxt_work_handler_t  handler;
    nxt_task_t          *task;
} nxt_file_event_t;


#endif /* _NXT_FILE_EVENT_H_INCLUDED_ */
