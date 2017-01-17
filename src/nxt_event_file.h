/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_EVENT_FILE_H_INCLUDED_
#define _NXT_EVENT_FILE_H_INCLUDED_


typedef struct {
    void                *data;
    nxt_file_t          *file;
    nxt_work_handler_t  handler;
} nxt_event_file_t;


#endif /* _NXT_EVENT_FILE_H_INCLUDED_ */
