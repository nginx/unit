
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_PORT_H_INCLUDED_
#define _NXT_PORT_H_INCLUDED_


#define NXT_PORT_MSG_MAX  NXT_PORT_MSG_DATA

typedef enum {
    NXT_PORT_MSG_QUIT = 0,
    NXT_PORT_MSG_NEW_PORT,
    NXT_PORT_MSG_PORTGE_FILE,
    NXT_PORT_MSG_DATA,
} nxt_port_msg_type_e;


typedef struct {
    nxt_pid_t   pid;
    uint32_t    engine;
    uint32_t    generation;
    nxt_port_t  *port;
} nxt_process_port_t;


typedef struct {
    nxt_pid_t   pid;
    uint32_t    engine;
    size_t      max_size;
    size_t      max_share;
} nxt_proc_msg_new_port_t;


/*
 * nxt_process_port_data_t is allocaiton size
 * enabling effective reuse of memory pool cache.
 */
typedef union {
    nxt_buf_t                buf;
    nxt_proc_msg_new_port_t  new_port;
} nxt_process_port_data_t;


typedef void (*nxt_process_port_handler_t)(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);


void nxt_process_port_create(nxt_thread_t *thr, nxt_process_port_t *proc,
    nxt_process_port_handler_t *handlers);
void nxt_process_port_write(nxt_task_t *task, nxt_cycle_t *cycle,
    nxt_uint_t type, nxt_fd_t fd, uint32_t stream, nxt_buf_t *b);
void nxt_process_new_port(nxt_task_t *task, nxt_cycle_t *cycle,
    nxt_process_port_t *proc);
void nxt_process_port_change_log_file(nxt_task_t *task, nxt_cycle_t *cycle,
    nxt_uint_t slot, nxt_fd_t fd);

void nxt_process_port_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_process_port_new_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_process_port_change_log_file_handler(nxt_task_t *task,
    nxt_port_recv_msg_t *msg);
void nxt_process_port_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);
void nxt_process_port_empty_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg);


#endif /* _NXT_PORT_H_INCLUDED_ */
