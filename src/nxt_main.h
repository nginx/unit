
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_LIB_H_INCLUDED_
#define _NXT_LIB_H_INCLUDED_


#include <nxt_auto_config.h>
#include <nxt_version.h>

#define NXT_SERVER                   "Unit/" NXT_VERSION

typedef struct nxt_port_s            nxt_port_t;
typedef struct nxt_task_s            nxt_task_t;
typedef struct nxt_port_recv_msg_s   nxt_port_recv_msg_t;
typedef void (*nxt_port_handler_t)(nxt_task_t *task, nxt_port_recv_msg_t *msg);
typedef struct nxt_port_handlers_s   nxt_port_handlers_t;
typedef struct nxt_sig_event_s       nxt_sig_event_t;
typedef struct nxt_runtime_s         nxt_runtime_t;

typedef struct nxt_thread_s          nxt_thread_t;
typedef struct nxt_event_engine_s    nxt_event_engine_t;
typedef struct nxt_log_s             nxt_log_t;
typedef struct nxt_thread_pool_s     nxt_thread_pool_t;

typedef void (*nxt_work_handler_t)(nxt_task_t *task, void *obj, void *data);

#include <nxt_unix.h>
#include <nxt_clang.h>
#include <nxt_types.h>
#include <nxt_time.h>
#include <nxt_mp.h>
#include <nxt_array.h>

typedef uint16_t                     nxt_port_id_t;

#include <nxt_queue.h>

#include <nxt_thread_id.h>

#include <nxt_errno.h>
#include <nxt_file.h>

#include <nxt_random.h>
#include <nxt_string.h>
#include <nxt_lvlhsh.h>
#include <nxt_atomic.h>
#include <nxt_spinlock.h>
#include <nxt_work_queue.h>
#include <nxt_log.h>
#include <nxt_thread_time.h>
#include <nxt_rbtree.h>
#include <nxt_timer.h>
#include <nxt_fiber.h>
#include <nxt_thread.h>
#include <nxt_process_type.h>
#include <nxt_process.h>
#include <nxt_utf8.h>
#include <nxt_file_name.h>

#include <nxt_sprintf.h>
#include <nxt_parse.h>


/* TODO: remove unused */

typedef struct nxt_fd_event_s           nxt_fd_event_t;
typedef struct nxt_sockaddr_s           nxt_sockaddr_t;


#include <nxt_malloc.h>
#include <nxt_mem_map.h>
#include <nxt_socket.h>
#include <nxt_dyld.h>


typedef void *(*nxt_mem_proto_alloc_t)(void *pool, size_t size);
typedef void (*nxt_mem_proto_free_t)(void *pool, void *p);

typedef struct {
    nxt_mem_proto_alloc_t  alloc;
    nxt_mem_proto_free_t   free;
} nxt_mem_proto_t;


#include <nxt_mem_zone.h>
#include <nxt_signal.h>
#include <nxt_semaphore.h>

#include <nxt_djb_hash.h>
#include <nxt_murmur_hash.h>
#include <nxt_hash.h>

#include <nxt_sort.h>
#include <nxt_vector.h>
#include <nxt_list.h>

#include <nxt_service.h>

typedef struct nxt_buf_s                nxt_buf_t;
#include <nxt_buf.h>
#include <nxt_buf_pool.h>
#include <nxt_recvbuf.h>

typedef struct nxt_conn_s               nxt_conn_t;
#include <nxt_sendbuf.h>

#include <nxt_log_moderation.h>

#if (NXT_TLS)
#include <nxt_tls.h>
#endif


#define nxt_thread()                                                          \
    (nxt_thread_t *) nxt_thread_get_data(nxt_thread_context)

nxt_thread_extern_data(nxt_thread_t, nxt_thread_context);


#include <nxt_thread_log.h>

#include <nxt_fd_event.h>
#include <nxt_file_event.h>

#include <nxt_port.h>
#include <nxt_port_memory.h>
#include <nxt_port_rpc.h>
#include <nxt_thread_pool.h>


typedef void (*nxt_event_conn_handler_t)(nxt_thread_t *thr, nxt_conn_t *c);
#include <nxt_listen_socket.h>

#include <nxt_conn.h>
#include <nxt_event_engine.h>

#include <nxt_job.h>
#include <nxt_job_file.h>
#include <nxt_buf_filter.h>

#include <nxt_job_resolve.h>
#include <nxt_sockaddr.h>

#include <nxt_cache.h>

#include <nxt_source.h>
typedef struct nxt_upstream_source_s  nxt_upstream_source_t;

#include <nxt_http_parse.h>
#include <nxt_stream_source.h>
#include <nxt_upstream.h>
#include <nxt_upstream_source.h>
#include <nxt_http_source.h>
#include <nxt_fastcgi_source.h>
#include <nxt_runtime.h>
#include <nxt_port_hash.h>


/*
 * The envp argument must be &environ if application may
 * change its process title with nxt_process_title().
 */
NXT_EXPORT nxt_int_t nxt_lib_start(const char *app, char **argv, char ***envp);
NXT_EXPORT void nxt_lib_stop(void);


NXT_EXPORT extern nxt_uint_t    nxt_ncpu;
NXT_EXPORT extern nxt_uint_t    nxt_pagesize;
NXT_EXPORT extern nxt_task_t    nxt_main_task;
NXT_EXPORT extern nxt_atomic_t  nxt_task_ident;


#endif /* _NXT_LIB_H_INCLUDED_ */
