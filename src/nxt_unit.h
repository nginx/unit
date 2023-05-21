
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIT_H_INCLUDED_
#define _NXT_UNIT_H_INCLUDED_


#include <inttypes.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <string.h>

#include "nxt_auto_config.h"
#include "nxt_version.h"
#include "nxt_unit_typedefs.h"


enum {
    NXT_UNIT_OK          = 0,
    NXT_UNIT_ERROR       = 1,
    NXT_UNIT_AGAIN       = 2,
    NXT_UNIT_CANCELLED   = 3,
};

enum {
    NXT_UNIT_LOG_ALERT   = 0,
    NXT_UNIT_LOG_ERR     = 1,
    NXT_UNIT_LOG_WARN    = 2,
    NXT_UNIT_LOG_NOTICE  = 3,
    NXT_UNIT_LOG_INFO    = 4,
    NXT_UNIT_LOG_DEBUG   = 5,
};

#define NXT_UNIT_INIT_ENV  "NXT_UNIT_INIT"

#define NXT_UNIT_SHARED_PORT_ID  ((uint16_t) 0xFFFFu)

/*
 * Mostly opaque structure with library state.
 *
 * Only the user defined 'data' pointer is exposed here.  The rest is unit
 * implementation specific and hidden.
 */
struct nxt_unit_s {
    void                  *data;  /* User defined data. */
};

/*
 * Thread context.
 *
 * First (main) context is provided 'for free'.  To receive and process
 * requests in other threads, one needs to allocate a new context and use it
 * further in that thread.
 */
struct nxt_unit_ctx_s {
    void                  *data;  /* User context-specific data. */
    nxt_unit_t            *unit;
};

/*
 * Unit port identification structure.
 *
 * Each port can be uniquely identified by listen process id (pid) and port id.
 * This identification is required to refer the port from different process.
 */
struct nxt_unit_port_id_s {
    pid_t                 pid;
    uint32_t              hash;
    uint16_t              id;
};

/*
 * Unit provides port storage which is able to store and find the following
 * data structures.
 */
struct nxt_unit_port_s {
    nxt_unit_port_id_t    id;

    int                   in_fd;
    int                   out_fd;

    void                  *data;
};


struct nxt_unit_buf_s {
    char                  *start;
    char                  *free;
    char                  *end;
};


struct nxt_unit_request_info_s {
    nxt_unit_t            *unit;
    nxt_unit_ctx_t        *ctx;

    nxt_unit_port_t       *response_port;

    nxt_unit_request_t    *request;
    nxt_unit_buf_t        *request_buf;

    nxt_unit_response_t   *response;
    nxt_unit_buf_t        *response_buf;
    uint32_t              response_max_fields;

    nxt_unit_buf_t        *content_buf;
    uint64_t              content_length;
    int                   content_fd;

    void                  *data;
};


/*
 * Set of application-specific callbacks.  The application may leave all
 * optional callbacks as NULL.
 */
struct nxt_unit_callbacks_s {
    /*
     * Process request. Unlike all other callbacks, this callback is required
     * and needs to be defined by the application.
     *
     * This callback will be called when all request header and body data is
     * available.  If the data_handler callback is not NULL, then the
     * request_handler callback may also sometimes be called without body data.
     */
    void     (*request_handler)(nxt_unit_request_info_t *req);

    /*
     * Data handler. Optional.
     *
     * If this is NULL, then the request_handler() callback will only be called
     * once all the request body data has been received.
     *
     * If this is not NULL, then the request workflow is changed such that the
     * request_handler() callback may sometimes be called with just the request
     * header data, before the body content data is available.
     *
     * The data_handler() callback will be called only if in request_handler()
     * the available data was less than the request's content_length and the
     * nxt_unit_request_done() function was not yet called.
     *
     * This callback will be called at most once, when all data becomes
     * available.
     */
    void     (*data_handler)(nxt_unit_request_info_t *req);

    /* Process websocket frame. Optional. */
    void     (*websocket_handler)(nxt_unit_websocket_frame_t *ws);

    /*
     * Connection closed. Optional. Called only for websockets that were closed
     * or requests that were aborted.
     */
    void     (*close_handler)(nxt_unit_request_info_t *req);

    /* Add new Unit port to communicate with process pid. Optional. */
    int      (*add_port)(nxt_unit_ctx_t *, nxt_unit_port_t *port);

    /* Remove previously added port. Optional. */
    void     (*remove_port)(nxt_unit_t *, nxt_unit_ctx_t *,
                            nxt_unit_port_t *port);

    /* Remove all data associated with process pid including ports. Optional. */
    void     (*remove_pid)(nxt_unit_t *, pid_t pid);

    /* Gracefully quit the application. Optional. */
    void     (*quit)(nxt_unit_ctx_t *);

    /* Shared memory release acknowledgement. Optional. */
    void     (*shm_ack_handler)(nxt_unit_ctx_t *);

    /* Send data and control to process pid using port id. Optional. */
    ssize_t  (*port_send)(nxt_unit_ctx_t *, nxt_unit_port_t *port,
                 const void *buf, size_t buf_size,
                 const void *oob, size_t oob_size);

    /* Receive data on port id. Optional. */
    ssize_t  (*port_recv)(nxt_unit_ctx_t *, nxt_unit_port_t *port,
                 void *buf, size_t buf_size, void *oob, size_t *oob_size);

    int      (*ready_handler)(nxt_unit_ctx_t *);
};


struct nxt_unit_init_s {
    void                  *data;     /* Opaque pointer to user-defined data. */
    void                  *ctx_data; /* Opaque pointer to user-defined data. */
    int                   max_pending_requests;

    uint32_t              request_data_size;
    uint32_t              shm_limit;
    uint32_t              request_limit;

    nxt_unit_callbacks_t  callbacks;

    nxt_unit_port_t       ready_port;
    uint32_t              ready_stream;
    nxt_unit_port_t       router_port;
    nxt_unit_port_t       read_port;
    int                   shared_port_fd;
    int                   shared_queue_fd;
    int                   log_fd;
};


typedef ssize_t (*nxt_unit_read_func_t)(nxt_unit_read_info_t *read_info,
    void *dst, size_t size);


struct nxt_unit_read_info_s {
    nxt_unit_read_func_t  read;
    int                   eof;
    uint32_t              buf_size;
    void                  *data;
};


/*
 * Initialize Unit application library with necessary callbacks and
 * ready/reply port parameters, send 'READY' response to main.
 */
nxt_unit_ctx_t *nxt_unit_init(nxt_unit_init_t *);

/*
 * Main function, useful in case the application does not have its own event
 * loop. nxt_unit_run() starts an infinite message wait and process loop.
 *
 *  for (;;) {
 *      app_lib->port_recv(...);
 *      nxt_unit_process_msg(...);
 *  }
 *
 * The function returns normally when a QUIT message is received from Unit.
 */
int nxt_unit_run(nxt_unit_ctx_t *);

int nxt_unit_run_ctx(nxt_unit_ctx_t *ctx);

int nxt_unit_run_shared(nxt_unit_ctx_t *ctx);

nxt_unit_request_info_t *nxt_unit_dequeue_request(nxt_unit_ctx_t *ctx);

/*
 * Receive and process one message, and invoke configured callbacks.
 *
 * If the application implements its own event loop, each datagram received
 * from the port socket should be initially processed by unit.  This function
 * may invoke other application-defined callback for message processing.
 */
int nxt_unit_run_once(nxt_unit_ctx_t *ctx);

int nxt_unit_process_port_msg(nxt_unit_ctx_t *ctx, nxt_unit_port_t *port);

/* Destroy application library object. */
void nxt_unit_done(nxt_unit_ctx_t *);

/*
 * Allocate and initialize a new execution context with a new listen port to
 * process requests in another thread.
 *
 * The new context must be deallocated with nxt_unit_done before the old context
 * is deallocated.
 */
nxt_unit_ctx_t *nxt_unit_ctx_alloc(nxt_unit_ctx_t *, void *);

/* Initialize port_id, calculate hash. */
void nxt_unit_port_id_init(nxt_unit_port_id_t *port_id, pid_t pid, uint16_t id);

/* Calculates hash for given field name. */
uint16_t nxt_unit_field_hash(const char* name, size_t name_length);

/* Split host for server name and port. */
void nxt_unit_split_host(char *host_start, uint32_t host_length,
    char **name, uint32_t *name_length, char **port, uint32_t *port_length);

/* Group duplicate fields for easy enumeration. */
void nxt_unit_request_group_dup_fields(nxt_unit_request_info_t *req);

/*
 * Allocate response structure capable of storing a limited numer of fields.
 * The structure may be accessed directly via req->response pointer or
 * filled step-by-step using functions add_field and add_content.
 */
int nxt_unit_response_init(nxt_unit_request_info_t *req,
    uint16_t status, uint32_t max_fields_count, uint32_t max_fields_size);

int nxt_unit_response_realloc(nxt_unit_request_info_t *req,
    uint32_t max_fields_count, uint32_t max_fields_size);

int nxt_unit_response_is_init(nxt_unit_request_info_t *req);

int nxt_unit_response_add_field(nxt_unit_request_info_t *req,
    const char* name, uint8_t name_length,
    const char* value, uint32_t value_length);

int nxt_unit_response_add_content(nxt_unit_request_info_t *req,
    const void* src, uint32_t size);

/*
 * Send the prepared response to the Unit server.  The Response structure is
 * destroyed during this call.
 *
 * Asynchronously, the Unit server will attempt to send the data to the client
 * as soon as it can, using the "Transfer-Encoding: chunked" method, and may
 * combine chunks for slow-reading clients.  The connection will then remain
 * open, and more chunks can be scheduled using using nxt_unit_buf_send() and/or
 * nxt_unit_write_response(), or the connection can be closed with
 * nxt_unit_request_done().
 */
int nxt_unit_response_send(nxt_unit_request_info_t *req);

int nxt_unit_response_is_sent(nxt_unit_request_info_t *req);

/*
 * Allocate a buffer for an additional response chunk to be sent.  Multiple
 * buffers may be allocated at the same time, and they may be sent or dropped
 * in any order.
 *
 * See nxt_unit_buf_max() for the maximum size that may be requested.
 */
nxt_unit_buf_t *nxt_unit_response_buf_alloc(nxt_unit_request_info_t *req,
    uint32_t size);

int nxt_unit_request_is_websocket_handshake(nxt_unit_request_info_t *req);

int nxt_unit_response_upgrade(nxt_unit_request_info_t *req);

int nxt_unit_response_is_websocket(nxt_unit_request_info_t *req);

nxt_unit_request_info_t *nxt_unit_get_request_info_from_data(void *data);

/*
 * Send and deallocate a response data chunk.  The data is immediately sent to
 * the client as a chunk using the "Transfer-Encoding: chunked" method.
 *
 * If the initial response was not yet sent with nxt_unit_response_send(), this
 * function will automatically call it.
 */
int nxt_unit_buf_send(nxt_unit_buf_t *buf);

/*
 * Deallocate a response data chunk without sending it.
 */
void nxt_unit_buf_free(nxt_unit_buf_t *buf);

nxt_unit_buf_t *nxt_unit_buf_next(nxt_unit_buf_t *buf);

/*
 * The maximum size that can be requested with nxt_unit_response_buf_alloc().
 */
uint32_t nxt_unit_buf_max(void);

/*
 * The minimum size that will be allocated by nxt_unit_response_buf_alloc().
 */
uint32_t nxt_unit_buf_min(void);

/*
 * Schedule a response to be sent to the client.  This will repeatedly call
 * nxt_unit_response_write_nb with a min_size equal to the size, which will
 * block until the Unit server has received the entire data.
 *
 * The Unit server will buffer the response data, and will attempt to send it to
 * the client asynchronously, as soon as it can.
 */
int nxt_unit_response_write(nxt_unit_request_info_t *req, const void *start,
    size_t size);

/*
 * Schedule a response to be sent to the client, blocking until at least
 * min_size bytes have been received by the Unit server.
 */
ssize_t nxt_unit_response_write_nb(nxt_unit_request_info_t *req,
    const void *start, size_t size, size_t min_size);

/*
 * Schedule a response to be sent to the client, using a user-provided callback
 * that will be called repeatedly with buffers to write to.  This function will
 * return once the Unit server has received all the data.
 */
int nxt_unit_response_write_cb(nxt_unit_request_info_t *req,
    nxt_unit_read_info_t *read_info);

/*
 * Read bytes from the request body.  This is non-blocking.  This function will
 * return 0 when no more data can be received from the Unit server in the
 * current request handler callback.
 *
 * If the data_handler callback is NULL, then the Unit server will already have
 * the entire request body data buffered, and this function can receive the
 * whole request.
 *
 * If the data_handler callback is not NULL, then:
 *
 * 1. Inside request_handler(), this function may sometimes return 0 before the
 *    amount of received data reaches the request's content_length.  In this
 *    case, Unit will call the data_handler() callback once the entire request
 *    body is available.
 * 2. Inside data_handler(), the whole request body data is guaranteed to be
 *    buffered, and this function can receive the whole request.
 */
ssize_t nxt_unit_request_read(nxt_unit_request_info_t *req, void *dst,
    size_t size);

/* Read bytes until (and including) the next "\n" byte. */
ssize_t nxt_unit_request_readline_size(nxt_unit_request_info_t *req,
    size_t max_size);

/*
 * Close the request.  This function must be called, or the request will hang.
 *
 * With NXT_UNIT_ERROR, if no parts of a response have been sent yet, Unit will
 * send a default "503 Service Unavailable" response.
 */
void nxt_unit_request_done(nxt_unit_request_info_t *req, int rc);


int nxt_unit_websocket_send(nxt_unit_request_info_t *req, uint8_t opcode,
    uint8_t last, const void *start, size_t size);

int nxt_unit_websocket_sendv(nxt_unit_request_info_t *req, uint8_t opcode,
    uint8_t last, const struct iovec *iov, int iovcnt);

ssize_t nxt_unit_websocket_read(nxt_unit_websocket_frame_t *ws, void *dst,
    size_t size);

int nxt_unit_websocket_retain(nxt_unit_websocket_frame_t *ws);

void nxt_unit_websocket_done(nxt_unit_websocket_frame_t *ws);


void *nxt_unit_malloc(nxt_unit_ctx_t *ctx, size_t size);

void nxt_unit_free(nxt_unit_ctx_t *ctx, void *p);

#if defined __has_attribute

#if __has_attribute(format)

#define NXT_ATTR_FORMAT  __attribute__((format(printf, 3, 4)))

#endif

#endif


#if !defined(NXT_ATTR_FORMAT)

#define NXT_ATTR_FORMAT

#endif


void nxt_unit_log(nxt_unit_ctx_t *ctx, int level, const char* fmt, ...)
    NXT_ATTR_FORMAT;

void nxt_unit_req_log(nxt_unit_request_info_t *req, int level,
    const char* fmt, ...) NXT_ATTR_FORMAT;

#if (NXT_DEBUG)

#define nxt_unit_debug(ctx, fmt, ARGS...) \
    nxt_unit_log(ctx, NXT_UNIT_LOG_DEBUG, fmt, ##ARGS)

#define nxt_unit_req_debug(req, fmt, ARGS...) \
    nxt_unit_req_log(req, NXT_UNIT_LOG_DEBUG, fmt, ##ARGS)

#else

#define nxt_unit_debug(ctx, fmt, ARGS...)

#define nxt_unit_req_debug(req, fmt, ARGS...)

#endif


#define nxt_unit_warn(ctx, fmt, ARGS...) \
    nxt_unit_log(ctx, NXT_UNIT_LOG_WARN, fmt, ##ARGS)

#define nxt_unit_req_warn(req, fmt, ARGS...) \
    nxt_unit_req_log(req, NXT_UNIT_LOG_WARN, fmt, ##ARGS)

#define nxt_unit_error(ctx, fmt, ARGS...) \
    nxt_unit_log(ctx, NXT_UNIT_LOG_ERR, fmt, ##ARGS)

#define nxt_unit_req_error(req, fmt, ARGS...) \
    nxt_unit_req_log(req, NXT_UNIT_LOG_ERR, fmt, ##ARGS)

#define nxt_unit_alert(ctx, fmt, ARGS...) \
    nxt_unit_log(ctx, NXT_UNIT_LOG_ALERT, fmt, ##ARGS)

#define nxt_unit_req_alert(req, fmt, ARGS...) \
    nxt_unit_req_log(req, NXT_UNIT_LOG_ALERT, fmt, ##ARGS)


#endif /* _NXT_UNIT_H_INCLUDED_ */
