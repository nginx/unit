
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_BUF_FILTER_H_INCLUDED_
#define _NXT_BUF_FILTER_H_INCLUDED_


/*
 * nxt_buf_filter is a framework intended to simplify processing file
 * buffers content by a filter.  The filter should set callbacks and
 * call nxt_buf_filter_add() to start processing.
 *
 * At first buf_filter calls filter_ready() and the filter ensures
 * it may allocate or reuse its internal buffer.  No real allocation
 * is performed at this step.
 *
 * TODO prevent unneeded allocaiton if no input data.
 *
 *
 * TODO:  The filter can flush data buffered
 * previously, if all internal buffers are full.
 *
 * Then buf_filter looks buffer chains.  There are two buffer chains:
 * the input chain is a chain of original incoming memory, file, and sync
 * buffers; and the current chain is a chain of memory/file buffers read
 * from a file-only buffer.  The current chain is processed first.  Since
 * buffers in this chain always contains a memory part, they can be passed
 * one by one to the filter using filter_process().  If there is an output
 * buffer after the buffer processing, it is added to output chain.  The
 * output buffers are not filter internal buffers.  They just point to these
 * internal buffers and one internal buffer can correspond to several output
 * buffers which point to adjoining parts of the internal buffer.  Further
 * processing depends on filter_process() result code: if it returns NXT_OK,
 * then the filter internal buffer is not full and buf_filter looks the next
 * current or input buffer.  If result code is NXT_AGAIN, then the filter
 * internal buffer is full and buf_filter calls filter_flush() and then
 * schedules to run nxt_buf_filter_repeat().  nxt_buf_filter_repeat() will
 * run after all ready output buffer completion handlers and will call
 * buf_filter again if no one completion handler will do it already using
 * nxt_buf_filter_enqueue().  So in any case buf_filter will run again only
 * once.
 *
 * TODO:
 * in ideal just one the filter internal buffer.
 * This allows to minimize number of the filter internal buffers if they
 * flush fast.
 *
 * If the current chain is empty, the buf_filter processes the input chain.
 * Memory buffers are passed to the filter using filter_process().  If an
 * input buffer is a file buffer, then buf_filter calls filter_flush()
 * and starts a file job to read the buffer in memory.  The file job reads
 * file parts into memory/file buffers and adds them to the current chain.
 *
 * Sync buffers are passed to the filter using filter_sync().  Its
 * post-processing is similar to the filter_process() post-processing,
 * except sync buffers are always added unmodified to the output chain.
 */

typedef struct {
    nxt_job_file_t               job_file;
    nxt_buf_pool_t               buffers;
} nxt_buf_filter_file_t;


typedef struct nxt_buf_filter_s  nxt_buf_filter_t;

typedef struct {
    nxt_int_t                    (*filter_ready)(nxt_buf_filter_t *f);
    nxt_int_t                    (*filter_process)(nxt_buf_filter_t *f);
    nxt_int_t                    (*filter_flush)(nxt_buf_filter_t *f);

    nxt_int_t                    (*filter_sync_nobuf)(nxt_buf_filter_t *f);
    nxt_int_t                    (*filter_sync_flush)(nxt_buf_filter_t *f);
    nxt_int_t                    (*filter_sync_last)(nxt_buf_filter_t *f);

    void                         (*filter_next)(nxt_buf_filter_t *f);
    nxt_work_handler_t           filter_error;

    nxt_buf_filter_file_t        *(*job_file_create)(nxt_buf_filter_t *f);
    void                         (*job_file_retain)(nxt_buf_filter_t *f);
    void                         (*job_file_release)(nxt_buf_filter_t *f);
} nxt_buf_filter_ops_t;


struct nxt_buf_filter_s {
    nxt_buf_t                    *current;
    nxt_buf_t                    *input;
    nxt_buf_t                    *output;
    nxt_buf_t                    *last;

    nxt_work_queue_t             *work_queue;
    nxt_buf_filter_file_t        *filter_file;
    void                         *data;
    nxt_mp_t                     *mem_pool;

    const nxt_buf_filter_ops_t   *run;

    uint8_t                      mmap;       /* 1 bit */
    uint8_t                      done;       /* 1 bit */
    uint8_t                      queued;     /* 1 bit */
    uint8_t                      reading;    /* 1 bit */
    uint8_t                      buffering;  /* 1 bit */
};


NXT_EXPORT void nxt_buf_filter_add(nxt_task_t *task, nxt_buf_filter_t *f,
    nxt_buf_t *b);
NXT_EXPORT void nxt_buf_filter(nxt_task_t *task, void *obj, void *data);
NXT_EXPORT void nxt_buf_filter_enqueue(nxt_task_t *task, nxt_buf_filter_t *f);


#endif /* _NXT_BUF_FILTER_H_INCLUDED_ */
