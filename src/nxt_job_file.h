
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_JOB_FILE_H_INCLUDED_
#define _NXT_JOB_FILE_H_INCLUDED_


/*
 * nxt_job_file_read() allows to open a file, to get its type, size, and
 * modification time, to read or map file content to memory, and to close
 * the file.  It can be done as one operation for small file or as several
 * operations for large file.  On each operation completion ready_handler
 * or error_handler completion handlers are called.  Since they are job
 * operations, they can be run by a thread pool.
 *
 * If a file is not opened then it is opened and its type, size, and
 * modification time are got.  Then file content starting from given offset
 * is read or mapped in memory if there is a buffer supplied.  The offset
 * field is correspondingly updated.
 *
 * If there is no buffer but the read_ahead flag is set then the first
 * byte is read to initiate read ahead operation.
 *
 * If the close flag is set then file descriptor is closed when the file
 * is completely read.
 *
 * The complete flag is set by nxt_job_file_read() when the file is
 * completely read.
 *
 * The test_before_open flag allows to save syscalls in some case, for
 * example, not to open and then not to close a directory.  It calls
 * nxt_file_info() to get file type, size, and modification time before
 * opening the file.  A custom read_required() callback combined with this
 * flag can also omit opening and reading on some conditions.  However,
 * if the callback forces opening then additional nxt_file_info() is
 * called after opening.  The default read_required() callback always
 * forces opening and reading.
 */


typedef struct nxt_job_file_s  nxt_job_file_t;

struct nxt_job_file_s {
    nxt_job_t           job;

    nxt_file_t          file;

    nxt_off_t           offset;
    nxt_buf_t           *buffer;

    nxt_work_handler_t  ready_handler;
    nxt_work_handler_t  error_handler;

    nxt_int_t           (*read_required)(nxt_job_file_t *jbf);

    uint16_t            directory_end;

    uint16_t            close_before_open:1;
    uint16_t            test_before_open:1;
    uint16_t            read_ahead:1;
    uint16_t            close:1;
    uint16_t            complete:1;
};


NXT_EXPORT nxt_job_file_t *nxt_job_file_create(nxt_mp_t *mp);
NXT_EXPORT void nxt_job_file_init(nxt_job_file_t *jbf);
NXT_EXPORT void nxt_job_file_read(nxt_task_t *task, nxt_job_t *job);


#endif /* _NXT_JOB_FILE_H_INCLUDED_ */
