
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */


#include <nxt_main.h>


static void nxt_job_file_open_and_read(nxt_task_t *task, void *obj, void *data);
static nxt_int_t nxt_job_file_open(nxt_job_file_t *jbf);
static nxt_int_t nxt_job_file_info(nxt_job_file_t *jbf);
static nxt_int_t nxt_job_file_mmap(nxt_job_file_t *jbf, size_t size);
static nxt_int_t nxt_job_file_read_data(nxt_job_file_t *jbf, size_t size);
static nxt_int_t nxt_job_file_read_required(nxt_job_file_t *jbf);


nxt_job_file_t *
nxt_job_file_create(nxt_mp_t *mp)
{
    nxt_job_file_t  *jbf;

    jbf = nxt_job_create(mp, sizeof(nxt_job_file_t));

    if (nxt_fast_path(jbf != NULL)) {
        jbf->file.fd = NXT_FILE_INVALID;
        jbf->file.accessed = NXT_FILE_ACCESSED_LONG_AGO;
        jbf->read_required = nxt_job_file_read_required;
    }

    return jbf;
}


void
nxt_job_file_init(nxt_job_file_t *jbf)
{
    nxt_job_init(&jbf->job, sizeof(nxt_job_file_t));

    jbf->file.fd = NXT_FILE_INVALID;
    jbf->file.accessed = NXT_FILE_ACCESSED_LONG_AGO;
    jbf->read_required = nxt_job_file_read_required;
}


/*
 * Must be a function but not a macro, because
 * it can be used as function pointer.
 */

void
nxt_job_file_read(nxt_task_t *task, nxt_job_t *job)
{
    nxt_job_start(task, job, nxt_job_file_open_and_read);
}


static void
nxt_job_file_open_and_read(nxt_task_t *task, void *obj, void *data)
{
    size_t              size;
    nxt_int_t           n;
    nxt_bool_t          read_ahead;
    nxt_file_t          *file;
    nxt_job_file_t      *jbf;
    nxt_work_handler_t  handler;

    jbf = obj;
    file = &jbf->file;

    nxt_debug(task, "file job read: \"%FN\"", file->name);

    if (file->fd != NXT_FILE_INVALID && jbf->close_before_open) {
        nxt_file_close(file);
        file->fd = NXT_FILE_INVALID;
    }

    if (file->fd == NXT_FILE_INVALID) {

        switch (nxt_job_file_open(jbf)) {

        case NXT_OK:
            break;

        case NXT_DECLINED:
            handler = jbf->ready_handler;
            goto done;

        default: /* NXT_ERROR */
            handler = jbf->error_handler;
            goto done;
        }
    }

    if (file->size > 0) {

        if (jbf->buffer != NULL) {
            size = nxt_buf_mem_size(&jbf->buffer->mem);
            size = nxt_min(file->size, (nxt_off_t) size);
            read_ahead = nxt_buf_is_mmap(jbf->buffer);

        } else {
            size = nxt_min(file->size, 1024 * 1024);
            read_ahead = jbf->read_ahead;
        }

        if (read_ahead) {
            nxt_file_read_ahead(&jbf->file, jbf->offset, size);
        }

        if (jbf->buffer != NULL) {

            if (nxt_buf_is_mmap(jbf->buffer)) {
                n = nxt_job_file_mmap(jbf, size);

            } else {
                n = nxt_job_file_read_data(jbf, size);
            }

            if (nxt_slow_path(n != NXT_OK)) {
                handler = jbf->error_handler;
                goto done;
            }
        }
    }

    if (jbf->offset == file->size) {
        jbf->complete = 1;

        if (jbf->close) {
            nxt_file_close(file);
            file->fd = NXT_FILE_INVALID;
        }
    }

    nxt_job_return(task, &jbf->job, jbf->ready_handler);
    return;

done:

    if (file->fd != NXT_FILE_INVALID) {
        nxt_file_close(file);
        file->fd = NXT_FILE_INVALID;
    }

    nxt_job_return(task, &jbf->job, handler);
}


static nxt_int_t
nxt_job_file_open(nxt_job_file_t *jbf)
{
    nxt_int_t  n;

    if (jbf->test_before_open) {
        n = nxt_job_file_info(jbf);

        if (n != NXT_OK) {
            goto test_directory;
        }

        if (jbf->file.type == NXT_FILE_DIRECTORY) {
            return NXT_DECLINED;
        }

        if (jbf->read_required(jbf) != NXT_OK) {
            return NXT_DECLINED;
        }
    }

    n = nxt_file_open(&jbf->file, NXT_FILE_RDONLY, NXT_FILE_OPEN, 0);

    if (n == NXT_OK) {
        n = nxt_job_file_info(jbf);

        if (nxt_fast_path(n == NXT_OK)) {

            if (jbf->file.type == NXT_FILE_DIRECTORY) {
                return NXT_DECLINED;
            }

            return jbf->read_required(jbf);
        }

        return n;
    }

test_directory:

    if (jbf->directory_end != 0
        && jbf->file.error != NXT_ENOTDIR
        && jbf->file.error != NXT_ENAMETOOLONG
        && jbf->file.error != NXT_EACCES)
    {
        jbf->file.name[jbf->directory_end] = '\0';

        return nxt_job_file_info(jbf);
    }

    return n;
}


static nxt_int_t
nxt_job_file_info(nxt_job_file_t *jbf)
{
    nxt_int_t        n;
    nxt_file_t       *file;
    nxt_file_info_t  fi;

    file = &jbf->file;

    n = nxt_file_info(file, &fi);

    if (n != NXT_OK) {
        return NXT_ERROR;
    }

    if (nxt_is_file(&fi)) {
        file->type = NXT_FILE_REGULAR;
        file->size = nxt_file_size(&fi);
        file->mtime = nxt_file_mtime(&fi);

    } else if (nxt_is_dir(&fi)) {
        file->type = NXT_FILE_DIRECTORY;
        file->size = nxt_file_size(&fi);
        file->mtime = nxt_file_mtime(&fi);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_job_file_mmap(nxt_job_file_t *jbf, size_t size)
{
    u_char             *p, *end;
    static nxt_uint_t  n;

    p = nxt_mem_map(NULL, &jbf->buffer->mmap, size, NXT_MEM_MAP_READ,
                    (NXT_MEM_MAP_FILE | NXT_MEM_MAP_PREFAULT),
                    jbf->file.fd, jbf->offset);

    if (nxt_fast_path(p != NXT_MEM_MAP_FAILED)) {

        end = p + size;

        jbf->buffer->mem.pos = p;
        jbf->buffer->mem.free = end;
        jbf->buffer->mem.start = p;
        jbf->buffer->mem.end = end;
        jbf->buffer->file_end += size;
        jbf->offset += size;

        /*
         * The mapped pages should be already preloaded in the kernel page
         * cache by nxt_file_read_ahead().  Touching them should wire the pages
         * in user land memory if mmap() did not do this.  Adding to the static
         * variable "n" disables the loop elimination during optimization.
         */
        n += *p;

        for (p = nxt_align_ptr(p, nxt_pagesize); p < end; p += nxt_pagesize) {
            n += *p;
        }

        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_job_file_read_data(nxt_job_file_t *jbf, size_t size)
{
    ssize_t  n;

    n = nxt_file_read(&jbf->file, jbf->buffer->mem.free, size, jbf->offset);

    if (nxt_fast_path(n > 0)) {

        jbf->buffer->mem.free += n;
        jbf->offset += n;

        if (nxt_buf_is_file(jbf->buffer)) {
            jbf->buffer->file_end += n;
        }

        return NXT_OK;
    }

    return NXT_ERROR;
}


static nxt_int_t
nxt_job_file_read_required(nxt_job_file_t *jbf)
{
    return NXT_OK;
}
