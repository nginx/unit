
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>

#if (NXT_HAVE_MEMFD_CREATE)

#include <linux/memfd.h>
#include <unistd.h>
#include <sys/syscall.h>

#endif

#include <nxt_port_memory_int.h>

void
nxt_port_mmap_destroy(nxt_port_mmap_t *port_mmap)
{
    if (port_mmap->hdr != NULL) {
        nxt_mem_munmap(port_mmap->hdr, PORT_MMAP_SIZE);
        port_mmap->hdr = NULL;
    }
}


static nxt_array_t *
nxt_port_mmaps_create()
{
    nxt_mp_t  *mp;

    mp = nxt_mp_create(1024, 128, 256, 32);

    if (nxt_slow_path(mp == NULL)) {
        return NULL;
    }

    return nxt_array_create(mp, 1, sizeof(nxt_port_mmap_t));
}


static nxt_port_mmap_t *
nxt_port_mmap_add(nxt_array_t *port_mmaps)
{
    nxt_mp_thread_adopt(port_mmaps->mem_pool);

    return nxt_array_zero_add(port_mmaps);
}


void
nxt_port_mmaps_destroy(nxt_array_t *port_mmaps, nxt_bool_t destroy_pool)
{
    uint32_t         i;
    nxt_port_mmap_t  *port_mmap;

    if (port_mmaps == NULL) {
        return;
    }

    nxt_mp_thread_adopt(port_mmaps->mem_pool);

    port_mmap = port_mmaps->elts;

    for (i = 0; i < port_mmaps->nelts; i++) {
        nxt_port_mmap_destroy(port_mmap);
    }

    port_mmaps->nelts = 0;

    if (destroy_pool != 0) {
        nxt_mp_destroy(port_mmaps->mem_pool);
    }
}


#define nxt_port_mmap_free_junk(p, size)                                      \
    memset((p), 0xA5, size)


static void
nxt_port_mmap_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    u_char                  *p;
    nxt_mp_t                *mp;
    nxt_buf_t               *b;
    nxt_chunk_id_t          c;
    nxt_port_mmap_header_t  *hdr;

    if (nxt_buf_ts_handle(task, obj, data)) {
        return;
    }

    b = obj;

    mp = b->data;

#if (NXT_DEBUG)
    if (nxt_slow_path(data != b->parent)) {
        nxt_log_alert(task->log, "completion data (%p) != b->parent (%p)",
                      data, b->parent);
        nxt_abort();
    }
#endif

    hdr = data;

    if (b->is_port_mmap_sent && b->mem.pos > b->mem.start) {
        /*
         * Chunks until b->mem.pos has been sent to other side,
         * let's release rest (if any).
         */
        p = b->mem.pos - 1;
        c = nxt_port_mmap_chunk_id(hdr, p) + 1;
        p = nxt_port_mmap_chunk_start(hdr, c);

    } else {
        p = b->mem.start;
        c = nxt_port_mmap_chunk_id(hdr, p);
    }

    nxt_port_mmap_free_junk(p, b->mem.end - p);

    nxt_debug(task, "mmap buf completion: %p [%p,%d] (sent=%d), %PI,%d,%d", b,
              b->mem.start, b->mem.end - b->mem.start, b->is_port_mmap_sent,
              hdr->pid, hdr->id, c);

    while (p < b->mem.end) {
        nxt_port_mmap_set_chunk_free(hdr, c);

        p += PORT_MMAP_CHUNK_SIZE;
        c++;
    }

    nxt_mp_release(mp, b);
}


nxt_port_mmap_header_t *
nxt_port_incoming_port_mmap(nxt_task_t *task, nxt_process_t *process,
    nxt_fd_t fd)
{
    void                    *mem;
    struct stat             mmap_stat;
    nxt_port_mmap_t         *port_mmap;
    nxt_port_mmap_header_t  *hdr;

    nxt_debug(task, "got new mmap fd #%FD from process %PI",
              fd, process->pid);

    port_mmap = NULL;
    hdr = NULL;

    if (fstat(fd, &mmap_stat) == -1) {
        nxt_log(task, NXT_LOG_WARN, "fstat(%FD) failed %E", fd, nxt_errno);

        return NULL;
    }

    nxt_thread_mutex_lock(&process->incoming_mutex);

    if (process->incoming == NULL) {
        process->incoming = nxt_port_mmaps_create();
    }

    if (nxt_slow_path(process->incoming == NULL)) {
        nxt_log(task, NXT_LOG_WARN, "failed to allocate incoming array");

        goto fail;
    }

    port_mmap = nxt_port_mmap_add(process->incoming);
    if (nxt_slow_path(port_mmap == NULL)) {
        nxt_log(task, NXT_LOG_WARN, "failed to add mmap to incoming array");

        goto fail;
    }

    mem = nxt_mem_mmap(NULL, mmap_stat.st_size,
                       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_log(task, NXT_LOG_WARN, "mmap() failed %E", nxt_errno);

        port_mmap = NULL;

        goto fail;
    }

    port_mmap->hdr = mem;
    hdr = port_mmap->hdr;

    if (nxt_slow_path(port_mmap->hdr->id != process->incoming->nelts - 1)) {
        nxt_log(task, NXT_LOG_WARN, "port mmap id mismatch (%d != %d)",
                port_mmap->hdr->id, process->incoming->nelts - 1);
        nxt_abort();
    }

    hdr->sent_over = 0xFFFFu;

fail:

    nxt_thread_mutex_unlock(&process->incoming_mutex);

    return hdr;
}


static nxt_port_mmap_header_t *
nxt_port_new_port_mmap(nxt_task_t *task, nxt_process_t *process,
    nxt_port_t *port)
{
    void                    *mem;
    u_char                  *p, name[64];
    nxt_fd_t                fd;
    nxt_port_mmap_t         *port_mmap;
    nxt_port_mmap_header_t  *hdr;

    port_mmap = NULL;

    if (process->outgoing == NULL) {
        process->outgoing = nxt_port_mmaps_create();
    }

    if (nxt_slow_path(process->outgoing == NULL)) {
        nxt_log(task, NXT_LOG_WARN, "failed to allocate outgoing array");

        return NULL;
    }

    port_mmap = nxt_port_mmap_add(process->outgoing);
    if (nxt_slow_path(port_mmap == NULL)) {
        nxt_log(task, NXT_LOG_WARN,
                "failed to add port mmap to outgoing array");

        return NULL;
    }

    p = nxt_sprintf(name, name + sizeof(name), "/unit.%PI.%uxD",
                    nxt_pid, nxt_random(&task->thread->random));
    *p = '\0';

#if (NXT_HAVE_MEMFD_CREATE)

    fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC);

    if (nxt_slow_path(fd == -1)) {
        nxt_log(task, NXT_LOG_CRIT, "memfd_create(%s) failed %E",
                name, nxt_errno);

        goto remove_fail;
    }

    nxt_debug(task, "memfd_create(%s): %FD", name, fd);

#elif (NXT_HAVE_SHM_OPEN)

    /* Just in case. */
    shm_unlink((char *) name);

    fd = shm_open((char *) name, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);

    nxt_debug(task, "shm_open(%s): %FD", name, fd);

    if (nxt_slow_path(fd == -1)) {
        nxt_log(task, NXT_LOG_CRIT, "shm_open(%s) failed %E", name, nxt_errno);

        goto remove_fail;
    }

    if (nxt_slow_path(shm_unlink((char *) name) == -1)) {
        nxt_log(task, NXT_LOG_WARN, "shm_unlink(%s) failed %E", name,
                nxt_errno);
    }

#endif

    if (nxt_slow_path(ftruncate(fd, PORT_MMAP_SIZE) == -1)) {
        nxt_log(task, NXT_LOG_WARN, "ftruncate() failed %E", nxt_errno);

        goto remove_fail;
    }

    mem = nxt_mem_mmap(NULL, PORT_MMAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);

    if (nxt_slow_path(mem == MAP_FAILED)) {
        goto remove_fail;
    }

    port_mmap->hdr = mem;

    /* Init segment header. */
    hdr = port_mmap->hdr;

    nxt_memset(hdr->free_map, 0xFFU, sizeof(hdr->free_map));

    hdr->id = process->outgoing->nelts - 1;
    hdr->pid = process->pid;
    hdr->sent_over = port->id;

    /* Mark first chunk as busy */
    nxt_port_mmap_set_chunk_busy(hdr, 0);

    /* Mark as busy chunk followed the last available chunk. */
    nxt_port_mmap_set_chunk_busy(hdr, PORT_MMAP_CHUNK_COUNT);

    nxt_debug(task, "send mmap fd %FD to process %PI", fd,
              port->pid);

    /* TODO handle error */
    (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_MMAP, fd, 0, 0, NULL);

    nxt_log(task, NXT_LOG_DEBUG, "new mmap #%D created for %PI -> %PI",
            hdr->id, nxt_pid, process->pid);

    return hdr;

remove_fail:

    nxt_array_remove(process->outgoing, port_mmap);

    return NULL;
}


static nxt_port_mmap_header_t *
nxt_port_mmap_get(nxt_task_t *task, nxt_port_t *port, nxt_chunk_id_t *c,
    size_t size)
{
    nxt_array_t             *outgoing;
    nxt_process_t           *process;
    nxt_port_mmap_t         *port_mmap;
    nxt_port_mmap_t         *end_port_mmap;
    nxt_port_mmap_header_t  *hdr;

    process = port->process;
    if (nxt_slow_path(process == NULL)) {
        return NULL;
    }

    *c = 0;
    port_mmap = NULL;
    hdr = NULL;

    nxt_thread_mutex_lock(&process->outgoing_mutex);

    if (process->outgoing == NULL) {
        hdr = nxt_port_new_port_mmap(task, process, port);

        goto unlock_return;
    }

    outgoing = process->outgoing;
    port_mmap = outgoing->elts;
    end_port_mmap = port_mmap + outgoing->nelts;

    while (port_mmap < end_port_mmap) {

        if ( (port_mmap->hdr->sent_over == 0xFFFFu ||
              port_mmap->hdr->sent_over == port->id) &&
            nxt_port_mmap_get_free_chunk(port_mmap->hdr, c)) {
            hdr = port_mmap->hdr;

            goto unlock_return;
        }

        port_mmap++;
    }

    /* TODO introduce port_mmap limit and release wait. */

    hdr = nxt_port_new_port_mmap(task, process, port);

unlock_return:

    nxt_thread_mutex_unlock(&process->outgoing_mutex);

    return hdr;
}


static nxt_port_mmap_header_t *
nxt_port_get_port_incoming_mmap(nxt_task_t *task, nxt_pid_t spid, uint32_t id)
{
    nxt_array_t             *incoming;
    nxt_process_t           *process;
    nxt_port_mmap_t         *port_mmap;
    nxt_port_mmap_header_t  *hdr;

    process = nxt_runtime_process_find(task->thread->runtime, spid);
    if (nxt_slow_path(process == NULL)) {
        return NULL;
    }

    hdr = NULL;

    nxt_thread_mutex_lock(&process->incoming_mutex);

    incoming = process->incoming;

    if (nxt_fast_path(incoming != NULL && incoming->nelts > id)) {
        port_mmap = incoming->elts;
        hdr = port_mmap[id].hdr;

    } else {
        nxt_log(task, NXT_LOG_WARN,
                "failed to get incoming mmap #%d for process %PI", id, spid);
    }

    nxt_thread_mutex_unlock(&process->incoming_mutex);

    return hdr;
}


nxt_buf_t *
nxt_port_mmap_get_buf(nxt_task_t *task, nxt_port_t *port, size_t size)
{
    size_t                  nchunks;
    nxt_buf_t               *b;
    nxt_chunk_id_t          c;
    nxt_port_mmap_header_t  *hdr;

    nxt_debug(task, "request %z bytes shm buffer", size);

    b = nxt_buf_mem_ts_alloc(task, task->thread->engine->mem_pool, 0);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->completion_handler = nxt_port_mmap_buf_completion;
    nxt_buf_set_port_mmap(b);

    hdr = nxt_port_mmap_get(task, port, &c, size);
    if (nxt_slow_path(hdr == NULL)) {
        nxt_mp_release(task->thread->engine->mem_pool, b);
        return NULL;
    }

    b->parent = hdr;

    b->mem.start = nxt_port_mmap_chunk_start(hdr, c);
    b->mem.pos = b->mem.start;
    b->mem.free = b->mem.start;
    b->mem.end = b->mem.start + PORT_MMAP_CHUNK_SIZE;

    nchunks = size / PORT_MMAP_CHUNK_SIZE;
    if ((size % PORT_MMAP_CHUNK_SIZE) != 0 || nchunks == 0) {
        nchunks++;
    }

    nxt_debug(task, "outgoing mmap buf allocation: %p [%p,%d] %PI,%d,%d", b,
              b->mem.start, b->mem.end - b->mem.start,
              hdr->pid, hdr->id, c);

    c++;
    nchunks--;

    /* Try to acquire as much chunks as required. */
    while (nchunks > 0) {

        if (nxt_port_mmap_chk_set_chunk_busy(hdr, c) == 0) {
            break;
        }

        b->mem.end += PORT_MMAP_CHUNK_SIZE;
        c++;
        nchunks--;
    }

    return b;
}


nxt_int_t
nxt_port_mmap_increase_buf(nxt_task_t *task, nxt_buf_t *b, size_t size,
    size_t min_size)
{
    size_t                  nchunks, free_size;
    nxt_chunk_id_t          c, start;
    nxt_port_mmap_header_t  *hdr;

    nxt_debug(task, "request increase %z bytes shm buffer", size);

    if (nxt_slow_path(nxt_buf_is_port_mmap(b) == 0)) {
        nxt_log(task, NXT_LOG_WARN,
                "failed to increase, not a mmap buffer");
        return NXT_ERROR;
    }

    free_size = nxt_buf_mem_free_size(&b->mem);

    if (nxt_slow_path(size <= free_size)) {
        return NXT_OK;
    }

    hdr = b->parent;

    start = nxt_port_mmap_chunk_id(hdr, b->mem.end);

    size -= free_size;

    nchunks = size / PORT_MMAP_CHUNK_SIZE;
    if ((size % PORT_MMAP_CHUNK_SIZE) != 0 || nchunks == 0) {
        nchunks++;
    }

    c = start;

    /* Try to acquire as much chunks as required. */
    while (nchunks > 0) {

        if (nxt_port_mmap_chk_set_chunk_busy(hdr, c) == 0) {
            break;
        }

        c++;
        nchunks--;
    }

    if (nchunks != 0
        && min_size > free_size + PORT_MMAP_CHUNK_SIZE * (c - start))
    {
        c--;
        while (c >= start) {
            nxt_port_mmap_set_chunk_free(hdr, c);
            c--;
        }

        nxt_debug(task, "failed to increase, %d chunks busy", nchunks);

        return NXT_ERROR;

    } else {
        b->mem.end += PORT_MMAP_CHUNK_SIZE * (c - start);

        return NXT_OK;
    }
}


static nxt_buf_t *
nxt_port_mmap_get_incoming_buf(nxt_task_t *task, nxt_port_t *port,
    nxt_pid_t spid, nxt_port_mmap_msg_t *mmap_msg)
{
    size_t                  nchunks;
    nxt_buf_t               *b;
    nxt_port_mmap_header_t  *hdr;

    hdr = nxt_port_get_port_incoming_mmap(task, spid, mmap_msg->mmap_id);
    if (nxt_slow_path(hdr == NULL)) {
        return NULL;
    }

    b = nxt_buf_mem_ts_alloc(task, port->mem_pool, 0);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->completion_handler = nxt_port_mmap_buf_completion;

    nxt_buf_set_port_mmap(b);

    nchunks = mmap_msg->size / PORT_MMAP_CHUNK_SIZE;
    if ((mmap_msg->size % PORT_MMAP_CHUNK_SIZE) != 0) {
        nchunks++;
    }

    b->mem.start = nxt_port_mmap_chunk_start(hdr, mmap_msg->chunk_id);
    b->mem.pos = b->mem.start;
    b->mem.free = b->mem.start + mmap_msg->size;
    b->mem.end = b->mem.start + nchunks * PORT_MMAP_CHUNK_SIZE;

    b->parent = hdr;

    nxt_debug(task, "incoming mmap buf allocation: %p [%p,%d] %PI,%d,%d",
              b, b->mem.start, b->mem.end - b->mem.start,
              hdr->pid, hdr->id, mmap_msg->chunk_id);

    return b;
}


void
nxt_port_mmap_write(nxt_task_t *task, nxt_port_t *port,
    nxt_port_send_msg_t *msg, nxt_sendbuf_coalesce_t *sb)
{
    size_t                  bsize;
    nxt_buf_t               *bmem;
    nxt_uint_t              i;
    nxt_port_mmap_msg_t     *mmap_msg;
    nxt_port_mmap_header_t  *hdr;

    nxt_debug(task, "prepare %z bytes message for transfer to process %PI "
                    "via shared memory", sb->size, port->pid);

    bsize = sb->niov * sizeof(nxt_port_mmap_msg_t);
    mmap_msg = port->mmsg_buf;

    bmem = msg->buf;

    for (i = 0; i < sb->niov; i++, mmap_msg++) {

        /* Lookup buffer which starts current iov_base. */
        while (bmem && sb->iobuf[i].iov_base != bmem->mem.pos) {
            bmem = bmem->next;
        }

        if (nxt_slow_path(bmem == NULL)) {
            nxt_log_error(NXT_LOG_ERR, task->log,
                          "failed to find buf for iobuf[%d]", i);
            return;
            /* TODO clear b and exit */
        }

        hdr = bmem->parent;

        mmap_msg->mmap_id = hdr->id;
        mmap_msg->chunk_id = nxt_port_mmap_chunk_id(hdr, bmem->mem.pos);
        mmap_msg->size = sb->iobuf[i].iov_len;

        nxt_debug(task, "mmap_msg={%D, %D, %D} to %PI",
                  mmap_msg->mmap_id, mmap_msg->chunk_id, mmap_msg->size,
                  port->pid);
    }

    sb->iobuf[0].iov_base = port->mmsg_buf;
    sb->iobuf[0].iov_len = bsize;
    sb->niov = 1;
    sb->size = bsize;

    msg->port_msg.mmap = 1;
}


void
nxt_port_mmap_read(nxt_task_t *task, nxt_port_t *port,
    nxt_port_recv_msg_t *msg)
{
    nxt_buf_t            *b, **pb;
    nxt_port_mmap_msg_t  *end, *mmap_msg;

    b = msg->buf;

    mmap_msg = (nxt_port_mmap_msg_t *) b->mem.pos;
    end = (nxt_port_mmap_msg_t *) b->mem.free;

    pb = &msg->buf;
    msg->size = 0;

    while (mmap_msg < end) {
        nxt_debug(task, "mmap_msg={%D, %D, %D} from %PI",
                  mmap_msg->mmap_id, mmap_msg->chunk_id, mmap_msg->size,
                  msg->port_msg.pid);

        *pb = nxt_port_mmap_get_incoming_buf(task, port, msg->port_msg.pid,
                                             mmap_msg);
        if (nxt_slow_path(*pb == NULL)) {
            nxt_log_error(NXT_LOG_ERR, task->log, "failed to get mmap buffer");

            break;
        }

        msg->size += mmap_msg->size;
        pb = &(*pb)->next;
        mmap_msg++;
    }

    /* Mark original buf as complete. */
    b->mem.pos += nxt_buf_used_size(b);
}


nxt_port_method_t
nxt_port_mmap_get_method(nxt_task_t *task, nxt_port_t *port, nxt_buf_t *b)
{
    nxt_port_method_t       m;
    nxt_port_mmap_header_t  *hdr;

    m = NXT_PORT_METHOD_ANY;

    for (; b != NULL; b = b->next) {
        if (nxt_buf_used_size(b) == 0) {
            /* empty buffers does not affect method */
            continue;
        }

        if (nxt_buf_is_port_mmap(b)) {
            hdr = b->parent;

            if (m == NXT_PORT_METHOD_PLAIN) {
                nxt_log_error(NXT_LOG_ERR, task->log,
                              "mixing plain and mmap buffers, "
                              "using plain mode");

                break;
            }

            if (port->pid != hdr->pid) {
                nxt_log_error(NXT_LOG_ERR, task->log,
                              "send mmap buffer for %PI to %PI, "
                              "using plain mode", hdr->pid, port->pid);

                m = NXT_PORT_METHOD_PLAIN;

                break;
            }

            if (m == NXT_PORT_METHOD_ANY) {
                nxt_debug(task, "using mmap mode");

                m = NXT_PORT_METHOD_MMAP;
            }
        } else {
            if (m == NXT_PORT_METHOD_MMAP) {
                nxt_log_error(NXT_LOG_ERR, task->log,
                              "mixing mmap and plain buffers, "
                              "switching to plain mode");

                m = NXT_PORT_METHOD_PLAIN;

                break;
            }

            if (m == NXT_PORT_METHOD_ANY) {
                nxt_debug(task, "using plain mode");

                m = NXT_PORT_METHOD_PLAIN;
            }
        }
    }

    return m;
}
