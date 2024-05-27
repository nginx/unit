
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


static void nxt_port_broadcast_shm_ack(nxt_task_t *task, nxt_port_t *port,
    void *data);


nxt_inline void
nxt_port_mmap_handler_use(nxt_port_mmap_handler_t *mmap_handler, int i)
{
    int  c;

    c = nxt_atomic_fetch_add(&mmap_handler->use_count, i);

    if (i < 0 && c == -i) {
        if (mmap_handler->hdr != NULL) {
            nxt_mem_munmap(mmap_handler->hdr, PORT_MMAP_SIZE);
            mmap_handler->hdr = NULL;
        }

        if (mmap_handler->fd != -1) {
            nxt_fd_close(mmap_handler->fd);
        }

        nxt_free(mmap_handler);
    }
}


static nxt_port_mmap_t *
nxt_port_mmap_at(nxt_port_mmaps_t *port_mmaps, uint32_t i)
{
    uint32_t  cap;

    cap = port_mmaps->cap;

    if (cap == 0) {
        cap = i + 1;
    }

    while (i + 1 > cap) {

        if (cap < 16) {
            cap = cap * 2;

        } else {
            cap = cap + cap / 2;
        }
    }

    if (cap != port_mmaps->cap) {

        port_mmaps->elts = nxt_realloc(port_mmaps->elts,
                                       cap * sizeof(nxt_port_mmap_t));
        if (nxt_slow_path(port_mmaps->elts == NULL)) {
            return NULL;
        }

        nxt_memzero(port_mmaps->elts + port_mmaps->cap,
                    sizeof(nxt_port_mmap_t) * (cap - port_mmaps->cap));

        port_mmaps->cap = cap;
    }

    if (i + 1 > port_mmaps->size) {
        port_mmaps->size = i + 1;
    }

    return port_mmaps->elts + i;
}


void
nxt_port_mmaps_destroy(nxt_port_mmaps_t *port_mmaps, nxt_bool_t free_elts)
{
    uint32_t         i;
    nxt_port_mmap_t  *port_mmap;

    if (port_mmaps == NULL) {
        return;
    }

    port_mmap = port_mmaps->elts;

    for (i = 0; i < port_mmaps->size; i++) {
        nxt_port_mmap_handler_use(port_mmap[i].mmap_handler, -1);
    }

    port_mmaps->size = 0;

    if (free_elts != 0) {
        nxt_free(port_mmaps->elts);
    }
}


#define nxt_port_mmap_free_junk(p, size)                                      \
    memset((p), 0xA5, size)


static void
nxt_port_mmap_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    u_char                   *p;
    nxt_mp_t                 *mp;
    nxt_buf_t                *b, *next;
    nxt_process_t            *process;
    nxt_chunk_id_t           c;
    nxt_port_mmap_header_t   *hdr;
    nxt_port_mmap_handler_t  *mmap_handler;

    if (nxt_buf_ts_handle(task, obj, data)) {
        return;
    }

    b = obj;

    nxt_assert(data == b->parent);

    mmap_handler = data;

complete_buf:

    hdr = mmap_handler->hdr;

    if (nxt_slow_path(hdr->src_pid != nxt_pid && hdr->dst_pid != nxt_pid)) {
        nxt_debug(task, "mmap buf completion: mmap for other process pair "
                  "%PI->%PI", hdr->src_pid, hdr->dst_pid);

        goto release_buf;
    }

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

    nxt_debug(task, "mmap buf completion: %p [%p,%uz] (sent=%d), "
              "%PI->%PI,%d,%d", b, b->mem.start, b->mem.end - b->mem.start,
              b->is_port_mmap_sent, hdr->src_pid, hdr->dst_pid, hdr->id, c);

    while (p < b->mem.end) {
        nxt_port_mmap_set_chunk_free(hdr->free_map, c);

        p += PORT_MMAP_CHUNK_SIZE;
        c++;
    }

    if (hdr->dst_pid == nxt_pid
        && nxt_atomic_cmp_set(&hdr->oosm, 1, 0))
    {
        process = nxt_runtime_process_find(task->thread->runtime, hdr->src_pid);

        nxt_process_broadcast_shm_ack(task, process);
    }

release_buf:

    nxt_port_mmap_handler_use(mmap_handler, -1);

    next = b->next;
    mp = b->data;

    nxt_mp_free(mp, b);
    nxt_mp_release(mp);

    if (next != NULL) {
        b = next;
        mmap_handler = b->parent;

        goto complete_buf;
    }
}


nxt_port_mmap_handler_t *
nxt_port_incoming_port_mmap(nxt_task_t *task, nxt_process_t *process,
    nxt_fd_t fd)
{
    void                     *mem;
    struct stat              mmap_stat;
    nxt_port_mmap_t          *port_mmap;
    nxt_port_mmap_header_t   *hdr;
    nxt_port_mmap_handler_t  *mmap_handler;

    nxt_debug(task, "got new mmap fd #%FD from process %PI",
              fd, process->pid);

    port_mmap = NULL;

    if (fstat(fd, &mmap_stat) == -1) {
        nxt_log(task, NXT_LOG_WARN, "fstat(%FD) failed %E", fd, nxt_errno);

        return NULL;
    }

    mem = nxt_mem_mmap(NULL, mmap_stat.st_size,
                       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_log(task, NXT_LOG_WARN, "mmap() failed %E", nxt_errno);

        return NULL;
    }

    hdr = mem;

    if (nxt_slow_path(hdr->src_pid != process->pid
                      || hdr->dst_pid != nxt_pid))
    {
        nxt_log(task, NXT_LOG_WARN, "unexpected pid in mmap header detected: "
                "%PI != %PI or %PI != %PI", hdr->src_pid, process->pid,
                hdr->dst_pid, nxt_pid);

        nxt_mem_munmap(mem, PORT_MMAP_SIZE);

        return NULL;
    }

    mmap_handler = nxt_zalloc(sizeof(nxt_port_mmap_handler_t));
    if (nxt_slow_path(mmap_handler == NULL)) {
        nxt_log(task, NXT_LOG_WARN, "failed to allocate mmap_handler");

        nxt_mem_munmap(mem, PORT_MMAP_SIZE);

        return NULL;
    }

    mmap_handler->hdr = hdr;
    mmap_handler->fd = -1;

    nxt_thread_mutex_lock(&process->incoming.mutex);

    port_mmap = nxt_port_mmap_at(&process->incoming, hdr->id);
    if (nxt_slow_path(port_mmap == NULL)) {
        nxt_log(task, NXT_LOG_WARN, "failed to add mmap to incoming array");

        nxt_mem_munmap(mem, PORT_MMAP_SIZE);

        nxt_free(mmap_handler);
        mmap_handler = NULL;

        goto fail;
    }

    port_mmap->mmap_handler = mmap_handler;
    nxt_port_mmap_handler_use(mmap_handler, 1);

    hdr->sent_over = 0xFFFFu;

fail:

    nxt_thread_mutex_unlock(&process->incoming.mutex);

    return mmap_handler;
}


static nxt_port_mmap_handler_t *
nxt_port_new_port_mmap(nxt_task_t *task, nxt_port_mmaps_t *mmaps,
    nxt_bool_t tracking, nxt_int_t n)
{
    void                     *mem;
    nxt_fd_t                 fd;
    nxt_int_t                i;
    nxt_free_map_t           *free_map;
    nxt_port_mmap_t          *port_mmap;
    nxt_port_mmap_header_t   *hdr;
    nxt_port_mmap_handler_t  *mmap_handler;

    mmap_handler = nxt_zalloc(sizeof(nxt_port_mmap_handler_t));
    if (nxt_slow_path(mmap_handler == NULL)) {
        nxt_alert(task, "failed to allocate mmap_handler");

        return NULL;
    }

    port_mmap = nxt_port_mmap_at(mmaps, mmaps->size);
    if (nxt_slow_path(port_mmap == NULL)) {
        nxt_alert(task, "failed to add port mmap to mmaps array");

        nxt_free(mmap_handler);
        return NULL;
    }

    fd = nxt_shm_open(task, PORT_MMAP_SIZE);
    if (nxt_slow_path(fd == -1)) {
        goto remove_fail;
    }

    mem = nxt_mem_mmap(NULL, PORT_MMAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);

    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_fd_close(fd);
        goto remove_fail;
    }

    mmap_handler->hdr = mem;
    mmap_handler->fd = fd;
    port_mmap->mmap_handler = mmap_handler;
    nxt_port_mmap_handler_use(mmap_handler, 1);

    /* Init segment header. */
    hdr = mmap_handler->hdr;

    nxt_memset(hdr->free_map, 0xFFU, sizeof(hdr->free_map));
    nxt_memset(hdr->free_tracking_map, 0xFFU, sizeof(hdr->free_tracking_map));

    hdr->id = mmaps->size - 1;
    hdr->src_pid = nxt_pid;
    hdr->sent_over = 0xFFFFu;

    /* Mark first chunk as busy */
    free_map = tracking ? hdr->free_tracking_map : hdr->free_map;

    for (i = 0; i < n; i++) {
        nxt_port_mmap_set_chunk_busy(free_map, i);
    }

    /* Mark as busy chunk followed the last available chunk. */
    nxt_port_mmap_set_chunk_busy(hdr->free_map, PORT_MMAP_CHUNK_COUNT);
    nxt_port_mmap_set_chunk_busy(hdr->free_tracking_map, PORT_MMAP_CHUNK_COUNT);

    nxt_log(task, NXT_LOG_DEBUG, "new mmap #%D created for %PI -> ...",
            hdr->id, nxt_pid);

    return mmap_handler;

remove_fail:

    nxt_free(mmap_handler);

    mmaps->size--;

    return NULL;
}


nxt_int_t
nxt_shm_open(nxt_task_t *task, size_t size)
{
    nxt_fd_t  fd;

#if (NXT_HAVE_MEMFD_CREATE || NXT_HAVE_SHM_OPEN)

    u_char    *p, name[64];

    p = nxt_sprintf(name, name + sizeof(name), NXT_SHM_PREFIX "unit.%PI.%uxD",
                    nxt_pid, nxt_random(&task->thread->random));
    *p = '\0';

#endif

#if (NXT_HAVE_MEMFD_CREATE)

    fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC);

    if (nxt_slow_path(fd == -1)) {
        nxt_alert(task, "memfd_create(%s) failed %E", name, nxt_errno);

        return -1;
    }

    nxt_debug(task, "memfd_create(%s): %FD", name, fd);

#elif (NXT_HAVE_SHM_OPEN_ANON)

    fd = shm_open(SHM_ANON, O_RDWR, S_IRUSR | S_IWUSR);

    if (nxt_slow_path(fd == -1)) {
        nxt_alert(task, "shm_open(SHM_ANON) failed %E", nxt_errno);

        return -1;
    }

    nxt_debug(task, "shm_open(SHM_ANON): %FD", fd);

#elif (NXT_HAVE_SHM_OPEN)

    /* Just in case. */
    shm_unlink((char *) name);

    fd = shm_open((char *) name, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);

    if (nxt_slow_path(fd == -1)) {
        nxt_alert(task, "shm_open(%s) failed %E", name, nxt_errno);

        return -1;
    }

    nxt_debug(task, "shm_open(%s): %FD", name, fd);

    if (nxt_slow_path(shm_unlink((char *) name) == -1)) {
        nxt_log(task, NXT_LOG_WARN, "shm_unlink(%s) failed %E", name,
                nxt_errno);
    }

#else

#error No working shared memory implementation.

#endif

    if (nxt_slow_path(ftruncate(fd, size) == -1)) {
        nxt_alert(task, "ftruncate() failed %E", nxt_errno);

        nxt_fd_close(fd);

        return -1;
    }

    return fd;
}


static nxt_port_mmap_handler_t *
nxt_port_mmap_get(nxt_task_t *task, nxt_port_mmaps_t *mmaps, nxt_chunk_id_t *c,
    nxt_int_t n, nxt_bool_t tracking)
{
    nxt_int_t                i, res, nchunks;
    nxt_free_map_t           *free_map;
    nxt_port_mmap_t          *port_mmap;
    nxt_port_mmap_t          *end_port_mmap;
    nxt_port_mmap_header_t   *hdr;
    nxt_port_mmap_handler_t  *mmap_handler;

    nxt_thread_mutex_lock(&mmaps->mutex);

    if (nxt_slow_path(mmaps->elts == NULL)) {
        goto end;
    }

    end_port_mmap = mmaps->elts + mmaps->size;

    for (port_mmap = mmaps->elts;
         port_mmap < end_port_mmap;
         port_mmap++)
    {
        mmap_handler = port_mmap->mmap_handler;
        hdr = mmap_handler->hdr;

        if (hdr->sent_over != 0xFFFFu) {
            continue;
        }

        *c = 0;

        free_map = tracking ? hdr->free_tracking_map : hdr->free_map;

        while (nxt_port_mmap_get_free_chunk(free_map, c)) {
            nchunks = 1;

            while (nchunks < n) {
                res = nxt_port_mmap_chk_set_chunk_busy(free_map, *c + nchunks);

                if (res == 0) {
                    for (i = 0; i < nchunks; i++) {
                        nxt_port_mmap_set_chunk_free(free_map, *c + i);
                    }

                    *c += nchunks + 1;
                    nchunks = 0;
                    break;
                }

                nchunks++;
            }

            if (nchunks == n) {
                goto unlock_return;
            }
        }

        hdr->oosm = 1;
    }

    /* TODO introduce port_mmap limit and release wait. */

end:

    *c = 0;
    mmap_handler = nxt_port_new_port_mmap(task, mmaps, tracking, n);

unlock_return:

    nxt_thread_mutex_unlock(&mmaps->mutex);

    return mmap_handler;
}


static nxt_port_mmap_handler_t *
nxt_port_get_port_incoming_mmap(nxt_task_t *task, nxt_pid_t spid, uint32_t id)
{
    nxt_process_t            *process;
    nxt_port_mmap_handler_t  *mmap_handler;

    process = nxt_runtime_process_find(task->thread->runtime, spid);
    if (nxt_slow_path(process == NULL)) {
        return NULL;
    }

    nxt_thread_mutex_lock(&process->incoming.mutex);

    if (nxt_fast_path(process->incoming.size > id)) {
        mmap_handler = process->incoming.elts[id].mmap_handler;

    } else {
        mmap_handler = NULL;

        nxt_debug(task, "invalid incoming mmap id %uD for pid %PI", id, spid);
    }

    nxt_thread_mutex_unlock(&process->incoming.mutex);

    return mmap_handler;
}


nxt_buf_t *
nxt_port_mmap_get_buf(nxt_task_t *task, nxt_port_mmaps_t *mmaps, size_t size)
{
    nxt_mp_t                 *mp;
    nxt_buf_t                *b;
    nxt_int_t                nchunks;
    nxt_chunk_id_t           c;
    nxt_port_mmap_header_t   *hdr;
    nxt_port_mmap_handler_t  *mmap_handler;

    nxt_debug(task, "request %z bytes shm buffer", size);

    nchunks = (size + PORT_MMAP_CHUNK_SIZE - 1) / PORT_MMAP_CHUNK_SIZE;

    if (nxt_slow_path(nchunks > PORT_MMAP_CHUNK_COUNT)) {
        nxt_alert(task, "requested buffer (%z) too big", size);

        return NULL;
    }

    b = nxt_buf_mem_ts_alloc(task, task->thread->engine->mem_pool, 0);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->completion_handler = nxt_port_mmap_buf_completion;
    nxt_buf_set_port_mmap(b);

    mmap_handler = nxt_port_mmap_get(task, mmaps, &c, nchunks, 0);
    if (nxt_slow_path(mmap_handler == NULL)) {
        mp = task->thread->engine->mem_pool;
        nxt_mp_free(mp, b);
        nxt_mp_release(mp);
        return NULL;
    }

    b->parent = mmap_handler;

    nxt_port_mmap_handler_use(mmap_handler, 1);

    hdr = mmap_handler->hdr;

    b->mem.start = nxt_port_mmap_chunk_start(hdr, c);
    b->mem.pos = b->mem.start;
    b->mem.free = b->mem.start;
    b->mem.end = b->mem.start + nchunks * PORT_MMAP_CHUNK_SIZE;

    nxt_debug(task, "outgoing mmap buf allocation: %p [%p,%uz] %PI->%PI,%d,%d",
              b, b->mem.start, b->mem.end - b->mem.start,
              hdr->src_pid, hdr->dst_pid, hdr->id, c);

    return b;
}


nxt_int_t
nxt_port_mmap_increase_buf(nxt_task_t *task, nxt_buf_t *b, size_t size,
    size_t min_size)
{
    size_t                   nchunks, free_size;
    nxt_chunk_id_t           c, start;
    nxt_port_mmap_header_t   *hdr;
    nxt_port_mmap_handler_t  *mmap_handler;

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

    mmap_handler = b->parent;
    hdr = mmap_handler->hdr;

    start = nxt_port_mmap_chunk_id(hdr, b->mem.end);

    size -= free_size;

    nchunks = (size + PORT_MMAP_CHUNK_SIZE - 1) / PORT_MMAP_CHUNK_SIZE;

    c = start;

    /* Try to acquire as much chunks as required. */
    while (nchunks > 0) {

        if (nxt_port_mmap_chk_set_chunk_busy(hdr->free_map, c) == 0) {
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
            nxt_port_mmap_set_chunk_free(hdr->free_map, c);
            c--;
        }

        nxt_debug(task, "failed to increase, %uz chunks busy", nchunks);

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
    size_t                   nchunks;
    nxt_buf_t                *b;
    nxt_port_mmap_header_t   *hdr;
    nxt_port_mmap_handler_t  *mmap_handler;

    mmap_handler = nxt_port_get_port_incoming_mmap(task, spid,
                                                   mmap_msg->mmap_id);
    if (nxt_slow_path(mmap_handler == NULL)) {
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

    hdr = mmap_handler->hdr;

    b->mem.start = nxt_port_mmap_chunk_start(hdr, mmap_msg->chunk_id);
    b->mem.pos = b->mem.start;
    b->mem.free = b->mem.start + mmap_msg->size;
    b->mem.end = b->mem.start + nchunks * PORT_MMAP_CHUNK_SIZE;

    b->parent = mmap_handler;
    nxt_port_mmap_handler_use(mmap_handler, 1);

    nxt_debug(task, "incoming mmap buf allocation: %p [%p,%uz] %PI->%PI,%d,%d",
              b, b->mem.start, b->mem.end - b->mem.start,
              hdr->src_pid, hdr->dst_pid, hdr->id, mmap_msg->chunk_id);

    return b;
}


void
nxt_port_mmap_write(nxt_task_t *task, nxt_port_t *port,
    nxt_port_send_msg_t *msg, nxt_sendbuf_coalesce_t *sb, void *mmsg_buf)
{
    size_t                   bsize;
    nxt_buf_t                *bmem;
    nxt_uint_t               i;
    nxt_port_mmap_msg_t      *mmap_msg;
    nxt_port_mmap_header_t   *hdr;
    nxt_port_mmap_handler_t  *mmap_handler;

    nxt_debug(task, "prepare %z bytes message for transfer to process %PI "
                    "via shared memory", sb->size, port->pid);

    bsize = sb->niov * sizeof(nxt_port_mmap_msg_t);
    mmap_msg = mmsg_buf;

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

        mmap_handler = bmem->parent;
        hdr = mmap_handler->hdr;

        mmap_msg->mmap_id = hdr->id;
        mmap_msg->chunk_id = nxt_port_mmap_chunk_id(hdr, bmem->mem.pos);
        mmap_msg->size = sb->iobuf[i].iov_len;

        nxt_debug(task, "mmap_msg={%D, %D, %D} to %PI",
                  mmap_msg->mmap_id, mmap_msg->chunk_id, mmap_msg->size,
                  port->pid);
    }

    sb->iobuf[0].iov_base = mmsg_buf;
    sb->iobuf[0].iov_len = bsize;
    sb->niov = 1;
    sb->size = bsize;

    msg->port_msg.mmap = 1;
}


void
nxt_port_mmap_read(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    nxt_buf_t            *b, **pb;
    nxt_port_mmap_msg_t  *end, *mmap_msg;

    pb = &msg->buf;
    msg->size = 0;

    for (b = msg->buf; b != NULL; b = b->next) {

        mmap_msg = (nxt_port_mmap_msg_t *) b->mem.pos;
        end = (nxt_port_mmap_msg_t *) b->mem.free;

        while (mmap_msg < end) {
            nxt_debug(task, "mmap_msg={%D, %D, %D} from %PI",
                      mmap_msg->mmap_id, mmap_msg->chunk_id, mmap_msg->size,
                      msg->port_msg.pid);

            *pb = nxt_port_mmap_get_incoming_buf(task, msg->port,
                                                 msg->port_msg.pid, mmap_msg);
            if (nxt_slow_path(*pb == NULL)) {
                nxt_log_error(NXT_LOG_ERR, task->log,
                              "failed to get mmap buffer");

                break;
            }

            msg->size += mmap_msg->size;
            pb = &(*pb)->next;
            mmap_msg++;

            /* Mark original buf as complete. */
            b->mem.pos += sizeof(nxt_port_mmap_msg_t);
        }
    }
}


nxt_port_method_t
nxt_port_mmap_get_method(nxt_task_t *task, nxt_port_t *port, nxt_buf_t *b)
{
    nxt_port_method_t  m;

    m = NXT_PORT_METHOD_ANY;

    for (/* void */; b != NULL; b = b->next) {
        if (nxt_buf_used_size(b) == 0) {
            /* empty buffers does not affect method */
            continue;
        }

        if (nxt_buf_is_port_mmap(b)) {
            if (m == NXT_PORT_METHOD_PLAIN) {
                nxt_log_error(NXT_LOG_ERR, task->log,
                              "mixing plain and mmap buffers, "
                              "using plain mode");

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


void
nxt_process_broadcast_shm_ack(nxt_task_t *task, nxt_process_t *process)
{
    nxt_port_t  *port;

    if (nxt_slow_path(process == NULL || nxt_queue_is_empty(&process->ports)))
    {
        return;
    }

    port = nxt_process_port_first(process);

    if (port->type == NXT_PROCESS_APP) {
        nxt_port_post(task, port, nxt_port_broadcast_shm_ack, process);
    }
}


static void
nxt_port_broadcast_shm_ack(nxt_task_t *task, nxt_port_t *port, void *data)
{
    nxt_process_t  *process;

    process = data;

    nxt_queue_each(port, &process->ports, nxt_port_t, link) {
        (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_SHM_ACK,
                                     -1, 0, 0, NULL);
    } nxt_queue_loop;
}
