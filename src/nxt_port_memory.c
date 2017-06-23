
#include <nxt_main.h>

#if (NXT_HAVE_MEMFD_CREATE)

#include <linux/memfd.h>
#include <unistd.h>
#include <sys/syscall.h>

#endif

#define PORT_MMAP_CHUNK_SIZE    (1024 * 16)
#define PORT_MMAP_HEADER_SIZE   (1024 * 4)
#define PORT_MMAP_SIZE          (PORT_MMAP_HEADER_SIZE + 1024 * 1024 * 10)

#define PORT_MMAP_CHUNK_COUNT                                                 \
    ( (PORT_MMAP_SIZE - PORT_MMAP_HEADER_SIZE) / PORT_MMAP_CHUNK_SIZE )


typedef uint32_t  nxt_chunk_id_t;

typedef nxt_atomic_uint_t  nxt_free_map_t;

#define FREE_BITS (sizeof(nxt_free_map_t) * 8)

#define FREE_IDX(nchunk) ((nchunk) / FREE_BITS)

#define FREE_MASK(nchunk)                                                     \
    ( 1ULL << ( (nchunk) % FREE_BITS ) )

#define MAX_FREE_IDX FREE_IDX(PORT_MMAP_CHUNK_COUNT)


/* Mapped at the start of shared memory segment. */
struct nxt_port_mmap_header_s {
    nxt_free_map_t  free_map[MAX_FREE_IDX];
};


/*
 * Element of nxt_process_t.incoming/outgoing, shared memory segment
 * descriptor.
 */
struct nxt_port_mmap_s {
    uint32_t                    id;
    nxt_fd_t                    fd;
    nxt_pid_t                   pid; /* For sanity check. */
    union {
        void                    *mem;
        nxt_port_mmap_header_t  *hdr;
    } u;
};


/* Passed as a second iov chunk when 'mmap' bit in nxt_port_msg_t is 1. */
typedef struct {
    uint32_t            mmap_id;    /* Mmap index in nxt_process_t.outgoing. */
    nxt_chunk_id_t      chunk_id;   /* Mmap chunk index. */
    uint32_t            size;       /* Payload data size. */
} nxt_port_mmap_msg_t;


static nxt_bool_t
nxt_port_mmap_get_free_chunk(nxt_port_mmap_t *port_mmap, nxt_chunk_id_t *c);

#define nxt_port_mmap_get_chunk_busy(hdr, c)                                  \
    ((hdr->free_map[FREE_IDX(c)] & FREE_MASK(c)) == 0)

nxt_inline void
nxt_port_mmap_set_chunk_busy(nxt_port_mmap_header_t *hdr, nxt_chunk_id_t c);

nxt_inline void
nxt_port_mmap_set_chunk_free(nxt_port_mmap_header_t *hdr, nxt_chunk_id_t c);

#define nxt_port_mmap_chunk_id(port_mmap, b)                                  \
    ((((u_char *) (b) - (u_char *) (port_mmap->u.mem)) -                      \
        PORT_MMAP_HEADER_SIZE) / PORT_MMAP_CHUNK_SIZE)

#define nxt_port_mmap_chunk_start(port_mmap, chunk)                           \
    (((u_char *) (port_mmap->u.mem)) + PORT_MMAP_HEADER_SIZE +                \
        (chunk) * PORT_MMAP_CHUNK_SIZE)


void
nxt_port_mmap_destroy(nxt_port_mmap_t *port_mmap)
{
    if (port_mmap->u.mem != NULL) {
        nxt_mem_munmap(port_mmap->u.mem, PORT_MMAP_SIZE);
        port_mmap->u.mem = NULL;
    }

    if (port_mmap->fd != -1) {
        close(port_mmap->fd);
        port_mmap->fd = -1;
    }
}


static void
nxt_port_mmap_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    u_char                  *p;
    nxt_mp_t                *mp;
    nxt_buf_t               *b;
    nxt_chunk_id_t          c;
    nxt_port_mmap_t         *port_mmap;
    nxt_port_mmap_header_t  *hdr;

    b = obj;

    nxt_debug(task, "mmap buf completion: %p %p", b, b->mem.start);

    mp = b->data;

    port_mmap = (nxt_port_mmap_t *) b->parent;
    hdr = port_mmap->u.hdr;

    if (b->is_port_mmap_sent && b->mem.pos > b->mem.start) {
        /*
         * Chunks until b->mem.pos has been sent to other side,
         * let's release rest (if any).
         */
        p = b->mem.pos - 1;
        c = nxt_port_mmap_chunk_id(port_mmap, p) + 1;
        p = nxt_port_mmap_chunk_start(port_mmap, c);
    } else {
        p = b->mem.start;
        c = nxt_port_mmap_chunk_id(port_mmap, p);
    }

    while (p < b->mem.end) {
        nxt_port_mmap_set_chunk_free(hdr, c);

        p += PORT_MMAP_CHUNK_SIZE;
        c++;
    }

    nxt_buf_free(mp, b);
}


static nxt_bool_t
nxt_port_mmap_get_free_chunk(nxt_port_mmap_t *port_mmap, nxt_chunk_id_t *c)
{
    int             ffs;
    size_t          i;
    nxt_free_map_t  bits;
    nxt_free_map_t  *free_map;

    free_map = port_mmap->u.hdr->free_map;

    for (i = 0; i < MAX_FREE_IDX; i++) {
        bits = free_map[i];
        if (bits == 0) {
            continue;
        }

        ffs = __builtin_ffsll(bits);
        if (ffs != 0) {
            *c = i * FREE_BITS + ffs - 1;
            return 1;
        }
    }

    return 0;
}


nxt_inline void
nxt_port_mmap_set_chunk_busy(nxt_port_mmap_header_t *hdr, nxt_chunk_id_t c)
{
    nxt_atomic_and_fetch(hdr->free_map + FREE_IDX(c), ~FREE_MASK(c));

    nxt_thread_log_debug("set_chunk_busy: hdr %p; b %D", hdr, c);
}


nxt_inline void
nxt_port_mmap_set_chunk_free(nxt_port_mmap_header_t *hdr, nxt_chunk_id_t c)
{
    nxt_atomic_or_fetch(hdr->free_map + FREE_IDX(c), FREE_MASK(c));

    nxt_thread_log_debug("set_chunk_free: hdr %p; b %D", hdr, c);
}


nxt_port_mmap_t *
nxt_port_incoming_port_mmap(nxt_task_t *task, nxt_process_t *process,
    nxt_fd_t fd)
{
    struct stat      mmap_stat;
    nxt_port_mmap_t  *port_mmap;

    nxt_debug(task, "got new mmap fd #%FD from process %PI",
              fd, process->pid);

    if (fstat(fd, &mmap_stat) == -1) {
        nxt_log(task, NXT_LOG_WARN, "fstat(%FD) failed %E", fd, nxt_errno);

        return NULL;
    }

    if (process->incoming == NULL) {
        process->incoming = nxt_array_create(process->mem_pool, 1,
            sizeof(nxt_port_mmap_t));
    }

    if (nxt_slow_path(process->incoming == NULL)) {
        nxt_log(task, NXT_LOG_WARN, "failed to allocate incoming array");

        return NULL;
    }

    port_mmap = nxt_array_zero_add(process->incoming);
    if (nxt_slow_path(port_mmap == NULL)) {
        nxt_log(task, NXT_LOG_WARN, "failed to add mmap to incoming array");

        return NULL;
    }

    port_mmap->id = process->incoming->nelts - 1;
    port_mmap->fd = -1;
    port_mmap->pid = process->pid;
    port_mmap->u.mem = nxt_mem_mmap(NULL, mmap_stat.st_size,
                                    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (nxt_slow_path(port_mmap->u.mem == MAP_FAILED)) {
        nxt_log(task, NXT_LOG_WARN, "mmap() failed %E", nxt_errno);

        port_mmap->u.mem = NULL;

        return NULL;
    }

    return port_mmap;
}


static void
nxt_port_mmap_send_fd_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_buf_t        *b;
    nxt_port_t       *port;
    nxt_port_mmap_t  *port_mmap;

    b = obj;
    port = b->data;
    port_mmap = (nxt_port_mmap_t *) b->parent;

    nxt_debug(task, "mmap fd %FD sent to %PI", port_mmap->fd, port->pid);

    close(port_mmap->fd);
    port_mmap->fd = -1;

    nxt_buf_free(port->mem_pool, b);
}


static nxt_port_mmap_t *
nxt_port_new_port_mmap(nxt_task_t *task, nxt_process_t *process,
    nxt_port_t *port)
{
    u_char                  *p, name[64];
    nxt_buf_t               *b;
    nxt_port_mmap_t         *port_mmap;
    nxt_port_mmap_header_t  *hdr;

    if (process->outgoing == NULL) {
        process->outgoing = nxt_array_create(process->mem_pool, 1,
                                             sizeof(nxt_port_mmap_t));
    }

    if (nxt_slow_path(process->outgoing == NULL)) {
        nxt_log(task, NXT_LOG_WARN, "failed to allocate outgoing array");

        return NULL;
    }

    port_mmap = nxt_array_zero_add(process->outgoing);
    if (nxt_slow_path(port_mmap == NULL)) {
        nxt_log(task, NXT_LOG_WARN,
                "failed to add port mmap to outgoing array");

        return NULL;
    }

    port_mmap->id = process->outgoing->nelts - 1;
    port_mmap->pid = process->pid;

    p = nxt_sprintf(name, name + sizeof(name), "/nginext.%PI.%uxD",
                    nxt_pid, nxt_random(&nxt_random_data));
    *p = '\0';

#if (NXT_HAVE_MEMFD_CREATE)
    port_mmap->fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC);

    if (nxt_slow_path(port_mmap->fd == -1)) {
        nxt_log(task, NXT_LOG_CRIT, "memfd_create(%s) failed %E",
                name, nxt_errno);

        goto remove_fail;
    }

    nxt_debug(task, "memfd_create(%s): %FD", name, port_mmap->fd);

#elif (NXT_HAVE_SHM_OPEN)
    shm_unlink((char *) name); // just in case

    port_mmap->fd = shm_open((char *) name, O_CREAT | O_EXCL | O_RDWR,
                             S_IRUSR | S_IWUSR);

    nxt_debug(task, "shm_open(%s): %FD", name, port_mmap->fd);

    if (nxt_slow_path(port_mmap->fd == -1)) {
        nxt_log(task, NXT_LOG_CRIT, "shm_open(%s) failed %E", name, nxt_errno);

        goto remove_fail;
    }

    if (nxt_slow_path(shm_unlink((char *) name) == -1)) {
        nxt_log(task, NXT_LOG_WARN, "shm_unlink(%s) failed %E", name,
                nxt_errno);
    }
#endif

    if (nxt_slow_path(ftruncate(port_mmap->fd, PORT_MMAP_SIZE) == -1)) {
        nxt_log(task, NXT_LOG_WARN, "ftruncate() failed %E", nxt_errno);

        goto remove_fail;
    }

    port_mmap->u.mem = nxt_mem_mmap(NULL, PORT_MMAP_SIZE,
                                    PROT_READ | PROT_WRITE, MAP_SHARED,
                                    port_mmap->fd, 0);

    if (nxt_slow_path(port_mmap->u.mem == MAP_FAILED)) {
        goto remove_fail;
    }

    /* Init segment header. */
    hdr = port_mmap->u.hdr;

    nxt_memset(hdr->free_map, 0xFFU, sizeof(hdr->free_map));

    /* Mark as busy chunk followed the last available chunk. */
    nxt_port_mmap_set_chunk_busy(hdr, PORT_MMAP_CHUNK_COUNT);

    nxt_debug(task, "send mmap fd %FD to process %PI", port_mmap->fd,
              port->pid);

    b = nxt_buf_mem_alloc(port->mem_pool, 0, 0);
    b->completion_handler = nxt_port_mmap_send_fd_buf_completion;
    b->data = port;
    b->parent = port_mmap;

    /* TODO handle error */
    (void) nxt_port_socket_write(task, port, NXT_PORT_MSG_MMAP, port_mmap->fd,
                                 0, 0, b);

    nxt_log(task, NXT_LOG_DEBUG, "new mmap #%D created for %PI -> %PI",
            port_mmap->id, nxt_pid, process->pid);

    return port_mmap;

remove_fail:

    nxt_array_remove(process->outgoing, port_mmap);

    return NULL;
}


static nxt_port_mmap_t *
nxt_port_mmap_get(nxt_task_t *task, nxt_port_t *port, nxt_chunk_id_t *c,
    size_t size)
{
    nxt_array_t      *outgoing;
    nxt_process_t    *process;
    nxt_port_mmap_t  *port_mmap;
    nxt_port_mmap_t  *end_port_mmap;

    process = nxt_runtime_process_get(task->thread->runtime, port->pid);
    if (nxt_slow_path(process == NULL)) {
        return NULL;
    }

    *c = 0;

    if (process->outgoing == NULL) {
        return nxt_port_new_port_mmap(task, process, port);
    }

    outgoing = process->outgoing;
    port_mmap = outgoing->elts;
    end_port_mmap = port_mmap + outgoing->nelts;

    while (port_mmap < end_port_mmap) {

        if (nxt_port_mmap_get_free_chunk(port_mmap, c)) {
            return port_mmap;
        }

        port_mmap++;
    }

    /* TODO introduce port_mmap limit and release wait. */
    return nxt_port_new_port_mmap(task, process, port);
}


static nxt_port_mmap_t *
nxt_port_get_port_incoming_mmap(nxt_task_t *task, nxt_pid_t spid, uint32_t id)
{
    nxt_array_t      *incoming;
    nxt_process_t    *process;
    nxt_port_mmap_t  *port_mmap;

    process = nxt_runtime_process_get(task->thread->runtime, spid);
    if (nxt_slow_path(process == NULL)) {
        return NULL;
    }

    incoming = process->incoming;
    if (nxt_slow_path(incoming == NULL)) {
        /* TODO add warning */
        return NULL;
    }

    if (nxt_slow_path(incoming->nelts <= id)) {
        /* TODO add warning */
        return NULL;
    }

    port_mmap = incoming->elts;

    return port_mmap + id;
}


nxt_buf_t *
nxt_port_mmap_get_buf(nxt_task_t *task, nxt_port_t *port, size_t size)
{
    size_t                  nchunks;
    nxt_buf_t               *b;
    nxt_chunk_id_t          c;
    nxt_port_mmap_t         *port_mmap;
    nxt_port_mmap_header_t  *hdr;

    nxt_debug(task, "request %z bytes shm buffer", size);

    b = nxt_mp_zalloc(port->mem_pool, NXT_BUF_PORT_MMAP_SIZE);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->data = port->mem_pool;
    b->completion_handler = nxt_port_mmap_buf_completion;
    b->size = NXT_BUF_PORT_MMAP_SIZE;

    nxt_buf_set_port_mmap(b);

    port_mmap = nxt_port_mmap_get(task, port, &c, size);
    if (nxt_slow_path(port_mmap == NULL)) {
        nxt_buf_free(port->mem_pool, b);
        return NULL;
    }

    hdr = port_mmap->u.hdr;

    b->parent = port_mmap;
    b->mem.start = nxt_port_mmap_chunk_start(port_mmap, c);
    b->mem.pos = b->mem.start;
    b->mem.free = b->mem.start;
    b->mem.end = b->mem.start + PORT_MMAP_CHUNK_SIZE;

    nxt_port_mmap_set_chunk_busy(hdr, c);

    nchunks = size / PORT_MMAP_CHUNK_SIZE;
    if ((size % PORT_MMAP_CHUNK_SIZE) != 0 || nchunks == 0) {
        nchunks++;
    }

    c++;
    nchunks--;

    /* Try to acquire as much chunks as required. */
    while (nchunks > 0) {

        if (nxt_port_mmap_get_chunk_busy(hdr, c)) {
            break;
        }
        nxt_port_mmap_set_chunk_busy(hdr, c);

        b->mem.end += PORT_MMAP_CHUNK_SIZE;
        c++;
        nchunks--;
    }

    return b;
}


static nxt_buf_t *
nxt_port_mmap_get_incoming_buf(nxt_task_t *task, nxt_port_t *port,
    nxt_pid_t spid, nxt_port_mmap_msg_t *mmap_msg)
{
    size_t                  nchunks;
    nxt_buf_t               *b;
    nxt_port_mmap_t         *port_mmap;

    b = nxt_mp_zalloc(port->mem_pool, NXT_BUF_PORT_MMAP_SIZE);
    if (nxt_slow_path(b == NULL)) {
        return NULL;
    }

    b->data = port->mem_pool;
    b->completion_handler = nxt_port_mmap_buf_completion;
    b->size = NXT_BUF_PORT_MMAP_SIZE;

    nxt_buf_set_port_mmap(b);

    port_mmap = nxt_port_get_port_incoming_mmap(task, spid, mmap_msg->mmap_id);
    if (nxt_slow_path(port_mmap == NULL)) {
        nxt_buf_free(port->mem_pool, b);
        return NULL;
    }

    nchunks = mmap_msg->size / PORT_MMAP_CHUNK_SIZE;
    if ((mmap_msg->size % PORT_MMAP_CHUNK_SIZE) != 0) {
        nchunks++;
    }

    b->mem.start = nxt_port_mmap_chunk_start(port_mmap, mmap_msg->chunk_id);
    b->mem.pos = b->mem.start;
    b->mem.free = b->mem.start + mmap_msg->size;
    b->mem.end = b->mem.start + nchunks * PORT_MMAP_CHUNK_SIZE;

    b->parent = port_mmap;

    return b;
}


void
nxt_port_mmap_write(nxt_task_t *task, nxt_port_t *port,
    nxt_port_send_msg_t *msg, nxt_sendbuf_coalesce_t *sb)
{
    size_t               bsize;
    nxt_buf_t            *b, *bmem;
    nxt_uint_t           i;
    nxt_port_mmap_t      *port_mmap;
    nxt_port_mmap_msg_t  *mmap_msg;

    nxt_debug(task, "prepare %z bytes message for transfer to process %PI "
              "via shared memory", sb->size, port->pid);

    bsize = sb->niov * sizeof(nxt_port_mmap_msg_t);

    b = nxt_buf_mem_alloc(port->mem_pool, bsize, 0);
    if (nxt_slow_path(b == NULL)) {
        return;
    }

    mmap_msg = (nxt_port_mmap_msg_t *) b->mem.start;
    bmem = msg->buf;

    for (i = 0; i < sb->niov; i++, mmap_msg++) {

        /* Lookup buffer which starts current iov_base. */
        while (bmem && sb->iobuf[i].iov_base != bmem->mem.pos) {
            bmem = bmem->next;
        }

        if (nxt_slow_path(bmem == NULL)) {
            nxt_log_error(NXT_LOG_ERR, task->log, "failed to find buf for "
                          "iobuf[%d]", i);
            return;
            /* TODO clear b and exit */
        }

        port_mmap = (nxt_port_mmap_t *) bmem->parent;

        mmap_msg->mmap_id = port_mmap->id;
        mmap_msg->chunk_id = nxt_port_mmap_chunk_id(port_mmap, bmem->mem.pos);
        mmap_msg->size = sb->iobuf[i].iov_len;

        nxt_debug(task, "mmap_msg={%D, %D, %D} to %PI",
                  mmap_msg->mmap_id, mmap_msg->chunk_id, mmap_msg->size,
                  port->pid);
    }

    msg->buf = b;
    b->mem.free += bsize;

    sb->iobuf[0].iov_base = b->mem.pos;
    sb->iobuf[0].iov_len = bsize;
    sb->niov = 1;
    sb->size = bsize;

    msg->port_msg.mmap = 1;
}


void
nxt_port_mmap_read(nxt_task_t *task, nxt_port_t *port,
    nxt_port_recv_msg_t *msg, size_t size)
{
    nxt_buf_t            *b, **pb;
    nxt_port_mmap_msg_t  *end, *mmap_msg;

    b = msg->buf;

    mmap_msg = (nxt_port_mmap_msg_t *) b->mem.pos;
    end = (nxt_port_mmap_msg_t *) b->mem.free;

    pb = &msg->buf;

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

        pb = &(*pb)->next;
        mmap_msg++;
    }

    /* Mark original buf as complete. */
    b->mem.pos += nxt_buf_used_size(b);
}


nxt_port_method_t
nxt_port_mmap_get_method(nxt_task_t *task, nxt_port_t *port, nxt_buf_t *b)
{
    nxt_port_mmap_t    *port_mmap;
    nxt_port_method_t  m;

    m = NXT_PORT_METHOD_ANY;

    for (; b != NULL; b = b->next) {
        if (nxt_buf_used_size(b) == 0) {
            /* empty buffers does not affect method */
            continue;
        }

        if (nxt_buf_is_port_mmap(b)) {
            port_mmap = (nxt_port_mmap_t *) b->parent;

            if (m == NXT_PORT_METHOD_PLAIN) {
                nxt_log_error(NXT_LOG_ERR, task->log,
                              "mixing plain and mmap buffers, "
                              "using plain mode");

                break;
            }

            if (port->pid != port_mmap->pid) {
                nxt_log_error(NXT_LOG_ERR, task->log,
                              "send mmap buffer for %PI to %PI, "
                              "using plain mode", port_mmap->pid, port->pid);

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
