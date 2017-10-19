
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef NXT_CONFIGURE


#include "nxt_go_port_memory.h"
#include "nxt_go_process.h"
#include "nxt_go_array.h"
#include "nxt_go_log.h"

#include <nxt_go_gen.h>
#include <nxt_main.h>

#if (NXT_HAVE_MEMFD_CREATE)

#include <linux/memfd.h>
#include <unistd.h>
#include <sys/syscall.h>

#endif


static nxt_port_mmap_header_t *
nxt_go_new_port_mmap(nxt_go_process_t *process, nxt_port_id_t id)
{
    int                     name_len, rc;
    void                    *mem;
    char                    name[64];
    nxt_fd_t                fd;
    nxt_port_msg_t          port_msg;
    nxt_go_port_mmap_t      *port_mmap;
    nxt_port_mmap_header_t  *hdr;

    fd = -1;

    union {
        struct cmsghdr  cm;
        char            space[CMSG_SPACE(sizeof(int))];
    } cmsg;

    port_mmap = nxt_go_array_zero_add(&process->outgoing);
    if (nxt_slow_path(port_mmap == NULL)) {
        nxt_go_warn("failed to add port mmap to outgoing array");

        return NULL;
    }

    name_len = snprintf(name, sizeof(name) - 1, "/unit.go.%p", name);

#if (NXT_HAVE_MEMFD_CREATE)

    fd = syscall(SYS_memfd_create, name, MFD_CLOEXEC);

    if (nxt_slow_path(fd == -1)) {
        nxt_go_warn("memfd_create(%s) failed %d", name, errno);

        goto remove_fail;
    }

    nxt_go_debug("memfd_create(%s): %d", name, fd);

#elif (NXT_HAVE_SHM_OPEN)

    /* Just in case. */
    shm_unlink((char *) name);

    fd = shm_open((char *) name, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR);

    nxt_go_debug("shm_open(%s): %d", name, fd);

    if (nxt_slow_path(fd == -1)) {
        nxt_go_warn("shm_open(%s) failed %d", name, errno);

        goto remove_fail;
    }

    if (nxt_slow_path(shm_unlink((char *) name) == -1)) {
        nxt_go_warn("shm_unlink(%s) failed %d", name, errno);
    }

#endif

    if (nxt_slow_path(ftruncate(fd, PORT_MMAP_SIZE) == -1)) {
        nxt_go_warn("ftruncate() failed %d", errno);

        goto remove_fail;
    }

    mem = mmap(NULL, PORT_MMAP_SIZE,
               PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (nxt_slow_path(mem == MAP_FAILED)) {
        goto remove_fail;
    }

    port_mmap->hdr = mem;

    /* Init segment header. */
    hdr = port_mmap->hdr;

    memset(hdr->free_map, 0xFFU, sizeof(hdr->free_map));

    hdr->id = process->outgoing.nelts - 1;
    hdr->src_pid = getpid();
    hdr->dst_pid = process->pid;
    hdr->sent_over = id;

    /* Mark first chunk as busy */
    nxt_port_mmap_set_chunk_busy(hdr, 0);

    /* Mark as busy chunk followed the last available chunk. */
    nxt_port_mmap_set_chunk_busy(hdr, PORT_MMAP_CHUNK_COUNT);

    port_msg.stream = 0;
    port_msg.pid = getpid();
    port_msg.reply_port = 0;
    port_msg.type = _NXT_PORT_MSG_MMAP;
    port_msg.last = 1;
    port_msg.mmap = 0;

    cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
    cmsg.cm.cmsg_level = SOL_SOCKET;
    cmsg.cm.cmsg_type = SCM_RIGHTS;

    /*
     * nxt_memcpy() is used instead of simple
     *   *(int *) CMSG_DATA(&cmsg.cm) = fd;
     * because GCC 4.4 with -O2/3/s optimization may issue a warning:
     *   dereferencing type-punned pointer will break strict-aliasing rules
     *
     * Fortunately, GCC with -O1 compiles this nxt_memcpy()
     * in the same simple assignment as in the code above.
     */
    memcpy(CMSG_DATA(&cmsg.cm), &fd, sizeof(int));

    rc = nxt_go_port_send(hdr->dst_pid, id, &port_msg, sizeof(port_msg),
                          &cmsg, sizeof(cmsg));

    nxt_go_debug("new mmap #%d created for %d -> %d",
            (int) hdr->id, (int) getpid(), (int) process->pid);

    close(fd);

    return hdr;

remove_fail:

    if (fd != -1) {
        close(fd);
    }

    process->outgoing.nelts--;

    return NULL;
}

nxt_port_mmap_header_t *
nxt_go_port_mmap_get(nxt_go_process_t *process, nxt_port_id_t port_id,
    nxt_chunk_id_t *c)
{
    nxt_go_port_mmap_t      *port_mmap;
    nxt_go_port_mmap_t      *end_port_mmap;
    nxt_port_mmap_header_t  *hdr;

    port_mmap = NULL;
    hdr = NULL;

    nxt_go_mutex_lock(&process->outgoing_mutex);

    port_mmap = process->outgoing.elts;
    end_port_mmap = port_mmap + process->outgoing.nelts;

    while (port_mmap < end_port_mmap) {

        if ( (port_mmap->hdr->sent_over == 0xFFFFu ||
              port_mmap->hdr->sent_over == port_id) &&
            nxt_port_mmap_get_free_chunk(port_mmap->hdr, c)) {
            hdr = port_mmap->hdr;

            goto unlock_return;
        }

        port_mmap++;
    }

    hdr = nxt_go_new_port_mmap(process, port_id);

unlock_return:

    nxt_go_mutex_unlock(&process->outgoing_mutex);

    return hdr;
}


#endif /* NXT_CONFIGURE */
