
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include "nxt_go_process.h"
#include "nxt_go_array.h"
#include "nxt_go_mutex.h"
#include "nxt_go_log.h"
#include "nxt_go_port_memory.h"

#include <nxt_port_memory_int.h>


static nxt_array_t processes; /* of nxt_go_process_t */

static nxt_go_process_t *
nxt_go_find_process(nxt_pid_t pid, uint32_t *pos)
{
    uint32_t          l, r, i;
    nxt_go_process_t  *process;

    if (nxt_slow_path(processes.size == 0)) {
        nxt_go_array_init(&processes, 1, sizeof(nxt_go_process_t));
    }

    l = 0;
    r = processes.nelts;
    i = (l + r) / 2;

    while (r > l) {
        process = nxt_go_array_at(&processes, i);

        nxt_go_debug("compare process #%d (%p) at %d",
                     (int) process->pid, process, (int) i);

        if (pid == process->pid) {
            nxt_go_debug("found process %d at %d", (int) pid, (int) i);

            if (pos != NULL) {
                *pos = i;
            }

            return process;
        }

        if (pid < process->pid) {
            r = i;

        } else {
            l = i + 1;
        }

        i = (l + r) / 2;
    }

    if (pos != NULL) {
        *pos = i;
    }

    nxt_go_debug("process %d not found, best pos %d", (int) pid, (int) i);

    return NULL;
}


nxt_go_process_t *
nxt_go_get_process(nxt_pid_t pid)
{
    uint32_t          pos;
    nxt_go_process_t  *process;

    process = nxt_go_find_process(pid, &pos);

    if (process == NULL) {
        nxt_go_array_add(&processes);
        process = nxt_go_array_at(&processes, pos);

        nxt_go_debug("init process #%d (%p) at %d",
                     (int) pid, process, (int) pos);

        if (pos < processes.nelts - 1) {
            memmove(process + 1, process,
                    processes.size * (processes.nelts - 1 - pos));
        }

        process->pid = pid;
        nxt_go_mutex_create(&process->incoming_mutex);
        nxt_go_array_init(&process->incoming, 1, sizeof(nxt_go_port_mmap_t));
        nxt_go_mutex_create(&process->outgoing_mutex);
        nxt_go_array_init(&process->outgoing, 1, sizeof(nxt_go_port_mmap_t));
    }

    return process;
}


void
nxt_go_new_incoming_mmap(nxt_pid_t pid, nxt_fd_t fd)
{
    void                *mem;
    struct stat         mmap_stat;
    nxt_go_process_t    *process;
    nxt_go_port_mmap_t  *port_mmap;

    process = nxt_go_get_process(pid);

    nxt_go_debug("got new mmap fd #%d from process %d",
                 (int) fd, (int) pid);

    if (fstat(fd, &mmap_stat) == -1) {
        nxt_go_warn("fstat(%d) failed %d", (int) fd, errno);

        return;
    }

    nxt_go_mutex_lock(&process->incoming_mutex);

    port_mmap = nxt_go_array_zero_add(&process->incoming);
    if (nxt_slow_path(port_mmap == NULL)) {
        nxt_go_warn("failed to add mmap to incoming array");

        goto fail;
    }

    mem = mmap(NULL, mmap_stat.st_size,
               PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    if (nxt_slow_path(mem == MAP_FAILED)) {
        nxt_go_warn("mmap() failed %d", errno);

        goto fail;
    }

    port_mmap->hdr = mem;

    if (nxt_slow_path(port_mmap->hdr->id != process->incoming.nelts - 1)) {
        nxt_go_warn("port mmap id mismatch (%d != %d)",
                    port_mmap->hdr->id, process->incoming.nelts - 1);
    }

    port_mmap->hdr->sent_over = 0xFFFFu;

fail:

    nxt_go_mutex_unlock(&process->incoming_mutex);
}
