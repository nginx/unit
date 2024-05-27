/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>

#if (NXT_HAVE_LINUX_CAPABILITY)

#include <linux/capability.h>
#include <sys/syscall.h>


#if (_LINUX_CAPABILITY_VERSION_3)
#define NXT_CAPABILITY_VERSION  _LINUX_CAPABILITY_VERSION_3
#elif (_LINUX_CAPABILITY_VERSION_2)
#define NXT_CAPABILITY_VERSION  _LINUX_CAPABILITY_VERSION_2
#else
#define NXT_CAPABILITY_VERSION  _LINUX_CAPABILITY_VERSION
#endif


#define nxt_capget(hdrp, datap)                                               \
            syscall(SYS_capget, hdrp, datap)
#define nxt_capset(hdrp, datap)                                               \
            syscall(SYS_capset, hdrp, datap)

#endif /* NXT_HAVE_LINUX_CAPABILITY */


static nxt_int_t nxt_capability_specific_set(nxt_task_t *task,
    nxt_capabilities_t *cap);


nxt_int_t
nxt_capability_set(nxt_task_t *task, nxt_capabilities_t *cap)
{
    nxt_assert(cap->setid == 0);

    if (geteuid() == 0) {
        cap->setid = 1;
        cap->chroot = 1;
        return NXT_OK;
    }

    return nxt_capability_specific_set(task, cap);
}


#if (NXT_HAVE_LINUX_CAPABILITY)

static uint32_t
nxt_capability_linux_get_version(void)
{
    struct __user_cap_header_struct hdr;

    hdr.version = NXT_CAPABILITY_VERSION;
    hdr.pid     = nxt_pid;

    nxt_capget(&hdr, NULL);
    return hdr.version;
}


static nxt_int_t
nxt_capability_specific_set(nxt_task_t *task, nxt_capabilities_t *cap)
{
    struct __user_cap_data_struct    *val, data[2];
    struct __user_cap_header_struct  hdr;

    /*
     * Linux capability v1 fills an u32 struct.
     * Linux capability v2 and v3 fills an u64 struct.
     * We allocate data[2] for compatibility, we waste 4 bytes on v1.
     *
     * This is safe as we only need to check CAP_SETUID and CAP_SETGID
     * that resides in the first 32-bit chunk.
     */

    val = &data[0];

    /*
     * Ask the kernel the preferred capability version
     * instead of using _LINUX_CAPABILITY_VERSION from header.
     * This is safer when distributing a pre-compiled Unit binary.
     */
    hdr.version = nxt_capability_linux_get_version();
    hdr.pid = nxt_pid;

    if (nxt_slow_path(nxt_capget(&hdr, val) == -1)) {
        nxt_alert(task, "failed to get process capabilities: %E", nxt_errno);
        return NXT_ERROR;
    }

    if ((val->effective & (1 << CAP_SYS_CHROOT)) != 0) {
        cap->chroot = 1;
    }

    if ((val->effective & (1 << CAP_SETUID)) == 0) {
        return NXT_OK;
    }

    if ((val->effective & (1 << CAP_SETGID)) == 0) {
        return NXT_OK;
    }

    cap->setid = 1;
    return NXT_OK;
}

#else

static nxt_int_t
nxt_capability_specific_set(nxt_task_t *task, nxt_capabilities_t *cap)
{
    return NXT_OK;
}

#endif
