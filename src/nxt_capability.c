/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>

static nxt_int_t
nxt_capability_specific_set(nxt_task_t *task, nxt_capability_t *cap);

nxt_int_t
nxt_capability_set(nxt_task_t *task, nxt_capability_t *cap)
{
    uint8_t is_root = geteuid() == 0;

    nxt_assert(cap->setuid == 0);
    nxt_assert(cap->setgid == 0);

    if (is_root) {
        cap->setuid = 1;
        cap->setgid = 1;
        return NXT_OK;
    }

    return nxt_capability_specific_set(task, cap);
}

#ifdef NXT_LINUX

static __u32
nxt_capability_linux_get_version()
{
    struct __user_cap_header_struct hdr;

    hdr.version = _LINUX_CAPABILITY_VERSION; 
    hdr.pid     = nxt_pid;
    nxt_assert(nxt_capget(&hdr, NULL) == -1); /* einval returns version */
    nxt_assert(nxt_errno == EINVAL);

    return hdr.version;
}

static nxt_int_t
nxt_capability_specific_set(nxt_task_t *task, nxt_capability_t *cap)
{
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct   *val, data[2]; // 64-bits

    val = &data[0];

    /**
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

    if ((val->effective & (1 << CAP_SETUID)) != 0) {
        cap->setuid = 1;
    }

    if ((val->effective & (1 << CAP_SETGID)) != 0) {
        cap->setgid = 1;
    }
    
    return NXT_OK;
}

void
nxt_capability_insufficient(nxt_task_t *task)
{
    nxt_log(task, NXT_LOG_NOTICE, "It requires CAP_SETUID and CAP_SETGID. You can:");
    nxt_log(task, NXT_LOG_NOTICE, "\t- # setcap cap_setuid,cap_setgid=+ep"
                " %s", *nxt_process_argv); 
    nxt_log(task, NXT_LOG_NOTICE, "\t- or run  as root");
}

#elif NXT_SOLARIS

static nxt_int_t
nxt_capability_specific_set(nxt_task_t *task, nxt_capability_t *cap)
{
    priv_set_t *effective_privs;

    effective_privs = priv_allocset();
    if (effective_privs == NULL) {
        nxt_alert(task, "failed to allocate priv set: %E", nxt_errno);
        return NXT_ERROR;
    }

    PRIV_EMPTY(effective_privs);

    if (getppriv(PRIV_EFFECTIVE, effective_privs) == -1) {
        nxt_alert(task, "failed to get process privileges: %E", nxt_errno);
        priv_freeset(effective_privs);
        return NXT_ERROR;
    }

    cap->setuid = PRIV_ISASSERT(effective_privs, PRIV_PROC_SETID);
    cap->setgid = cap->setgid;

    priv_freeset(effective_privs);
	return NXT_OK;
}

void
nxt_capability_insufficient(nxt_task_t *task)
{
    nxt_log(task, NXT_LOG_NOTICE, "It requires the privilege PRIV_PROC_SETID."
            " You can create a new user with the priv:");
    nxt_log(task, NXT_LOG_NOTICE, "\t- # usermod -K defaultpriv=basic,proc_setid <user>");
    nxt_log(task, NXT_LOG_NOTICE, "\t- or run  as root");
}

#else

static nxt_int_t
nxt_capability_specific_set(nxt_task_t *task, nxt_capability_t *cap) {
    return NXT_OK;
}

void
nxt_capability_insufficient(nxt_task_t *task)
{
    const char *user = getenv("USER");

    nxt_log(task, NXT_LOG_NOTICE, "run as root or pass --user=%s",
            user ? user : "<invoking user>");
}

#endif