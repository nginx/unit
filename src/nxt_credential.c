/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static nxt_int_t nxt_credential_groups_get(nxt_task_t *task, nxt_mp_t *mp,
    nxt_credential_t *uc);


nxt_int_t
nxt_credential_get(nxt_task_t *task, nxt_mp_t *mp, nxt_credential_t *uc,
    const char *group)
{
    struct group   *grp;
    struct passwd  *pwd;

    nxt_errno = 0;

    pwd = getpwnam(uc->user);

    if (nxt_slow_path(pwd == NULL)) {

        if (nxt_errno == 0) {
            nxt_alert(task, "getpwnam(\"%s\") failed, user \"%s\" not found",
                      uc->user, uc->user);
        } else {
            nxt_alert(task, "getpwnam(\"%s\") failed %E", uc->user, nxt_errno);
        }

        return NXT_ERROR;
    }

    uc->uid = pwd->pw_uid;
    uc->base_gid = pwd->pw_gid;

    if (group != NULL && group[0] != '\0') {
        nxt_errno = 0;

        grp = getgrnam(group);

        if (nxt_slow_path(grp == NULL)) {

            if (nxt_errno == 0) {
                nxt_alert(task,
                          "getgrnam(\"%s\") failed, group \"%s\" not found",
                          group, group);
            } else {
                nxt_alert(task, "getgrnam(\"%s\") failed %E", group, nxt_errno);
            }

            return NXT_ERROR;
        }

        uc->base_gid = grp->gr_gid;
    }

    nxt_debug(task, "about to get \"%s\" groups (uid:%d, base gid:%d)",
              uc->user, uc->uid, uc->base_gid);

    if (nxt_credential_groups_get(task, mp, uc) != NXT_OK) {
        return NXT_ERROR;
    }

#if (NXT_DEBUG)
    {
        u_char      *p, *end;
        nxt_uint_t  i;
        u_char      msg[NXT_MAX_ERROR_STR];

        p = msg;
        end = msg + NXT_MAX_ERROR_STR;

        for (i = 0; i < uc->ngroups; i++) {
            p = nxt_sprintf(p, end, "%d,", uc->gids[i]);
        }

        if (uc->ngroups > 0) {
            p--;
        }

        nxt_debug(task, "user \"%s\" has gids:%*s", uc->user, p - msg, msg);
    }
#endif

    return NXT_OK;
}


#if (NXT_HAVE_GETGROUPLIST && !NXT_MACOSX)

#define NXT_NGROUPS nxt_min(256, NGROUPS_MAX)


static nxt_int_t
nxt_credential_groups_get(nxt_task_t *task, nxt_mp_t *mp,
    nxt_credential_t *uc)
{
    int    ngroups;
    gid_t  groups[NXT_NGROUPS];

    ngroups = NXT_NGROUPS;

    if (getgrouplist(uc->user, uc->base_gid, groups, &ngroups) < 0) {
        if (nxt_slow_path(ngroups <= NXT_NGROUPS)) {
            nxt_alert(task, "getgrouplist(\"%s\", %d, ...) failed %E", uc->user,
                      uc->base_gid, nxt_errno);

            return NXT_ERROR;
        }
    }

    if (ngroups > NXT_NGROUPS) {
        if (ngroups > NGROUPS_MAX) {
            ngroups = NGROUPS_MAX;
        }

        uc->ngroups = ngroups;

        uc->gids = nxt_mp_alloc(mp, ngroups * sizeof(gid_t));
        if (nxt_slow_path(uc->gids == NULL)) {
            return NXT_ERROR;
        }

        if (nxt_slow_path(getgrouplist(uc->user, uc->base_gid, uc->gids,
                                       &ngroups) < 0)) {

            nxt_alert(task, "getgrouplist(\"%s\", %d) failed %E", uc->user,
                      uc->base_gid, nxt_errno);

            return NXT_ERROR;
        }

        return NXT_OK;
    }

    uc->ngroups = ngroups;

    uc->gids = nxt_mp_alloc(mp, ngroups * sizeof(gid_t));
    if (nxt_slow_path(uc->gids == NULL)) {
        return NXT_ERROR;
    }

    nxt_memcpy(uc->gids, groups, ngroups * sizeof(gid_t));

    return NXT_OK;
}


#else

/*
 * For operating systems that lack getgrouplist(3) or it's buggy (MacOS),
 * nxt_credential_groups_get() stores an array of groups IDs which should be
 * set by the setgroups() function for a given user.  The initgroups()
 * may block a just forked worker process for some time if LDAP or NDIS+
 * is used, so nxt_credential_groups_get() allows to get worker user groups in
 * main process.  In a nutshell the initgroups() calls getgrouplist()
 * followed by setgroups().  However older Solaris lacks the getgrouplist().
 * Besides getgrouplist() does not allow to query the exact number of
 * groups in some platforms, while NGROUPS_MAX can be quite large (e.g.
 * 65536 on Linux).
 * So nxt_credential_groups_get() emulates getgrouplist(): at first the
 * function saves the super-user groups IDs, then calls initgroups() and saves
 * the specified user groups IDs, and then restores the super-user groups IDs.
 * This works at least on Linux, FreeBSD, and Solaris, but does not work
 * on MacOSX, getgroups(2):
 *
 *   To provide compatibility with applications that use getgroups() in
 *   environments where users may be in more than {NGROUPS_MAX} groups,
 *   a variant of getgroups(), obtained when compiling with either the
 *   macros _DARWIN_UNLIMITED_GETGROUPS or _DARWIN_C_SOURCE defined, can
 *   be used that is not limited to {NGROUPS_MAX} groups.  However, this
 *   variant only returns the user's default group access list and not
 *   the group list modified by a call to setgroups(2).
 *
 * For such cases initgroups() is used in worker process as fallback.
 */

static nxt_int_t
nxt_credential_groups_get(nxt_task_t *task, nxt_mp_t *mp, nxt_credential_t *uc)
{
    int        nsaved, ngroups;
    nxt_int_t  ret;
    nxt_gid_t  *saved;

    nsaved = getgroups(0, NULL);

    if (nxt_slow_path(nsaved == -1)) {
        nxt_alert(task, "getgroups(0, NULL) failed %E", nxt_errno);
        return NXT_ERROR;
    }

    nxt_debug(task, "getgroups(0, NULL): %d", nsaved);

    if (nsaved > NGROUPS_MAX) {
        /* MacOSX case. */

        uc->gids = NULL;
        uc->ngroups = 0;

        return NXT_OK;
    }

    saved = nxt_mp_alloc(mp, nsaved * sizeof(nxt_gid_t));

    if (nxt_slow_path(saved == NULL)) {
        return NXT_ERROR;
    }

    ret = NXT_ERROR;

    nsaved = getgroups(nsaved, saved);

    if (nxt_slow_path(nsaved == -1)) {
        nxt_alert(task, "getgroups(%d) failed %E", nsaved, nxt_errno);
        goto free;
    }

    nxt_debug(task, "getgroups(): %d", nsaved);

    if (initgroups(uc->user, uc->base_gid) != 0) {
        if (nxt_errno == NXT_EPERM) {
            nxt_log(task, NXT_LOG_NOTICE,
                    "initgroups(%s, %d) failed %E, ignored",
                    uc->user, uc->base_gid, nxt_errno);

            ret = NXT_OK;

            goto free;

        } else {
            nxt_alert(task, "initgroups(%s, %d) failed %E",
                      uc->user, uc->base_gid, nxt_errno);
            goto restore;
        }
    }

    ngroups = getgroups(0, NULL);

    if (nxt_slow_path(ngroups == -1)) {
        nxt_alert(task, "getgroups(0, NULL) failed %E", nxt_errno);
        goto restore;
    }

    nxt_debug(task, "getgroups(0, NULL): %d", ngroups);

    uc->gids = nxt_mp_alloc(mp, ngroups * sizeof(nxt_gid_t));

    if (nxt_slow_path(uc->gids == NULL)) {
        goto restore;
    }

    ngroups = getgroups(ngroups, uc->gids);

    if (nxt_slow_path(ngroups == -1)) {
        nxt_alert(task, "getgroups(%d) failed %E", ngroups, nxt_errno);
        goto restore;
    }

    uc->ngroups = ngroups;

    ret = NXT_OK;

restore:

    if (nxt_slow_path(setgroups(nsaved, saved) != 0)) {
        nxt_alert(task, "setgroups(%d) failed %E", nsaved, nxt_errno);
        ret = NXT_ERROR;
    }

free:

    nxt_mp_free(mp, saved);

    return ret;
}


#endif


nxt_int_t
nxt_credential_setuid(nxt_task_t *task, nxt_credential_t *uc)
{
    nxt_debug(task, "user cred set: \"%s\" uid:%d", uc->user, uc->uid);

    if (setuid(uc->uid) != 0) {

#if (NXT_HAVE_LINUX_NS)
        if (nxt_errno == EINVAL) {
            nxt_log(task, NXT_LOG_ERR, "The uid %d (user \"%s\") isn't "
                    "valid in the application namespace.", uc->uid, uc->user);
            return NXT_ERROR;
        }
#endif

        nxt_alert(task, "setuid(%d) failed %E", uc->uid, nxt_errno);
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_int_t
nxt_credential_setgids(nxt_task_t *task, nxt_credential_t *uc)
{
    nxt_runtime_t  *rt;

    nxt_debug(task, "user cred set gids: base gid:%d, ngroups: %d",
              uc->base_gid, uc->ngroups);

    rt = task->thread->runtime;

    if (setgid(uc->base_gid) != 0) {

#if (NXT_HAVE_LINUX_NS)
        if (nxt_errno == EINVAL) {
            nxt_log(task, NXT_LOG_ERR, "The gid %d isn't valid in the "
                    "application namespace.", uc->base_gid);
            return NXT_ERROR;
        }
#endif

        nxt_alert(task, "setgid(%d) failed %E", uc->base_gid, nxt_errno);
        return NXT_ERROR;
    }

    if (!rt->capabilities.setid) {
        return NXT_OK;
    }

    if (nxt_slow_path(uc->ngroups > 0
                      && setgroups(uc->ngroups, uc->gids) != 0)) {

#if (NXT_HAVE_LINUX_NS)
        if (nxt_errno == EINVAL) {
            nxt_log(task, NXT_LOG_ERR, "The user \"%s\" (uid: %d) has "
                    "supplementary group ids not valid in the application "
                    "namespace.", uc->user, uc->uid);
            return NXT_ERROR;
        }
#endif

        nxt_alert(task, "setgroups(%i) failed %E", uc->ngroups, nxt_errno);
        return NXT_ERROR;
    }

    return NXT_OK;
}
