/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_application.h>
#include <nxt_process.h>
#include <nxt_isolation.h>
#include <nxt_cgroup.h>

#if (NXT_HAVE_MNTENT_H)
#include <mntent.h>
#endif


static nxt_int_t nxt_isolation_set(nxt_task_t *task,
    nxt_conf_value_t *isolation, nxt_process_t *process);

#if (NXT_HAVE_CGROUP)
static nxt_int_t nxt_isolation_set_cgroup(nxt_task_t *task,
    nxt_conf_value_t *isolation, nxt_process_t *process);
#endif

#if (NXT_HAVE_LINUX_NS)
static nxt_int_t nxt_isolation_set_namespaces(nxt_task_t *task,
    nxt_conf_value_t *isolation, nxt_process_t *process);
static nxt_int_t nxt_isolation_clone_flags(nxt_task_t *task,
    nxt_conf_value_t *namespaces, nxt_clone_t *clone);
#endif

#if (NXT_HAVE_CLONE_NEWUSER)
static nxt_int_t nxt_isolation_set_creds(nxt_task_t *task,
    nxt_conf_value_t *isolation, nxt_process_t *process);
static nxt_int_t nxt_isolation_credential_map(nxt_task_t *task,
    nxt_mp_t *mem_pool, nxt_conf_value_t *map_array,
    nxt_clone_credential_map_t *map);
static nxt_int_t nxt_isolation_vldt_creds(nxt_task_t *task,
    nxt_process_t *process);
#endif

#if (NXT_HAVE_ISOLATION_ROOTFS)
static nxt_int_t nxt_isolation_set_rootfs(nxt_task_t *task,
    nxt_conf_value_t *isolation, nxt_process_t *process);
static nxt_int_t nxt_isolation_set_automount(nxt_task_t *task,
    nxt_conf_value_t *isolation, nxt_process_t *process);
static nxt_int_t nxt_isolation_set_mounts(nxt_task_t *task,
    nxt_process_t *process, nxt_str_t *app_type);
static nxt_int_t nxt_isolation_set_lang_mounts(nxt_task_t *task,
    nxt_process_t *process, nxt_array_t *syspaths);
static int nxt_cdecl nxt_isolation_mount_compare(const void *v1,
    const void *v2);
static void nxt_isolation_unmount_all(nxt_task_t *task, nxt_process_t *process);

#if (NXT_HAVE_LINUX_PIVOT_ROOT) && (NXT_HAVE_CLONE_NEWNS)
static nxt_int_t nxt_isolation_pivot_root(nxt_task_t *task, const char *rootfs);
static nxt_int_t nxt_isolation_make_private_mount(nxt_task_t *task,
    const char *rootfs);
nxt_inline int nxt_pivot_root(const char *new_root, const char *old_root);
#endif

static nxt_int_t nxt_isolation_chroot(nxt_task_t *task, const char *path);
#endif

#if (NXT_HAVE_PR_SET_NO_NEW_PRIVS)
static nxt_int_t nxt_isolation_set_new_privs(nxt_task_t *task,
    nxt_conf_value_t *isolation, nxt_process_t *process);
#endif


nxt_int_t
nxt_isolation_main_prefork(nxt_task_t *task, nxt_process_t *process,
    nxt_mp_t *mp)
{
    nxt_int_t              cap_setid;
    nxt_int_t              ret;
    nxt_runtime_t          *rt;
    nxt_common_app_conf_t  *app_conf;

    rt = task->thread->runtime;
    app_conf = process->data.app;
    cap_setid = rt->capabilities.setid;

#if (NXT_HAVE_PR_SET_NO_NEW_PRIVS)
    process->isolation.new_privs = 1;
#endif

    if (app_conf->isolation != NULL) {
        ret = nxt_isolation_set(task, app_conf->isolation, process);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }
    }

#if (NXT_HAVE_CLONE_NEWUSER)
    if (nxt_is_clone_flag_set(process->isolation.clone.flags, NEWUSER)) {
        cap_setid = 1;
    }
#endif

    if (cap_setid) {
        ret = nxt_process_creds_set(task, process, &app_conf->user,
                                    &app_conf->group);

        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

    } else {
        if (!nxt_str_eq(&app_conf->user, (u_char *) rt->user_cred.user,
                        nxt_strlen(rt->user_cred.user)))
        {
            nxt_alert(task, "cannot set user \"%V\" for app \"%V\": "
                      "missing capabilities", &app_conf->user, &app_conf->name);

            return NXT_ERROR;
        }

        if (app_conf->group.length > 0
            && !nxt_str_eq(&app_conf->group, (u_char *) rt->group,
                           nxt_strlen(rt->group)))
        {
            nxt_alert(task, "cannot set group \"%V\" for app \"%V\": "
                            "missing capabilities", &app_conf->group,
                            &app_conf->name);

            return NXT_ERROR;
        }
    }

#if (NXT_HAVE_ISOLATION_ROOTFS)
    if (process->isolation.rootfs != NULL) {
        nxt_int_t  has_mnt;

        ret = nxt_isolation_set_mounts(task, process, &app_conf->type);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

#if (NXT_HAVE_CLONE_NEWNS)
        has_mnt = nxt_is_clone_flag_set(process->isolation.clone.flags, NEWNS);
#else
        has_mnt = 0;
#endif

        if (process->user_cred->uid == 0 && !has_mnt) {
            nxt_log(task, NXT_LOG_WARN,
                    "setting user \"root\" with \"rootfs\" is unsafe without "
                    "\"mount\" namespace isolation");
        }
    }
#endif

#if (NXT_HAVE_CLONE_NEWUSER)
    ret = nxt_isolation_vldt_creds(task, process);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }
#endif

    return NXT_OK;
}


static nxt_int_t
nxt_isolation_set(nxt_task_t *task, nxt_conf_value_t *isolation,
    nxt_process_t *process)
{
#if (NXT_HAVE_CGROUP)
    if (nxt_slow_path(nxt_isolation_set_cgroup(task, isolation, process)
                      != NXT_OK))
    {
        return NXT_ERROR;
    }
#endif

#if (NXT_HAVE_LINUX_NS)
    if (nxt_slow_path(nxt_isolation_set_namespaces(task, isolation, process)
                      != NXT_OK))
    {
        return NXT_ERROR;
    }
#endif

#if (NXT_HAVE_CLONE_NEWUSER)
    if (nxt_slow_path(nxt_isolation_set_creds(task, isolation, process)
                      != NXT_OK))
    {
        return NXT_ERROR;
    }
#endif

#if (NXT_HAVE_ISOLATION_ROOTFS)
    if (nxt_slow_path(nxt_isolation_set_rootfs(task, isolation, process)
                      != NXT_OK))
    {
        return NXT_ERROR;
    }

    if (nxt_slow_path(nxt_isolation_set_automount(task, isolation, process)
                      != NXT_OK))
    {
        return NXT_ERROR;
    }
#endif

#if (NXT_HAVE_PR_SET_NO_NEW_PRIVS)
    if (nxt_slow_path(nxt_isolation_set_new_privs(task, isolation, process)
                      != NXT_OK))
    {
        return NXT_ERROR;
    }
#endif

    return NXT_OK;
}


#if (NXT_HAVE_CGROUP)

static nxt_int_t
nxt_isolation_set_cgroup(nxt_task_t *task, nxt_conf_value_t *isolation,
    nxt_process_t *process)
{
    nxt_str_t         str;
    nxt_conf_value_t  *obj;

    static const nxt_str_t  cgname = nxt_string("cgroup");
    static const nxt_str_t  path = nxt_string("path");

    obj = nxt_conf_get_object_member(isolation, &cgname, NULL);
    if (obj == NULL) {
        return NXT_OK;
    }

    obj = nxt_conf_get_object_member(obj, &path, NULL);
    if (obj == NULL) {
        return NXT_ERROR;
    }

    nxt_conf_get_string(obj, &str);
    process->isolation.cgroup.path = nxt_mp_alloc(process->mem_pool,
                                                  str.length + 1);
    nxt_memcpy(process->isolation.cgroup.path, str.start, str.length);
    process->isolation.cgroup.path[str.length] = '\0';

    process->isolation.cgroup_cleanup = nxt_cgroup_cleanup;

    return NXT_OK;
}

#endif


#if (NXT_HAVE_LINUX_NS)

static nxt_int_t
nxt_isolation_set_namespaces(nxt_task_t *task, nxt_conf_value_t *isolation,
    nxt_process_t *process)
{
    nxt_int_t         ret;
    nxt_conf_value_t  *obj;

    static const nxt_str_t  nsname = nxt_string("namespaces");

    obj = nxt_conf_get_object_member(isolation, &nsname, NULL);
    if (obj != NULL) {
        ret = nxt_isolation_clone_flags(task, obj, &process->isolation.clone);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}

#endif


#if (NXT_HAVE_CLONE_NEWUSER)

static nxt_int_t
nxt_isolation_set_creds(nxt_task_t *task, nxt_conf_value_t *isolation,
    nxt_process_t *process)
{
    nxt_int_t         ret;
    nxt_clone_t       *clone;
    nxt_conf_value_t  *array;

    static const nxt_str_t uidname = nxt_string("uidmap");
    static const nxt_str_t gidname = nxt_string("gidmap");

    clone = &process->isolation.clone;

    array = nxt_conf_get_object_member(isolation, &uidname, NULL);
    if (array != NULL) {
        ret = nxt_isolation_credential_map(task, process->mem_pool, array,
                                           &clone->uidmap);

        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    array = nxt_conf_get_object_member(isolation, &gidname, NULL);
    if (array != NULL) {
        ret = nxt_isolation_credential_map(task, process->mem_pool, array,
                                           &clone->gidmap);

        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_isolation_credential_map(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *map_array, nxt_clone_credential_map_t *map)
{
    nxt_int_t         ret;
    nxt_uint_t        i;
    nxt_conf_value_t  *obj;

    static const nxt_conf_map_t  nxt_clone_map_entry_conf[] = {
        {
            nxt_string("container"),
            NXT_CONF_MAP_INT64,
            offsetof(nxt_clone_map_entry_t, container),
        },

        {
            nxt_string("host"),
            NXT_CONF_MAP_INT64,
            offsetof(nxt_clone_map_entry_t, host),
        },

        {
            nxt_string("size"),
            NXT_CONF_MAP_INT64,
            offsetof(nxt_clone_map_entry_t, size),
        },
    };

    map->size = nxt_conf_array_elements_count(map_array);

    if (map->size == 0) {
        return NXT_OK;
    }

    map->map = nxt_mp_alloc(mp, map->size * sizeof(nxt_clone_map_entry_t));
    if (nxt_slow_path(map->map == NULL)) {
        return NXT_ERROR;
    }

    for (i = 0; i < map->size; i++) {
        obj = nxt_conf_get_array_element(map_array, i);

        ret = nxt_conf_map_object(mp, obj, nxt_clone_map_entry_conf,
                                  nxt_nitems(nxt_clone_map_entry_conf),
                                  map->map + i);
        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_alert(task, "clone map entry map error");
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_isolation_vldt_creds(nxt_task_t *task, nxt_process_t *process)
{
    nxt_int_t         ret;
    nxt_clone_t       *clone;
    nxt_credential_t  *creds;

    clone = &process->isolation.clone;
    creds = process->user_cred;

    if (clone->uidmap.size == 0 && clone->gidmap.size == 0) {
        return NXT_OK;
    }

    if (!nxt_is_clone_flag_set(clone->flags, NEWUSER)) {
        if (nxt_slow_path(clone->uidmap.size > 0)) {
            nxt_log(task, NXT_LOG_ERR, "\"uidmap\" is set but "
                    "\"isolation.namespaces.credential\" is false or unset");

            return NXT_ERROR;
        }

        if (nxt_slow_path(clone->gidmap.size > 0)) {
            nxt_log(task, NXT_LOG_ERR, "\"gidmap\" is set but "
                    "\"isolation.namespaces.credential\" is false or unset");

            return NXT_ERROR;
        }

        return NXT_OK;
    }

    ret = nxt_clone_vldt_credential_uidmap(task, &clone->uidmap, creds);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    return nxt_clone_vldt_credential_gidmap(task, &clone->gidmap, creds);
}

#endif


#if (NXT_HAVE_LINUX_NS)

static nxt_int_t
nxt_isolation_clone_flags(nxt_task_t *task, nxt_conf_value_t *namespaces,
    nxt_clone_t *clone)
{
    uint32_t          index;
    nxt_str_t         name;
    nxt_int_t         flag;
    nxt_conf_value_t  *value;

    index = 0;

    for ( ;; ) {
        value = nxt_conf_next_object_member(namespaces, &name, &index);

        if (value == NULL) {
            break;
        }

        flag = 0;

#if (NXT_HAVE_CLONE_NEWUSER)
        if (nxt_str_eq(&name, "credential", 10)) {
            flag = CLONE_NEWUSER;
        }
#endif

#if (NXT_HAVE_CLONE_NEWPID)
        if (nxt_str_eq(&name, "pid", 3)) {
            flag = CLONE_NEWPID;
        }
#endif

#if (NXT_HAVE_CLONE_NEWNET)
        if (nxt_str_eq(&name, "network", 7)) {
            flag = CLONE_NEWNET;
        }
#endif

#if (NXT_HAVE_CLONE_NEWUTS)
        if (nxt_str_eq(&name, "uname", 5)) {
            flag = CLONE_NEWUTS;
        }
#endif

#if (NXT_HAVE_CLONE_NEWNS)
        if (nxt_str_eq(&name, "mount", 5)) {
            flag = CLONE_NEWNS;
        }
#endif

#if (NXT_HAVE_CLONE_NEWCGROUP)
        if (nxt_str_eq(&name, "cgroup", 6)) {
            flag = CLONE_NEWCGROUP;
        }
#endif

        if (!flag) {
            nxt_alert(task, "unknown namespace flag: \"%V\"", &name);
            return NXT_ERROR;
        }

        if (nxt_conf_get_boolean(value)) {
            clone->flags |= flag;
        }
    }

    return NXT_OK;
}

#endif


#if (NXT_HAVE_ISOLATION_ROOTFS)

static nxt_int_t
nxt_isolation_set_rootfs(nxt_task_t *task, nxt_conf_value_t *isolation,
    nxt_process_t *process)
{
    nxt_str_t         str;
    nxt_conf_value_t  *obj;

    static const nxt_str_t  rootfs_name = nxt_string("rootfs");

    obj = nxt_conf_get_object_member(isolation, &rootfs_name, NULL);
    if (obj != NULL) {
        nxt_conf_get_string(obj, &str);

        if (nxt_slow_path(str.length <= 1 || str.start[0] != '/')) {
            nxt_log(task, NXT_LOG_ERR, "rootfs requires an absolute path other "
                    "than \"/\" but given \"%V\"", &str);

            return NXT_ERROR;
        }

        if (str.start[str.length - 1] == '/') {
            str.length--;
        }

        process->isolation.rootfs = nxt_mp_alloc(process->mem_pool,
                                                 str.length + 1);

        if (nxt_slow_path(process->isolation.rootfs == NULL)) {
            return NXT_ERROR;
        }

        nxt_memcpy(process->isolation.rootfs, str.start, str.length);

        process->isolation.rootfs[str.length] = '\0';
    }

    return NXT_OK;
}


static nxt_int_t
nxt_isolation_set_automount(nxt_task_t *task, nxt_conf_value_t *isolation,
    nxt_process_t *process)
{
    nxt_conf_value_t         *conf, *value;
    nxt_process_automount_t  *automount;

    static const nxt_str_t  automount_name = nxt_string("automount");
    static const nxt_str_t  langdeps_name = nxt_string("language_deps");
    static const nxt_str_t  tmp_name = nxt_string("tmpfs");
    static const nxt_str_t  proc_name = nxt_string("procfs");

    automount = &process->isolation.automount;

    automount->language_deps = 1;
    automount->tmpfs = 1;
    automount->procfs = 1;

    conf = nxt_conf_get_object_member(isolation, &automount_name, NULL);
    if (conf != NULL) {
        value = nxt_conf_get_object_member(conf, &langdeps_name, NULL);
        if (value != NULL) {
            automount->language_deps = nxt_conf_get_boolean(value);
        }

        value = nxt_conf_get_object_member(conf, &tmp_name, NULL);
        if (value != NULL) {
            automount->tmpfs = nxt_conf_get_boolean(value);
        }

        value = nxt_conf_get_object_member(conf, &proc_name, NULL);
        if (value != NULL) {
            automount->procfs = nxt_conf_get_boolean(value);
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_isolation_set_mounts(nxt_task_t *task, nxt_process_t *process,
    nxt_str_t *app_type)
{
    nxt_int_t              ret, cap_chroot;
    nxt_runtime_t          *rt;
    nxt_app_lang_module_t  *lang;

    rt = task->thread->runtime;
    cap_chroot = rt->capabilities.chroot;
    lang = nxt_app_lang_module(rt, app_type);

    nxt_assert(lang != NULL);

#if (NXT_HAVE_CLONE_NEWUSER)
    if (nxt_is_clone_flag_set(process->isolation.clone.flags, NEWUSER)) {
        cap_chroot = 1;
    }
#endif

    if (!cap_chroot) {
        nxt_log(task, NXT_LOG_ERR, "The \"rootfs\" field requires privileges");
        return NXT_ERROR;
    }

    ret = nxt_isolation_set_lang_mounts(task, process, lang->mounts);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    process->isolation.cleanup = nxt_isolation_unmount_all;

    return NXT_OK;
}


static nxt_int_t
nxt_isolation_set_lang_mounts(nxt_task_t *task, nxt_process_t *process,
    nxt_array_t *lang_mounts)
{
    u_char          *p;
    size_t          i, n, rootfs_len, len;
    nxt_mp_t        *mp;
    nxt_array_t     *mounts;
    const u_char    *rootfs;
    nxt_fs_mount_t  *mnt, *lang_mnt;

    mp = process->mem_pool;

    /* copy to init mem pool */
    mounts = nxt_array_copy(mp, NULL, lang_mounts);
    if (mounts == NULL) {
        return NXT_ERROR;
    }

    n = mounts->nelts;
    mnt = mounts->elts;
    lang_mnt = lang_mounts->elts;

    rootfs = process->isolation.rootfs;
    rootfs_len = nxt_strlen(rootfs);

    for (i = 0; i < n; i++) {
        len = nxt_strlen(lang_mnt[i].dst);

        mnt[i].dst = nxt_mp_alloc(mp, rootfs_len + len + 1);
        if (nxt_slow_path(mnt[i].dst == NULL)) {
            return NXT_ERROR;
        }

        p = nxt_cpymem(mnt[i].dst, rootfs, rootfs_len);
        p = nxt_cpymem(p, lang_mnt[i].dst, len);
        *p = '\0';
    }

    if (process->isolation.automount.tmpfs) {
        mnt = nxt_array_add(mounts);
        if (nxt_slow_path(mnt == NULL)) {
            return NXT_ERROR;
        }

        mnt->src = (u_char *) "tmpfs";
        mnt->name = (u_char *) "tmpfs";
        mnt->type = NXT_FS_TMP;
        mnt->flags = (NXT_FS_FLAGS_NOSUID
                      | NXT_FS_FLAGS_NODEV
                      | NXT_FS_FLAGS_NOEXEC);
        mnt->data = (u_char *) "size=1m,mode=1777";
        mnt->builtin = 1;
        mnt->deps = 0;

        mnt->dst = nxt_mp_nget(mp, rootfs_len + nxt_length("/tmp") + 1);
        if (nxt_slow_path(mnt->dst == NULL)) {
            return NXT_ERROR;
        }

        p = nxt_cpymem(mnt->dst, rootfs, rootfs_len);
        p = nxt_cpymem(p, "/tmp", 4);
        *p = '\0';
    }

    if (process->isolation.automount.procfs) {
        mnt = nxt_array_add(mounts);
        if (nxt_slow_path(mnt == NULL)) {
            return NXT_ERROR;
        }

        mnt->name = (u_char *) "proc";
        mnt->type = NXT_FS_PROC;
        mnt->src = (u_char *) "none";
        mnt->dst = nxt_mp_nget(mp, rootfs_len + nxt_length("/proc") + 1);
        if (nxt_slow_path(mnt->dst == NULL)) {
            return NXT_ERROR;
        }

        p = nxt_cpymem(mnt->dst, rootfs, rootfs_len);
        p = nxt_cpymem(p, "/proc", 5);
        *p = '\0';

        mnt->data = (u_char *) "";
        mnt->flags = NXT_FS_FLAGS_NOEXEC | NXT_FS_FLAGS_NOSUID;
        mnt->builtin = 1;
        mnt->deps = 0;
    }

    qsort(mounts->elts, mounts->nelts, sizeof(nxt_fs_mount_t),
          nxt_isolation_mount_compare);

    process->isolation.mounts = mounts;

    return NXT_OK;
}


static int nxt_cdecl
nxt_isolation_mount_compare(const void *v1, const void *v2)
{
    const nxt_fs_mount_t  *mnt1, *mnt2;

    mnt1 = v1;
    mnt2 = v2;

    return nxt_strlen(mnt1->src) > nxt_strlen(mnt2->src);
}


void
nxt_isolation_unmount_all(nxt_task_t *task, nxt_process_t *process)
{
    size_t                   n;
    nxt_array_t              *mounts;
    nxt_runtime_t            *rt;
    nxt_fs_mount_t           *mnt;
    nxt_process_automount_t  *automount;

    rt = task->thread->runtime;

    if (!rt->capabilities.setid) {
        return;
    }

    nxt_debug(task, "unmount all (%s)", process->name);

    automount = &process->isolation.automount;
    mounts = process->isolation.mounts;
    n = mounts->nelts;
    mnt = mounts->elts;

    while (n > 0) {
        n--;

        if (mnt[n].deps && !automount->language_deps) {
            continue;
        }

        nxt_fs_unmount(mnt[n].dst);
    }
}


nxt_int_t
nxt_isolation_prepare_rootfs(nxt_task_t *task, nxt_process_t *process)
{
    size_t                   i, n;
    nxt_int_t                ret;
    struct stat              st;
    nxt_array_t              *mounts;
    const u_char             *dst;
    nxt_fs_mount_t           *mnt;
    nxt_process_automount_t  *automount;

    automount = &process->isolation.automount;
    mounts = process->isolation.mounts;

    n = mounts->nelts;
    mnt = mounts->elts;

    for (i = 0; i < n; i++) {
        dst = mnt[i].dst;

        if (mnt[i].deps && !automount->language_deps) {
            continue;
        }

        if (nxt_slow_path(mnt[i].type == NXT_FS_BIND
                          && stat((const char *) mnt[i].src, &st) != 0))
        {
            nxt_log(task, NXT_LOG_WARN, "host path not found: %s", mnt[i].src);
            continue;
        }

        ret = nxt_fs_mkdir_all(dst, S_IRWXU | S_IRWXG | S_IRWXO);
        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_alert(task, "mkdir(%s) %E", dst, nxt_errno);
            goto undo;
        }

        ret = nxt_fs_mount(task, &mnt[i]);
        if (nxt_slow_path(ret != NXT_OK)) {
            goto undo;
        }
    }

    return NXT_OK;

undo:

    n = i + 1;

    for (i = 0; i < n; i++) {
        nxt_fs_unmount(mnt[i].dst);
    }

    return NXT_ERROR;
}


#if (NXT_HAVE_LINUX_PIVOT_ROOT) && (NXT_HAVE_CLONE_NEWNS)

nxt_int_t
nxt_isolation_change_root(nxt_task_t *task, nxt_process_t *process)
{
    char       *rootfs;
    nxt_int_t  ret;

    rootfs = (char *) process->isolation.rootfs;

    nxt_debug(task, "change root: %s", rootfs);

    if (nxt_is_clone_flag_set(process->isolation.clone.flags, NEWNS)) {
        ret = nxt_isolation_pivot_root(task, rootfs);

    } else {
        ret = nxt_isolation_chroot(task, rootfs);
    }

    if (nxt_fast_path(ret == NXT_OK)) {
        if (nxt_slow_path(chdir("/") < 0)) {
            nxt_alert(task, "chdir(\"/\") %E", nxt_errno);
            return NXT_ERROR;
        }
    }

    return ret;
}


/*
 * pivot_root(2) can only be safely used with containers, otherwise it can
 * umount(2) the global root filesystem and screw up the machine.
 */

static nxt_int_t
nxt_isolation_pivot_root(nxt_task_t *task, const char *path)
{
    /*
     * This implementation makes use of a kernel trick that works for ages
     * and now documented in Linux kernel 5.
     * https://lore.kernel.org/linux-man/87r24piwhm.fsf@x220.int.ebiederm.org/T/
     */

    if (nxt_slow_path(mount("", "/", "", MS_SLAVE|MS_REC, "") != 0)) {
        nxt_alert(task, "mount(\"/\", MS_SLAVE|MS_REC) failed: %E", nxt_errno);
        return NXT_ERROR;
    }

    if (nxt_slow_path(nxt_isolation_make_private_mount(task, path) != NXT_OK)) {
        return NXT_ERROR;
    }

    if (nxt_slow_path(mount(path, path, "bind", MS_BIND|MS_REC, "") != 0)) {
        nxt_alert(task, "error bind mounting rootfs %E", nxt_errno);
        return NXT_ERROR;
    }

    if (nxt_slow_path(chdir(path) != 0)) {
        nxt_alert(task, "failed to chdir(%s) %E", path, nxt_errno);
        return NXT_ERROR;
    }

    if (nxt_slow_path(nxt_pivot_root(".", ".") != 0)) {
        nxt_alert(task, "failed to pivot_root %E", nxt_errno);
        return NXT_ERROR;
    }

    /*
     * Demote the oldroot mount to avoid unmounts getting propagated to
     * the host.
     */
    if (nxt_slow_path(mount("", ".", "", MS_SLAVE | MS_REC, NULL) != 0)) {
        nxt_alert(task, "failed to bind mount rootfs %E", nxt_errno);
        return NXT_ERROR;
    }

    if (nxt_slow_path(umount2(".", MNT_DETACH) != 0)) {
        nxt_alert(task, "failed to umount old root directory %E", nxt_errno);
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_isolation_make_private_mount(nxt_task_t *task, const char *rootfs)
{
    char           *parent_mnt;
    FILE           *procfile;
    u_char         **mounts;
    size_t         len;
    uint8_t        *shared;
    nxt_int_t      ret, index, nmounts;
    struct mntent  *ent;

    static const char  *mount_path = "/proc/self/mounts";

    ret = NXT_ERROR;
    ent = NULL;
    shared = NULL;
    procfile = NULL;
    parent_mnt = NULL;

    nmounts = 256;

    mounts = nxt_malloc(nmounts * sizeof(uintptr_t));
    if (nxt_slow_path(mounts == NULL)) {
        goto fail;
    }

    shared = nxt_malloc(nmounts);
    if (nxt_slow_path(shared == NULL)) {
        goto fail;
    }

    procfile = setmntent(mount_path, "r");
    if (nxt_slow_path(procfile == NULL)) {
        nxt_alert(task, "failed to open %s %E", mount_path, nxt_errno);

        goto fail;
    }

    index = 0;

again:

    for ( ; index < nmounts; index++) {
        ent = getmntent(procfile);
        if (ent == NULL) {
            nmounts = index;
            break;
        }

        mounts[index] = (u_char *) strdup(ent->mnt_dir);
        shared[index] = hasmntopt(ent, "shared") != NULL;
    }

    if (ent != NULL) {
        /* there are still entries to be read */

        nmounts *= 2;
        mounts = nxt_realloc(mounts, nmounts);
        if (nxt_slow_path(mounts == NULL)) {
            goto fail;
        }

        shared = nxt_realloc(shared, nmounts);
        if (nxt_slow_path(shared == NULL)) {
            goto fail;
        }

        goto again;
    }

    for (index = 0; index < nmounts; index++) {
        if (nxt_strcmp(mounts[index], rootfs) == 0) {
            parent_mnt = (char *) rootfs;
            break;
        }
    }

    if (parent_mnt == NULL) {
        len = nxt_strlen(rootfs);

        parent_mnt = nxt_malloc(len + 1);
        if (parent_mnt == NULL) {
            goto fail;
        }

        nxt_memcpy(parent_mnt, rootfs, len);
        parent_mnt[len] = '\0';

        if (parent_mnt[len - 1] == '/') {
            parent_mnt[len - 1] = '\0';
            len--;
        }

        for ( ;; ) {
            for (index = 0; index < nmounts; index++) {
                if (nxt_strcmp(mounts[index], parent_mnt) == 0) {
                    goto found;
                }
            }

            if (len == 1 && parent_mnt[0] == '/') {
                nxt_alert(task, "parent mount not found");
                goto fail;
            }

            /* parent dir */
            while (parent_mnt[len - 1] != '/' && len > 0) {
                len--;
            }

            if (nxt_slow_path(len == 0)) {
                nxt_alert(task, "parent mount not found");
                goto fail;
            }

            if (len == 1) {
                parent_mnt[len] = '\0';     /* / */
            } else {
                parent_mnt[len - 1] = '\0'; /* /<path> */
            }
        }
    }

found:

    if (shared[index]) {
        if (nxt_slow_path(mount("", parent_mnt, "", MS_PRIVATE, "") != 0)) {
            nxt_alert(task, "mount(\"\", \"%s\", MS_PRIVATE) %E", parent_mnt,
                      nxt_errno);

            goto fail;
        }
    }

    ret = NXT_OK;

fail:

    if (procfile != NULL) {
        endmntent(procfile);
    }

    if (mounts != NULL) {
        for (index = 0; index < nmounts; index++) {
            nxt_free(mounts[index]);
        }

        nxt_free(mounts);
    }

    if (shared != NULL) {
        nxt_free(shared);
    }

    if (parent_mnt != NULL && parent_mnt != rootfs) {
        nxt_free(parent_mnt);
    }

    return ret;
}


nxt_inline int
nxt_pivot_root(const char *new_root, const char *old_root)
{
    return syscall(SYS_pivot_root, new_root, old_root);
}


#else /* !(NXT_HAVE_LINUX_PIVOT_ROOT) || !(NXT_HAVE_CLONE_NEWNS) */


nxt_int_t
nxt_isolation_change_root(nxt_task_t *task, nxt_process_t *process)
{
    char       *rootfs;

    rootfs = (char *) process->isolation.rootfs;

    nxt_debug(task, "change root: %s", rootfs);

    if (nxt_fast_path(nxt_isolation_chroot(task, rootfs) == NXT_OK)) {
        if (nxt_slow_path(chdir("/") < 0)) {
            nxt_alert(task, "chdir(\"/\") %E", nxt_errno);
            return NXT_ERROR;
        }

        return NXT_OK;
    }

    return NXT_ERROR;
}

#endif


static nxt_int_t
nxt_isolation_chroot(nxt_task_t *task, const char *path)
{
    if (nxt_slow_path(chroot(path) < 0)) {
        nxt_alert(task, "chroot(%s) %E", path, nxt_errno);
        return NXT_ERROR;
    }

    return NXT_OK;
}

#endif /* NXT_HAVE_ISOLATION_ROOTFS */


#if (NXT_HAVE_PR_SET_NO_NEW_PRIVS)

static nxt_int_t
nxt_isolation_set_new_privs(nxt_task_t *task, nxt_conf_value_t *isolation,
    nxt_process_t *process)
{
    nxt_conf_value_t  *obj;

    static const nxt_str_t  new_privs_name = nxt_string("new_privs");

    obj = nxt_conf_get_object_member(isolation, &new_privs_name, NULL);
    if (obj != NULL) {
        process->isolation.new_privs = nxt_conf_get_boolean(obj);
    }

    return NXT_OK;
}

#endif
