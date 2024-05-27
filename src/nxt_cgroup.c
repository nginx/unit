/*
 * Copyright (C) Andrew Clayton
 * Copyright (C) F5, Inc.
 */

#include <nxt_main.h>

#include <nxt_cgroup.h>


static int nxt_mk_cgpath_relative(nxt_task_t *task, const char *dir,
    char *cgpath);
static nxt_int_t nxt_mk_cgpath(nxt_task_t *task, const char *dir,
    char *cgpath);


nxt_int_t
nxt_cgroup_proc_add(nxt_task_t *task, nxt_process_t *process)
{
    int        len;
    char       cgprocs[NXT_MAX_PATH_LEN];
    FILE       *fp;
    nxt_int_t  ret;

    if (task->thread->runtime->type != NXT_PROCESS_MAIN
        || nxt_process_type(process) != NXT_PROCESS_PROTOTYPE
        || process->isolation.cgroup.path == NULL)
    {
        return NXT_OK;
    }

    ret = nxt_mk_cgpath(task, process->isolation.cgroup.path, cgprocs);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return NXT_ERROR;
    }

    ret = nxt_fs_mkdir_all((const u_char *) cgprocs, 0777);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return NXT_ERROR;
    }

    len = strlen(cgprocs);

    len = snprintf(cgprocs + len, NXT_MAX_PATH_LEN - len, "/cgroup.procs");
    if (nxt_slow_path(len >= NXT_MAX_PATH_LEN - len)) {
        nxt_errno = ENAMETOOLONG;
        return NXT_ERROR;
    }

    fp = nxt_file_fopen(task, cgprocs, "we");
    if (nxt_slow_path(fp == NULL)) {
        return NXT_ERROR;
    }

    setvbuf(fp, NULL, _IONBF, 0);
    len = fprintf(fp, "%d\n", process->pid);
    nxt_file_fclose(task, fp);

    if (nxt_slow_path(len < 0)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


void
nxt_cgroup_cleanup(nxt_task_t *task, const nxt_process_t *process)
{
    char       *ptr;
    char       cgroot[NXT_MAX_PATH_LEN], cgpath[NXT_MAX_PATH_LEN];
    nxt_int_t  ret;

    ret = nxt_mk_cgpath(task, "", cgroot);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return;
    }

    ret = nxt_mk_cgpath(task, process->isolation.cgroup.path, cgpath);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return;
    }

    while (*cgpath != '\0' && strcmp(cgroot, cgpath) != 0) {
        rmdir(cgpath);
        ptr = strrchr(cgpath, '/');
        *ptr = '\0';
    }
}


static int
nxt_mk_cgpath_relative(nxt_task_t *task, const char *dir, char *cgpath)
{
    int         i, len;
    char        *buf, *ptr;
    FILE        *fp;
    size_t      size;
    ssize_t     nread;
    nxt_bool_t  found;

    fp = nxt_file_fopen(task, "/proc/self/cgroup", "re");
    if (nxt_slow_path(fp == NULL)) {
        return -1;
    }

    len = -1;
    buf = NULL;
    found = 0;
    while ((nread = getline(&buf, &size, fp)) != -1) {
        if (strncmp(buf, "0::", 3) == 0) {
            found = 1;
            break;
        }
    }

    nxt_file_fclose(task, fp);

    if (!found) {
        nxt_errno = ENODATA;
        goto out_free_buf;
    }

    buf[nread - 1] = '\0';  /* lose the trailing '\n' */
    ptr = buf;
    for (i = 0; i < 2; i++) {
        ptr = strchr(ptr, ':');
        if (ptr == NULL) {
            nxt_errno = ENODATA;
            goto out_free_buf;
        }

        ptr++;
    }

    len = snprintf(cgpath, NXT_MAX_PATH_LEN, NXT_CGROUP_ROOT "%s/%s",
                   ptr, dir);

out_free_buf:

    nxt_free(buf);

    return len;
}


static nxt_int_t
nxt_mk_cgpath(nxt_task_t *task, const char *dir, char *cgpath)
{
    int  len;

    /*
     * If the path from the config is relative, we need to make
     * the cgroup path include the main unit processes cgroup. I.e
     *
     *   NXT_CGROUP_ROOT/<main process cgroup>/<cgroup path>
     */
    if (dir[0] != '/') {
        len = nxt_mk_cgpath_relative(task, dir, cgpath);
    } else {
        len = snprintf(cgpath, NXT_MAX_PATH_LEN, NXT_CGROUP_ROOT "%s", dir);
    }

    if (len == -1) {
        return NXT_ERROR;
    }

    if (len >= NXT_MAX_PATH_LEN) {
        nxt_errno = ENAMETOOLONG;
        return NXT_ERROR;
    }

    return NXT_OK;
}
