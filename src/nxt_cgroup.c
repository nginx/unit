/*
 * Copyright (C) Andrew Clayton
 * Copyright (C) F5, Inc.
 */

#include <nxt_main.h>

#include <nxt_cgroup.h>


static char *nxt_mk_cgpath_relative(nxt_task_t *task, const char *dir,
    char *cgpath);
static char *nxt_mk_cgpath(nxt_task_t *task, const char *dir,
    char *cgpath);


nxt_int_t
nxt_cgroup_proc_add(nxt_task_t *task, nxt_process_t *process)
{
    int        len;
    char       *p, *past_end;
    char       cgprocs[NXT_MAX_PATH_LEN];
    FILE       *fp;
    nxt_int_t  ret;

    if (task->thread->runtime->type != NXT_PROCESS_MAIN
        || nxt_process_type(process) != NXT_PROCESS_PROTOTYPE
        || process->isolation.cgroup.path == NULL)
    {
        return NXT_OK;
    }

    p = nxt_mk_cgpath(task, process->isolation.cgroup.path, cgprocs);
    if (nxt_slow_path(p == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_fs_mkdir_all((const u_char *) cgprocs, 0777);
    if (nxt_slow_path(ret == NXT_ERROR)) {
        return NXT_ERROR;
    }

    past_end = cgprocs + NXT_MAX_PATH_LEN;
    p = nxt_stpecpy(p, past_end, "/cgroup.procs");
    if (nxt_slow_path(p == past_end)) {
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
    char  *ptr, *ret;
    char  cgroot[NXT_MAX_PATH_LEN], cgpath[NXT_MAX_PATH_LEN];

    ret = nxt_mk_cgpath(task, "", cgroot);
    if (nxt_slow_path(ret == NULL)) {
        return;
    }

    ret = nxt_mk_cgpath(task, process->isolation.cgroup.path, cgpath);
    if (nxt_slow_path(ret == NULL)) {
        return;
    }

    while (*cgpath != '\0' && strcmp(cgroot, cgpath) != 0) {
        rmdir(cgpath);
        ptr = strrchr(cgpath, '/');
        *ptr = '\0';
    }
}


static char *
nxt_mk_cgpath_relative(nxt_task_t *task, const char *dir, char *cgpath)
{
    int         i;
    char        *buf, *ptr, *p, *past_end;
    FILE        *fp;
    size_t      size;
    ssize_t     nread;
    nxt_bool_t  found;

    fp = nxt_file_fopen(task, "/proc/self/cgroup", "re");
    if (nxt_slow_path(fp == NULL)) {
        return NULL;
    }

    p = NULL;
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

    past_end = cgpath + NXT_MAX_PATH_LEN;
    p = cgpath;
    p = nxt_stpecpy(p, past_end, NXT_CGROUP_ROOT);
    p = nxt_stpecpy(p, past_end, ptr);
    p = nxt_stpecpy(p, past_end, "/");
    p = nxt_stpecpy(p, past_end, dir);

out_free_buf:

    nxt_free(buf);

    return p;
}


static char *
nxt_mk_cgpath(nxt_task_t *task, const char *dir, char *cgpath)
{
    char  *p, *past_end;

    past_end = cgpath + NXT_MAX_PATH_LEN;

    /*
     * If the path from the config is relative, we need to make
     * the cgroup path include the main unit processes cgroup. I.e
     *
     *   NXT_CGROUP_ROOT/<main process cgroup>/<cgroup path>
     */
    if (dir[0] != '/') {
        p = nxt_mk_cgpath_relative(task, dir, cgpath);
    } else {
        p = cgpath;
        p = nxt_stpecpy(p, past_end, NXT_CGROUP_ROOT);
        p = nxt_stpecpy(p, past_end, dir);
    }

    if (nxt_slow_path(p == past_end)) {
        nxt_errno = ENAMETOOLONG;
        return NULL;
    }

    return p;
}
