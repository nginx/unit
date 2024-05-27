
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_int_t
nxt_file_open(nxt_task_t *task, nxt_file_t *file, nxt_uint_t mode,
    nxt_uint_t create, nxt_file_access_t access)
{
#ifdef __CYGWIN__
    mode |= O_BINARY;
#endif

    /* O_NONBLOCK is to prevent blocking on FIFOs, special devices, etc. */
    mode |= (O_NONBLOCK | create);

    file->fd = open((char *) file->name, mode, access);

    file->error = (file->fd == -1) ? nxt_errno : 0;

#if (NXT_DEBUG)
    nxt_thread_time_update(task->thread);
#endif

    nxt_debug(task, "open(\"%FN\", 0x%uXi, 0x%uXi): %FD err:%d",
              file->name, mode, access, file->fd, file->error);

    if (file->fd != -1) {
        return NXT_OK;
    }

    if (file->log_level != 0) {
        nxt_log(task, file->log_level, "open(\"%FN\") failed %E",
                file->name, file->error);
    }

    return NXT_ERROR;
}


#if (NXT_HAVE_OPENAT2)

nxt_int_t
nxt_file_openat2(nxt_task_t *task, nxt_file_t *file, nxt_uint_t mode,
    nxt_uint_t create, nxt_file_access_t access, nxt_fd_t dfd,
    nxt_uint_t resolve)
{
    struct open_how  how;

    nxt_memzero(&how, sizeof(how));

    /* O_NONBLOCK is to prevent blocking on FIFOs, special devices, etc. */
    mode |= (O_NONBLOCK | create);

    how.flags = mode;
    how.mode = access;
    how.resolve = resolve;

    file->fd = syscall(SYS_openat2, dfd, file->name, &how, sizeof(how));

    file->error = (file->fd == -1) ? nxt_errno : 0;

#if (NXT_DEBUG)
    nxt_thread_time_update(task->thread);
#endif

    nxt_debug(task, "openat2(%FD, \"%FN\"): %FD err:%d", dfd, file->name,
              file->fd, file->error);

    if (file->fd != -1) {
        return NXT_OK;
    }

    if (file->log_level != 0) {
        nxt_log(task, file->log_level, "openat2(%FD, \"%FN\") failed %E", dfd,
                file->name, file->error);
    }

    return NXT_ERROR;
}

#endif


void
nxt_file_close(nxt_task_t *task, nxt_file_t *file)
{
    nxt_debug(task, "close(%FD)", file->fd);

    if (close(file->fd) != 0) {
        nxt_alert(task, "close(%FD, \"%FN\") failed %E",
                  file->fd, file->name, nxt_errno);
    }
}


ssize_t
nxt_file_write(nxt_file_t *file, const u_char *buf, size_t size,
    nxt_off_t offset)
{
    ssize_t  n;

    nxt_thread_debug(thr);

    n = pwrite(file->fd, buf, size, offset);

    file->error = (n < 0) ? nxt_errno : 0;

    nxt_thread_time_debug_update(thr);

    nxt_log_debug(thr->log, "pwrite(%FD, %p, %uz, %O): %z",
                  file->fd, buf, size, offset, n);

    if (nxt_fast_path(n >= 0)) {
        return n;
    }

    nxt_thread_log_alert("pwrite(%FD, \"%FN\", %p, %uz, %O) failed %E",
                         file->fd, file->name, buf, size,
                         offset, file->error);

    return NXT_ERROR;
}


ssize_t
nxt_file_read(nxt_file_t *file, u_char *buf, size_t size, nxt_off_t offset)
{
    ssize_t  n;

    nxt_thread_debug(thr);

    n = pread(file->fd, buf, size, offset);

    file->error = (n <= 0) ? nxt_errno : 0;

    nxt_thread_time_debug_update(thr);

    nxt_log_debug(thr->log, "pread(%FD, %p, %uz, %O): %z",
                  file->fd, buf, size, offset, n);

    if (nxt_fast_path(n >= 0)) {
        return n;
    }

    nxt_thread_log_alert("pread(%FD, \"%FN\", %p, %uz, %O) failed %E",
                         file->fd, file->name, buf, size,
                         offset, file->error);

    return NXT_ERROR;
}


#if (NXT_HAVE_READAHEAD)

/* FreeBSD 8.0 fcntl(F_READAHEAD, size) enables read ahead up to the size. */

void
nxt_file_read_ahead(nxt_file_t *file, nxt_off_t offset, size_t size)
{
    int     ret;
    u_char  buf;

    ret = fcntl(file->fd, F_READAHEAD, (int) size);

    nxt_thread_log_debug("fcntl(%FD, F_READAHEAD, %uz): %d",
                         file->fd, size, ret);

    if (nxt_fast_path(ret != -1)) {
        (void) nxt_file_read(file, &buf, 1, offset);
        return;
    }

    nxt_thread_log_alert("fcntl(%FD, \"%FN\", F_READAHEAD, %uz) failed %E",
                         file->fd, file->name, size, nxt_errno);
}

#elif (NXT_HAVE_POSIX_FADVISE)

/*
 * POSIX_FADV_SEQUENTIAL
 *   Linux doubles the default readahead window size of a backing device
 *   which is usually 128K.
 *
 *   FreeBSD does nothing.
 *
 * POSIX_FADV_WILLNEED
 *   Linux preloads synchronously up to 2M of specified file region in
 *   the kernel page cache.  Linux-specific readahead(2) syscall does
 *   the same.  Both operations are blocking despite posix_fadvise(2)
 *   claims the opposite.
 *
 *   FreeBSD does nothing.
 */

void
nxt_file_read_ahead(nxt_file_t *file, nxt_off_t offset, size_t size)
{
    nxt_err_t  err;

    err = posix_fadvise(file->fd, offset, size, POSIX_FADV_WILLNEED);

    nxt_thread_log_debug("posix_fadvise(%FD, \"%FN\", %O, %uz, %d): %d",
                         file->fd, file->name, offset, size,
                         POSIX_FADV_WILLNEED, err);

    if (nxt_fast_path(err == 0)) {
        return;
    }

    nxt_thread_log_alert("posix_fadvise(%FD, \"%FN\", %O, %uz, %d) failed %E",
                         file->fd, file->name, offset, size,
                         POSIX_FADV_WILLNEED, err);
}

#elif (NXT_HAVE_RDAHEAD)

/* MacOSX fcntl(F_RDAHEAD). */

void
nxt_file_read_ahead(nxt_file_t *file, nxt_off_t offset, size_t size)
{
    int     ret;
    u_char  buf;

    ret = fcntl(file->fd, F_RDAHEAD, 1);

    nxt_thread_log_debug("fcntl(%FD, F_RDAHEAD, 1): %d", file->fd, ret);

    if (nxt_fast_path(ret != -1)) {
        (void) nxt_file_read(file, &buf, 1, offset);
        return;
    }

    nxt_thread_log_alert("fcntl(%FD, \"%FN\", F_RDAHEAD, 1) failed %E",
                         file->fd, file->name, nxt_errno);
}

#else

void
nxt_file_read_ahead(nxt_file_t *file, nxt_off_t offset, size_t size)
{
    u_char  buf;

    (void) nxt_file_read(file, &buf, 1, offset);
}

#endif


nxt_int_t
nxt_file_info(nxt_file_t *file, nxt_file_info_t *fi)
{
    int  n;

    if (file->fd == NXT_FILE_INVALID) {
        n = stat((char *) file->name, fi);

        file->error = (n != 0) ? nxt_errno : 0;

        nxt_thread_log_debug("stat(\"%FN)\": %d", file->name, n);

        if (n == 0) {
            return NXT_OK;
        }

        if (file->log_level != 0) {
            nxt_thread_log_error(file->log_level, "stat(\"%FN\") failed %E",
                                 file->name, file->error);
        }

        return NXT_ERROR;

    } else {
        n = fstat(file->fd, fi);

        file->error = (n != 0) ? nxt_errno : 0;

        nxt_thread_log_debug("fstat(%FD): %d", file->fd, n);

        if (n == 0) {
            return NXT_OK;
        }

        /* Use NXT_LOG_ALERT because fstat() error on open file is strange. */

        nxt_thread_log_alert("fstat(%FD, \"%FN\") failed %E",
                             file->fd, file->name, file->error);

        return NXT_ERROR;
    }
}


nxt_int_t
nxt_file_delete(nxt_file_name_t *name)
{
    nxt_thread_log_debug("unlink(\"%FN\")", name);

    if (nxt_fast_path(unlink((char *) name) == 0)) {
        return NXT_OK;
    }

    nxt_thread_log_alert("unlink(\"%FN\") failed %E", name, nxt_errno);

    return NXT_ERROR;
}


nxt_int_t
nxt_file_set_access(nxt_file_name_t *name, nxt_file_access_t access)
{
    if (nxt_fast_path(chmod((char *) name, access) == 0)) {
        return NXT_OK;
    }

    nxt_thread_log_alert("chmod(\"%FN\") failed %E", name, nxt_errno);

    return NXT_ERROR;
}


nxt_int_t
nxt_file_chown(nxt_file_name_t *name, const char *owner, const char *group)
{
    int    err;
    char   *buf;
    long   bufsize;
    gid_t  gid = ~0;
    uid_t  uid = ~0;

    if (owner == NULL && group == NULL) {
        return NXT_OK;
    }

    if (owner != NULL) {
        struct passwd  pwd, *result;

        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize == -1) {
            bufsize = 32768;
        }

        buf = nxt_malloc(bufsize);
        if (buf == NULL) {
            return NXT_ERROR;
        }

        err = getpwnam_r(owner, &pwd, buf, bufsize, &result);
        if (result == NULL) {
            nxt_thread_log_alert("getpwnam_r(\"%s\", ...) failed %E %s",
                                 owner, nxt_errno,
                                 err == 0 ? "(User not found)" : "");
            goto out_err_free;
        }

        uid = pwd.pw_uid;

        nxt_free(buf);
    }

    if (group != NULL) {
        struct group  grp, *result;

        bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
        if (bufsize == -1) {
            bufsize = 32768;
        }

        buf = nxt_malloc(bufsize);
        if (buf == NULL) {
            return NXT_ERROR;
        }

        err = getgrnam_r(group, &grp, buf, bufsize, &result);
        if (result == NULL) {
            nxt_thread_log_alert("getgrnam_r(\"%s\", ...) failed %E %s",
                                 group, nxt_errno,
                                 err == 0 ? "(Group not found)" : "");
            goto out_err_free;
        }

        gid = grp.gr_gid;

        nxt_free(buf);
    }

    if (nxt_fast_path(chown((const char *) name, uid, gid) == 0)) {
        return NXT_OK;
    }

    nxt_thread_log_alert("chown(\"%FN\", %l, %l) failed %E", name,
                         owner != NULL ? (long) uid : -1,
                         group != NULL ? (long) gid : -1, nxt_errno);

    return NXT_ERROR;

out_err_free:
    nxt_free(buf);

    return NXT_ERROR;
}


nxt_int_t
nxt_file_rename(nxt_file_name_t *old_name, nxt_file_name_t *new_name)
{
    int  ret;

    nxt_thread_log_debug("rename(\"%FN\", \"%FN\")", old_name, new_name);

    ret = rename((char *) old_name, (char *) new_name);
    if (nxt_fast_path(ret == 0)) {
        return NXT_OK;
    }

    nxt_thread_log_alert("rename(\"%FN\", \"%FN\") failed %E",
                         old_name, new_name, nxt_errno);

    return NXT_ERROR;
}


/*
 * ioctl(FIONBIO) sets a non-blocking mode using one syscall,
 * thereas fcntl(F_SETFL, O_NONBLOCK) needs to learn the current state
 * using fcntl(F_GETFL).
 *
 * ioctl() and fcntl() are syscalls at least in Linux 2.2, FreeBSD 2.x,
 * and Solaris 7.
 *
 * Linux 2.4 uses BKL for ioctl() and fcntl(F_SETFL).
 * Linux 2.6 does not use BKL.
 */

#if (NXT_HAVE_FIONBIO)

nxt_int_t
nxt_fd_nonblocking(nxt_task_t *task, nxt_fd_t fd)
{
    int  nb;

    nb = 1;

    if (nxt_fast_path(ioctl(fd, FIONBIO, &nb) != -1)) {
        return NXT_OK;
    }

    nxt_alert(task, "ioctl(%d, FIONBIO) failed %E", fd, nxt_errno);

    return NXT_ERROR;

}


nxt_int_t
nxt_fd_blocking(nxt_task_t *task, nxt_fd_t fd)
{
    int  nb;

    nb = 0;

    if (nxt_fast_path(ioctl(fd, FIONBIO, &nb) != -1)) {
        return NXT_OK;
    }

    nxt_alert(task, "ioctl(%d, !FIONBIO) failed %E", fd, nxt_errno);

    return NXT_ERROR;
}

#else /* !(NXT_HAVE_FIONBIO) */

nxt_int_t
nxt_fd_nonblocking(nxt_task_t *task, nxt_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (nxt_slow_path(flags == -1)) {
        nxt_alert(task, "fcntl(%d, F_GETFL) failed %E", fd, nxt_errno);
        return NXT_ERROR;
    }

    flags |= O_NONBLOCK;

    if (nxt_slow_path(fcntl(fd, F_SETFL, flags) == -1)) {
        nxt_alert(task, "fcntl(%d, F_SETFL, O_NONBLOCK) failed %E",
                  fd, nxt_errno);
        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_int_t
nxt_fd_blocking(nxt_task_t *task, nxt_fd_t fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFL);

    if (nxt_slow_path(flags == -1)) {
        nxt_alert(task, "fcntl(%d, F_GETFL) failed %E", fd, nxt_errno);
        return NXT_ERROR;
    }

    flags &= O_NONBLOCK;

    if (nxt_slow_path(fcntl(fd, F_SETFL, flags) == -1)) {
        nxt_alert(task, "fcntl(%d, F_SETFL, !O_NONBLOCK) failed %E",
                  fd, nxt_errno);
        return NXT_ERROR;
    }

    return NXT_OK;
}

#endif /* NXT_HAVE_FIONBIO */


ssize_t
nxt_fd_write(nxt_fd_t fd, u_char *buf, size_t size)
{
    ssize_t    n;
    nxt_err_t  err;

    n = write(fd, buf, size);

    err = (n == -1) ? nxt_errno : 0;

    nxt_thread_log_debug("write(%FD, %p, %uz): %z", fd, buf, size, n);

    if (nxt_slow_path(n <= 0)) {
        nxt_thread_log_alert("write(%FD) failed %E", fd, err);
    }

    return n;
}


ssize_t
nxt_fd_read(nxt_fd_t fd, u_char *buf, size_t size)
{
    ssize_t    n;
    nxt_err_t  err;

    n = read(fd, buf, size);

    err = (n == -1) ? nxt_errno : 0;

    nxt_thread_log_debug("read(%FD, %p, %uz): %z", fd, buf, size, n);

    if (nxt_slow_path(n <= 0)) {

        if (err == NXT_EAGAIN) {
            return 0;
        }

        nxt_thread_log_alert("read(%FD) failed %E", fd, err);
    }

    return n;
}


void
nxt_fd_close(nxt_fd_t fd)
{
    nxt_thread_log_debug("close(%FD)", fd);

    if (nxt_slow_path(close(fd) != 0)) {
        nxt_thread_log_alert("close(%FD) failed %E", fd, nxt_errno);
    }
}


FILE *
nxt_file_fopen(nxt_task_t *task, const char *pathname, const char *mode)
{
    int   err;
    FILE  *fp;

#if (NXT_DEBUG)
    nxt_thread_time_update(task->thread);
#endif

    fp = fopen(pathname, mode);
    err = (fp == NULL) ? nxt_errno : 0;

    nxt_debug(task, "fopen(\"%s\", \"%s\"): fp:%p err:%d", pathname, mode, fp,
              err);

    if (nxt_fast_path(fp != NULL)) {
        return fp;
    }

    nxt_alert(task, "fopen(\"%s\") failed %E", pathname, err);

    return NULL;
}


void
nxt_file_fclose(nxt_task_t *task, FILE *fp)
{
    nxt_debug(task, "fclose(%p)", fp);

    if (nxt_slow_path(fclose(fp) == -1)) {
        nxt_alert(task, "fclose() failed %E", nxt_errno);
    }
}


/*
 * nxt_file_redirect() redirects the file to the fd descriptor.
 * Then the fd descriptor is closed.
 */

nxt_int_t
nxt_file_redirect(nxt_file_t *file, nxt_fd_t fd)
{
    nxt_thread_log_debug("dup2(%FD, %FD, \"%FN\")", fd, file->fd, file->name);

    if (dup2(fd, file->fd) == -1) {
        nxt_thread_log_alert("dup2(%FD, %FD, \"%FN\") failed %E",
                             fd, file->fd, file->name, nxt_errno);
        return NXT_ERROR;
    }

    if (close(fd) != 0) {
        nxt_thread_log_alert("close(%FD, \"%FN\") failed %E",
                             fd, file->name, nxt_errno);
        return NXT_ERROR;
    }

    return NXT_OK;
}


/* nxt_file_stdout() redirects the stdout descriptor to the file. */

nxt_int_t
nxt_file_stdout(nxt_file_t *file)
{
    nxt_thread_log_debug("dup2(%FD, %FD, \"%FN\")",
                         file->fd, STDOUT_FILENO, file->name);

    if (dup2(file->fd, STDOUT_FILENO) != -1) {
        return NXT_OK;
    }

    nxt_thread_log_alert("dup2(%FD, %FD, \"%FN\") failed %E",
                         file->fd, STDOUT_FILENO, file->name, nxt_errno);

    return NXT_ERROR;
}


/* nxt_file_stderr() redirects the stderr descriptor to the file. */

nxt_int_t
nxt_file_stderr(nxt_file_t *file)
{
    nxt_thread_log_debug("dup2(%FD, %FD, \"%FN\")",
                         file->fd, STDERR_FILENO, file->name);

    if (dup2(file->fd, STDERR_FILENO) != -1) {
        return NXT_OK;
    }

    nxt_thread_log_alert("dup2(%FD, %FD, \"%FN\") failed %E",
                         file->fd, STDERR_FILENO, file->name, nxt_errno);

    return NXT_ERROR;
}


nxt_int_t
nxt_stderr_start(void)
{
    int  flags, fd;

    flags = fcntl(nxt_stderr, F_GETFL);

    if (flags != -1) {
        /*
         * If the stderr output of a multithreaded application is
         * redirected to a file:
         *    Linux, Solaris and MacOSX do not write atomically to the output;
         *    MacOSX besides adds zeroes to the output.
         * O_APPEND fixes this.
         */
        (void) fcntl(nxt_stderr, F_SETFL, flags | O_APPEND);

    } else {
        /*
         * The stderr descriptor is closed before application start.
         * Reserve the stderr descriptor for future use.  Errors are
         * ignored because anyway they could be written nowhere.
         */
        fd = open("/dev/null", O_WRONLY | O_APPEND);

        if (fd != -1) {
            (void) dup2(fd, nxt_stderr);

            if (fd != nxt_stderr) {
                (void) close(fd);
            }
        }
    }

    return flags;
}


nxt_int_t
nxt_pipe_create(nxt_task_t *task, nxt_fd_t *pp, nxt_bool_t nbread,
    nxt_bool_t nbwrite)
{
    if (pipe(pp) != 0) {
        nxt_alert(task, "pipe() failed %E", nxt_errno);

        return NXT_ERROR;
    }

    nxt_debug(task, "pipe(): %FD:%FD", pp[0], pp[1]);

    if (nbread) {
        if (nxt_fd_nonblocking(task, pp[0]) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    if (nbwrite) {
        if (nxt_fd_nonblocking(task, pp[1]) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


void
nxt_pipe_close(nxt_task_t *task, nxt_fd_t *pp)
{
    nxt_debug(task, "pipe close(%FD:%FD)", pp[0], pp[1]);

    if (close(pp[0]) != 0) {
        nxt_alert(task, "pipe close(%FD) failed %E", pp[0], nxt_errno);
    }

    if (close(pp[1]) != 0) {
        nxt_alert(task, "pipe close(%FD) failed %E", pp[1], nxt_errno);
    }
}


size_t
nxt_dir_current(char *buf, size_t len)
{
    if (nxt_fast_path(getcwd(buf, len) != NULL)) {
        return nxt_strlen(buf);
    }

    nxt_thread_log_alert("getcwd(%uz) failed %E", len, nxt_errno);

    return 0;
}
