
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_UNIX_FILE_H_INCLUDED_
#define _NXT_UNIX_FILE_H_INCLUDED_


typedef int                         nxt_fd_t;

#define NXT_FILE_INVALID            -1

typedef nxt_uint_t                  nxt_file_access_t;
typedef struct stat                 nxt_file_info_t;


#define NXT_FILE_SYSTEM_NAME_UTF8   1

typedef u_char                      nxt_file_name_t;


typedef struct {
    size_t                          len;
    nxt_file_name_t                 *start;
} nxt_file_name_str_t;


#define nxt_file_name_str_set(file_name, mem_pool, name)                      \
    ((file_name) = (nxt_file_name_t *) (name), NXT_OK)


#define nxt_file_name_alloc(mem_pool, len)                                    \
    nxt_mp_nget(mem_pool, len)


#define nxt_file_name_copy(dst, src, len)                                     \
    nxt_cpymem(dst, src, len)


#define nxt_file_name_add(dst, src, len)                                      \
    nxt_cpymem(dst, src, len)


#if (NXT_HAVE_CASELESS_FILESYSTEM)

/* MacOSX, Cygwin. */

#define nxt_file_name_eq(fn1, fn2)                                            \
    (nxt_strcasecmp(fn1, fn2) == 0)

#else

#define nxt_file_name_eq(fn1, fn2)                                            \
    (nxt_strcmp(fn1, fn2) == 0)

#endif


#define nxt_file_name_is_absolute(name)                                       \
    (name[0] == '/')


#define NXT_MAX_PATH_LEN            MAXPATHLEN


typedef enum {
    NXT_FILE_UNKNOWN = 0,
    NXT_FILE_REGULAR,
    NXT_FILE_DIRECTORY,
} nxt_file_type_t;


typedef struct {
    nxt_file_name_t                 *name;

    /* Both are int's. */
    nxt_fd_t                        fd;
    nxt_err_t                       error;

#define NXT_FILE_ACCESSED_LONG_AGO  0xFFFF
    /*
     * Number of seconds ago the file content was last
     * read.  The maximum value is about 18 hours.
     */
    uint16_t                        accessed;

    uint8_t                         type;       /* nxt_file_type_t */

    /*
     * Log open() file error with given log level if it is non zero.
     * Note that zero log level is NXT_LOG_ALERT.
     */
    uint8_t                         log_level;

    nxt_time_t                      mtime;
    nxt_off_t                       size;
} nxt_file_t;


NXT_EXPORT nxt_int_t nxt_file_open(nxt_task_t *task, nxt_file_t *file,
    nxt_uint_t mode, nxt_uint_t create, nxt_file_access_t access);

#if (NXT_HAVE_OPENAT2)
NXT_EXPORT nxt_int_t nxt_file_openat2(nxt_task_t *task, nxt_file_t *file,
    nxt_uint_t mode, nxt_uint_t create, nxt_file_access_t access, nxt_fd_t dfd,
    nxt_uint_t resolve);
#endif


/* The file open access modes. */
#define NXT_FILE_RDONLY             O_RDONLY
#define NXT_FILE_WRONLY             O_WRONLY
#define NXT_FILE_RDWR               O_RDWR
#define NXT_FILE_APPEND             (O_WRONLY | O_APPEND)

#if (NXT_HAVE_OPENAT2)

#if defined(O_DIRECTORY)
#define NXT_FILE_DIRECTORY          O_DIRECTORY
#else
#define NXT_FILE_DIRECTORY          0
#endif

#if defined(O_SEARCH)
#define NXT_FILE_SEARCH             (O_SEARCH|NXT_FILE_DIRECTORY)

#elif defined(O_EXEC)
#define NXT_FILE_SEARCH             (O_EXEC|NXT_FILE_DIRECTORY)

#else
/*
 * O_PATH is used in combination with O_RDONLY.  The last one is ignored
 * if O_PATH is used, but it allows Unit to not fail when it was built on
 * modern system (i.e. glibc 2.14+) and run with a kernel older than 2.6.39.
 * Then O_PATH is unknown to the kernel and ignored, while O_RDONLY is used.
 */
#define NXT_FILE_SEARCH             (O_PATH|O_RDONLY|NXT_FILE_DIRECTORY)
#endif

#endif /* NXT_HAVE_OPENAT2 */

/* The file creation modes. */
#define NXT_FILE_CREATE_OR_OPEN     O_CREAT
#define NXT_FILE_OPEN               0
#define NXT_FILE_TRUNCATE           (O_CREAT | O_TRUNC)

/* The file access rights. */
#define NXT_FILE_DEFAULT_ACCESS     0644
#define NXT_FILE_OWNER_ACCESS       0600


NXT_EXPORT void nxt_file_close(nxt_task_t *task, nxt_file_t *file);
NXT_EXPORT ssize_t nxt_file_write(nxt_file_t *file, const u_char *buf,
    size_t size, nxt_off_t offset);
NXT_EXPORT ssize_t nxt_file_read(nxt_file_t *file, u_char *buf, size_t size,
    nxt_off_t offset);
NXT_EXPORT void nxt_file_read_ahead(nxt_file_t *file, nxt_off_t offset,
    size_t size);
NXT_EXPORT nxt_int_t nxt_file_info(nxt_file_t *file, nxt_file_info_t *fi);


#define nxt_is_dir(fi)                                                        \
    (S_ISDIR((fi)->st_mode))

#define nxt_is_file(fi)                                                       \
    (S_ISREG((fi)->st_mode))

#define nxt_file_size(fi)                                                     \
    (fi)->st_size

#define nxt_file_mtime(fi)                                                    \
    (fi)->st_mtime


NXT_EXPORT nxt_int_t nxt_file_delete(nxt_file_name_t *name);
NXT_EXPORT nxt_int_t nxt_file_set_access(nxt_file_name_t *name,
    nxt_file_access_t access);
NXT_EXPORT nxt_int_t nxt_file_chown(nxt_file_name_t *name, const char *owner,
    const char *group);
NXT_EXPORT nxt_int_t nxt_file_rename(nxt_file_name_t *old_name,
    nxt_file_name_t *new_name);

NXT_EXPORT nxt_int_t nxt_fd_nonblocking(nxt_task_t *task, nxt_fd_t fd);
NXT_EXPORT nxt_int_t nxt_fd_blocking(nxt_task_t *task, nxt_fd_t fd);
NXT_EXPORT ssize_t nxt_fd_write(nxt_fd_t fd, u_char *buf, size_t size);
NXT_EXPORT ssize_t nxt_fd_read(nxt_fd_t fd, u_char *buf, size_t size);
NXT_EXPORT void nxt_fd_close(nxt_fd_t fd);

NXT_EXPORT FILE *nxt_file_fopen(nxt_task_t *task, const char *pathname,
    const char *mode);
NXT_EXPORT void nxt_file_fclose(nxt_task_t *task, FILE *fp);

NXT_EXPORT nxt_int_t nxt_file_redirect(nxt_file_t *file, nxt_fd_t fd);
NXT_EXPORT nxt_int_t nxt_file_stdout(nxt_file_t *file);
NXT_EXPORT nxt_int_t nxt_file_stderr(nxt_file_t *file);
NXT_EXPORT nxt_int_t nxt_stderr_start(void);


#define nxt_stdout  STDOUT_FILENO
#define nxt_stderr  STDERR_FILENO


#define nxt_write_console(fd, buf, size)                                      \
    write(fd, buf, size)

#define nxt_write_syslog(priority, message)                                   \
    syslog(priority, "%s", message)


NXT_EXPORT nxt_int_t nxt_pipe_create(nxt_task_t *task, nxt_fd_t *pp,
    nxt_bool_t nbread, nxt_bool_t nbwrite);
NXT_EXPORT void nxt_pipe_close(nxt_task_t *task, nxt_fd_t *pp);

NXT_EXPORT size_t nxt_dir_current(char *buf, size_t len);


#endif /* _NXT_UNIX_FILE_H_INCLUDED_ */
