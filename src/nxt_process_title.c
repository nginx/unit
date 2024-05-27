
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


/* The arguments passed to main(). */
char  **nxt_process_argv;

/*
 * MacOSX environ(7):
 *
 *   Shared libraries and bundles don't have direct access to environ,
 *   which is only available to the loader ld(1) when a complete program
 *   is being linked.
 *
 * So nxt_process_environ contains an address of environ to allow
 * change environ[] placement.
 */
char  ***nxt_process_environ;


#if (NXT_SETPROCTITLE_ARGV)

/*
 * A process title on Linux, Solaris, and MacOSX can be changed by
 * copying a new title to a place where the program argument argv[0]
 * points originally to.  However, the argv[0] may be too small to hold
 * the new title.  Fortunately, these OSes place the program argument
 * argv[] strings and the environment environ[] strings contiguously
 * and their space can be used for the long new process title.
 *
 * Solaris "ps" command shows the new title only if it is run in
 * UCB mode: either "/usr/ucb/ps -axwww" or "/usr/bin/ps axwww".
 */


static u_char  *nxt_process_title_start;
static u_char  *nxt_process_title_end;


void
nxt_process_arguments(nxt_task_t *task, char **orig_argv, char ***orig_envp)
{
    u_char      *p, *end, *argv_end, **argv, **env;
    size_t      size, argv_size, environ_size, strings_size;
    nxt_uint_t  i;

    nxt_process_argv = orig_argv;
    nxt_process_environ = orig_envp;

    if (orig_envp == NULL) {
        return;
    }

    /*
     * Set a conservative title space for a case if program argument
     * strings and environment strings are not contiguous.
     */
    argv = (u_char **) orig_argv;
    nxt_process_title_start = argv[0];
    nxt_process_title_end = argv[0] + nxt_strlen(argv[0]);

    end = argv[0];
    strings_size = 0;
    argv_size = sizeof(void *);

    for (i = 0; argv[i] != NULL; i++) {
        argv_size += sizeof(void *);

        if (argv[i] == end) {
            /* Argument strings are contiguous. */
            size = nxt_strlen(argv[i]) + 1;
            strings_size += size;
            end = argv[i] + size;
        }
    }

    argv = nxt_malloc(argv_size);
    if (argv == NULL) {
        return;
    }

    /*
     * Copy the entire original argv[] array.  The elements of this array
     * can point to copied strings or if original argument strings are not
     * contiguous, to the original argument strings.
     */
    nxt_memcpy(argv, orig_argv, argv_size);

    /*
     * The argv[1] must be set to NULL on Solaris otherwise the "ps"
     * command outputs strings pointed by original argv[] elements.
     * The original argv[] array has always at least two elements so
     * it is safe to set argv[1].
     */
    orig_argv[1] = NULL;

    nxt_process_argv = (char **) argv;

    argv_end = end;
    env = (u_char **) *orig_envp;
    environ_size = sizeof(void *);

    for (i = 0; env[i] != NULL; i++) {
        environ_size += sizeof(void *);

        if (env[i] == end) {
            /* Environment strings are contiguous. */
            size = nxt_strlen(env[i]) + 1;
            strings_size += size;
            end = env[i] + size;
        }
    }

    p = nxt_malloc(strings_size);
    if (p == NULL) {
        return;
    }

    if (argv_end == end) {
        /*
         * There is no reason to modify environ if arguments
         * and environment are not contiguous.
         */
        nxt_debug(task, "arguments and environment are not contiguous");
        goto done;
    }

    end = argv[0];

    for (i = 0; argv[i] != NULL; i++) {

        if (argv[i] != end) {
            /* Argument strings are not contiguous. */
            goto done;
        }

        size = nxt_strlen(argv[i]) + 1;
        nxt_memcpy(p, argv[i], size);

        end = argv[i] + size;
        argv[i] = p;
        p += size;
    }

    env = nxt_malloc(environ_size);
    if (env == NULL) {
        return;
    }

    /*
     * Copy the entire original environ[] array.  The elements of
     * this array can point to copied strings or if original environ
     * strings are not contiguous, to the original environ strings.
     */
    nxt_memcpy(env, *orig_envp, environ_size);

    /* Set the global environ variable to the new array. */
    *orig_envp = (char **) env;

    for (i = 0; env[i] != NULL; i++) {

        if (env[i] != end) {
            /* Environment strings are not contiguous. */
            goto done;
        }

        size = nxt_strlen(env[i]) + 1;
        nxt_memcpy(p, env[i], size);

        end = env[i] + size;
        env[i] = p;
        p += size;
    }

done:

    /* Preserve space for the trailing zero. */
    end--;

    nxt_process_title_end = end;
}


void
nxt_process_title(nxt_task_t *task, const char *fmt, ...)
{
    u_char   *p, *start, *end;
    va_list  args;

    start = nxt_process_title_start;

    if (start == NULL) {
        return;
    }

    end = nxt_process_title_end;

    va_start(args, fmt);
    p = nxt_vsprintf(start, end, fmt, args);
    va_end(args);

#if (NXT_SOLARIS)
    /*
     * Solaris "ps" command shows a new process title only if it is
     * longer than original command line.  A simple workaround is just
     * to append the original command line in parenthesis to the title.
     */
    {
        size_t      size;
        nxt_uint_t  i;

        size = 0;

        for (i = 0; nxt_process_argv[i] != NULL; i++) {
            size += nxt_strlen(nxt_process_argv[i]);
        }

        if (size > (size_t) (p - start)) {

            p = nxt_sprintf(p, end, " (");

            for (i = 0; nxt_process_argv[i] != NULL; i++) {
                p = nxt_sprintf(p, end, "%s ", nxt_process_argv[i]);
            }

            if (*(p - 1) == ' ') {
                *(p - 1) = ')';
            }
        }
    }
#endif

    /*
     * A process title must be padded with zeros on MacOSX.  Otherwise
     * the "ps" command may output parts of environment strings.
     */
    nxt_memset(p, '\0', end - p);

    nxt_debug(task, "setproctitle: \"%s\"", start);
}

#else /* !(NXT_SETPROCTITLE_ARGV) */

void
nxt_process_arguments(nxt_task_t *task, char **orig_argv, char ***orig_envp)
{
    nxt_process_argv = orig_argv;
    nxt_process_environ = orig_envp;
}

#endif
