
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


extern char  **environ;

static nxt_int_t nxt_utf8_file_name_test(nxt_thread_t *thr);


nxt_module_init_t  nxt_init_modules[1];
nxt_uint_t         nxt_init_modules_n;


int nxt_cdecl
main(int argc, char **argv)
{
    nxt_thread_t     *thr;

    if (nxt_lib_start("utf8_file_name_test", argv, &environ) != NXT_OK) {
        return 1;
    }

    nxt_main_log.level = NXT_LOG_INFO;

    thr = nxt_thread();

    if (nxt_utf8_file_name_test(thr) != NXT_OK) {
        return 1;
    }

    return 0;
}


static nxt_int_t
nxt_utf8_file_name_test(nxt_thread_t *thr)
{
    u_char               *p, test[4], buf[32];
    ssize_t              n;
    uint32_t             uc, lc;
    nxt_int_t            ret;
    nxt_task_t           task;
    nxt_file_t           uc_file, lc_file;
    const u_char         *pp;
    nxt_file_name_t      uc_name[10], lc_name[10];
    static const u_char  utf8[4] = "UTF8";

    nxt_thread_time_update(thr);

    uc_name[0] = 'u';
    uc_name[1] = 't';
    uc_name[2] = 'f';
    uc_name[3] = '8';
    uc_name[4] = '_';

    lc_name[0] = 'u';
    lc_name[1] = 't';
    lc_name[2] = 'f';
    lc_name[3] = '8';
    lc_name[4] = '_';

    nxt_memzero(&uc_file, sizeof(nxt_file_t));

    uc_file.name = uc_name;
    uc_file.log_level = NXT_LOG_ALERT;

    nxt_memzero(&lc_file, sizeof(nxt_file_t));

    lc_file.name = lc_name;

    task.thread = thr;
    task.log = thr->log;

    for (uc = 0x41; uc < 0x110000; uc++) {

        p = nxt_utf8_encode(&uc_name[5], uc);

        if (p == NULL) {
            nxt_log_alert(thr->log, "nxt_utf8_encode(%05uxD) failed", uc);
            return NXT_ERROR;
        }

        *p = '\0';

        pp = &uc_name[5];
        lc = nxt_utf8_lowcase(&pp, p);

        if (lc == 0xFFFFFFFF) {
            nxt_log_alert(thr->log, "nxt_utf8_lowcase(%05uxD) failed: %05uxD",
                          uc, lc);
            return NXT_ERROR;
        }

        if (uc == lc) {
            continue;
        }

        p = nxt_utf8_encode(&lc_name[5], lc);

        if (p == NULL) {
            nxt_log_alert(thr->log, "nxt_utf8_encode(%05uxD) failed", lc);
            return NXT_ERROR;
        }

        *p = '\0';

        ret = nxt_file_open(&task, &uc_file, NXT_FILE_WRONLY, NXT_FILE_TRUNCATE,
                            NXT_FILE_DEFAULT_ACCESS);
        if (ret != NXT_OK) {
            return NXT_ERROR;
        }

        if (nxt_file_write(&uc_file, utf8, 4, 0) != 4) {
            return NXT_ERROR;
        }

        nxt_file_close(&task, &uc_file);

        ret = nxt_file_open(&task, &lc_file, NXT_FILE_RDONLY, NXT_FILE_OPEN,
                            NXT_FILE_DEFAULT_ACCESS);

        if (ret == NXT_OK) {
            n = nxt_file_read(&lc_file, test, 4, 0);

            nxt_file_close(&task, &lc_file);

            if (n != 4 || memcmp(utf8, test, 4) != 0) {
                nxt_log_alert(thr->log, "nxt_file_read() mismatch");

                nxt_file_delete(lc_file.name);
            }

            p = nxt_sprintf(buf, buf + 32, "%04uXD; C; %04uXD;%n", uc, lc);

            nxt_fd_write(nxt_stdout, buf, p - buf);
        }

        nxt_file_delete(uc_file.name);
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "utf8 file name test passed");
    return NXT_OK;
}
