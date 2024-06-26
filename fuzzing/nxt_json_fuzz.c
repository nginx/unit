/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#include <nxt_router.h>

#define KMININPUTLENGTH 2
#define KMAXINPUTLENGTH 1024


extern int LLVMFuzzerInitialize(int *argc, char ***argv);
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);


extern char  **environ;


int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    if (nxt_lib_start("fuzzing", NULL, &environ) != NXT_OK) {
        return NXT_ERROR;
    }

    return 0;
}


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    nxt_mp_t               *mp;
    nxt_str_t              input;
    nxt_thread_t           *thr;
    nxt_runtime_t          *rt;
    nxt_conf_value_t       *conf;
    nxt_conf_validation_t  vldt;

    if (size < KMININPUTLENGTH || size > KMAXINPUTLENGTH) {
        return 0;
    }

    thr = nxt_thread();

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        return 0;
    }

    rt = nxt_mp_zget(mp, sizeof(nxt_runtime_t));
    if (rt == NULL) {
        goto failed;
    }

    thr->runtime = rt;
    rt->mem_pool = mp;

    input.start = (u_char *)data;
    input.length = size;

    conf = nxt_conf_json_parse_str(mp, &input);
    if (conf == NULL) {
        goto failed;
    }

    nxt_memzero(&vldt, sizeof(nxt_conf_validation_t));

    vldt.pool = nxt_mp_create(1024, 128, 256, 32);
    if (vldt.pool == NULL) {
        goto failed;
    }

    vldt.conf = conf;
    vldt.conf_pool = mp;
    vldt.ver = NXT_VERNUM;

    rt->languages = nxt_array_create(mp, 1, sizeof(nxt_app_lang_module_t));
    if (rt->languages == NULL) {
        goto failed;
    }

    nxt_conf_validate(&vldt);

    nxt_mp_destroy(vldt.pool);

failed:

    nxt_mp_destroy(mp);

    return 0;
}
