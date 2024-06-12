/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_conf.h>


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
    nxt_conf_value_t       *conf;
    nxt_conf_validation_t  vldt;

    if (size < KMININPUTLENGTH || size > KMAXINPUTLENGTH) {
        return 0;
    }

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        return 0;
    }

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

    nxt_conf_validate(&vldt);

    nxt_mp_destroy(vldt.pool);

failed:

    nxt_mp_destroy(mp);

    return 0;
}
