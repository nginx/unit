/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Valentin V. Bartenev
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#include "nxt_tests.h"


#define UIDMAP 1
#define GIDMAP 2


typedef struct {
    nxt_int_t         map_type;
    nxt_str_t         map_data;
    nxt_int_t         setid;
    nxt_credential_t  creds;
    nxt_uid_t         unit_euid;
    nxt_gid_t         unit_egid;
    nxt_int_t         result;
    nxt_str_t         errmsg;
} nxt_clone_creds_testcase_t;

typedef struct {
    nxt_clone_creds_testcase_t  *tc;
} nxt_clone_creds_ctx_t;


nxt_int_t nxt_clone_test_mappings(nxt_task_t *task, nxt_mp_t *mp,
    nxt_clone_creds_ctx_t *ctx, nxt_clone_creds_testcase_t *tc);
void nxt_cdecl nxt_clone_test_log_handler(nxt_uint_t level, nxt_log_t *log,
    const char *fmt, ...);
nxt_int_t nxt_clone_test_map_assert(nxt_task_t *task,
    nxt_clone_creds_testcase_t *tc, nxt_clone_credential_map_t *map);
static nxt_int_t nxt_clone_test_parse_map(nxt_task_t *task,
    nxt_str_t *map_str, nxt_clone_credential_map_t *map);


nxt_log_t *test_log;

static nxt_gid_t gids[] = {1000, 10000, 60000};

static nxt_clone_creds_testcase_t testcases[] = {
    {
        /*
         * Unprivileged unit
         *
         * if no uid mapping and app creds and unit creds are the same,
         * then we automatically add a map for the creds->uid.
         * Then, child process can safely setuid(creds->uid) in
         * the new namespace.
         */
        UIDMAP,
        nxt_string(""),
        0,
        {"nobody", 65534, 65534, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        UIDMAP,
        nxt_string(""),
        0,
        {"johndoe", 10000, 10000, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        UIDMAP,
        nxt_string("[{\"container\": 1000, \"host\": 1000, \"size\": 1}]"),
        0,
        {"johndoe", 1000, 1000, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        UIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1}]"),
        0,
        {"root", 0, 0, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        UIDMAP,
        nxt_string("[{\"container\": 65534, \"host\": 1000, \"size\": 1}]"),
        0,
        {"nobody", 65534, 0, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        UIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1},"
                   " {\"container\": 1000, \"host\": 2000, \"size\": 1}]"),
        0,
        {"root", 0, 0, 0, NULL},
        1000, 1000,
        NXT_ERROR,
        nxt_string("\"uidmap\" field has 2 entries but unprivileged unit has "
                   "a maximum of 1 map.")
    },
    {
        UIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1},"
                   " {\"container\": 1000, \"host\": 2000, \"size\": 1}]"),
        1, /* privileged */
        {"root", 0, 0, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        UIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1000},"
                   " {\"container\": 1000, \"host\": 2000, \"size\": 1000}]"),
        1, /* privileged */
        {"johndoe", 500, 0, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        UIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1000},"
                   " {\"container\": 1000, \"host\": 2000, \"size\": 1000}]"),
        1, /* privileged */
        {"johndoe", 1000, 0, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        UIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1000},"
                   " {\"container\": 1000, \"host\": 2000, \"size\": 1000}]"),
        1, /* privileged */
        {"johndoe", 1500, 0, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        UIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1000},"
                   " {\"container\": 1000, \"host\": 2000, \"size\": 1000}]"),
        1, /* privileged */
        {"johndoe", 1999, 0, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        UIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1000},"
                   " {\"container\": 1000, \"host\": 2000, \"size\": 1000}]"),
        1, /* privileged */
        {"johndoe", 2000, 0, 0, NULL},
        1000, 1000,
        NXT_ERROR,
        nxt_string("\"uidmap\" field has no \"container\" entry for user "
                   "\"johndoe\" (uid 2000)")
    },
    {
        /*
         * Unprivileged unit
         *
         * if no gid mapping and app creds and unit creds are the same,
         * then we automatically add a map for the creds->base_gid.
         * Then, child process can safely setgid(creds->base_gid) in
         * the new namespace.
         */
        GIDMAP,
        nxt_string("[]"),
        0,
        {"nobody", 65534, 65534, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        /*
         * Unprivileged unit
         *
         * Inside the new namespace, we can have any gid but it
         * should map to parent gid (in this case 1000) in parent
         * namespace.
         */
        GIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1}]"),
        0,
        {"root", 0, 0, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        GIDMAP,
        nxt_string("[{\"container\": 65534, \"host\": 1000, \"size\": 1}]"),
        0,
        {"nobody", 65534, 65534, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        /*
         * Unprivileged unit
         *
         * There's no mapping for "johndoe" (gid 1000) inside the namespace.
         */
        GIDMAP,
        nxt_string("[{\"container\": 65535, \"host\": 1000, \"size\": 1}]"),
        0,
        {"johndoe", 1000, 1000, 0, NULL},
        1000, 1000,
        NXT_ERROR,
        nxt_string("\"gidmap\" field has no \"container\" entry for "
                    "gid 1000.")
    },
    {
        GIDMAP,
        nxt_string("[{\"container\": 1000, \"host\": 1000, \"size\": 2}]"),
        0,
        {"johndoe", 1000, 1000, 0, NULL},
        1000, 1000,
        NXT_ERROR,
        nxt_string("\"gidmap\" field has an entry with \"size\": 2, but "
                    "for unprivileged unit it must be 1.")
    },
    {
        GIDMAP,
        nxt_string("[{\"container\": 1000, \"host\": 1001, \"size\": 1}]"),
        0,
        {"johndoe", 1000, 1000, 0, NULL},
        1000, 1000,
        NXT_ERROR,
        nxt_string("\"gidmap\" field has an entry for host gid 1001 but "
                    "unprivileged unit can only map itself (gid 1000) "
                    "into child namespaces.")
    },
    {
        GIDMAP,
        nxt_string("[{\"container\": 1000, \"host\": 1000, \"size\": 1}]"),
        0,
        {"johndoe", 1000, 1000, 3, gids},
        1000, 1000,
        NXT_ERROR,
        nxt_string("unprivileged unit disallow supplementary groups for "
                    "new namespace (user \"johndoe\" has 3 groups).")
    },

    /* privileged unit */

    /* not root with capabilities */
    {
        GIDMAP,
        nxt_string("[]"),
        1,
        {"johndoe", 1000, 1000, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        GIDMAP,
        nxt_string(""),
        1,
        {"johndoe", 1000, 1000, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        /* missing gid of {"user": "nobody"} */
        GIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1}]"),
        1,
        {"nobody", 65534, 65534, 0, NULL},
        1000, 1000,
        NXT_ERROR,
        nxt_string("\"gidmap\" field has no \"container\" entry for "
                    "gid 65534.")
    },
    {
        /* solves the previous by mapping 65534 gids */
        GIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 65535}]"),
        1,
        {"nobody", 65534, 65534, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        /* solves by adding a separate mapping */
        GIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 1000, \"size\": 1},"
                   " {\"container\": 65534, \"host\": 1000, \"size\": 1}]"),
        1,
        {"nobody", 65534, 65534, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        /*
         * Map a big range
         */
        GIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 0, \"size\": 200000}]"),
        1,
        {"johndoe", 100000, 100000, 0, NULL},
        1000, 1000,
        NXT_OK,
        nxt_string("")
    },
    {
        /*
         * Validate if supplementary groups are mapped
         */
        GIDMAP,
        nxt_string("[]"),
        1,
        {"johndoe", 1000, 1000, 3, gids},
        1000, 1000,
        NXT_ERROR,
        nxt_string("\"gidmap\" field has no entries but user \"johndoe\" "
                   "has 3 suplementary groups."),
    },
    {
        GIDMAP,
        nxt_string("[{\"container\": 0, \"host\": 0, \"size\": 1}]"),
        1,
        {"johndoe", 1000, 1000, 3, gids},
        1000, 1000,
        NXT_ERROR,
        nxt_string("\"gidmap\" field has no \"container\" entry for "
                   "gid 1000."),
    },
    {
        GIDMAP,
        nxt_string("[{\"container\": 1000, \"host\": 0, \"size\": 1}]"),
        1,
        {"johndoe", 1000, 1000, 3, gids},
        1000, 1000,
        NXT_ERROR,
        nxt_string("\"gidmap\" field has missing suplementary gid mappings "
                   "(found 1 out of 3)."),
    },
    {
        GIDMAP,
        nxt_string("[{\"container\": 1000, \"host\": 0, \"size\": 1},"
                   " {\"container\": 10000, \"host\": 10000, \"size\": 1}]"),
        1,
        {"johndoe", 1000, 1000, 3, gids},
        1000, 1000,
        NXT_ERROR,
        nxt_string("\"gidmap\" field has missing suplementary gid mappings "
                   "(found 2 out of 3)."),
    },
    {
        /*
         * Fix all mappings
         */
        GIDMAP,
        nxt_string("[{\"container\": 1000, \"host\": 0, \"size\": 1},"
                   "{\"container\": 10000, \"host\": 10000, \"size\": 1},"
                   " {\"container\": 60000, \"host\": 60000, \"size\": 1}]"),
        1,
        {"johndoe", 1000, 1000, 3, gids},
        1000, 1000,
        NXT_OK,
        nxt_string(""),
    },
};


void nxt_cdecl
nxt_clone_test_log_handler(nxt_uint_t level, nxt_log_t *log,
    const char *fmt, ...)
{
    u_char                      *p, *end;
    va_list                     args;
    nxt_clone_creds_ctx_t       *ctx;
    nxt_clone_creds_testcase_t  *tc;
    u_char                      msg[NXT_MAX_ERROR_STR];

    p = msg;
    end = msg + NXT_MAX_ERROR_STR;

    ctx = log->ctx;
    tc = ctx->tc;

    va_start(args, fmt);
    p = nxt_vsprintf(p, end, fmt, args);
    va_end(args);

    *p++ = '\0';

    if (tc->result == NXT_OK && level == NXT_LOG_DEBUG) {
        return;
    }

    if (tc->errmsg.length == 0) {
        nxt_log_error(NXT_LOG_ERR, &nxt_main_log, "unexpected log: %s", msg);
        return;
    }

    if (!nxt_str_eq(&tc->errmsg, msg, (nxt_uint_t) (p - msg - 1))) {
        nxt_log_error(NXT_LOG_ERR, &nxt_main_log,
                      "error log mismatch: got [%s] but wants [%V]",
                      msg, &tc->errmsg);
        return;
    }
}


nxt_int_t
nxt_clone_creds_test(nxt_thread_t *thr)
{
    nxt_mp_t               *mp;
    nxt_int_t              ret;
    nxt_uint_t             count, i;
    nxt_task_t             *task;
    nxt_runtime_t          rt;
    nxt_clone_creds_ctx_t  ctx;

    nxt_log_t nxt_clone_creds_log = {
        NXT_LOG_INFO,
        0,
        nxt_clone_test_log_handler,
        NULL,
        &ctx
    };

    nxt_thread_time_update(thr);

    thr->runtime = &rt;

    task = thr->task;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        return NXT_ERROR;
    }

    rt.mem_pool = mp;

    test_log = task->log;
    task->log = &nxt_clone_creds_log;
    task->thread = thr;

    count = sizeof(testcases)/sizeof(nxt_clone_creds_testcase_t);

    for (i = 0; i < count; i++) {
        ret = nxt_clone_test_mappings(task, mp, &ctx, &testcases[i]);

        if (ret != NXT_OK) {
            goto fail;
        }
    }

    ret = NXT_OK;

    nxt_log_error(NXT_LOG_NOTICE, test_log, "clone creds test passed");

fail:
    task->log = test_log;
    nxt_mp_destroy(mp);

    return ret;
}


nxt_int_t
nxt_clone_test_mappings(nxt_task_t *task, nxt_mp_t *mp,
    nxt_clone_creds_ctx_t *ctx, nxt_clone_creds_testcase_t *tc)
{
    nxt_int_t                   ret;
    nxt_runtime_t               *rt;
    nxt_clone_credential_map_t  map;

    rt = task->thread->runtime;

    map.size = 0;

    if (tc->map_data.length > 0) {
        ret = nxt_clone_test_parse_map(task, &tc->map_data, &map);
        if (ret != NXT_OK) {
            return NXT_ERROR;
        }
    }

    rt->capabilities.setid = tc->setid;

    nxt_euid = tc->unit_euid;
    nxt_egid = tc->unit_egid;

    ctx->tc = tc;

    if (nxt_clone_test_map_assert(task, tc, &map) != NXT_OK) {
        return NXT_ERROR;
    }

    if (tc->setid && nxt_euid != 0) {
        /*
         * Running as root should have the same behavior as
         * passing Linux capabilities.
         */

        nxt_euid = 0;
        nxt_egid = 0;

        if (nxt_clone_test_map_assert(task, tc, &map) != NXT_OK) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


nxt_int_t
nxt_clone_test_map_assert(nxt_task_t *task, nxt_clone_creds_testcase_t *tc,
    nxt_clone_credential_map_t *map)
{
    nxt_int_t ret;

    if (tc->map_type == UIDMAP) {
        ret = nxt_clone_vldt_credential_uidmap(task, map, &tc->creds);
    } else {
        ret = nxt_clone_vldt_credential_gidmap(task, map, &tc->creds);
    }

    if (ret != tc->result) {
        nxt_log_error(NXT_LOG_ERR, &nxt_main_log,
                      "return %d instead of %d (map: %V)", ret, tc->result,
                      &tc->map_data);

        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_clone_test_parse_map(nxt_task_t *task, nxt_str_t *map_str,
    nxt_clone_credential_map_t *map)
{
    nxt_uint_t        i;
    nxt_runtime_t     *rt;
    nxt_conf_value_t  *array, *obj, *value;

    static nxt_str_t  host_name = nxt_string("host");
    static nxt_str_t  cont_name = nxt_string("container");
    static nxt_str_t  size_name = nxt_string("size");

    rt = task->thread->runtime;

    array = nxt_conf_json_parse_str(rt->mem_pool, map_str);
    if (array == NULL) {
        return NXT_ERROR;
    }

    map->size = nxt_conf_array_elements_count(array);

    if (map->size == 0) {
        return NXT_OK;
    }

    map->map = nxt_mp_alloc(rt->mem_pool,
                            map->size * sizeof(nxt_clone_map_entry_t));

    if (map->map == NULL) {
        return NXT_ERROR;
    }

    for (i = 0; i < map->size; i++) {
        obj = nxt_conf_get_array_element(array, i);

        value = nxt_conf_get_object_member(obj, &host_name, NULL);
        map->map[i].host = nxt_conf_get_number(value);

        value = nxt_conf_get_object_member(obj, &cont_name, NULL);
        map->map[i].container = nxt_conf_get_number(value);

        value = nxt_conf_get_object_member(obj, &size_name, NULL);
        map->map[i].size = nxt_conf_get_number(value);
    }

    return NXT_OK;
}
