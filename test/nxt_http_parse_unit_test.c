
/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Valentin V. Bartenev
 */

#include <nxt_main.h>


typedef struct {
    nxt_str_t  method;
    nxt_str_t  target;
    nxt_str_t  exten;
    nxt_str_t  args;
    u_char     version[8];

    /* target with "/." */
    unsigned   complex_target:1;
    /* target with "%" */
    unsigned   quoted_target:1;
    /* target with " " */
    unsigned   space_in_target:1;
    /* target with "+" */
    unsigned   plus_in_target:1;
} nxt_http_parse_unit_test_request_line_t;


typedef union {
    void                                     *pointer;
    nxt_http_parse_unit_test_request_line_t  request_line;
} nxt_http_parse_unit_test_data_t;


typedef struct {
    nxt_str_t  request;
    nxt_int_t  result;
    nxt_int_t  (*handler)(nxt_http_request_parse_t *rp,
                          nxt_http_parse_unit_test_data_t *data,
                          nxt_str_t *request, nxt_log_t *log);

    nxt_http_parse_unit_test_data_t  data;
} nxt_http_parse_unit_test_case_t;


static nxt_int_t nxt_http_parse_unit_test_run(nxt_http_request_parse_t *rp,
    nxt_str_t *request);

static nxt_int_t nxt_http_parse_unit_test_request_line(
    nxt_http_request_parse_t *rp, nxt_http_parse_unit_test_data_t *data,
    nxt_str_t *request, nxt_log_t *log);

static nxt_int_t nxt_http_unit_test_header_return(void *ctx, nxt_str_t *name,
    nxt_str_t *value, uintptr_t data);


static nxt_http_parse_unit_test_case_t  nxt_http_unit_test_cases[] = {
    {
        nxt_string("GET / HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_unit_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/"),
            nxt_null_string,
            nxt_null_string,
            "HTTP/1.0",
            0, 0, 0, 0
        }}
    },
    {
        nxt_string("XXX-METHOD    /d.ir/fi+le.ext?key=val    HTTP/1.2\n\n"),
        NXT_DONE,
        &nxt_http_parse_unit_test_request_line,
        { .request_line = {
            nxt_string("XXX-METHOD"),
            nxt_string("/d.ir/fi+le.ext?key=val"),
            nxt_string("ext?key=val"),
            nxt_string("key=val"),
            "HTTP/1.2",
            0, 0, 0, 1
        }}
    },
    {
        nxt_string("GET /di.r/? HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_unit_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/di.r/?"),
            nxt_null_string,
            nxt_string(""),
            "HTTP/1.0",
            0, 0, 0, 0
        }}
    },
    {
        nxt_string("GEt / HTTP/1.0\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET /\0 HTTP/1.0\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET /\r HTTP/1.0\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET /\n HTTP/1.0\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.0\r\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET /. HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_unit_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/."),
            nxt_null_string,
            nxt_null_string,
            "HTTP/1.0",
            1, 0, 0, 0
        }}
    },
    {
        nxt_string("GET /# HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_unit_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/#"),
            nxt_null_string,
            nxt_null_string,
            "HTTP/1.0",
            1, 0, 0, 0
        }}
    },
    {
        nxt_string("GET /?# HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_unit_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/?#"),
            nxt_null_string,
            nxt_string("#"),
            "HTTP/1.0",
            1, 0, 0, 0
        }}
    },
    {
        nxt_string("GET // HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_unit_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("//"),
            nxt_null_string,
            nxt_null_string,
            "HTTP/1.0",
            1, 0, 0, 0
        }}
    },
    {
        nxt_string("GET /%20 HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_unit_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/%20"),
            nxt_null_string,
            nxt_null_string,
            "HTTP/1.0",
            0, 1, 0, 0
        }}
    },
    {
        nxt_string("GET / a HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_unit_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/ a"),
            nxt_null_string,
            nxt_null_string,
            "HTTP/1.0",
            0, 0, 1, 0
        }}
    },
    {
        nxt_string("GET / HTTP/1.0 HTTP/1.1\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_unit_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/ HTTP/1.0"),
            nxt_null_string,
            nxt_null_string,
            "HTTP/1.1",
            0, 0, 1, 0
        }}
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host: example.com\r\n\r\n"),
        NXT_DONE,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   ":Host: example.com\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Ho_st: example.com\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Ho\0st: example.com\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Ho\rst: example.com\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host: exa\0mple.com\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host: exa\rmple.com\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "X-Bad-Header: value\r\n\r\n"),
        NXT_ERROR,
        NULL, { NULL }
    },
};


static nxt_http_fields_t  nxt_http_unit_test_headers[] = {
    { nxt_string("X-Bad-Header"),
      &nxt_http_unit_test_header_return,
      (uintptr_t) NXT_ERROR },

    { nxt_null_string, NULL, 0 }
};


nxt_int_t
nxt_http_parse_unit_test(nxt_thread_t *thr)
{
    nxt_int_t                        rc;
    nxt_uint_t                       i;
    nxt_mem_pool_t                   *pool;
    nxt_http_fields_hash_t           *hash;
    nxt_http_request_parse_t         rp;
    nxt_http_parse_unit_test_case_t  *test;

    nxt_thread_time_update(thr);

    pool = nxt_mem_pool_create(512);
    if (pool == NULL) {
        return NXT_ERROR;
    }

    hash = nxt_http_fields_hash(nxt_http_unit_test_headers, pool);

    if (hash == NULL) {
        return NXT_ERROR;
    }

    for (i = 0; i < nxt_nitems(nxt_http_unit_test_cases); i++) {
        test = &nxt_http_unit_test_cases[i];

        nxt_memzero(&rp, sizeof(nxt_http_request_parse_t));

        rp.hash = hash;

        rc = nxt_http_parse_unit_test_run(&rp, &test->request);

        if (rc != test->result) {
            nxt_log_alert(thr->log, "http parse unit test case failed:\n"
                                    " - request:\n\"%V\"\n"
                                    " - result: %i (expected: %i)",
                                    &test->request, rc, test->result);
            return NXT_ERROR;
        }

        if (test->handler != NULL
            && test->handler(&rp, &test->data, &test->request, thr->log)
               != NXT_OK)
        {
            return NXT_ERROR;
        }
    }

    nxt_mem_pool_destroy(pool);

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "http parse unit test passed");

    return NXT_OK;
}


static nxt_int_t
nxt_http_parse_unit_test_run(nxt_http_request_parse_t *rp, nxt_str_t *request)
{
    nxt_int_t      rc;
    nxt_buf_mem_t  buf;

    buf.start = request->start;
    buf.end = request->start + request->length;

    buf.pos = buf.start;
    buf.free = buf.pos + 1;

    do {
        buf.free++;
        rc = nxt_http_parse_request(rp, &buf);
    } while (buf.free < buf.end && rc == NXT_AGAIN);

    return rc;
}


static nxt_int_t
nxt_http_parse_unit_test_request_line(nxt_http_request_parse_t *rp,
    nxt_http_parse_unit_test_data_t *data, nxt_str_t *request, nxt_log_t *log)
{
    nxt_str_t  str;

    nxt_http_parse_unit_test_request_line_t  *test = &data->request_line;

    if (rp->method.start != test->method.start
        && !nxt_strstr_eq(&rp->method, &test->method))
    {
        nxt_log_alert(log, "http parse unit test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - method: \"%V\" (expected: \"%V\")",
                           request, &rp->method, &test->method);
        return NXT_ERROR;
    }

    str.length = rp->target_end - rp->target_start;
    str.start = rp->target_start;

    if (str.start != test->target.start
        && !nxt_strstr_eq(&str, &test->target))
    {
        nxt_log_alert(log, "http parse unit test case failed:\n"
                            " - request:\n\"%V\"\n"
                            " - target: \"%V\" (expected: \"%V\")",
                            request, &str, &test->target);
        return NXT_ERROR;
    }

    str.length = (rp->exten_start != NULL) ? rp->target_end - rp->exten_start
                                           : 0;
    str.start = rp->exten_start;

    if (str.start != test->exten.start
        && !nxt_strstr_eq(&str, &test->exten))
    {
        nxt_log_alert(log, "http parse unit test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - exten: \"%V\" (expected: \"%V\")",
                           request, &str, &test->exten);
        return NXT_ERROR;
    }

    str.length = (rp->args_start != NULL) ? rp->target_end - rp->args_start
                                          : 0;
    str.start = rp->args_start;

    if (str.start != test->args.start
        && !nxt_strstr_eq(&str, &test->args))
    {
        nxt_log_alert(log, "http parse unit test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - args: \"%V\" (expected: \"%V\")",
                           request, &str, &test->args);
        return NXT_ERROR;
    }

    if (nxt_memcmp(rp->version.str, test->version, 8) != 0) {
        nxt_log_alert(log, "http parse unit test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - version: \"%*s\" (expected: \"%*s\")",
                           request, 8, rp->version.str, 8, test->version);
        return NXT_ERROR;
    }

    if (rp->complex_target != test->complex_target) {
        nxt_log_alert(log, "http parse unit test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - complex_target: %d (expected: %d)",
                           request, rp->complex_target, test->complex_target);
        return NXT_ERROR;
    }

    if (rp->quoted_target != test->quoted_target) {
        nxt_log_alert(log, "http parse unit test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - quoted_target: %d (expected: %d)",
                           request, rp->quoted_target, test->quoted_target);
        return NXT_ERROR;
    }

    if (rp->space_in_target != test->space_in_target) {
        nxt_log_alert(log, "http parse unit test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - space_in_target: %d (expected: %d)",
                           request, rp->space_in_target, test->space_in_target);
        return NXT_ERROR;
    }

    if (rp->plus_in_target != test->plus_in_target) {
        nxt_log_alert(log, "http parse unit test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - plus_in_target: %d (expected: %d)",
                           request, rp->plus_in_target, test->plus_in_target);
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_unit_test_header_return(void *ctx, nxt_str_t *name, nxt_str_t *value,
    uintptr_t data)
{
    return (nxt_int_t) data;
}
