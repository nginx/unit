
/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Valentin V. Bartenev
 */

#include <nxt_main.h>
#include "nxt_tests.h"


typedef struct {
    nxt_str_t  method;
    nxt_str_t  target;
    nxt_str_t  args;
    u_char     version[8];

    /* target with "/." */
    unsigned   complex_target:1;
    /* target with "%" */
    unsigned   quoted_target:1;
    /* target with " " */
    unsigned   space_in_target:1;
} nxt_http_parse_test_request_line_t;


typedef struct {
    nxt_int_t  result;
    unsigned   discard_unsafe_fields:1;
} nxt_http_parse_test_fields_t;


typedef union {
    void                                *pointer;
    nxt_http_parse_test_fields_t        fields;
    nxt_http_parse_test_request_line_t  request_line;
} nxt_http_parse_test_data_t;


typedef struct {
    nxt_str_t  request;
    nxt_int_t  result;
    nxt_int_t  (*handler)(nxt_http_request_parse_t *rp,
                          nxt_http_parse_test_data_t *data,
                          nxt_str_t *request, nxt_log_t *log);

    nxt_http_parse_test_data_t  data;
} nxt_http_parse_test_case_t;


static nxt_int_t nxt_http_parse_test_run(nxt_http_request_parse_t *rp,
    nxt_str_t *request);
static nxt_int_t nxt_http_parse_test_bench(nxt_thread_t *thr,
    nxt_str_t *request, nxt_lvlhsh_t *hash, const char *name, nxt_uint_t n);
static nxt_int_t nxt_http_parse_test_request_line(nxt_http_request_parse_t *rp,
    nxt_http_parse_test_data_t *data,
    nxt_str_t *request, nxt_log_t *log);
static nxt_int_t nxt_http_parse_test_fields(nxt_http_request_parse_t *rp,
    nxt_http_parse_test_data_t *data, nxt_str_t *request, nxt_log_t *log);


static nxt_int_t nxt_http_test_header_return(void *ctx, nxt_http_field_t *field,
    uintptr_t data);


static nxt_http_parse_test_case_t  nxt_http_test_cases[] = {
    {
        nxt_string("GET / HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/"),
            nxt_null_string,
            "HTTP/1.0",
            0, 0, 0
        }}
    },
    {
        nxt_string("XXX-METHOD    /d.ir/fi+le.ext?key=val    HTTP/1.2\n\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("XXX-METHOD"),
            nxt_string("/d.ir/fi+le.ext?key=val"),
            nxt_string("key=val"),
            "HTTP/1.2",
            0, 0, 0
        }}
    },
    {
        nxt_string("GET /di.r/? HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/di.r/?"),
            nxt_string(""),
            "HTTP/1.0",
            0, 0, 0
        }}
    },
    {
        nxt_string("GEt / HTTP/1.0\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET /\0 HTTP/1.0\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET /\r HTTP/1.0\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET /\n HTTP/1.0\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.0\r\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/2.0\r\n"),
        NXT_HTTP_PARSE_UNSUPPORTED_VERSION,
        NULL, { NULL }
    },
    {
        nxt_string("GET /. HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/."),
            nxt_null_string,
            "HTTP/1.0",
            1, 0, 0
        }}
    },
    {
        nxt_string("GET /# HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/#"),
            nxt_null_string,
            "HTTP/1.0",
            1, 0, 0
        }}
    },
    {
        nxt_string("GET /?# HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/?#"),
            nxt_string(""),
            "HTTP/1.0",
            1, 0, 0
        }}
    },
    {
        nxt_string("GET // HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("//"),
            nxt_null_string,
            "HTTP/1.0",
            1, 0, 0
        }}
    },
    {
        nxt_string("GET /%20 HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/%20"),
            nxt_null_string,
            "HTTP/1.0",
            0, 1, 0
        }}
    },
    {
        nxt_string("GET / a HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/ a"),
            nxt_null_string,
            "HTTP/1.0",
            0, 0, 1
        }}
    },
    {
        nxt_string("GET /na %20me.ext?args HTTP/1.0\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/na %20me.ext?args"),
            nxt_string("args"),
            "HTTP/1.0",
            0, 1, 1
        }}
    },
    {
        nxt_string("GET / HTTP/1.0 HTTP/1.1\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_request_line,
        { .request_line = {
            nxt_string("GET"),
            nxt_string("/ HTTP/1.0"),
            nxt_null_string,
            "HTTP/1.1",
            0, 0, 1
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
                   "Host:example.com \r\n\r\n"),
        NXT_DONE,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host:\r\n\r\n"),
        NXT_DONE,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host example.com\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   ":Host: example.com\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Ho_st: example.com\r\n\r\n"),
        NXT_DONE,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Ho\0st: example.com\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Ho\rst: example.com\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Ho\nst: example.com\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host : example.com\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host: exa\0mple.com\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host: exa\rmple.com\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host: exa\bmple.com\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host: пример.испытание\r\n\r\n"),
        NXT_DONE,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host: xn--e1afmkfd.xn--80akhbyknj4f\r\n\r\n"),
        NXT_DONE,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host: exa\nmple.com\r\n\r\n"),
        NXT_HTTP_PARSE_INVALID,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "Host: exa\tmple.com\r\n\r\n"),
        NXT_DONE,
        NULL, { NULL }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "X-Unknown-Header: value\r\n"
                   "X-Good-Header: value\r\n"
                   "!#$%&'*+.^_`|~: skipped\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_fields,
        { .fields = { NXT_OK, 1 } }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "X-Good-Header: value\r\n"
                   "X-Unknown-Header: value\r\n"
                   "X-Bad-Header: value\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_fields,
        { .fields = { NXT_ERROR, 1 } }
    },
    {
        nxt_string("GET / HTTP/1.1\r\n"
                   "!#$%&'*+.^_`|~: allowed\r\n\r\n"),
        NXT_DONE,
        &nxt_http_parse_test_fields,
        { .fields = { NXT_ERROR, 0 } }
    },
};


static nxt_http_field_proc_t  nxt_http_test_fields[] = {
    { nxt_string("X-Bad-Header"),
      &nxt_http_test_header_return,
      NXT_ERROR },

    { nxt_string("X-Good-Header"),
      &nxt_http_test_header_return,
      NXT_OK },

    { nxt_string("!#$%&'*+.^_`|~"),
      &nxt_http_test_header_return,
      NXT_ERROR },
};


static nxt_lvlhsh_t  nxt_http_test_fields_hash;


static nxt_http_field_proc_t  nxt_http_test_bench_fields[] = {
    { nxt_string("Host"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("User-Agent"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Accept"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Accept-Encoding"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Accept-Language"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Connection"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Content-Length"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Content-Range"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Content-Type"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Cookie"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Range"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("If-Range"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Transfer-Encoding"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Expect"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Via"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("If-Modified-Since"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("If-Unmodified-Since"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("If-Match"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("If-None-Match"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Referer"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Date"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Upgrade"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Authorization"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Keep-Alive"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Forwarded-For"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Forwarded-Host"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Forwarded-Proto"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Http-Method-Override"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Real-IP"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("X-Request-ID"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("TE"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Pragma"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Cache-Control"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Origin"),
      &nxt_http_test_header_return, NXT_OK },
    { nxt_string("Upgrade-Insecure-Requests"),
      &nxt_http_test_header_return, NXT_OK },
};


static nxt_str_t nxt_http_test_simple_request = nxt_string(
    "GET /page HTTP/1.1\r\n"
    "Host: example.com\r\n\r\n"
);


static nxt_str_t nxt_http_test_big_request = nxt_string(
    "POST /path/to/very/interesting/article/on.this.site?arg1=value&arg2=value"
        "2&very_big_arg=even_bigger_value HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "User-Agent: Mozilla/5.0 (X11; Gentoo Linux x86_64; rv:42.0) Firefox/42.0"
        "\r\n"
    "Accept: text/html,application/json,application/xml;q=0.9,*/*;q=0.8\r\n"
    "Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4\r\n"
    "Accept-Encoding: gzip, deflate, br\r\n"
    "If-Modified-Since: Wed, 31 Dec 1986 16:00:00 GMT\r\n"
    "Referer: https://example.org/path/to/not-interesting/article.html\r\n"
    "Cookie: name=value; name2=value2; some_big_cookie=iVBORw0KGgoAAAANSUhEUgA"
        "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\r\n"
    "Connection: keep-alive\r\n"
    "Content-Length: 0\r\n"
    "Upgrade-Insecure-Requests: 1\r\n"
    "Pragma: no-cache\r\n"
    "Cache-Control: no-cache\r\n"
    "X-Forwarded-For: 192.0.2.0, 198.51.100.0, 203.0.113.0\r\n"
    "\r\n"
);


nxt_int_t
nxt_http_parse_test(nxt_thread_t *thr)
{
    nxt_mp_t                    *mp_temp;
    nxt_int_t                   rc;
    nxt_uint_t                  i, colls, lvl_colls;
    nxt_lvlhsh_t                hash;
    nxt_http_request_parse_t    rp;
    nxt_http_parse_test_case_t  *test;

    nxt_thread_time_update(thr);

    rc = nxt_http_fields_hash(&nxt_http_test_fields_hash,
                              nxt_http_test_fields,
                              nxt_nitems(nxt_http_test_fields));
    if (rc != NXT_OK) {
        return NXT_ERROR;
    }

    for (i = 0; i < nxt_nitems(nxt_http_test_cases); i++) {
        test = &nxt_http_test_cases[i];

        nxt_memzero(&rp, sizeof(nxt_http_request_parse_t));

        mp_temp = nxt_mp_create(1024, 128, 256, 32);
        if (mp_temp == NULL) {
            return NXT_ERROR;
        }

        if (nxt_http_parse_request_init(&rp, mp_temp) != NXT_OK) {
            return NXT_ERROR;
        }

        if (test->handler == &nxt_http_parse_test_fields) {
            rp.discard_unsafe_fields = test->data.fields.discard_unsafe_fields;
        }

        rc = nxt_http_parse_test_run(&rp, &test->request);

        if (rc != test->result) {
            nxt_log_alert(thr->log, "http parse test case failed:\n"
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

        nxt_mp_destroy(mp_temp);
    }

    nxt_log_error(NXT_LOG_NOTICE, thr->log, "http parse test passed");

    nxt_memzero(&hash, sizeof(nxt_lvlhsh_t));

    colls = nxt_http_fields_hash_collisions(&hash,
                                        nxt_http_test_bench_fields,
                                        nxt_nitems(nxt_http_test_bench_fields),
                                        0);

    nxt_memzero(&hash, sizeof(nxt_lvlhsh_t));

    lvl_colls = nxt_http_fields_hash_collisions(&hash,
                                        nxt_http_test_bench_fields,
                                        nxt_nitems(nxt_http_test_bench_fields),
                                        1);

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "http parse test hash collisions %ui out of %uz, level: %ui",
                  colls, nxt_nitems(nxt_http_test_bench_fields), lvl_colls);

    nxt_memzero(&hash, sizeof(nxt_lvlhsh_t));

    rc = nxt_http_fields_hash(&hash, nxt_http_test_bench_fields,
                              nxt_nitems(nxt_http_test_bench_fields));
    if (rc != NXT_OK) {
        return NXT_ERROR;
    }

    if (nxt_http_parse_test_bench(thr, &nxt_http_test_simple_request,
                                  &hash, "simple", 1000000)
        != NXT_OK)
    {
        return NXT_ERROR;
    }

    if (nxt_http_parse_test_bench(thr, &nxt_http_test_big_request,
                                  &hash, "big", 100000)
        != NXT_OK)
    {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_parse_test_run(nxt_http_request_parse_t *rp, nxt_str_t *request)
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
nxt_http_parse_test_bench(nxt_thread_t *thr, nxt_str_t *request,
    nxt_lvlhsh_t *hash, const char *name, nxt_uint_t n)
{
    nxt_mp_t                  *mp;
    nxt_nsec_t                start, end;
    nxt_uint_t                i;
    nxt_buf_mem_t             buf;
    nxt_http_request_parse_t  rp;

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "http parse %s request bench started: %uz bytes, %ui runs",
                  name, request->length, n);

    buf.start = request->start;
    buf.end = request->start + request->length;

    nxt_thread_time_update(thr);
    start = nxt_thread_monotonic_time(thr);

    for (i = 0; nxt_fast_path(i < n); i++) {
        nxt_memzero(&rp, sizeof(nxt_http_request_parse_t));

        mp = nxt_mp_create(1024, 128, 256, 32);
        if (nxt_slow_path(mp == NULL)) {
            return NXT_ERROR;
        }

        if (nxt_slow_path(nxt_http_parse_request_init(&rp, mp) != NXT_OK)) {
            return NXT_ERROR;
        }

        buf.pos = buf.start;
        buf.free = buf.end;

        if (nxt_slow_path(nxt_http_parse_request(&rp, &buf) != NXT_DONE)) {
            nxt_log_alert(thr->log, "http parse %s request bench failed "
                                    "while parsing", name);
            return NXT_ERROR;
        }

        if (nxt_slow_path(nxt_http_fields_process(rp.fields, hash, NULL)
                          != NXT_OK))
        {
            nxt_log_alert(thr->log, "http parse %s request bench failed "
                                    "while fields processing", name);
            return NXT_ERROR;
        }

        nxt_mp_destroy(mp);
    }

    nxt_thread_time_update(thr);
    end = nxt_thread_monotonic_time(thr);

    nxt_log_error(NXT_LOG_NOTICE, thr->log,
                  "http parse %s request bench: %0.3fs",
                  name, (end - start) / 1000000000.0);

    return NXT_OK;
}


static nxt_int_t
nxt_http_parse_test_request_line(nxt_http_request_parse_t *rp,
    nxt_http_parse_test_data_t *data, nxt_str_t *request, nxt_log_t *log)
{
    nxt_str_t  str;

    nxt_http_parse_test_request_line_t  *test = &data->request_line;

    if (rp->method.start != test->method.start
        && !nxt_strstr_eq(&rp->method, &test->method))
    {
        nxt_log_alert(log, "http parse test case failed:\n"
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
        nxt_log_alert(log, "http parse test case failed:\n"
                            " - request:\n\"%V\"\n"
                            " - target: \"%V\" (expected: \"%V\")",
                            request, &str, &test->target);
        return NXT_ERROR;
    }

    if (rp->args.start != test->args.start
        && !nxt_strstr_eq(&rp->args, &test->args))
    {
        nxt_log_alert(log, "http parse test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - args: \"%V\" (expected: \"%V\")",
                           request, &rp->args, &test->args);
        return NXT_ERROR;
    }

    if (memcmp(rp->version.str, test->version, 8) != 0) {
        nxt_log_alert(log, "http parse test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - version: \"%*s\" (expected: \"%*s\")", request,
                           (size_t) 8, rp->version.str,
                           (size_t) 8, test->version);
        return NXT_ERROR;
    }

    if (rp->complex_target != test->complex_target) {
        nxt_log_alert(log, "http parse test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - complex_target: %d (expected: %d)",
                           request, rp->complex_target, test->complex_target);
        return NXT_ERROR;
    }

    if (rp->quoted_target != test->quoted_target) {
        nxt_log_alert(log, "http parse test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - quoted_target: %d (expected: %d)",
                           request, rp->quoted_target, test->quoted_target);
        return NXT_ERROR;
    }

#if 0
    if (rp->space_in_target != test->space_in_target) {
        nxt_log_alert(log, "http parse test case failed:\n"
                           " - request:\n\"%V\"\n"
                           " - space_in_target: %d (expected: %d)",
                           request, rp->space_in_target, test->space_in_target);
        return NXT_ERROR;
    }
#endif

    return NXT_OK;
}


static nxt_int_t
nxt_http_parse_test_fields(nxt_http_request_parse_t *rp,
    nxt_http_parse_test_data_t *data, nxt_str_t *request, nxt_log_t *log)
{
    nxt_int_t  rc;

    rc = nxt_http_fields_process(rp->fields, &nxt_http_test_fields_hash, NULL);

    if (rc != data->fields.result) {
        nxt_log_alert(log, "http parse test hash failed:\n"
                           " - request:\n\"%V\"\n"
                           " - result: %i (expected: %i)",
                           request, rc, data->fields.result);
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_test_header_return(void *ctx, nxt_http_field_t *field, uintptr_t data)
{
    return data;
}
