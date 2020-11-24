
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_sockaddr.h>
#include <nxt_http_route_addr.h>
#include <nxt_regex.h>


typedef enum {
    NXT_HTTP_ROUTE_TABLE = 0,
    NXT_HTTP_ROUTE_STRING,
    NXT_HTTP_ROUTE_STRING_PTR,
    NXT_HTTP_ROUTE_HEADER,
    NXT_HTTP_ROUTE_ARGUMENT,
    NXT_HTTP_ROUTE_COOKIE,
    NXT_HTTP_ROUTE_SCHEME,
    NXT_HTTP_ROUTE_SOURCE,
    NXT_HTTP_ROUTE_DESTINATION,
} nxt_http_route_object_t;


typedef enum {
    NXT_HTTP_ROUTE_PATTERN_EXACT = 0,
    NXT_HTTP_ROUTE_PATTERN_BEGIN,
    NXT_HTTP_ROUTE_PATTERN_END,
    NXT_HTTP_ROUTE_PATTERN_SUBSTRING,
} nxt_http_route_pattern_type_t;


typedef enum {
    NXT_HTTP_ROUTE_PATTERN_NOCASE = 0,
    NXT_HTTP_ROUTE_PATTERN_LOWCASE,
    NXT_HTTP_ROUTE_PATTERN_UPCASE,
} nxt_http_route_pattern_case_t;


typedef enum {
    NXT_HTTP_ROUTE_ENCODING_NONE = 0,
    NXT_HTTP_ROUTE_ENCODING_URI,
    NXT_HTTP_ROUTE_ENCODING_URI_PLUS
} nxt_http_route_encoding_t;


typedef struct {
    nxt_conf_value_t               *pass;
    nxt_conf_value_t               *ret;
    nxt_str_t                      location;
    nxt_conf_value_t               *share;
    nxt_conf_value_t               *proxy;
    nxt_conf_value_t               *fallback;
} nxt_http_route_action_conf_t;


typedef struct {
    nxt_conf_value_t               *host;
    nxt_conf_value_t               *uri;
    nxt_conf_value_t               *method;
    nxt_conf_value_t               *headers;
    nxt_conf_value_t               *arguments;
    nxt_conf_value_t               *cookies;
    nxt_conf_value_t               *scheme;
    nxt_conf_value_t               *source;
    nxt_conf_value_t               *destination;
} nxt_http_route_match_conf_t;


typedef struct {
    u_char                         *start;
    uint32_t                       length;
    nxt_http_route_pattern_type_t  type:8;
} nxt_http_route_pattern_slice_t;


typedef struct {
    union {
        nxt_array_t                *pattern_slices;
#if (NXT_HAVE_REGEX)
        nxt_regex_t                *regex;
#endif
    } u;
    uint32_t                       min_length;

    uint8_t                        case_sensitive;  /* 1 bit */
    uint8_t                        negative;        /* 1 bit */
    uint8_t                        any;             /* 1 bit */
#if (NXT_HAVE_REGEX)
    uint8_t                        regex;           /* 1 bit */
#endif
} nxt_http_route_pattern_t;


typedef struct {
    uint16_t                       hash;
    uint16_t                       name_length;
    uint32_t                       value_length;
    u_char                         *name;
    u_char                         *value;
} nxt_http_name_value_t;


typedef struct {
    uint16_t                       hash;
    uint16_t                       name_length;
    uint32_t                       value_length;
    u_char                         *name;
    u_char                         *value;
} nxt_http_cookie_t;


typedef struct {
    /* The object must be the first field. */
    nxt_http_route_object_t        object:8;
    uint32_t                       items;

    union {
        uintptr_t                  offset;

        struct {
            u_char                 *start;
            uint16_t               hash;
            uint16_t               length;
        } name;
    } u;

    nxt_http_route_pattern_t       pattern[0];
} nxt_http_route_rule_t;


typedef struct {
    uint32_t                       items;
    nxt_http_route_rule_t          *rule[0];
} nxt_http_route_ruleset_t;


typedef struct {
    /* The object must be the first field. */
    nxt_http_route_object_t        object:8;
    uint32_t                       items;
    nxt_http_route_ruleset_t       *ruleset[0];
} nxt_http_route_table_t;


typedef struct {
    /* The object must be the first field. */
    nxt_http_route_object_t        object:8;
    uint32_t                       items;
    nxt_http_route_addr_pattern_t  addr_pattern[0];
} nxt_http_route_addr_rule_t;


typedef union {
    nxt_http_route_rule_t          *rule;
    nxt_http_route_table_t         *table;
    nxt_http_route_addr_rule_t     *addr_rule;
} nxt_http_route_test_t;


typedef struct {
    uint32_t                       items;
    nxt_http_action_t              action;
    nxt_http_route_test_t          test[0];
} nxt_http_route_match_t;


struct nxt_http_route_s {
    nxt_str_t                      name;
    uint32_t                       items;
    nxt_http_route_match_t         *match[0];
};


struct nxt_http_routes_s {
    uint32_t                       items;
    nxt_http_route_t               *route[0];
};


#define NXT_COOKIE_HASH                                                       \
    (nxt_http_field_hash_end(                                                 \
     nxt_http_field_hash_char(                                                \
     nxt_http_field_hash_char(                                                \
     nxt_http_field_hash_char(                                                \
     nxt_http_field_hash_char(                                                \
     nxt_http_field_hash_char(                                                \
     nxt_http_field_hash_char(NXT_HTTP_FIELD_HASH_INIT,                       \
        'c'), 'o'), 'o'), 'k'), 'i'), 'e')) & 0xFFFF)


static nxt_http_route_t *nxt_http_route_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_conf_value_t *cv);
static nxt_http_route_match_t *nxt_http_route_match_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_conf_value_t *cv);
static nxt_int_t nxt_http_route_action_create(nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *cv, nxt_http_action_t *action);
static nxt_http_route_table_t *nxt_http_route_table_create(nxt_task_t *task,
    nxt_mp_t *mp, nxt_conf_value_t *table_cv, nxt_http_route_object_t object,
    nxt_bool_t case_sensitive, nxt_http_route_encoding_t encoding);
static nxt_http_route_ruleset_t *nxt_http_route_ruleset_create(nxt_task_t *task,
    nxt_mp_t *mp, nxt_conf_value_t *ruleset_cv, nxt_http_route_object_t object,
    nxt_bool_t case_sensitive, nxt_http_route_encoding_t encoding);
static nxt_http_route_rule_t *nxt_http_route_rule_name_create(nxt_task_t *task,
    nxt_mp_t *mp, nxt_conf_value_t *rule_cv, nxt_str_t *name,
    nxt_bool_t case_sensitive, nxt_http_route_encoding_t encoding);
static nxt_http_route_addr_rule_t *nxt_http_route_addr_rule_create(
    nxt_task_t *task, nxt_mp_t *mp, nxt_conf_value_t *cv);
static nxt_http_route_rule_t *nxt_http_route_rule_create(nxt_task_t *task,
    nxt_mp_t *mp, nxt_conf_value_t *cv, nxt_bool_t case_sensitive,
    nxt_http_route_pattern_case_t pattern_case,
    nxt_http_route_encoding_t encoding);
static int nxt_http_pattern_compare(const void *one, const void *two);
static int nxt_http_addr_pattern_compare(const void *one, const void *two);
static nxt_int_t nxt_http_route_pattern_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *cv, nxt_http_route_pattern_t *pattern,
    nxt_http_route_pattern_case_t pattern_case,
    nxt_http_route_encoding_t encoding);
static nxt_int_t nxt_http_route_decode_str(nxt_str_t *str,
    nxt_http_route_encoding_t encoding);
static nxt_int_t nxt_http_route_pattern_slice(nxt_array_t *slices,
    nxt_str_t *test,
    nxt_http_route_pattern_type_t type,
    nxt_http_route_encoding_t encoding,
    nxt_http_route_pattern_case_t pattern_case);

static nxt_int_t nxt_http_route_resolve(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_http_route_t *route);
static nxt_int_t nxt_http_action_resolve(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_http_action_t *action);
static nxt_http_action_t *nxt_http_action_pass_var(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_action_t *action);
static void nxt_http_action_pass_var_ready(nxt_task_t *task, void *obj,
    void *data);
static void nxt_http_action_pass_var_error(nxt_task_t *task, void *obj,
    void *data);
static nxt_int_t nxt_http_pass_find(nxt_task_t *task, nxt_mp_t *mp,
    nxt_router_conf_t *rtcf, nxt_http_action_t *action);
static nxt_int_t nxt_http_route_find(nxt_http_routes_t *routes, nxt_str_t *name,
    nxt_http_action_t *action);

static nxt_http_action_t *nxt_http_route_handler(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_action_t *start);
static nxt_http_action_t *nxt_http_route_match(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_route_match_t *match);
static nxt_int_t nxt_http_route_table(nxt_http_request_t *r,
    nxt_http_route_table_t *table);
static nxt_int_t nxt_http_route_ruleset(nxt_http_request_t *r,
    nxt_http_route_ruleset_t *ruleset);
static nxt_int_t nxt_http_route_addr_rule(nxt_http_request_t *r,
    nxt_http_route_addr_rule_t *addr_rule, nxt_sockaddr_t *sockaddr);
static nxt_int_t nxt_http_route_rule(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule);
static nxt_int_t nxt_http_route_header(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule);
static nxt_int_t nxt_http_route_arguments(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule);
static nxt_array_t *nxt_http_route_arguments_parse(nxt_http_request_t *r);
static nxt_http_name_value_t *nxt_http_route_argument(nxt_array_t *array,
    u_char *name, size_t name_length, uint32_t hash, u_char *start,
    u_char *end);
static nxt_int_t nxt_http_route_test_argument(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule, nxt_array_t *array);
static nxt_int_t nxt_http_route_scheme(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule);
static nxt_int_t nxt_http_route_cookies(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule);
static nxt_array_t *nxt_http_route_cookies_parse(nxt_http_request_t *r);
static nxt_int_t nxt_http_route_cookie_parse(nxt_array_t *cookies,
    u_char *start, u_char *end);
static nxt_http_name_value_t *nxt_http_route_cookie(nxt_array_t *array,
    u_char *name, size_t name_length, u_char *start, u_char *end);
static nxt_int_t nxt_http_route_test_cookie(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule, nxt_array_t *array);
static nxt_int_t nxt_http_route_test_rule(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule, u_char *start, size_t length);
static nxt_int_t nxt_http_route_pattern(nxt_http_request_t *r,
    nxt_http_route_pattern_t *pattern, u_char *start, size_t length);
static nxt_int_t nxt_http_route_memcmp(u_char *start, u_char *test,
    size_t length, nxt_bool_t case_sensitive);


nxt_http_routes_t *
nxt_http_routes_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *routes_conf)
{
    size_t             size;
    uint32_t           i, n, next;
    nxt_mp_t           *mp;
    nxt_str_t          name, *string;
    nxt_bool_t         object;
    nxt_conf_value_t   *route_conf;
    nxt_http_route_t   *route;
    nxt_http_routes_t  *routes;

    object = (nxt_conf_type(routes_conf) == NXT_CONF_OBJECT);
    n = object ? nxt_conf_object_members_count(routes_conf) : 1;
    size = sizeof(nxt_http_routes_t) + n * sizeof(nxt_http_route_t *);

    mp = tmcf->router_conf->mem_pool;

    routes = nxt_mp_alloc(mp, size);
    if (nxt_slow_path(routes == NULL)) {
        return NULL;
    }

    routes->items = n;

    if (object) {
        next = 0;

        for (i = 0; i < n; i++) {
            route_conf = nxt_conf_next_object_member(routes_conf, &name, &next);

            route = nxt_http_route_create(task, tmcf, route_conf);
            if (nxt_slow_path(route == NULL)) {
                return NULL;
            }

            routes->route[i] = route;

            string = nxt_str_dup(mp, &route->name, &name);
            if (nxt_slow_path(string == NULL)) {
                return NULL;
            }
        }

    } else {
        route = nxt_http_route_create(task, tmcf, routes_conf);
        if (nxt_slow_path(route == NULL)) {
            return NULL;
        }

        routes->route[0] = route;

        route->name.length = 0;
        route->name.start = NULL;
    }

    return routes;
}


static nxt_conf_map_t  nxt_http_route_match_conf[] = {
    {
        nxt_string("scheme"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_match_conf_t, scheme)
    },
    {
        nxt_string("host"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_match_conf_t, host),
    },

    {
        nxt_string("uri"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_match_conf_t, uri),
    },

    {
        nxt_string("method"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_match_conf_t, method),
    },

    {
        nxt_string("headers"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_match_conf_t, headers),
    },

    {
        nxt_string("arguments"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_match_conf_t, arguments),
    },

    {
        nxt_string("cookies"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_match_conf_t, cookies),
    },

    {
        nxt_string("source"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_match_conf_t, source),
    },

    {
        nxt_string("destination"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_match_conf_t, destination),
    },
};


static nxt_http_route_t *
nxt_http_route_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *cv)
{
    size_t                  size;
    uint32_t                i, n;
    nxt_conf_value_t        *value;
    nxt_http_route_t        *route;
    nxt_http_route_match_t  *match, **m;

    n = nxt_conf_array_elements_count(cv);
    size = sizeof(nxt_http_route_t) + n * sizeof(nxt_http_route_match_t *);

    route = nxt_mp_alloc(tmcf->router_conf->mem_pool, size);
    if (nxt_slow_path(route == NULL)) {
        return NULL;
    }

    route->items = n;
    m = &route->match[0];

    for (i = 0; i < n; i++) {
        value = nxt_conf_get_array_element(cv, i);

        match = nxt_http_route_match_create(task, tmcf, value);
        if (match == NULL) {
            return NULL;
        }

        *m++ = match;
    }

    return route;
}


static nxt_http_route_match_t *
nxt_http_route_match_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *cv)
{
    size_t                       size;
    uint32_t                     n;
    nxt_mp_t                     *mp;
    nxt_int_t                    ret;
    nxt_conf_value_t             *match_conf, *action_conf;
    nxt_http_route_test_t        *test;
    nxt_http_route_rule_t        *rule;
    nxt_http_route_table_t       *table;
    nxt_http_route_match_t       *match;
    nxt_http_route_addr_rule_t   *addr_rule;
    nxt_http_route_match_conf_t  mtcf;

    static nxt_str_t  match_path = nxt_string("/match");
    static nxt_str_t  action_path = nxt_string("/action");

    match_conf = nxt_conf_get_path(cv, &match_path);

    n = (match_conf != NULL) ? nxt_conf_object_members_count(match_conf) : 0;
    size = sizeof(nxt_http_route_match_t) + n * sizeof(nxt_http_route_rule_t *);

    mp = tmcf->router_conf->mem_pool;

    match = nxt_mp_alloc(mp, size);
    if (nxt_slow_path(match == NULL)) {
        return NULL;
    }

    match->items = n;

    action_conf = nxt_conf_get_path(cv, &action_path);
    if (nxt_slow_path(action_conf == NULL)) {
        return NULL;
    }

    ret = nxt_http_route_action_create(tmcf, action_conf, &match->action);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NULL;
    }

    if (n == 0) {
        return match;
    }

    nxt_memzero(&mtcf, sizeof(mtcf));

    ret = nxt_conf_map_object(tmcf->mem_pool,
                              match_conf, nxt_http_route_match_conf,
                              nxt_nitems(nxt_http_route_match_conf), &mtcf);
    if (ret != NXT_OK) {
        return NULL;
    }

    test = &match->test[0];

    if (mtcf.scheme != NULL) {
        rule = nxt_http_route_rule_create(task, mp, mtcf.scheme, 1,
                                          NXT_HTTP_ROUTE_PATTERN_NOCASE,
                                          NXT_HTTP_ROUTE_ENCODING_NONE);
        if (rule == NULL) {
            return NULL;
        }

        rule->object = NXT_HTTP_ROUTE_SCHEME;
        test->rule = rule;
        test++;
    }

    if (mtcf.host != NULL) {
        rule = nxt_http_route_rule_create(task, mp, mtcf.host, 1,
                                          NXT_HTTP_ROUTE_PATTERN_LOWCASE,
                                          NXT_HTTP_ROUTE_ENCODING_NONE);
        if (rule == NULL) {
            return NULL;
        }

        rule->u.offset = offsetof(nxt_http_request_t, host);
        rule->object = NXT_HTTP_ROUTE_STRING;
        test->rule = rule;
        test++;
    }

    if (mtcf.uri != NULL) {
        rule = nxt_http_route_rule_create(task, mp, mtcf.uri, 1,
                                          NXT_HTTP_ROUTE_PATTERN_NOCASE,
                                          NXT_HTTP_ROUTE_ENCODING_URI);
        if (rule == NULL) {
            return NULL;
        }

        rule->u.offset = offsetof(nxt_http_request_t, path);
        rule->object = NXT_HTTP_ROUTE_STRING_PTR;
        test->rule = rule;
        test++;
    }

    if (mtcf.method != NULL) {
        rule = nxt_http_route_rule_create(task, mp, mtcf.method, 1,
                                          NXT_HTTP_ROUTE_PATTERN_UPCASE,
                                          NXT_HTTP_ROUTE_ENCODING_NONE);
        if (rule == NULL) {
            return NULL;
        }

        rule->u.offset = offsetof(nxt_http_request_t, method);
        rule->object = NXT_HTTP_ROUTE_STRING_PTR;
        test->rule = rule;
        test++;
    }

    if (mtcf.headers != NULL) {
        table = nxt_http_route_table_create(task, mp, mtcf.headers,
                                            NXT_HTTP_ROUTE_HEADER, 0,
                                            NXT_HTTP_ROUTE_ENCODING_NONE);
        if (table == NULL) {
            return NULL;
        }

        test->table = table;
        test++;
    }

    if (mtcf.arguments != NULL) {
        table = nxt_http_route_table_create(task, mp, mtcf.arguments,
                                            NXT_HTTP_ROUTE_ARGUMENT, 1,
                                            NXT_HTTP_ROUTE_ENCODING_URI_PLUS);
        if (table == NULL) {
            return NULL;
        }

        test->table = table;
        test++;
    }

    if (mtcf.cookies != NULL) {
        table = nxt_http_route_table_create(task, mp, mtcf.cookies,
                                            NXT_HTTP_ROUTE_COOKIE, 1,
                                            NXT_HTTP_ROUTE_ENCODING_NONE);
        if (table == NULL) {
            return NULL;
        }

        test->table = table;
        test++;
    }

    if (mtcf.source != NULL) {
        addr_rule = nxt_http_route_addr_rule_create(task, mp, mtcf.source);
        if (addr_rule == NULL) {
            return NULL;
        }

        addr_rule->object = NXT_HTTP_ROUTE_SOURCE;
        test->addr_rule = addr_rule;
        test++;
    }

    if (mtcf.destination != NULL) {
        addr_rule = nxt_http_route_addr_rule_create(task, mp, mtcf.destination);
        if (addr_rule == NULL) {
            return NULL;
        }

        addr_rule->object = NXT_HTTP_ROUTE_DESTINATION;
        test->addr_rule = addr_rule;
        test++;
    }

    return match;
}


static nxt_conf_map_t  nxt_http_route_action_conf[] = {
    {
        nxt_string("pass"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_action_conf_t, pass)
    },
    {
        nxt_string("return"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_action_conf_t, ret)
    },
    {
        nxt_string("location"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_http_route_action_conf_t, location)
    },
    {
        nxt_string("share"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_action_conf_t, share)
    },
    {
        nxt_string("proxy"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_action_conf_t, proxy)
    },
    {
        nxt_string("fallback"),
        NXT_CONF_MAP_PTR,
        offsetof(nxt_http_route_action_conf_t, fallback)
    },
};


static nxt_int_t
nxt_http_route_action_create(nxt_router_temp_conf_t *tmcf, nxt_conf_value_t *cv,
    nxt_http_action_t *action)
{
    nxt_mp_t                      *mp;
    nxt_int_t                     ret;
    nxt_str_t                     name, *string;
    nxt_uint_t                    encode;
    nxt_conf_value_t              *conf;
    nxt_http_route_action_conf_t  accf;

    nxt_memzero(&accf, sizeof(accf));

    ret = nxt_conf_map_object(tmcf->mem_pool, cv, nxt_http_route_action_conf,
                              nxt_nitems(nxt_http_route_action_conf), &accf);
    if (ret != NXT_OK) {
        return ret;
    }

    nxt_memzero(action, sizeof(nxt_http_action_t));

    mp = tmcf->router_conf->mem_pool;

    if (accf.ret != NULL) {
        action->handler = nxt_http_return_handler;
        action->u.return_code = nxt_conf_get_number(accf.ret);

        if (accf.location.length > 0) {
            if (nxt_is_complex_uri_encoded(accf.location.start,
                                           accf.location.length))
            {
                string = nxt_str_dup(mp, &action->name, &accf.location);
                if (nxt_slow_path(string == NULL)) {
                    return NXT_ERROR;
                }

            } else {
                string = &action->name;

                encode = nxt_encode_complex_uri(NULL, accf.location.start,
                                                accf.location.length);
                string->length = accf.location.length + encode * 2;

                string->start = nxt_mp_nget(mp, string->length);
                if (nxt_slow_path(string->start == NULL)) {
                    return NXT_ERROR;
                }

                nxt_encode_complex_uri(string->start, accf.location.start,
                                       accf.location.length);
            }
        }

        return NXT_OK;
    }

    conf = accf.pass;

    if (accf.share != NULL) {
        conf = accf.share;
        action->handler = nxt_http_static_handler;

    } else if (accf.proxy != NULL) {
        conf = accf.proxy;
    }

    nxt_conf_get_string(conf, &name);

    string = nxt_str_dup(mp, &action->name, &name);
    if (nxt_slow_path(string == NULL)) {
        return NXT_ERROR;
    }

    if (accf.fallback != NULL) {
        action->u.fallback = nxt_mp_alloc(mp, sizeof(nxt_http_action_t));
        if (nxt_slow_path(action->u.fallback == NULL)) {
            return NXT_ERROR;
        }

        return nxt_http_route_action_create(tmcf, accf.fallback,
                                            action->u.fallback);
    }

    if (accf.proxy != NULL) {
        return nxt_http_proxy_create(mp, action);
    }

    return NXT_OK;
}


static nxt_http_route_table_t *
nxt_http_route_table_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *table_cv, nxt_http_route_object_t object,
    nxt_bool_t case_sensitive, nxt_http_route_encoding_t encoding)
{
    size_t                    size;
    uint32_t                  i, n;
    nxt_bool_t                array;
    nxt_conf_value_t          *ruleset_cv;
    nxt_http_route_table_t    *table;
    nxt_http_route_ruleset_t  *ruleset;

    array = (nxt_conf_type(table_cv) == NXT_CONF_ARRAY);
    n = array ? nxt_conf_array_elements_count(table_cv) : 1;
    size = sizeof(nxt_http_route_table_t)
           + n * sizeof(nxt_http_route_ruleset_t *);

    table = nxt_mp_alloc(mp, size);
    if (nxt_slow_path(table == NULL)) {
        return NULL;
    }

    table->items = n;
    table->object = NXT_HTTP_ROUTE_TABLE;

    if (!array) {
        ruleset = nxt_http_route_ruleset_create(task, mp, table_cv, object,
                                                case_sensitive, encoding);
        if (nxt_slow_path(ruleset == NULL)) {
            return NULL;
        }

        table->ruleset[0] = ruleset;

        return table;
    }

    for (i = 0; i < n; i++) {
        ruleset_cv = nxt_conf_get_array_element(table_cv, i);

        ruleset = nxt_http_route_ruleset_create(task, mp, ruleset_cv, object,
                                                case_sensitive, encoding);
        if (nxt_slow_path(ruleset == NULL)) {
            return NULL;
        }

        table->ruleset[i] = ruleset;
    }

    return table;
}


static nxt_http_route_ruleset_t *
nxt_http_route_ruleset_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *ruleset_cv, nxt_http_route_object_t object,
    nxt_bool_t case_sensitive, nxt_http_route_encoding_t encoding)
{
    size_t                    size;
    uint32_t                  i, n, next;
    nxt_str_t                 name;
    nxt_conf_value_t          *rule_cv;
    nxt_http_route_rule_t     *rule;
    nxt_http_route_ruleset_t  *ruleset;

    n = nxt_conf_object_members_count(ruleset_cv);
    size = sizeof(nxt_http_route_ruleset_t)
           + n * sizeof(nxt_http_route_rule_t *);

    ruleset = nxt_mp_alloc(mp, size);
    if (nxt_slow_path(ruleset == NULL)) {
        return NULL;
    }

    ruleset->items = n;

    next = 0;

    for (i = 0; i < n; i++) {
        rule_cv = nxt_conf_next_object_member(ruleset_cv, &name, &next);

        rule = nxt_http_route_rule_name_create(task, mp, rule_cv, &name,
                                               case_sensitive, encoding);
        if (nxt_slow_path(rule == NULL)) {
            return NULL;
        }

        rule->object = object;
        ruleset->rule[i] = rule;
    }

    return ruleset;
}


static nxt_http_route_rule_t *
nxt_http_route_rule_name_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *rule_cv, nxt_str_t *name, nxt_bool_t case_sensitive,
    nxt_http_route_encoding_t encoding)
{
    u_char                 c, *p, *src, *start, *end, plus;
    uint8_t                d0, d1;
    uint32_t               hash;
    nxt_uint_t             i;
    nxt_http_route_rule_t  *rule;

    rule = nxt_http_route_rule_create(task, mp, rule_cv, case_sensitive,
                                      NXT_HTTP_ROUTE_PATTERN_NOCASE,
                                      encoding);
    if (nxt_slow_path(rule == NULL)) {
        return NULL;
    }

    rule->u.name.length = name->length;

    p = nxt_mp_nget(mp, name->length);
    if (nxt_slow_path(p == NULL)) {
        return NULL;
    }

    hash = NXT_HTTP_FIELD_HASH_INIT;
    rule->u.name.start = p;

    if (encoding == NXT_HTTP_ROUTE_ENCODING_NONE) {
        for (i = 0; i < name->length; i++) {
            c = name->start[i];
            *p++ = c;

            c = case_sensitive ? c : nxt_lowcase(c);
            hash = nxt_http_field_hash_char(hash, c);
        }

        goto end;
    }

    plus = (encoding == NXT_HTTP_ROUTE_ENCODING_URI_PLUS) ? ' ' : '+';

    start = name->start;
    end = start + name->length;

    for (src = start; src < end; src++) {
        c = *src;

        switch (c) {
        case '%':
            if (nxt_slow_path(end - src <= 2)) {
                return NULL;
            }

            d0 = nxt_hex2int[src[1]];
            d1 = nxt_hex2int[src[2]];
            src += 2;

            if (nxt_slow_path((d0 | d1) >= 16)) {
                return NULL;
            }

            c = (d0 << 4) + d1;
            *p++ = c;
            break;

        case '+':
            c = plus;
            *p++ = c;
            break;

        default:
            *p++ = c;
            break;
        }

        c = case_sensitive ? c : nxt_lowcase(c);
        hash = nxt_http_field_hash_char(hash, c);
    }

    rule->u.name.length = p - rule->u.name.start;

end:

    rule->u.name.hash = nxt_http_field_hash_end(hash) & 0xFFFF;

    return rule;
}


static nxt_http_route_rule_t *
nxt_http_route_rule_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *cv, nxt_bool_t case_sensitive,
    nxt_http_route_pattern_case_t pattern_case,
    nxt_http_route_encoding_t encoding)
{
    size_t                    size;
    uint32_t                  i, n;
    nxt_int_t                 ret;
    nxt_bool_t                string;
    nxt_conf_value_t          *value;
    nxt_http_route_rule_t     *rule;
    nxt_http_route_pattern_t  *pattern;

    string = (nxt_conf_type(cv) != NXT_CONF_ARRAY);
    n = string ? 1 : nxt_conf_array_elements_count(cv);
    size = sizeof(nxt_http_route_rule_t) + n * sizeof(nxt_http_route_pattern_t);

    rule = nxt_mp_alloc(mp, size);
    if (nxt_slow_path(rule == NULL)) {
        return NULL;
    }

    rule->items = n;

    pattern = &rule->pattern[0];

    if (string) {
        pattern[0].case_sensitive = case_sensitive;
        ret = nxt_http_route_pattern_create(task, mp, cv, &pattern[0],
                                            pattern_case, encoding);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NULL;
        }

        return rule;
    }

    nxt_conf_array_qsort(cv, nxt_http_pattern_compare);

    for (i = 0; i < n; i++) {
        pattern[i].case_sensitive = case_sensitive;
        value = nxt_conf_get_array_element(cv, i);

        ret = nxt_http_route_pattern_create(task, mp, value, &pattern[i],
                                            pattern_case, encoding);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NULL;
        }
    }

    return rule;
}


static nxt_http_route_addr_rule_t *
nxt_http_route_addr_rule_create(nxt_task_t *task, nxt_mp_t *mp,
     nxt_conf_value_t *cv)
{
    size_t                         size;
    uint32_t                       i, n;
    nxt_bool_t                     array;
    nxt_conf_value_t               *value;
    nxt_http_route_addr_rule_t     *addr_rule;
    nxt_http_route_addr_pattern_t  *pattern;

    array = (nxt_conf_type(cv) == NXT_CONF_ARRAY);
    n = array ? nxt_conf_array_elements_count(cv) : 1;

    size = sizeof(nxt_http_route_addr_rule_t)
           + n * sizeof(nxt_http_route_addr_pattern_t);

    addr_rule = nxt_mp_alloc(mp, size);
    if (nxt_slow_path(addr_rule == NULL)) {
        return NULL;
    }

    addr_rule->items = n;

    if (!array) {
        pattern = &addr_rule->addr_pattern[0];

        if (nxt_http_route_addr_pattern_parse(mp, pattern, cv) != NXT_OK) {
            return NULL;
        }

        return addr_rule;
    }

    for (i = 0; i < n; i++) {
        pattern = &addr_rule->addr_pattern[i];
        value = nxt_conf_get_array_element(cv, i);

        if (nxt_http_route_addr_pattern_parse(mp, pattern, value) != NXT_OK) {
            return NULL;
        }
    }

    if (n > 1) {
        nxt_qsort(addr_rule->addr_pattern, addr_rule->items,
            sizeof(nxt_http_route_addr_pattern_t),
            nxt_http_addr_pattern_compare);
    }

    return addr_rule;
}


static int
nxt_http_pattern_compare(const void *one, const void *two)
{
    nxt_str_t         test;
    nxt_bool_t        negative1, negative2;
    nxt_conf_value_t  *value;

    value = (nxt_conf_value_t *) one;
    nxt_conf_get_string(value, &test);
    negative1 = (test.length != 0 && test.start[0] == '!');

    value = (nxt_conf_value_t *) two;
    nxt_conf_get_string(value, &test);
    negative2 = (test.length != 0 && test.start[0] == '!');

    return (negative2 - negative1);
}


static int
nxt_http_addr_pattern_compare(const void *one, const void *two)
{
    const nxt_http_route_addr_pattern_t  *p1, *p2;

    p1 = one;
    p2 = two;

    return (p2->base.negative - p1->base.negative);
}


static nxt_int_t
nxt_http_route_pattern_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *cv, nxt_http_route_pattern_t *pattern,
    nxt_http_route_pattern_case_t pattern_case,
    nxt_http_route_encoding_t encoding)
{
    u_char                          c, *p, *end;
    nxt_str_t                       test, tmp;
    nxt_int_t                       ret;
    nxt_array_t                     *slices;
#if (NXT_HAVE_REGEX)
    nxt_regex_t                     *re;
    nxt_regex_err_t                 err;
#endif
    nxt_http_route_pattern_type_t   type;
    nxt_http_route_pattern_slice_t  *slice;

    type = NXT_HTTP_ROUTE_PATTERN_EXACT;

    nxt_conf_get_string(cv, &test);

    pattern->u.pattern_slices = NULL;
    pattern->negative = 0;
    pattern->any = 1;
    pattern->min_length = 0;
#if (NXT_HAVE_REGEX)
    pattern->regex = 0;
#endif

    if (test.length != 0 && test.start[0] == '!') {
        test.start++;
        test.length--;

        pattern->negative = 1;
        pattern->any = 0;
    }

    if (test.length > 0 && test.start[0] == '~') {
#if (NXT_HAVE_REGEX)
        test.start++;
        test.length--;

        re = nxt_regex_compile(mp, &test, &err);
        if (nxt_slow_path(re == NULL)) {
            if (err.offset < test.length) {
                nxt_alert(task, "nxt_regex_compile(%V) failed: %s at offset %d",
                          &test, err.msg, (int) err.offset);
                return NXT_ERROR;
            }

            nxt_alert(task, "nxt_regex_compile(%V) failed %s", &test, err.msg);

            return NXT_ERROR;
        }

        pattern->u.regex = re;
        pattern->regex = 1;

        return NXT_OK;

#else
        return NXT_ERROR;
#endif
    }

    slices = nxt_array_create(mp, 1, sizeof(nxt_http_route_pattern_slice_t));
    if (nxt_slow_path(slices == NULL)) {
        return NXT_ERROR;
    }

    pattern->u.pattern_slices = slices;

    if (test.length == 0) {
        slice = nxt_array_add(slices);
        if (nxt_slow_path(slice == NULL)) {
            return NXT_ERROR;
        }

        slice->type = NXT_HTTP_ROUTE_PATTERN_EXACT;
        slice->start = NULL;
        slice->length = 0;

        return NXT_OK;
    }

    if (test.start[0] == '*') {
        /* 'type' is no longer 'EXACT', assume 'END'. */
        type = NXT_HTTP_ROUTE_PATTERN_END;
        test.start++;
        test.length--;
    }

    if (type == NXT_HTTP_ROUTE_PATTERN_EXACT) {
        tmp.start = test.start;

        p = nxt_memchr(test.start, '*', test.length);

        if (p == NULL) {
            /* No '*' found - EXACT pattern. */
            tmp.length = test.length;
            type = NXT_HTTP_ROUTE_PATTERN_EXACT;

            test.start += test.length;
            test.length = 0;

        } else {
            /* '*' found - BEGIN pattern. */
            tmp.length = p - test.start;
            type = NXT_HTTP_ROUTE_PATTERN_BEGIN;

            test.start = p + 1;
            test.length -= tmp.length + 1;
        }

        ret = nxt_http_route_pattern_slice(slices, &tmp, type, encoding,
                                           pattern_case);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

        pattern->min_length += tmp.length;
    }

    end = test.start + test.length;

    if (test.length != 0 && end[-1] != '*') {
        p = end - 1;

        while (p != test.start) {
            c = *p--;

            if (c == '*') {
                p += 2;
                break;
            }
        }

        tmp.start = p;
        tmp.length = end - p;

        test.length -= tmp.length;
        end = p;

        ret = nxt_http_route_pattern_slice(slices, &tmp,
                                           NXT_HTTP_ROUTE_PATTERN_END,
                                           encoding, pattern_case);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

        pattern->min_length += tmp.length;
    }

    tmp.start = test.start;
    tmp.length = 0;

    p = tmp.start;

    while (p != end) {
        c = *p++;

        if (c != '*') {
            tmp.length++;
            continue;
        }

        if (tmp.length == 0) {
            tmp.start = p;
            continue;
        }

        ret = nxt_http_route_pattern_slice(slices, &tmp,
                                           NXT_HTTP_ROUTE_PATTERN_SUBSTRING,
                                           encoding, pattern_case);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

        pattern->min_length += tmp.length;

        tmp.start = p;
        tmp.length = 0;
    }

    if (tmp.length != 0) {
        ret = nxt_http_route_pattern_slice(slices, &tmp,
                                           NXT_HTTP_ROUTE_PATTERN_SUBSTRING,
                                           encoding, pattern_case);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

        pattern->min_length += tmp.length;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_route_decode_str(nxt_str_t *str, nxt_http_route_encoding_t encoding)
{
    u_char  *start, *end;

    switch (encoding) {
    case NXT_HTTP_ROUTE_ENCODING_NONE:
        break;

    case NXT_HTTP_ROUTE_ENCODING_URI:
        start = str->start;

        end = nxt_decode_uri(start, start, str->length);
        if (nxt_slow_path(end == NULL)) {
            return NXT_ERROR;
        }

        str->length = end - start;
        break;

    case NXT_HTTP_ROUTE_ENCODING_URI_PLUS:
        start = str->start;

        end = nxt_decode_uri_plus(start, start, str->length);
        if (nxt_slow_path(end == NULL)) {
            return NXT_ERROR;
        }

        str->length = end - start;
        break;

    default:
        nxt_unreachable();
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_route_pattern_slice(nxt_array_t *slices,
    nxt_str_t *test,
    nxt_http_route_pattern_type_t type,
    nxt_http_route_encoding_t encoding,
    nxt_http_route_pattern_case_t pattern_case)
{
    u_char                          *start;
    nxt_int_t                       ret;
    nxt_http_route_pattern_slice_t  *slice;

    ret = nxt_http_route_decode_str(test, encoding);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    start = nxt_mp_nget(slices->mem_pool, test->length);
    if (nxt_slow_path(start == NULL)) {
        return NXT_ERROR;
    }

    switch (pattern_case) {

    case NXT_HTTP_ROUTE_PATTERN_UPCASE:
        nxt_memcpy_upcase(start, test->start, test->length);
        break;

    case NXT_HTTP_ROUTE_PATTERN_LOWCASE:
        nxt_memcpy_lowcase(start, test->start, test->length);
        break;

    case NXT_HTTP_ROUTE_PATTERN_NOCASE:
        nxt_memcpy(start, test->start, test->length);
        break;
    }

    slice = nxt_array_add(slices);
    if (nxt_slow_path(slice == NULL)) {
        return NXT_ERROR;
    }

    slice->type = type;
    slice->start = start;
    slice->length = test->length;

    return NXT_OK;
}


nxt_int_t
nxt_http_routes_resolve(nxt_task_t *task, nxt_router_temp_conf_t *tmcf)
{
    nxt_int_t          ret;
    nxt_http_route_t   **route, **end;
    nxt_http_routes_t  *routes;

    routes = tmcf->router_conf->routes;

    if (routes != NULL) {
        route = &routes->route[0];
        end = route + routes->items;

        while (route < end) {
            ret = nxt_http_route_resolve(task, tmcf, *route);
            if (nxt_slow_path(ret != NXT_OK)) {
                return NXT_ERROR;
            }

            route++;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_route_resolve(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_http_route_t *route)
{
    nxt_int_t               ret;
    nxt_http_route_match_t  **match, **end;

    match = &route->match[0];
    end = match + route->items;

    while (match < end) {
        ret = nxt_http_action_resolve(task, tmcf, &(*match)->action);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }

        match++;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_http_action_resolve(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_http_action_t *action)
{
    nxt_var_t  *var;
    nxt_int_t  ret;

    if (action->handler != NULL) {
        if (action->handler == nxt_http_static_handler
            && action->u.fallback != NULL)
        {
            return nxt_http_action_resolve(task, tmcf, action->u.fallback);
        }

        return NXT_OK;
    }

    if (nxt_is_var(&action->name)) {
        var = nxt_var_compile(&action->name, tmcf->router_conf->mem_pool);
        if (nxt_slow_path(var == NULL)) {
            return NXT_ERROR;
        }

        action->u.var = var;
        action->handler = nxt_http_action_pass_var;
        return NXT_OK;
    }

    ret = nxt_http_pass_find(task, tmcf->mem_pool, tmcf->router_conf, action);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_http_action_t *
nxt_http_action_pass_var(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *action)
{
    nxt_var_t  *var;
    nxt_int_t  ret;

    ret = nxt_var_query_init(&r->var_query, r, r->mem_pool);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    var = action->u.var;

    action = nxt_mp_get(r->mem_pool, sizeof(nxt_http_action_t));
    if (nxt_slow_path(action == NULL)) {
        goto fail;
    }

    nxt_var_query(task, r->var_query, var, &action->name);
    nxt_var_query_resolve(task, r->var_query, action,
                          nxt_http_action_pass_var_ready,
                          nxt_http_action_pass_var_error);
    return NULL;

fail:

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
    return NULL;
}


static void
nxt_http_action_pass_var_ready(nxt_task_t *task, void *obj, void *data)
{
    nxt_int_t           ret;
    nxt_router_conf_t   *rtcf;
    nxt_http_action_t   *action;
    nxt_http_status_t   status;
    nxt_http_request_t  *r;

    r = obj;
    action = data;
    rtcf = r->conf->socket_conf->router_conf;

    nxt_debug(task, "http pass lookup: %V", &action->name);

    ret = nxt_http_pass_find(task, r->mem_pool, rtcf, action);

    if (ret != NXT_OK) {
        status = (ret == NXT_DECLINED) ? NXT_HTTP_NOT_FOUND
                                       : NXT_HTTP_INTERNAL_SERVER_ERROR;

        nxt_http_request_error(task, r, status);
        return;
    }

    nxt_http_request_action(task, r, action);
}


static void
nxt_http_action_pass_var_error(nxt_task_t *task, void *obj, void *data)
{
    nxt_http_request_t  *r;

    r = obj;

    nxt_http_request_error(task, r, NXT_HTTP_INTERNAL_SERVER_ERROR);
}


static nxt_int_t
nxt_http_pass_find(nxt_task_t *task, nxt_mp_t *mp, nxt_router_conf_t *rtcf,
    nxt_http_action_t *action)
{
    nxt_str_t   *targets;
    nxt_int_t   ret;
    nxt_uint_t  i;
    nxt_str_t   segments[3];

    ret = nxt_http_pass_segments(mp, &action->name, segments, 3);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    if (nxt_str_eq(&segments[0], "applications", 12)) {
        ret = nxt_router_listener_application(rtcf, &segments[1], action);

        if (ret != NXT_OK) {
            return ret;
        }

        if (segments[2].length != 0) {
            targets = action->u.application->targets;

            for (i = 0; !nxt_strstr_eq(&segments[2], &targets[i]); i++);

            action->target = i;

        } else {
            action->target = 0;
        }

        return NXT_OK;
    }

    if (segments[2].length == 0) {
        if (nxt_str_eq(&segments[0], "upstreams", 9)) {
            return nxt_upstream_find(rtcf->upstreams, &segments[1], action);
        }

        if (nxt_str_eq(&segments[0], "routes", 6)) {
            return nxt_http_route_find(rtcf->routes, &segments[1], action);
        }
    }

    return NXT_DECLINED;
}


nxt_int_t
nxt_http_pass_segments(nxt_mp_t *mp, nxt_str_t *pass, nxt_str_t *segments,
    nxt_uint_t n)
{
    u_char     *p;
    nxt_str_t  rest;

    if (nxt_slow_path(nxt_str_dup(mp, &rest, pass) == NULL)) {
        return NXT_ERROR;
    }

    nxt_memzero(segments, n * sizeof(nxt_str_t));

    do {
        p = nxt_memchr(rest.start, '/', rest.length);

        if (p != NULL) {
            n--;

            if (n == 0) {
                return NXT_DECLINED;
            }

            segments->length = p - rest.start;
            segments->start = rest.start;

            rest.length -= segments->length + 1;
            rest.start = p + 1;

        } else {
            n = 0;
            *segments = rest;
        }

        if (segments->length == 0) {
            return NXT_DECLINED;
        }

        p = nxt_decode_uri(segments->start, segments->start, segments->length);
        if (p == NULL) {
            return NXT_DECLINED;
        }

        segments->length = p - segments->start;
        segments++;

    } while (n);

    return NXT_OK;
}


static nxt_int_t
nxt_http_route_find(nxt_http_routes_t *routes, nxt_str_t *name,
    nxt_http_action_t *action)
{
    nxt_http_route_t  **route, **end;

    route = &routes->route[0];
    end = route + routes->items;

    while (route < end) {
        if (nxt_strstr_eq(&(*route)->name, name)) {
            action->u.route = *route;
            action->handler = nxt_http_route_handler;

            return NXT_OK;
        }

        route++;
    }

    return NXT_DECLINED;
}


nxt_http_action_t *
nxt_http_action_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_str_t *name)
{
    nxt_int_t          ret;
    nxt_http_action_t  *action;

    action = nxt_mp_alloc(tmcf->router_conf->mem_pool,
                          sizeof(nxt_http_action_t));
    if (nxt_slow_path(action == NULL)) {
        return NULL;
    }

    action->name = *name;
    action->handler = NULL;

    ret = nxt_http_action_resolve(task, tmcf, action);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NULL;
    }

    return action;
}


/* COMPATIBILITY: listener application. */

nxt_http_action_t *
nxt_http_pass_application(nxt_task_t *task, nxt_router_conf_t *rtcf,
    nxt_str_t *name)
{
    nxt_http_action_t  *action;

    action = nxt_mp_alloc(rtcf->mem_pool, sizeof(nxt_http_action_t));
    if (nxt_slow_path(action == NULL)) {
        return NULL;
    }

    action->name = *name;

    (void) nxt_router_listener_application(rtcf, name, action);

    action->target = 0;

    return action;
}


static nxt_http_action_t *
nxt_http_route_handler(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_action_t *start)
{
    nxt_http_route_t        *route;
    nxt_http_action_t       *action;
    nxt_http_route_match_t  **match, **end;

    route = start->u.route;
    match = &route->match[0];
    end = match + route->items;

    while (match < end) {
        action = nxt_http_route_match(task, r, *match);
        if (action != NULL) {
            return action;
        }

        match++;
    }

    nxt_http_request_error(task, r, NXT_HTTP_NOT_FOUND);

    return NULL;
}


static nxt_http_action_t *
nxt_http_route_match(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_route_match_t *match)
{
    nxt_int_t              ret;
    nxt_http_route_test_t  *test, *end;

    test = &match->test[0];
    end = test + match->items;

    while (test < end) {
        switch (test->rule->object) {
        case NXT_HTTP_ROUTE_TABLE:
            ret = nxt_http_route_table(r, test->table);
            break;
        case NXT_HTTP_ROUTE_SOURCE:
            ret = nxt_http_route_addr_rule(r, test->addr_rule, r->remote);
            break;
        case NXT_HTTP_ROUTE_DESTINATION:
            if (r->local == NULL && nxt_fast_path(r->proto.any != NULL)) {
                nxt_http_proto[r->protocol].local_addr(task, r);
            }

            ret = nxt_http_route_addr_rule(r, test->addr_rule, r->local);
            break;
        default:
            ret = nxt_http_route_rule(r, test->rule);
            break;
        }

        if (ret <= 0) {
            /* 0 => NULL, -1 => NXT_HTTP_ACTION_ERROR. */
            return (nxt_http_action_t *) (intptr_t) ret;
        }

        test++;
    }

    return &match->action;
}


static nxt_int_t
nxt_http_route_table(nxt_http_request_t *r, nxt_http_route_table_t *table)
{
    nxt_int_t                 ret;
    nxt_http_route_ruleset_t  **ruleset, **end;

    ret = 1;
    ruleset = &table->ruleset[0];
    end = ruleset + table->items;

    while (ruleset < end) {
        ret = nxt_http_route_ruleset(r, *ruleset);

        if (ret != 0) {
            return ret;
        }

        ruleset++;
    }

    return ret;
}


static nxt_int_t
nxt_http_route_ruleset(nxt_http_request_t *r, nxt_http_route_ruleset_t *ruleset)
{
    nxt_int_t              ret;
    nxt_http_route_rule_t  **rule, **end;

    rule = &ruleset->rule[0];
    end = rule + ruleset->items;

    while (rule < end) {
        ret = nxt_http_route_rule(r, *rule);

        if (ret <= 0) {
            return ret;
        }

        rule++;
    }

    return 1;
}


static nxt_int_t
nxt_http_route_rule(nxt_http_request_t *r, nxt_http_route_rule_t *rule)
{
    void       *p, **pp;
    u_char     *start;
    size_t     length;
    nxt_str_t  *s;

    switch (rule->object) {

    case NXT_HTTP_ROUTE_HEADER:
        return nxt_http_route_header(r, rule);

    case NXT_HTTP_ROUTE_ARGUMENT:
        return nxt_http_route_arguments(r, rule);

    case NXT_HTTP_ROUTE_COOKIE:
        return nxt_http_route_cookies(r, rule);

    case NXT_HTTP_ROUTE_SCHEME:
        return nxt_http_route_scheme(r, rule);

    default:
        break;
    }

    p = nxt_pointer_to(r, rule->u.offset);

    if (rule->object == NXT_HTTP_ROUTE_STRING) {
        s = p;

    } else {
        /* NXT_HTTP_ROUTE_STRING_PTR */
        pp = p;
        s = *pp;

        if (s == NULL) {
            return 0;
        }
    }

    length = s->length;
    start = s->start;

    return nxt_http_route_test_rule(r, rule, start, length);
}


static nxt_int_t
nxt_http_route_addr_pattern_match(nxt_http_route_addr_pattern_t *p,
    nxt_sockaddr_t *sa)
{
#if (NXT_INET6)
    uint32_t                    i;
#endif
    in_port_t                   in_port;
    nxt_int_t                   match;
    struct sockaddr_in          *sin;
#if (NXT_INET6)
    struct sockaddr_in6         *sin6;
#endif
    nxt_http_route_addr_base_t  *base;

    base = &p->base;

    switch (sa->u.sockaddr.sa_family) {

    case AF_INET:

        match = (base->addr_family == AF_INET
                 || base->addr_family == AF_UNSPEC);
        if (!match) {
            break;
        }

        sin = &sa->u.sockaddr_in;
        in_port = ntohs(sin->sin_port);

        match = (in_port >= base->port.start && in_port <= base->port.end);
        if (!match) {
            break;
        }

        switch (base->match_type) {

        case NXT_HTTP_ROUTE_ADDR_ANY:
            break;

        case NXT_HTTP_ROUTE_ADDR_EXACT:
            match = (nxt_memcmp(&sin->sin_addr, &p->addr.v4.start,
                                sizeof(struct in_addr))
                     == 0);
            break;

        case NXT_HTTP_ROUTE_ADDR_RANGE:
            match = (nxt_memcmp(&sin->sin_addr, &p->addr.v4.start,
                                sizeof(struct in_addr)) >= 0
                     && nxt_memcmp(&sin->sin_addr, &p->addr.v4.end,
                                   sizeof(struct in_addr)) <= 0);
            break;

        case NXT_HTTP_ROUTE_ADDR_CIDR:
            match = ((sin->sin_addr.s_addr & p->addr.v4.end)
                     == p->addr.v4.start);
            break;

        default:
            nxt_unreachable();
        }

        break;

#if (NXT_INET6)
    case AF_INET6:

        match = (base->addr_family == AF_INET6
                 || base->addr_family == AF_UNSPEC);
        if (!match) {
            break;
        }

        sin6 = &sa->u.sockaddr_in6;
        in_port = ntohs(sin6->sin6_port);

        match = (in_port >= base->port.start && in_port <= base->port.end);
        if (!match) {
            break;
        }

        switch (base->match_type) {

        case NXT_HTTP_ROUTE_ADDR_ANY:
            break;

        case NXT_HTTP_ROUTE_ADDR_EXACT:
            match = (nxt_memcmp(&sin6->sin6_addr, &p->addr.v6.start,
                                sizeof(struct in6_addr))
                     == 0);
            break;

        case NXT_HTTP_ROUTE_ADDR_RANGE:
            match = (nxt_memcmp(&sin6->sin6_addr, &p->addr.v6.start,
                                sizeof(struct in6_addr)) >= 0
                     && nxt_memcmp(&sin6->sin6_addr, &p->addr.v6.end,
                                   sizeof(struct in6_addr)) <= 0);
            break;

        case NXT_HTTP_ROUTE_ADDR_CIDR:
            for (i = 0; i < 16; i++) {
                match = ((sin6->sin6_addr.s6_addr[i]
                          & p->addr.v6.end.s6_addr[i])
                         == p->addr.v6.start.s6_addr[i]);

                if (!match) {
                    break;
                }
            }

            break;

        default:
            nxt_unreachable();
        }

        break;
#endif

    default:
        match = 0;
        break;
    }

    return match ^ base->negative;
}


static nxt_int_t
nxt_http_route_addr_rule(nxt_http_request_t *r,
    nxt_http_route_addr_rule_t *addr_rule, nxt_sockaddr_t *sa)
{
    uint32_t                       n;
    nxt_bool_t                     matches;
    nxt_http_route_addr_pattern_t  *p;

    n = addr_rule->items;
    p = &addr_rule->addr_pattern[0] - 1;

    do {
        p++;
        n--;

        matches = nxt_http_route_addr_pattern_match(p, sa);

        if (p->base.negative) {
            if (matches) {
                continue;
            }

            return 0;
        }

        if (matches) {
            return 1;
        }

    } while (n > 0);

    return p->base.negative;
}


static nxt_int_t
nxt_http_route_header(nxt_http_request_t *r, nxt_http_route_rule_t *rule)
{
    nxt_int_t         ret;
    nxt_http_field_t  *f;

    ret = 0;

    nxt_list_each(f, r->fields) {

        if (rule->u.name.hash != f->hash
            || rule->u.name.length != f->name_length
            || nxt_strncasecmp(rule->u.name.start, f->name, f->name_length)
               != 0)
        {
            continue;
        }

        ret = nxt_http_route_test_rule(r, rule, f->value, f->value_length);
        if (nxt_slow_path(ret == NXT_ERROR)) {
            return NXT_ERROR;
        }

        if (ret == 0) {
            return ret;
        }

    } nxt_list_loop;

    return ret;
}


static nxt_int_t
nxt_http_route_arguments(nxt_http_request_t *r, nxt_http_route_rule_t *rule)
{
    nxt_array_t  *arguments;

    if (r->args == NULL) {
        return 0;
    }

    arguments = nxt_http_route_arguments_parse(r);
    if (nxt_slow_path(arguments == NULL)) {
        return -1;
    }

    return nxt_http_route_test_argument(r, rule, arguments);
}


static nxt_array_t *
nxt_http_route_arguments_parse(nxt_http_request_t *r)
{
    size_t                 name_length;
    u_char                 c, *p, *dst, *dst_start, *start, *end, *name;
    uint8_t                d0, d1;
    uint32_t               hash;
    nxt_bool_t             valid;
    nxt_array_t            *args;
    nxt_http_name_value_t  *nv;

    if (r->arguments != NULL) {
        return r->arguments;
    }

    args = nxt_array_create(r->mem_pool, 2, sizeof(nxt_http_name_value_t));
    if (nxt_slow_path(args == NULL)) {
        return NULL;
    }

    hash = NXT_HTTP_FIELD_HASH_INIT;
    valid = 1;
    name = NULL;
    name_length = 0;

    dst_start = nxt_mp_nget(r->mem_pool, r->args->length);
    if (nxt_slow_path(dst_start == NULL)) {
        return NULL;
    }

    start = r->args->start;
    end = start + r->args->length;

    for (p = start, dst = dst_start; p < end; p++, dst++) {
        c = *p;
        *dst = c;

        switch (c) {
        case '=':
            if (name != NULL) {
                break;
            }

            name_length = dst - dst_start;
            valid = (name_length != 0);
            name = dst_start;
            dst_start = dst + 1;

            continue;

        case '&':
            if (valid) {
                nv = nxt_http_route_argument(args, name, name_length, hash,
                                             dst_start, dst);
                if (nxt_slow_path(nv == NULL)) {
                    return NULL;
                }
            }

            hash = NXT_HTTP_FIELD_HASH_INIT;
            name_length = 0;
            valid = 1;
            name = NULL;
            dst_start = dst + 1;

            continue;

        case '+':
            c = ' ';
            *dst = ' ';

            break;

        case '%':
            if (nxt_slow_path(end - p <= 2)) {
                break;
            }

            d0 = nxt_hex2int[p[1]];
            d1 = nxt_hex2int[p[2]];

            if (nxt_slow_path((d0 | d1) >= 16)) {
                break;
            }

            p += 2;
            c = (d0 << 4) + d1;
            *dst = c;

            break;
        }

        if (name == NULL) {
            hash = nxt_http_field_hash_char(hash, c);
        }
    }

    if (valid) {
        nv = nxt_http_route_argument(args, name, name_length, hash, dst_start,
                                     dst);
        if (nxt_slow_path(nv == NULL)) {
            return NULL;
        }
    }

    r->arguments = args;

    return args;
}


static nxt_http_name_value_t *
nxt_http_route_argument(nxt_array_t *array, u_char *name, size_t name_length,
    uint32_t hash, u_char *start, u_char *end)
{
    size_t                 length;
    nxt_http_name_value_t  *nv;

    nv = nxt_array_add(array);
    if (nxt_slow_path(nv == NULL)) {
        return NULL;
    }

    nv->hash = nxt_http_field_hash_end(hash) & 0xFFFF;

    length = end - start;

    if (name == NULL) {
        name_length = length;
        name = start;
        length = 0;
    }

    nv->name_length = name_length;
    nv->value_length = length;
    nv->name = name;
    nv->value = start;

    return nv;
}


static nxt_int_t
nxt_http_route_test_argument(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule, nxt_array_t *array)
{
    nxt_int_t              ret;
    nxt_http_name_value_t  *nv, *end;

    ret = 0;

    nv = array->elts;
    end = nv + array->nelts;

    while (nv < end) {

        if (rule->u.name.hash == nv->hash
            && rule->u.name.length == nv->name_length
            && nxt_memcmp(rule->u.name.start, nv->name, nv->name_length) == 0)
        {
            ret = nxt_http_route_test_rule(r, rule, nv->value,
                                           nv->value_length);
            if (nxt_slow_path(ret == NXT_ERROR)) {
                return NXT_ERROR;
            }

            if (ret == 0) {
                break;
            }
        }

        nv++;
    }

    return ret;
}


static nxt_int_t
nxt_http_route_scheme(nxt_http_request_t *r, nxt_http_route_rule_t *rule)
{
    nxt_bool_t                      tls, https;
    nxt_http_route_pattern_slice_t  *pattern_slice;

    pattern_slice = rule->pattern[0].u.pattern_slices->elts;
    https = (pattern_slice->length == nxt_length("https"));
    tls = (r->tls != NULL);

    return (tls == https);
}


static nxt_int_t
nxt_http_route_cookies(nxt_http_request_t *r, nxt_http_route_rule_t *rule)
{
    nxt_array_t  *cookies;

    cookies = nxt_http_route_cookies_parse(r);
    if (nxt_slow_path(cookies == NULL)) {
        return -1;
    }

    return nxt_http_route_test_cookie(r, rule, cookies);
}


static nxt_array_t *
nxt_http_route_cookies_parse(nxt_http_request_t *r)
{
    nxt_int_t         ret;
    nxt_array_t       *cookies;
    nxt_http_field_t  *f;

    if (r->cookies != NULL) {
        return r->cookies;
    }

    cookies = nxt_array_create(r->mem_pool, 2, sizeof(nxt_http_name_value_t));
    if (nxt_slow_path(cookies == NULL)) {
        return NULL;
    }

    nxt_list_each(f, r->fields) {

        if (f->hash != NXT_COOKIE_HASH
            || f->name_length != 6
            || nxt_strncasecmp(f->name, (u_char *) "Cookie", 6) != 0)
        {
            continue;
        }

        ret = nxt_http_route_cookie_parse(cookies, f->value,
                                          f->value + f->value_length);
        if (ret != NXT_OK) {
            return NULL;
        }

    } nxt_list_loop;

    r->cookies = cookies;

    return cookies;
}


static nxt_int_t
nxt_http_route_cookie_parse(nxt_array_t *cookies, u_char *start, u_char *end)
{
    size_t                 name_length;
    u_char                 c, *p, *name;
    nxt_http_name_value_t  *nv;

    name = NULL;
    name_length = 0;

    for (p = start; p < end; p++) {
        c = *p;

        if (c == '=') {
            while (start[0] == ' ') { start++; }

            name_length = p - start;

            if (name_length != 0) {
                name = start;
            }

            start = p + 1;

        } else if (c == ';') {
            if (name != NULL) {
                nv = nxt_http_route_cookie(cookies, name, name_length,
                                           start, p);
                if (nxt_slow_path(nv == NULL)) {
                    return NXT_ERROR;
                }
            }

            name = NULL;
            start = p + 1;
         }
    }

    if (name != NULL) {
        nv = nxt_http_route_cookie(cookies, name, name_length, start, p);
        if (nxt_slow_path(nv == NULL)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static nxt_http_name_value_t *
nxt_http_route_cookie(nxt_array_t *array, u_char *name, size_t name_length,
    u_char *start, u_char *end)
{
    u_char                 c, *p;
    uint32_t               hash;
    nxt_http_name_value_t  *nv;

    nv = nxt_array_add(array);
    if (nxt_slow_path(nv == NULL)) {
        return NULL;
    }

    nv->name_length = name_length;
    nv->name = name;

    hash = NXT_HTTP_FIELD_HASH_INIT;

    for (p = name; p < name + name_length; p++) {
        c = *p;
        hash = nxt_http_field_hash_char(hash, c);
    }

    nv->hash = nxt_http_field_hash_end(hash) & 0xFFFF;

    while (start < end && end[-1] == ' ') { end--; }

    nv->value_length = end - start;
    nv->value = start;

    return nv;
}


static nxt_int_t
nxt_http_route_test_cookie(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule, nxt_array_t *array)
{
    nxt_int_t              ret;
    nxt_http_name_value_t  *nv, *end;

    ret = 0;

    nv = array->elts;
    end = nv + array->nelts;

    while (nv < end) {

        if (rule->u.name.hash == nv->hash
            && rule->u.name.length == nv->name_length
            && nxt_memcmp(rule->u.name.start, nv->name, nv->name_length) == 0)
        {
            ret = nxt_http_route_test_rule(r, rule, nv->value,
                                           nv->value_length);
            if (nxt_slow_path(ret == NXT_ERROR)) {
                return NXT_ERROR;
            }

            if (ret == 0) {
                break;
            }
        }

        nv++;
    }

    return ret;
}


static nxt_int_t
nxt_http_route_test_rule(nxt_http_request_t *r, nxt_http_route_rule_t *rule,
    u_char *start, size_t length)
{
    nxt_int_t                 ret;
    nxt_http_route_pattern_t  *pattern, *end;

    ret = 1;
    pattern = &rule->pattern[0];
    end = pattern + rule->items;

    while (pattern < end) {
        ret = nxt_http_route_pattern(r, pattern, start, length);
        if (nxt_slow_path(ret == NXT_ERROR)) {
            return NXT_ERROR;
        }

        /* nxt_http_route_pattern() returns either 1 or 0. */
        ret ^= pattern->negative;

        if (pattern->any == ret) {
            return ret;
        }

        pattern++;
    }

    return ret;
}


static nxt_int_t
nxt_http_route_pattern(nxt_http_request_t *r, nxt_http_route_pattern_t *pattern,
    u_char *start, size_t length)
{
    u_char                          *p, *end, *test;
    size_t                          test_length;
    uint32_t                        i;
    nxt_array_t                     *pattern_slices;
    nxt_http_route_pattern_slice_t  *pattern_slice;

#if (NXT_HAVE_REGEX)
    if (pattern->regex) {
        if (r->regex_match == NULL) {
            r->regex_match = nxt_regex_match_create(r->mem_pool, 0);
            if (nxt_slow_path(r->regex_match == NULL)) {
                return NXT_ERROR;
            }
        }

        return nxt_regex_match(pattern->u.regex, start, length, r->regex_match);
    }
#endif

    if (length < pattern->min_length) {
        return 0;
    }

    nxt_assert(pattern->u.pattern_slices != NULL);

    pattern_slices = pattern->u.pattern_slices;
    pattern_slice = pattern_slices->elts;
    end = start + length;

    for (i = 0; i < pattern_slices->nelts; i++, pattern_slice++) {
        test = pattern_slice->start;
        test_length = pattern_slice->length;

        switch (pattern_slice->type) {
        case NXT_HTTP_ROUTE_PATTERN_EXACT:
            return ((length == pattern->min_length) &&
                    nxt_http_route_memcmp(start, test, test_length,
                                          pattern->case_sensitive));

        case NXT_HTTP_ROUTE_PATTERN_BEGIN:
            if (nxt_http_route_memcmp(start, test, test_length,
                                      pattern->case_sensitive))
            {
                start += test_length;
                break;
            }

            return 0;

        case NXT_HTTP_ROUTE_PATTERN_END:
            p = end - test_length;

            if (nxt_http_route_memcmp(p, test, test_length,
                                      pattern->case_sensitive))
            {
                end = p;
                break;
            }

            return 0;

        case NXT_HTTP_ROUTE_PATTERN_SUBSTRING:
            if (pattern->case_sensitive) {
                p = nxt_memstrn(start, end, (char *) test, test_length);

            } else {
                p = nxt_memcasestrn(start, end, (char *) test, test_length);
            }

            if (p == NULL) {
                return 0;
            }

            start = p + test_length;
        }
    }

    return 1;
}


static nxt_int_t
nxt_http_route_memcmp(u_char *start, u_char *test, size_t test_length,
    nxt_bool_t case_sensitive)
{
    nxt_int_t  n;

    if (case_sensitive) {
        n = nxt_memcmp(start, test, test_length);

    } else {
        n = nxt_memcasecmp(start, test, test_length);
    }

    return (n == 0);
}
