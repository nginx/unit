
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


typedef enum {
    NXT_HTTP_ROUTE_TABLE = 0,
    NXT_HTTP_ROUTE_STRING,
    NXT_HTTP_ROUTE_STRING_PTR,
    NXT_HTTP_ROUTE_HEADER,
    NXT_HTTP_ROUTE_ARGUMENT,
    NXT_HTTP_ROUTE_COOKIE,
} nxt_http_route_object_t;


typedef enum {
    NXT_HTTP_ROUTE_PATTERN_EXACT = 0,
    NXT_HTTP_ROUTE_PATTERN_BEGIN,
    NXT_HTTP_ROUTE_PATTERN_MIDDLE,
    NXT_HTTP_ROUTE_PATTERN_END,
    NXT_HTTP_ROUTE_PATTERN_SUBSTRING,
} nxt_http_route_pattern_type_t;


typedef enum {
    NXT_HTTP_ROUTE_PATTERN_NOCASE = 0,
    NXT_HTTP_ROUTE_PATTERN_LOWCASE,
    NXT_HTTP_ROUTE_PATTERN_UPCASE,
} nxt_http_route_pattern_case_t;


typedef struct {
    nxt_conf_value_t               *host;
    nxt_conf_value_t               *uri;
    nxt_conf_value_t               *method;
    nxt_conf_value_t               *headers;
    nxt_conf_value_t               *arguments;
    nxt_conf_value_t               *cookies;
} nxt_http_route_match_conf_t;


typedef struct {
    u_char                         *start1;
    u_char                         *start2;
    uint32_t                       length1;
    uint32_t                       length2;
    uint32_t                       min_length;

    nxt_http_route_pattern_type_t  type:8;
    uint8_t                        case_sensitive;  /* 1 bit */
    uint8_t                        negative;        /* 1 bit */
    uint8_t                        any;             /* 1 bit */
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


typedef union {
    nxt_http_route_rule_t          *rule;
    nxt_http_route_table_t         *table;
} nxt_http_route_test_t;


typedef struct {
    uint32_t                       items;
    nxt_http_pass_t                pass;
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


#define NJS_COOKIE_HASH                                                       \
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
static nxt_http_route_table_t *nxt_http_route_table_create(nxt_task_t *task,
    nxt_mp_t *mp, nxt_conf_value_t *table_cv, nxt_http_route_object_t object,
    nxt_bool_t case_sensitive);
static nxt_http_route_ruleset_t *nxt_http_route_ruleset_create(nxt_task_t *task,
    nxt_mp_t *mp, nxt_conf_value_t *ruleset_cv, nxt_http_route_object_t object,
    nxt_bool_t case_sensitive);
static nxt_http_route_rule_t *nxt_http_route_rule_name_create(nxt_task_t *task,
    nxt_mp_t *mp, nxt_conf_value_t *rule_cv, nxt_str_t *name,
    nxt_bool_t case_sensitive);
static nxt_http_route_rule_t *nxt_http_route_rule_create(nxt_task_t *task,
    nxt_mp_t *mp, nxt_conf_value_t *cv, nxt_bool_t case_sensitive,
    nxt_http_route_pattern_case_t pattern_case);
static int nxt_http_pattern_compare(const void *one, const void *two);
static nxt_int_t nxt_http_route_pattern_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *cv, nxt_http_route_pattern_t *pattern,
    nxt_http_route_pattern_case_t pattern_case);
static u_char *nxt_http_route_pattern_copy(nxt_mp_t *mp, nxt_str_t *test,
    nxt_http_route_pattern_case_t pattern_case);

static void nxt_http_route_resolve(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_http_route_t *route);
static void nxt_http_pass_resolve(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_http_pass_t *pass);
static nxt_http_route_t *nxt_http_route_find(nxt_http_routes_t *routes,
    nxt_str_t *name);
static void nxt_http_route_cleanup(nxt_task_t *task, nxt_http_route_t *routes);

static nxt_http_pass_t *nxt_http_route_pass(nxt_task_t *task,
    nxt_http_request_t *r, nxt_http_pass_t *start);
static nxt_http_pass_t *nxt_http_route_match(nxt_http_request_t *r,
    nxt_http_route_match_t *match);
static nxt_int_t nxt_http_route_table(nxt_http_request_t *r,
    nxt_http_route_table_t *table);
static nxt_int_t nxt_http_route_ruleset(nxt_http_request_t *r,
    nxt_http_route_ruleset_t *ruleset);
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
    nxt_str_t                    pass, *string;
    nxt_conf_value_t             *match_conf, *pass_conf;
    nxt_http_route_test_t        *test;
    nxt_http_route_rule_t        *rule;
    nxt_http_route_table_t       *table;
    nxt_http_route_match_t       *match;
    nxt_http_route_match_conf_t  mtcf;

    static nxt_str_t  pass_path = nxt_string("/action/pass");
    static nxt_str_t  match_path = nxt_string("/match");

    pass_conf = nxt_conf_get_path(cv, &pass_path);
    if (nxt_slow_path(pass_conf == NULL)) {
        return NULL;
    }

    nxt_conf_get_string(pass_conf, &pass);

    match_conf = nxt_conf_get_path(cv, &match_path);

    n = (match_conf != NULL) ? nxt_conf_object_members_count(match_conf) : 0;
    size = sizeof(nxt_http_route_match_t) + n * sizeof(nxt_http_route_rule_t *);

    mp = tmcf->router_conf->mem_pool;

    match = nxt_mp_alloc(mp, size);
    if (nxt_slow_path(match == NULL)) {
        return NULL;
    }

    match->pass.u.route = NULL;
    match->pass.handler = NULL;
    match->items = n;

    string = nxt_str_dup(mp, &match->pass.name, &pass);
    if (nxt_slow_path(string == NULL)) {
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

    if (mtcf.host != NULL) {
        rule = nxt_http_route_rule_create(task, mp, mtcf.host, 1,
                                          NXT_HTTP_ROUTE_PATTERN_LOWCASE);
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
                                          NXT_HTTP_ROUTE_PATTERN_NOCASE);
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
                                          NXT_HTTP_ROUTE_PATTERN_UPCASE);
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
                                            NXT_HTTP_ROUTE_HEADER, 0);
        if (table == NULL) {
            return NULL;
        }

        test->table = table;
        test++;
    }

    if (mtcf.arguments != NULL) {
        table = nxt_http_route_table_create(task, mp, mtcf.arguments,
                                            NXT_HTTP_ROUTE_ARGUMENT, 1);
        if (table == NULL) {
            return NULL;
        }

        test->table = table;
        test++;
    }

    if (mtcf.cookies != NULL) {
        table = nxt_http_route_table_create(task, mp, mtcf.cookies,
                                            NXT_HTTP_ROUTE_COOKIE, 1);
        if (table == NULL) {
            return NULL;
        }

        test->table = table;
        test++;
    }

    return match;
}


static nxt_http_route_table_t *
nxt_http_route_table_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *table_cv, nxt_http_route_object_t object,
    nxt_bool_t case_sensitive)
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
        ruleset = nxt_http_route_ruleset_create(task, mp, table_cv,
                                                object, case_sensitive);
        if (nxt_slow_path(ruleset == NULL)) {
            return NULL;
        }

        table->ruleset[0] = ruleset;

        return table;
    }

    for (i = 0; i < n; i++) {
        ruleset_cv = nxt_conf_get_array_element(table_cv, i);

        ruleset = nxt_http_route_ruleset_create(task, mp, ruleset_cv,
                                                object, case_sensitive);
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
    nxt_bool_t case_sensitive)
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
                                               case_sensitive);
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
    nxt_conf_value_t *rule_cv, nxt_str_t *name, nxt_bool_t case_sensitive)
{
    u_char                 c, *p;
    uint32_t               hash;
    nxt_uint_t             i;
    nxt_http_route_rule_t  *rule;

    rule = nxt_http_route_rule_create(task, mp, rule_cv, case_sensitive,
                                      NXT_HTTP_ROUTE_PATTERN_NOCASE);
    if (nxt_slow_path(rule == NULL)) {
        return NULL;
    }

    rule->u.name.length = name->length;

    p = nxt_mp_nget(mp, name->length);
    if (nxt_slow_path(p == NULL)) {
        return NULL;
    }

    rule->u.name.start = p;

    hash = NXT_HTTP_FIELD_HASH_INIT;

    for (i = 0; i < name->length; i++) {
        c = name->start[i];
        *p++ = c;

        c = case_sensitive ? c : nxt_lowcase(c);
        hash = nxt_http_field_hash_char(hash, c);
    }

    rule->u.name.hash = nxt_http_field_hash_end(hash) & 0xFFFF;

    return rule;
}


static nxt_http_route_rule_t *
nxt_http_route_rule_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *cv, nxt_bool_t case_sensitive,
    nxt_http_route_pattern_case_t pattern_case)
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
                                            pattern_case);
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
                                            pattern_case);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NULL;
        }
    }

    return rule;
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


static nxt_int_t
nxt_http_route_pattern_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *cv, nxt_http_route_pattern_t *pattern,
    nxt_http_route_pattern_case_t pattern_case)
{
    u_char                         *start;
    nxt_str_t                      test;
    nxt_uint_t                     n, length;
    nxt_http_route_pattern_type_t  type;

    /* Suppress warning about uninitialized variable. */
    length = 0;

    type = NXT_HTTP_ROUTE_PATTERN_EXACT;

    nxt_conf_get_string(cv, &test);

    pattern->negative = 0;
    pattern->any = 1;

    if (test.length != 0) {

        if (test.start[0] == '!') {
            test.start++;
            test.length--;

            pattern->negative = 1;
            pattern->any = 0;
        }

        if (test.length != 0) {

            if (test.start[0] == '*') {
                test.start++;
                test.length--;

                if (test.length != 0) {
                    if (test.start[test.length - 1] == '*') {
                        test.length--;
                        type = NXT_HTTP_ROUTE_PATTERN_SUBSTRING;

                    } else {
                        type = NXT_HTTP_ROUTE_PATTERN_END;
                    }

                } else {
                    type = NXT_HTTP_ROUTE_PATTERN_BEGIN;
                }

            } else if (test.start[test.length - 1] == '*') {
                test.length--;
                type = NXT_HTTP_ROUTE_PATTERN_BEGIN;

            } else {
                length = test.length - 1;

                for (n = 1; n < length; n++) {
                    if (test.start[n] == '*') {
                        test.length = n;
                        type = NXT_HTTP_ROUTE_PATTERN_MIDDLE;
                        break;
                    }
                }
            }
        }
    }

    pattern->type = type;
    pattern->min_length = test.length;
    pattern->length1 = test.length;

    start = nxt_http_route_pattern_copy(mp, &test, pattern_case);
    if (nxt_slow_path(start == NULL)) {
        return NXT_ERROR;
    }

    pattern->start1 = start;

    if (type == NXT_HTTP_ROUTE_PATTERN_MIDDLE) {
        length -= test.length;
        pattern->length2 = length;
        pattern->min_length += length;

        test.start = &test.start[test.length + 1];
        test.length = length;

        start = nxt_http_route_pattern_copy(mp, &test, pattern_case);
        if (nxt_slow_path(start == NULL)) {
            return NXT_ERROR;
        }

        pattern->start2 = start;
    }

    return NXT_OK;
}


static u_char *
nxt_http_route_pattern_copy(nxt_mp_t *mp, nxt_str_t *test,
    nxt_http_route_pattern_case_t pattern_case)
{
    u_char  *start;

    start = nxt_mp_nget(mp, test->length);
    if (nxt_slow_path(start == NULL)) {
        return start;
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

    return start;
}


void
nxt_http_routes_resolve(nxt_task_t *task, nxt_router_temp_conf_t *tmcf)
{
    nxt_http_route_t   **route, **end;
    nxt_http_routes_t  *routes;

    routes = tmcf->router_conf->routes;

    if (routes != NULL) {
        route = &routes->route[0];
        end = route + routes->items;

        while (route < end) {
            nxt_http_route_resolve(task, tmcf, *route);

            route++;
        }
    }
}


static void
nxt_http_route_resolve(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_http_route_t *route)
{
    nxt_http_route_match_t  **match, **end;

    match = &route->match[0];
    end = match + route->items;

    while (match < end) {
        nxt_http_pass_resolve(task, tmcf, &(*match)->pass);

        match++;
    }
}


static void
nxt_http_pass_resolve(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_http_pass_t *pass)
{
    nxt_str_t  name;

    name = pass->name;

    if (nxt_str_start(&name, "applications/", 13)) {
        name.length -= 13;
        name.start += 13;

        pass->u.application = nxt_router_listener_application(tmcf, &name);
        nxt_router_app_use(task, pass->u.application, 1);

        pass->handler = nxt_http_request_application;

    } else if (nxt_str_start(&name, "routes", 6)) {

        if (name.length == 6) {
            name.length = 0;
            name.start = NULL;

        } else if (name.start[6] == '/') {
            name.length -= 7;
            name.start += 7;
        }

        pass->u.route = nxt_http_route_find(tmcf->router_conf->routes, &name);

        pass->handler = nxt_http_route_pass;
    }
}


static nxt_http_route_t *
nxt_http_route_find(nxt_http_routes_t *routes, nxt_str_t *name)
{
    nxt_http_route_t  **route, **end;

    route = &routes->route[0];
    end = route + routes->items;

    while (route < end) {
        if (nxt_strstr_eq(&(*route)->name, name)) {
            return *route;
        }

        route++;
    }

    return NULL;
}


nxt_http_pass_t *
nxt_http_pass_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_str_t *name)
{
    nxt_http_pass_t  *pass;

    pass = nxt_mp_alloc(tmcf->router_conf->mem_pool, sizeof(nxt_http_pass_t));
    if (nxt_slow_path(pass == NULL)) {
        return NULL;
    }

    pass->name = *name;

    nxt_http_pass_resolve(task, tmcf, pass);

    return pass;
}


/* COMPATIBILITY: listener application. */

nxt_http_pass_t *
nxt_http_pass_application(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_str_t *name)
{
    nxt_http_pass_t  *pass;

    pass = nxt_mp_alloc(tmcf->router_conf->mem_pool, sizeof(nxt_http_pass_t));
    if (nxt_slow_path(pass == NULL)) {
        return NULL;
    }

    pass->name = *name;

    pass->u.application = nxt_router_listener_application(tmcf, name);
    nxt_router_app_use(task, pass->u.application, 1);

    pass->handler = nxt_http_request_application;

    return pass;
}


void
nxt_http_routes_cleanup(nxt_task_t *task, nxt_http_routes_t *routes)
{
    nxt_http_route_t  **route, **end;

    if (routes != NULL) {
        route = &routes->route[0];
        end = route + routes->items;

        while (route < end) {
            nxt_http_route_cleanup(task, *route);

            route++;
        }
    }
}


static void
nxt_http_route_cleanup(nxt_task_t *task, nxt_http_route_t *route)
{
    nxt_http_route_match_t  **match, **end;

    match = &route->match[0];
    end = match + route->items;

    while (match < end) {
        nxt_http_pass_cleanup(task, &(*match)->pass);

        match++;
    }
}


void
nxt_http_pass_cleanup(nxt_task_t *task, nxt_http_pass_t *pass)
{
    if (pass->handler == nxt_http_request_application) {
        nxt_router_app_use(task, pass->u.application, -1);
    }
}


static nxt_http_pass_t *
nxt_http_route_pass(nxt_task_t *task, nxt_http_request_t *r,
    nxt_http_pass_t *start)
{
    nxt_http_pass_t         *pass;
    nxt_http_route_t        *route;
    nxt_http_route_match_t  **match, **end;

    route = start->u.route;
    match = &route->match[0];
    end = match + route->items;

    while (match < end) {
        pass = nxt_http_route_match(r, *match);
        if (pass != NULL) {
            return pass;
        }

        match++;
    }

    nxt_http_request_error(task, r, NXT_HTTP_NOT_FOUND);

    return NULL;
}


static nxt_http_pass_t *
nxt_http_route_match(nxt_http_request_t *r, nxt_http_route_match_t *match)
{
    nxt_int_t              ret;
    nxt_http_route_test_t  *test, *end;

    test = &match->test[0];
    end = test + match->items;

    while (test < end) {
        if (test->rule->object != NXT_HTTP_ROUTE_TABLE) {
            ret = nxt_http_route_rule(r, test->rule);

        } else {
            ret = nxt_http_route_table(r, test->table);
        }

        if (ret <= 0) {
            /* 0 => NULL, -1 => NXT_HTTP_PASS_ERROR. */
            return (nxt_http_pass_t *) (intptr_t) ret;
        }

        test++;
    }

    return &match->pass;
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
    u_char                 c, *p, *start, *end, *name;
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

    start = r->args->start;
    end = start + r->args->length;

    for (p = start; p < end; p++) {
        c = *p;

        if (c == '=') {
            name_length = p - start;
            name = start;
            start = p + 1;
            valid = (name_length != 0);

        } else if (c == '&') {
            if (valid) {
                nv = nxt_http_route_argument(args, name, name_length, hash,
                                             start, p);
                if (nxt_slow_path(nv == NULL)) {
                    return NULL;
                }
            }

            hash = NXT_HTTP_FIELD_HASH_INIT;
            valid = 1;
            name = NULL;
            start = p + 1;

        } else if (name == NULL) {
            hash = nxt_http_field_hash_char(hash, c);
        }
    }

    if (valid) {
        nv = nxt_http_route_argument(args, name, name_length, hash, start, p);
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
    nxt_bool_t             ret;
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
            if (ret == 0) {
                break;
            }
        }

        nv++;
    }

    return ret;
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

        if (f->hash != NJS_COOKIE_HASH
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
    nxt_bool_t             ret;
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
    u_char     *p, *end, *test;
    size_t     test_length;
    nxt_int_t  ret;

    if (length < pattern->min_length) {
        return 0;
    }

    test = pattern->start1;
    test_length = pattern->length1;

    switch (pattern->type) {

    case NXT_HTTP_ROUTE_PATTERN_EXACT:
        if (length != test_length) {
            return 0;
        }

        break;

    case NXT_HTTP_ROUTE_PATTERN_BEGIN:
        break;

    case NXT_HTTP_ROUTE_PATTERN_MIDDLE:
        ret = nxt_http_route_memcmp(start, test, test_length,
                                    pattern->case_sensitive);
        if (!ret) {
            return ret;
        }

        test = pattern->start2;
        test_length = pattern->length2;

        /* Fall through. */

    case NXT_HTTP_ROUTE_PATTERN_END:
        start += length - test_length;
        break;

    case NXT_HTTP_ROUTE_PATTERN_SUBSTRING:
        end = start + length;

        if (pattern->case_sensitive) {
            p = nxt_memstrn(start, end, (char *) test, test_length);

        } else {
            p = nxt_memcasestrn(start, end, (char *) test, test_length);
        }

        return (p != NULL);
    }

    return nxt_http_route_memcmp(start, test, test_length,
                                 pattern->case_sensitive);
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
