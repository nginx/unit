
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


typedef enum {
    NXT_HTTP_ROUTE_STRING = 0,
    NXT_HTTP_ROUTE_STRING_PTR,
    NXT_HTTP_ROUTE_FIELD,
    NXT_HTTP_ROUTE_HEADER,
    NXT_HTTP_ROUTE_ARGUMENT,
    NXT_HTTP_ROUTE_COOKIE,
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


typedef struct {
    nxt_conf_value_t               *host;
    nxt_conf_value_t               *uri;
    nxt_conf_value_t               *method;
} nxt_http_route_match_conf_t;


typedef struct {
    nxt_str_t                      test;
    uint32_t                       min_length;

    nxt_http_route_pattern_type_t  type:8;
    uint8_t                        case_sensitive;  /* 1 bit */
    uint8_t                        negative;        /* 1 bit */
    uint8_t                        any;             /* 1 bit */
} nxt_http_route_pattern_t;


typedef struct {
    uintptr_t                      offset;
    uint32_t                       items;
    nxt_http_route_object_t        object:8;
    nxt_http_route_pattern_t       pattern[0];
} nxt_http_route_rule_t;


typedef struct {
    uint32_t                       items;
    nxt_http_pass_t                pass;
    nxt_http_route_rule_t          *rule[0];
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


static nxt_http_route_t *nxt_http_route_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_conf_value_t *cv);
static nxt_http_route_match_t *nxt_http_route_match_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_conf_value_t *cv);
static nxt_http_route_rule_t *nxt_http_route_rule_create(nxt_task_t *task,
    nxt_router_temp_conf_t *tmcf, nxt_conf_value_t *cv,
    nxt_bool_t case_sensitive, nxt_http_route_pattern_case_t pattern_case);
static int nxt_http_pattern_compare(const void *one, const void *two);
static nxt_int_t nxt_http_route_pattern_create(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *cv, nxt_http_route_pattern_t *pattern,
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
static nxt_bool_t nxt_http_route_rule(nxt_http_request_t *r,
    nxt_http_route_rule_t *rule);
static nxt_bool_t nxt_http_route_pattern(nxt_http_request_t *r,
    nxt_http_route_pattern_t *pattern, u_char *start, size_t length);


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
    nxt_int_t                    ret;
    nxt_str_t                    pass, *string;
    nxt_conf_value_t             *match_conf, *pass_conf;
    nxt_http_route_rule_t        *rule, **p;
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

    match = nxt_mp_alloc(tmcf->router_conf->mem_pool, size);
    if (nxt_slow_path(match == NULL)) {
        return NULL;
    }

    match->pass.u.route = NULL;
    match->pass.handler = NULL;
    match->items = n;

    string = nxt_str_dup(tmcf->router_conf->mem_pool, &match->pass.name, &pass);
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

    p = &match->rule[0];

    if (mtcf.host != NULL) {
        rule = nxt_http_route_rule_create(task, tmcf, mtcf.host, 1,
                                          NXT_HTTP_ROUTE_PATTERN_LOWCASE);
        if (rule == NULL) {
            return NULL;
        }

        rule->offset = offsetof(nxt_http_request_t, host);
        rule->object = NXT_HTTP_ROUTE_STRING;
        *p++ = rule;
    }

    if (mtcf.uri != NULL) {
        rule = nxt_http_route_rule_create(task, tmcf, mtcf.uri, 1,
                                          NXT_HTTP_ROUTE_PATTERN_NOCASE);
        if (rule == NULL) {
            return NULL;
        }

        rule->offset = offsetof(nxt_http_request_t, path);
        rule->object = NXT_HTTP_ROUTE_STRING_PTR;
        *p++ = rule;
    }

    if (mtcf.method != NULL) {
        rule = nxt_http_route_rule_create(task, tmcf, mtcf.method, 1,
                                          NXT_HTTP_ROUTE_PATTERN_UPCASE);
        if (rule == NULL) {
            return NULL;
        }

        rule->offset = offsetof(nxt_http_request_t, method);
        rule->object = NXT_HTTP_ROUTE_STRING_PTR;
        *p++ = rule;
    }

    return match;
}


static nxt_http_route_rule_t *
nxt_http_route_rule_create(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_conf_value_t *cv, nxt_bool_t case_sensitive,
    nxt_http_route_pattern_case_t pattern_case)
{
    size_t                    size;
    uint32_t                  i, n;
    nxt_mp_t                  *mp;
    nxt_int_t                 ret;
    nxt_bool_t                string;
    nxt_conf_value_t          *value;
    nxt_http_route_rule_t     *rule;
    nxt_http_route_pattern_t  *pattern;

    mp = tmcf->router_conf->mem_pool;

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
    nxt_http_route_pattern_type_t  type;

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
            }
        }
    }

    pattern->type = type;
    pattern->min_length = test.length;
    pattern->test.length = test.length;

    start = nxt_mp_nget(mp, test.length);
    if (nxt_slow_path(start == NULL)) {
        return NXT_ERROR;
    }

    pattern->test.start = start;

    switch (pattern_case) {

    case NXT_HTTP_ROUTE_PATTERN_UPCASE:
        nxt_memcpy_upcase(start, test.start, test.length);
        break;

    case NXT_HTTP_ROUTE_PATTERN_LOWCASE:
        nxt_memcpy_lowcase(start, test.start, test.length);
        break;

    case NXT_HTTP_ROUTE_PATTERN_NOCASE:
        nxt_memcpy(start, test.start, test.length);
        break;
    }

    return NXT_OK;
}


void
nxt_http_routes_resolve(nxt_task_t *task, nxt_router_temp_conf_t *tmcf)
{
    nxt_uint_t         items;
    nxt_http_route_t   **route;
    nxt_http_routes_t  *routes;

    routes = tmcf->router_conf->routes;
    if (routes != NULL) {
        items = routes->items;
        route = &routes->route[0];

        while (items != 0) {
            nxt_http_route_resolve(task, tmcf, *route);

            route++;
            items--;
        }
    }
}


static void
nxt_http_route_resolve(nxt_task_t *task, nxt_router_temp_conf_t *tmcf,
    nxt_http_route_t *route)
{
    nxt_uint_t              items;
    nxt_http_route_match_t  **match;

    items = route->items;
    match = &route->match[0];

    while (items != 0) {
        nxt_http_pass_resolve(task, tmcf, &(*match)->pass);

        match++;
        items--;
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
    nxt_uint_t        items;
    nxt_http_route_t  **route;

    items = routes->items;
    route = &routes->route[0];

    do {
        if (nxt_strstr_eq(&(*route)->name, name)) {
            return *route;
        }

        route++;
        items--;

    } while (items != 0);

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
    nxt_uint_t        items;
    nxt_http_route_t  **route;

    if (routes != NULL) {
        items = routes->items;
        route = &routes->route[0];

        do {
            nxt_http_route_cleanup(task, *route);

            route++;
            items--;

        } while (items != 0);
    }
}


static void
nxt_http_route_cleanup(nxt_task_t *task, nxt_http_route_t *route)
{
    nxt_uint_t              items;
    nxt_http_route_match_t  **match;

    items = route->items;
    match = &route->match[0];

    do {
        nxt_http_pass_cleanup(task, &(*match)->pass);

        match++;
        items--;

    } while (items != 0);
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
    nxt_uint_t              items;
    nxt_http_pass_t         *pass;
    nxt_http_route_t        *route;
    nxt_http_route_match_t  **match;

    route = start->u.route;
    items = route->items;
    match = &route->match[0];

    while (items != 0) {
        pass = nxt_http_route_match(r, *match);
        if (pass != NULL) {
            return pass;
        }

        match++;
        items--;
    }

    nxt_http_request_error(task, r, NXT_HTTP_NOT_FOUND);

    return NULL;
}


static nxt_http_pass_t *
nxt_http_route_match(nxt_http_request_t *r, nxt_http_route_match_t *match)
{
    nxt_uint_t             items;
    nxt_http_route_rule_t  **rule;

    rule = &match->rule[0];
    items = match->items;

    while (items != 0) {
        if (!nxt_http_route_rule(r, *rule)) {
            return NULL;
        }

        rule++;
        items--;
    }

    return &match->pass;
}


static nxt_bool_t
nxt_http_route_rule(nxt_http_request_t *r, nxt_http_route_rule_t *rule)
{
    void                      *p, **pp;
    u_char                    *start;
    size_t                    length;
    nxt_str_t                 *s;
    nxt_uint_t                items;
    nxt_bool_t                ret;
    nxt_http_field_t          *f;
    nxt_http_route_pattern_t  *pattern;

    p = nxt_pointer_to(r, rule->offset);

    if (rule->object == NXT_HTTP_ROUTE_STRING) {
        s = p;
        length = s->length;
        start = s->start;

    } else {
        pp = p;
        p = *pp;

        if (p == NULL) {
            return 0;
        }

        switch (rule->object) {

        case NXT_HTTP_ROUTE_STRING_PTR:
            s = p;
            length = s->length;
            start = s->start;
            break;

        case NXT_HTTP_ROUTE_FIELD:
            f = p;
            length = f->value_length;
            start = f->value;
            break;

        case NXT_HTTP_ROUTE_HEADER:
            return 0;

        case NXT_HTTP_ROUTE_ARGUMENT:
            return 0;

        case NXT_HTTP_ROUTE_COOKIE:
            return 0;

        default:
            nxt_unreachable();
            return 0;
        }
    }

    items = rule->items;
    pattern = &rule->pattern[0];

    do {
        ret = nxt_http_route_pattern(r, pattern, start, length);

        ret ^= pattern->negative;

        if (pattern->any == ret) {
            return ret;
        }

        pattern++;
        items--;

    } while (items != 0);

    return ret;
}


static nxt_bool_t
nxt_http_route_pattern(nxt_http_request_t *r, nxt_http_route_pattern_t *pattern,
    u_char *start, size_t length)
{
    nxt_str_t  *test;

    if (length < pattern->min_length) {
        return 0;
    }

    test = &pattern->test;

    switch (pattern->type) {

    case NXT_HTTP_ROUTE_PATTERN_EXACT:
        if (length != test->length) {
            return 0;
        }

        break;

    case NXT_HTTP_ROUTE_PATTERN_BEGIN:
        break;

    case NXT_HTTP_ROUTE_PATTERN_END:
        start += length - test->length;
        break;

    case NXT_HTTP_ROUTE_PATTERN_SUBSTRING:
        if (pattern->case_sensitive) {
            return (nxt_memstrn(start, start + length,
                                (char *) test->start, test->length)
                    != NULL);
        }

        return (nxt_memcasestrn(start, start + length,
                                (char *) test->start, test->length)
                != NULL);
    }

    if (pattern->case_sensitive) {
        return (nxt_memcmp(start, test->start, test->length) == 0);
    }

    return (nxt_memcasecmp(start, test->start, test->length) == 0);
}
