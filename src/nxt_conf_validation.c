
/*
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#include <nxt_cert.h>
#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_sockaddr.h>
#include <nxt_http_route_addr.h>


typedef enum {
    NXT_CONF_VLDT_NULL    = 1 << NXT_CONF_NULL,
    NXT_CONF_VLDT_BOOLEAN = 1 << NXT_CONF_BOOLEAN,
    NXT_CONF_VLDT_INTEGER = 1 << NXT_CONF_INTEGER,
    NXT_CONF_VLDT_NUMBER  = (1 << NXT_CONF_NUMBER) | NXT_CONF_VLDT_INTEGER,
    NXT_CONF_VLDT_STRING  = 1 << NXT_CONF_STRING,
    NXT_CONF_VLDT_ARRAY   = 1 << NXT_CONF_ARRAY,
    NXT_CONF_VLDT_OBJECT  = 1 << NXT_CONF_OBJECT,
} nxt_conf_vldt_type_t;

#define NXT_CONF_VLDT_ANY_TYPE  (NXT_CONF_VLDT_NULL                           \
                                 |NXT_CONF_VLDT_BOOLEAN                       \
                                 |NXT_CONF_VLDT_NUMBER                        \
                                 |NXT_CONF_VLDT_STRING                        \
                                 |NXT_CONF_VLDT_ARRAY                         \
                                 |NXT_CONF_VLDT_OBJECT)


typedef enum {
    NXT_CONF_VLDT_REQUIRED = 1,
} nxt_conf_vldt_flags_t;


typedef nxt_int_t (*nxt_conf_vldt_handler_t)(nxt_conf_validation_t *vldt,
                                             nxt_conf_value_t *value,
                                             void *data);


typedef struct {
    nxt_str_t                name;
    nxt_conf_vldt_type_t     type:32;
    nxt_conf_vldt_flags_t    flags:32;
    nxt_conf_vldt_handler_t  validator;
    void                     *data;
} nxt_conf_vldt_object_t;


#define NXT_CONF_VLDT_NEXT(f)  { nxt_null_string, 0, 0, NULL, (f) }
#define NXT_CONF_VLDT_END      { nxt_null_string, 0, 0, NULL, NULL }


typedef nxt_int_t (*nxt_conf_vldt_member_t)(nxt_conf_validation_t *vldt,
                                            nxt_str_t *name,
                                            nxt_conf_value_t *value);
typedef nxt_int_t (*nxt_conf_vldt_element_t)(nxt_conf_validation_t *vldt,
                                             nxt_conf_value_t *value);

static nxt_int_t nxt_conf_vldt_type(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value, nxt_conf_vldt_type_t type);
static nxt_int_t nxt_conf_vldt_error(nxt_conf_validation_t *vldt,
    const char *fmt, ...);
static nxt_int_t nxt_conf_vldt_var(nxt_conf_validation_t *vldt,
    const char *option, nxt_str_t *value);

static nxt_int_t nxt_conf_vldt_mtypes(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_mtypes_type(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_mtypes_extension(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_listener(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value);
#if (NXT_TLS)
static nxt_int_t nxt_conf_vldt_certificate(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
#endif
static nxt_int_t nxt_conf_vldt_action(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_pass(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_return(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_proxy(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_routes(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_routes_member(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_route(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_match_encoded_patterns_sets(
    nxt_conf_validation_t *vldt, nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_match_encoded_patterns_set(
    nxt_conf_validation_t *vldt, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_match_encoded_patterns_set_member(
    nxt_conf_validation_t *vldt, nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_match_encoded_patterns(
    nxt_conf_validation_t *vldt, nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_match_encoded_pattern(
    nxt_conf_validation_t *vldt, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_match_patterns(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_match_pattern(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_match_patterns_sets(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_match_patterns_set(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_match_patterns_set_member(
    nxt_conf_validation_t *vldt, nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_match_scheme_pattern(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_match_addrs(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_match_addr(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_app_name(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_app(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_object(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_processes(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_object_iterator(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_array_iterator(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_environment(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_argument(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_php(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_php_targets_exclusive(
    nxt_conf_validation_t *vldt, nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_php_targets(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_php_target(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_php_option(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_java_classpath(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_java_option(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_upstream(nxt_conf_validation_t *vldt,
     nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_server(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_server_weight(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);

static nxt_int_t nxt_conf_vldt_isolation(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_clone_namespaces(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);

#if (NXT_HAVE_CLONE_NEWUSER)
static nxt_int_t nxt_conf_vldt_clone_procmap(nxt_conf_validation_t *vldt,
    const char* mapfile, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_clone_uidmap(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_clone_gidmap(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
#endif

static nxt_conf_vldt_object_t  nxt_conf_vldt_websocket_members[] = {
    { nxt_string("read_timeout"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("keepalive_interval"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("max_frame_size"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_static_members[] = {
    { nxt_string("mime_types"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_mtypes,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_http_members[] = {
    { nxt_string("header_read_timeout"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("body_read_timeout"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("send_timeout"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("idle_timeout"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("body_buffer_size"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("max_body_size"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("body_temp_path"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("websocket"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object,
      (void *) &nxt_conf_vldt_websocket_members },

    { nxt_string("static"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object,
      (void *) &nxt_conf_vldt_static_members },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_setting_members[] = {
    { nxt_string("http"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object,
      (void *) &nxt_conf_vldt_http_members },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_root_members[] = {
    { nxt_string("settings"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object,
      (void *) &nxt_conf_vldt_setting_members },

    { nxt_string("listeners"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object_iterator,
      (void *) &nxt_conf_vldt_listener },

    { nxt_string("routes"),
      NXT_CONF_VLDT_ARRAY | NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_routes,
      NULL },

    { nxt_string("applications"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object_iterator,
      (void *) &nxt_conf_vldt_app },

    { nxt_string("upstreams"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object_iterator,
      (void *) &nxt_conf_vldt_upstream },

    { nxt_string("access_log"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    NXT_CONF_VLDT_END
};


#if (NXT_TLS)

static nxt_conf_vldt_object_t  nxt_conf_vldt_tls_members[] = {
    { nxt_string("certificate"),
      NXT_CONF_VLDT_STRING,
      0,
      &nxt_conf_vldt_certificate,
      NULL },

    NXT_CONF_VLDT_END
};

#endif


static nxt_conf_vldt_object_t  nxt_conf_vldt_listener_members[] = {
    { nxt_string("pass"),
      NXT_CONF_VLDT_STRING,
      0,
      &nxt_conf_vldt_pass,
      NULL },

    { nxt_string("application"),
      NXT_CONF_VLDT_STRING,
      0,
      &nxt_conf_vldt_app_name,
      NULL },

#if (NXT_TLS)

    { nxt_string("tls"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object,
      (void *) &nxt_conf_vldt_tls_members },

#endif

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_match_members[] = {
    { nxt_string("method"),
      NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_match_patterns,
      NULL },

    { nxt_string("scheme"),
      NXT_CONF_VLDT_STRING,
      0,
      &nxt_conf_vldt_match_scheme_pattern,
      NULL },

    { nxt_string("host"),
      NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_match_patterns,
      NULL },

    { nxt_string("source"),
      NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_match_addrs,
      NULL },

    { nxt_string("destination"),
      NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_match_addrs,
      NULL },

    { nxt_string("uri"),
      NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_match_encoded_patterns,
      NULL },

    { nxt_string("arguments"),
      NXT_CONF_VLDT_OBJECT | NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_match_encoded_patterns_sets,
      NULL },

    { nxt_string("headers"),
      NXT_CONF_VLDT_OBJECT | NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_match_patterns_sets,
      NULL },

    { nxt_string("cookies"),
      NXT_CONF_VLDT_OBJECT | NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_match_patterns_sets,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_pass_action_members[] = {
    { nxt_string("pass"),
      NXT_CONF_VLDT_STRING,
      0,
      &nxt_conf_vldt_pass,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_return_action_members[] = {
    { nxt_string("return"),
      NXT_CONF_VLDT_INTEGER,
      0,
      &nxt_conf_vldt_return,
      NULL },

    { nxt_string("location"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_share_action_members[] = {
    { nxt_string("share"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("fallback"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_action,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_proxy_action_members[] = {
    { nxt_string("proxy"),
      NXT_CONF_VLDT_STRING,
      0,
      &nxt_conf_vldt_proxy,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_route_members[] = {
    { nxt_string("match"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object,
      (void *) &nxt_conf_vldt_match_members },

    { nxt_string("action"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_action,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_app_limits_members[] = {
    { nxt_string("timeout"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("requests"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("shm"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_app_processes_members[] = {
    { nxt_string("spare"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("max"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("idle_timeout"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_app_namespaces_members[] = {

#if (NXT_HAVE_CLONE_NEWUSER)
    { nxt_string("credential"),
      NXT_CONF_VLDT_BOOLEAN,
      0,
      NULL,
      NULL },
#endif

#if (NXT_HAVE_CLONE_NEWPID)
    { nxt_string("pid"),
      NXT_CONF_VLDT_BOOLEAN,
      0,
      NULL,
      NULL },
#endif

#if (NXT_HAVE_CLONE_NEWNET)
    { nxt_string("network"),
      NXT_CONF_VLDT_BOOLEAN,
      0,
      NULL,
      NULL },
#endif

#if (NXT_HAVE_CLONE_NEWNS)
    { nxt_string("mount"),
      NXT_CONF_VLDT_BOOLEAN,
      0,
      NULL,
      NULL },
#endif

#if (NXT_HAVE_CLONE_NEWUTS)
    { nxt_string("uname"),
      NXT_CONF_VLDT_BOOLEAN,
      0,
      NULL,
      NULL },
#endif

#if (NXT_HAVE_CLONE_NEWCGROUP)
    { nxt_string("cgroup"),
      NXT_CONF_VLDT_BOOLEAN,
      0,
      NULL,
      NULL },
#endif

    NXT_CONF_VLDT_END
};


#if (NXT_HAVE_CLONE_NEWUSER)

static nxt_conf_vldt_object_t nxt_conf_vldt_app_procmap_members[] = {
    { nxt_string("container"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("host"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    { nxt_string("size"),
      NXT_CONF_VLDT_INTEGER,
      0,
      NULL,
      NULL },

    NXT_CONF_VLDT_END
};

#endif


#if (NXT_HAVE_ISOLATION_ROOTFS)

static nxt_conf_vldt_object_t  nxt_conf_vldt_app_automount_members[] = {
    { nxt_string("language_deps"),
      NXT_CONF_VLDT_BOOLEAN,
      0,
      NULL,
      NULL },

    NXT_CONF_VLDT_END
};

#endif


static nxt_conf_vldt_object_t  nxt_conf_vldt_app_isolation_members[] = {
    { nxt_string("namespaces"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_clone_namespaces,
      (void *) &nxt_conf_vldt_app_namespaces_members },

#if (NXT_HAVE_CLONE_NEWUSER)

    { nxt_string("uidmap"),
      NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_array_iterator,
      (void *) &nxt_conf_vldt_clone_uidmap },

    { nxt_string("gidmap"),
      NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_array_iterator,
      (void *) &nxt_conf_vldt_clone_gidmap },

#endif

#if (NXT_HAVE_ISOLATION_ROOTFS)

    { nxt_string("rootfs"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("automount"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object,
      (void *) &nxt_conf_vldt_app_automount_members },

#endif

#if (NXT_HAVE_PR_SET_NO_NEW_PRIVS)

    { nxt_string("new_privs"),
      NXT_CONF_VLDT_BOOLEAN,
      0,
      NULL,
      NULL },

#endif

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_common_members[] = {
    { nxt_string("type"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("limits"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object,
      (void *) &nxt_conf_vldt_app_limits_members },

    { nxt_string("processes"),
      NXT_CONF_VLDT_INTEGER | NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_processes,
      (void *) &nxt_conf_vldt_app_processes_members },

    { nxt_string("user"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("group"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("working_directory"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("environment"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object_iterator,
      (void *) &nxt_conf_vldt_environment },

    { nxt_string("isolation"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_isolation,
      (void *) &nxt_conf_vldt_app_isolation_members },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_external_members[] = {
    { nxt_string("executable"),
      NXT_CONF_VLDT_STRING,
      NXT_CONF_VLDT_REQUIRED,
      NULL,
      NULL },

    { nxt_string("arguments"),
      NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_array_iterator,
      (void *) &nxt_conf_vldt_argument },

    NXT_CONF_VLDT_NEXT(&nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_python_members[] = {
    { nxt_string("home"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("path"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("module"),
      NXT_CONF_VLDT_STRING,
      NXT_CONF_VLDT_REQUIRED,
      NULL,
      NULL },

    NXT_CONF_VLDT_NEXT(&nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_php_target_members[] = {
    { nxt_string("root"),
      NXT_CONF_VLDT_STRING,
      NXT_CONF_VLDT_REQUIRED,
      NULL,
      NULL },

    { nxt_string("script"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("index"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_php_options_members[] = {
    { nxt_string("file"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("admin"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object_iterator,
      (void *) &nxt_conf_vldt_php_option },

    { nxt_string("user"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object_iterator,
      (void *) &nxt_conf_vldt_php_option },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_php_common_members[] = {
    { nxt_string("options"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object,
      (void *) &nxt_conf_vldt_php_options_members },

    NXT_CONF_VLDT_NEXT(&nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_php_notargets_members[] = {
    { nxt_string("root"),
      NXT_CONF_VLDT_STRING,
      NXT_CONF_VLDT_REQUIRED,
      NULL,
      NULL },

    { nxt_string("script"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    { nxt_string("index"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    NXT_CONF_VLDT_NEXT(&nxt_conf_vldt_php_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_php_members[] = {
    { nxt_string("root"),
      NXT_CONF_VLDT_ANY_TYPE,
      0,
      &nxt_conf_vldt_php_targets_exclusive,
      (void *) "root" },

    { nxt_string("script"),
      NXT_CONF_VLDT_ANY_TYPE,
      0,
      &nxt_conf_vldt_php_targets_exclusive,
      (void *) "script" },

    { nxt_string("index"),
      NXT_CONF_VLDT_ANY_TYPE,
      0,
      &nxt_conf_vldt_php_targets_exclusive,
      (void *) "index" },

    { nxt_string("targets"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_php_targets,
      NULL },

    NXT_CONF_VLDT_NEXT(&nxt_conf_vldt_php_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_perl_members[] = {
    { nxt_string("script"),
      NXT_CONF_VLDT_STRING,
      NXT_CONF_VLDT_REQUIRED,
      NULL,
      NULL },

    NXT_CONF_VLDT_NEXT(&nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_ruby_members[] = {
    { nxt_string("script"),
      NXT_CONF_VLDT_STRING,
      NXT_CONF_VLDT_REQUIRED,
      NULL,
      NULL },

    NXT_CONF_VLDT_NEXT(&nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_java_members[] = {
    { nxt_string("classpath"),
      NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_array_iterator,
      (void *) &nxt_conf_vldt_java_classpath },

    { nxt_string("webapp"),
      NXT_CONF_VLDT_STRING,
      NXT_CONF_VLDT_REQUIRED,
      NULL,
      NULL },

    { nxt_string("options"),
      NXT_CONF_VLDT_ARRAY,
      0,
      &nxt_conf_vldt_array_iterator,
      (void *) &nxt_conf_vldt_java_option },

    { nxt_string("unit_jars"),
      NXT_CONF_VLDT_STRING,
      0,
      NULL,
      NULL },

    NXT_CONF_VLDT_NEXT(&nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_upstream_members[] = {
    { nxt_string("servers"),
      NXT_CONF_VLDT_OBJECT,
      0,
      &nxt_conf_vldt_object_iterator,
      (void *) &nxt_conf_vldt_server },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_upstream_server_members[] = {
    { nxt_string("weight"),
      NXT_CONF_VLDT_NUMBER,
      0,
      &nxt_conf_vldt_server_weight,
      NULL },

    NXT_CONF_VLDT_END
};


nxt_int_t
nxt_conf_validate(nxt_conf_validation_t *vldt)
{
    nxt_int_t  ret;

    ret = nxt_conf_vldt_type(vldt, NULL, vldt->conf, NXT_CONF_VLDT_OBJECT);

    if (ret != NXT_OK) {
        return ret;
    }

    return nxt_conf_vldt_object(vldt, vldt->conf, nxt_conf_vldt_root_members);
}


#define NXT_CONF_VLDT_ANY_TYPE_STR                                            \
    "either a null, a boolean, an integer, "                                  \
    "a number, a string, an array, or an object"


static nxt_int_t
nxt_conf_vldt_type(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value, nxt_conf_vldt_type_t type)
{
    u_char      *p;
    nxt_str_t   expected;
    nxt_bool_t  comma;
    nxt_uint_t  value_type, n, t;
    u_char      buf[nxt_length(NXT_CONF_VLDT_ANY_TYPE_STR)];

    static nxt_str_t  type_name[] = {
        nxt_string("a null"),
        nxt_string("a boolean"),
        nxt_string("an integer number"),
        nxt_string("a fractional number"),
        nxt_string("a string"),
        nxt_string("an array"),
        nxt_string("an object"),
    };

    value_type = nxt_conf_type(value);

    if ((1 << value_type) & type) {
        return NXT_OK;
    }

    p = buf;

    n = nxt_popcount(type);

    if (n > 1) {
        p = nxt_cpymem(p, "either ", 7);
    }

    comma = (n > 2);

    for ( ;; ) {
        t = __builtin_ffs(type) - 1;

        p = nxt_cpymem(p, type_name[t].start, type_name[t].length);

        n--;

        if (n == 0) {
            break;
        }

        if (comma) {
            *p++ = ',';
        }

        if (n == 1) {
            p = nxt_cpymem(p, " or", 3);
        }

        *p++ = ' ';

        type = type & ~(1 << t);
    }

    expected.length = p - buf;
    expected.start = buf;

    if (name == NULL) {
        return nxt_conf_vldt_error(vldt,
                                   "The configuration must be %V, but not %V.",
                                   &expected, &type_name[value_type]);
    }

    return nxt_conf_vldt_error(vldt,
                               "The \"%V\" value must be %V, but not %V.",
                               name, &expected, &type_name[value_type]);
}


static nxt_int_t
nxt_conf_vldt_error(nxt_conf_validation_t *vldt, const char *fmt, ...)
{
    u_char   *p, *end;
    size_t   size;
    va_list  args;
    u_char   error[NXT_MAX_ERROR_STR];

    va_start(args, fmt);
    end = nxt_vsprintf(error, error + NXT_MAX_ERROR_STR, fmt, args);
    va_end(args);

    size = end - error;

    p = nxt_mp_nget(vldt->pool, size);
    if (p == NULL) {
        return NXT_ERROR;
    }

    nxt_memcpy(p, error, size);

    vldt->error.length = size;
    vldt->error.start = p;

    return NXT_DECLINED;
}


static nxt_int_t
nxt_conf_vldt_var(nxt_conf_validation_t *vldt, const char *option,
    nxt_str_t *value)
{
    u_char  error[NXT_MAX_ERROR_STR];

    if (nxt_var_test(value, error) != NXT_OK) {
        return nxt_conf_vldt_error(vldt, "%s in the \"%s\" value.",
                                   error, option);
    }

    return NXT_OK;
}


typedef struct {
    nxt_mp_t      *pool;
    nxt_str_t     *type;
    nxt_lvlhsh_t  hash;
} nxt_conf_vldt_mtypes_ctx_t;


static nxt_int_t
nxt_conf_vldt_mtypes(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_int_t                   ret;
    nxt_conf_vldt_mtypes_ctx_t  ctx;

    ctx.pool = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(ctx.pool == NULL)) {
        return NXT_ERROR;
    }

    nxt_lvlhsh_init(&ctx.hash);

    vldt->ctx = &ctx;

    ret = nxt_conf_vldt_object_iterator(vldt, value,
                                        &nxt_conf_vldt_mtypes_type);

    vldt->ctx = NULL;

    nxt_mp_destroy(ctx.pool);

    return ret;
}


static nxt_int_t
nxt_conf_vldt_mtypes_type(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    nxt_int_t                   ret;
    nxt_conf_vldt_mtypes_ctx_t  *ctx;

    ret = nxt_conf_vldt_type(vldt, name, value,
                             NXT_CONF_VLDT_STRING|NXT_CONF_VLDT_ARRAY);
    if (ret != NXT_OK) {
        return ret;
    }

    ctx = vldt->ctx;

    ctx->type = nxt_mp_get(ctx->pool, sizeof(nxt_str_t));
    if (nxt_slow_path(ctx->type == NULL)) {
        return NXT_ERROR;
    }

    *ctx->type = *name;

    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        return nxt_conf_vldt_array_iterator(vldt, value,
                                            &nxt_conf_vldt_mtypes_extension);
    }

    /* NXT_CONF_STRING */

    return nxt_conf_vldt_mtypes_extension(vldt, value);
}


static nxt_int_t
nxt_conf_vldt_mtypes_extension(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    nxt_str_t                   ext, *dup_type;
    nxt_conf_vldt_mtypes_ctx_t  *ctx;

    ctx = vldt->ctx;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" MIME type array must "
                                   "contain only strings.", ctx->type);
    }

    nxt_conf_get_string(value, &ext);

    if (ext.length == 0) {
        return nxt_conf_vldt_error(vldt, "An empty file extension for "
                                         "the \"%V\" MIME type.", ctx->type);
    }

    dup_type = nxt_http_static_mtypes_hash_find(&ctx->hash, &ext);

    if (dup_type != NULL) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" file extension has been "
                                         "declared for \"%V\" and \"%V\" "
                                         "MIME types at the same time.",
                                         &ext, dup_type, ctx->type);
    }

    return nxt_http_static_mtypes_hash_add(ctx->pool, &ctx->hash,
                                           &ext, ctx->type);
}


static nxt_int_t
nxt_conf_vldt_listener(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    nxt_int_t       ret;
    nxt_sockaddr_t  *sa;

    sa = nxt_sockaddr_parse(vldt->pool, name);
    if (nxt_slow_path(sa == NULL)) {
        return nxt_conf_vldt_error(vldt,
                                   "The listener address \"%V\" is invalid.",
                                   name);
    }

    ret = nxt_conf_vldt_type(vldt, name, value, NXT_CONF_VLDT_OBJECT);
    if (ret != NXT_OK) {
        return ret;
    }

    return nxt_conf_vldt_object(vldt, value, nxt_conf_vldt_listener_members);
}


static nxt_int_t
nxt_conf_vldt_action(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_uint_t              i;
    nxt_conf_value_t        *action;
    nxt_conf_vldt_object_t  *members;

    static struct {
        nxt_str_t               name;
        nxt_conf_vldt_object_t  *members;

    } actions[] = {
        { nxt_string("pass"), nxt_conf_vldt_pass_action_members },
        { nxt_string("return"), nxt_conf_vldt_return_action_members },
        { nxt_string("share"), nxt_conf_vldt_share_action_members },
        { nxt_string("proxy"), nxt_conf_vldt_proxy_action_members },
    };

    members = NULL;

    for (i = 0; i < nxt_nitems(actions); i++) {
        action = nxt_conf_get_object_member(value, &actions[i].name, NULL);

        if (action == NULL) {
            continue;
        }

        if (members != NULL) {
            return nxt_conf_vldt_error(vldt, "The \"action\" object must have "
                                       "just one of \"pass\", \"return\", "
                                       "\"share\", or \"proxy\" options set.");
        }

        members = actions[i].members;
    }

    if (members == NULL) {
        return nxt_conf_vldt_error(vldt, "The \"action\" object must have "
                                   "either \"pass\", \"return\", \"share\", "
                                   "or \"proxy\" option set.");
    }

    return nxt_conf_vldt_object(vldt, value, members);
}


static nxt_int_t
nxt_conf_vldt_pass(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_str_t  pass;
    nxt_int_t  ret;
    nxt_str_t  segments[3];

    static nxt_str_t  targets_str = nxt_string("targets");

    nxt_conf_get_string(value, &pass);

    if (nxt_is_var(&pass)) {
        return nxt_conf_vldt_var(vldt, "pass", &pass);
    }

    ret = nxt_http_pass_segments(vldt->pool, &pass, segments, 3);

    if (ret != NXT_OK) {
        if (ret == NXT_DECLINED) {
            return nxt_conf_vldt_error(vldt, "Request \"pass\" value \"%V\" "
                                       "is invalid.", &pass);
        }

        return NXT_ERROR;
    }

    if (nxt_str_eq(&segments[0], "applications", 12)) {

        if (segments[1].length == 0) {
            goto error;
        }

        value = nxt_conf_get_object_member(vldt->conf, &segments[0], NULL);

        if (value == NULL) {
            goto error;
        }

        value = nxt_conf_get_object_member(value, &segments[1], NULL);

        if (value == NULL) {
            goto error;
        }

        if (segments[2].length > 0) {
            value = nxt_conf_get_object_member(value, &targets_str, NULL);

            if (value == NULL) {
                goto error;
            }

            value = nxt_conf_get_object_member(value, &segments[2], NULL);

            if (value == NULL) {
                goto error;
            }
        }

        return NXT_OK;
    }

    if (nxt_str_eq(&segments[0], "upstreams", 9)) {

        if (segments[1].length == 0 || segments[2].length != 0) {
            goto error;
        }

        value = nxt_conf_get_object_member(vldt->conf, &segments[0], NULL);

        if (value == NULL) {
            goto error;
        }

        value = nxt_conf_get_object_member(value, &segments[1], NULL);

        if (value == NULL) {
            goto error;
        }

        return NXT_OK;
    }

    if (nxt_str_eq(&segments[0], "routes", 6)) {

        if (segments[2].length != 0) {
            goto error;
        }

        value = nxt_conf_get_object_member(vldt->conf, &segments[0], NULL);

        if (value == NULL) {
            goto error;
        }

        if (segments[1].length == 0) {
            if (nxt_conf_type(value) != NXT_CONF_ARRAY) {
                goto error;
            }

            return NXT_OK;
        }

        if (nxt_conf_type(value) != NXT_CONF_OBJECT) {
            goto error;
        }

        value = nxt_conf_get_object_member(value, &segments[1], NULL);

        if (value == NULL) {
            goto error;
        }

        return NXT_OK;
    }

error:

    return nxt_conf_vldt_error(vldt, "Request \"pass\" points to invalid "
                               "location \"%V\".", &pass);
}


static nxt_int_t
nxt_conf_vldt_return(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    int64_t  status;

    status = nxt_conf_get_number(value);

    if (status < NXT_HTTP_INVALID || status > NXT_HTTP_STATUS_MAX) {
        return nxt_conf_vldt_error(vldt, "The \"return\" value is out of "
                                   "allowed HTTP status code range 0-999.");
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_proxy(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_str_t       name;
    nxt_sockaddr_t  *sa;

    nxt_conf_get_string(value, &name);

    if (nxt_str_start(&name, "http://", 7)) {
        name.length -= 7;
        name.start += 7;

        sa = nxt_sockaddr_parse(vldt->pool, &name);
        if (sa != NULL) {
            return NXT_OK;
        }
    }

    return nxt_conf_vldt_error(vldt, "The \"proxy\" address is invalid \"%V\"",
                               &name);
}


static nxt_int_t
nxt_conf_vldt_routes(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        return nxt_conf_vldt_array_iterator(vldt, value,
                                            &nxt_conf_vldt_route);
    }

    /* NXT_CONF_OBJECT */

    return nxt_conf_vldt_object_iterator(vldt, value,
                                         &nxt_conf_vldt_routes_member);
}


static nxt_int_t
nxt_conf_vldt_routes_member(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    nxt_int_t  ret;

    ret = nxt_conf_vldt_type(vldt, name, value, NXT_CONF_VLDT_ARRAY);

    if (ret != NXT_OK) {
        return ret;
    }

    return nxt_conf_vldt_array_iterator(vldt, value, &nxt_conf_vldt_route);
}


static nxt_int_t
nxt_conf_vldt_route(nxt_conf_validation_t *vldt, nxt_conf_value_t *value)
{
    if (nxt_conf_type(value) != NXT_CONF_OBJECT) {
        return nxt_conf_vldt_error(vldt, "The \"routes\" array must contain "
                                   "only object values.");
    }

    return nxt_conf_vldt_object(vldt, value, nxt_conf_vldt_route_members);
}


static nxt_int_t
nxt_conf_vldt_match_patterns(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        return nxt_conf_vldt_array_iterator(vldt, value,
                                            &nxt_conf_vldt_match_pattern);
    }

    /* NXT_CONF_STRING */

    return nxt_conf_vldt_match_pattern(vldt, value);
}


static nxt_int_t
nxt_conf_vldt_match_pattern(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    nxt_str_t   pattern;
    nxt_uint_t  i, first, last;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"match\" patterns for \"host\", "
                                   "\"uri\", and \"method\" must be strings.");
    }

    nxt_conf_get_string(value, &pattern);

    if (pattern.length == 0) {
        return NXT_OK;
    }

    first = (pattern.start[0] == '!');
    last = pattern.length - 1;

    for (i = first; i < last; i++) {
        if (pattern.start[i] == '*' && pattern.start[i + 1] == '*') {
            return nxt_conf_vldt_error(vldt, "The \"match\" pattern must "
                                       "not contain double \"*\" markers.");
        }
    }

    return NXT_OK;
}


static nxt_int_t nxt_conf_vldt_match_encoded_patterns_sets(
    nxt_conf_validation_t *vldt, nxt_conf_value_t *value, void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        return nxt_conf_vldt_array_iterator(vldt, value,
                                     &nxt_conf_vldt_match_encoded_patterns_set);
    }

    /* NXT_CONF_STRING */

    return nxt_conf_vldt_match_encoded_patterns_set(vldt, value);
}


static nxt_int_t nxt_conf_vldt_match_encoded_patterns_set(
    nxt_conf_validation_t *vldt, nxt_conf_value_t *value)
{
    if (nxt_conf_type(value) != NXT_CONF_OBJECT) {
        return nxt_conf_vldt_error(vldt, "The \"match\" pattern for "
                                   "\"arguments\" must be an object.");
    }

    return nxt_conf_vldt_object_iterator(vldt, value,
                              &nxt_conf_vldt_match_encoded_patterns_set_member);
}


static nxt_int_t
nxt_conf_vldt_match_encoded_patterns_set_member(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value)
{
    u_char  *p, *end;

    if (nxt_slow_path(name->length == 0)) {
        return nxt_conf_vldt_error(vldt, "The \"match\" pattern objects must "
                                   "not contain empty member names.");
    }

    p = nxt_mp_nget(vldt->pool, name->length);
    if (nxt_slow_path(p == NULL)) {
        return NXT_ERROR;
    }

    end = nxt_decode_uri(p, name->start, name->length);
    if (nxt_slow_path(end == NULL)) {
        return nxt_conf_vldt_error(vldt, "The \"match\" pattern for "
                                   "\"arguments\" is encoded but is invalid.");
    }

    return nxt_conf_vldt_match_encoded_patterns(vldt, value, NULL);
}


static nxt_int_t
nxt_conf_vldt_match_encoded_patterns(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        return nxt_conf_vldt_array_iterator(vldt, value,
                                          &nxt_conf_vldt_match_encoded_pattern);
    }

    /* NXT_CONF_STRING */

    return nxt_conf_vldt_match_encoded_pattern(vldt, value);
}


static nxt_int_t
nxt_conf_vldt_match_encoded_pattern(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    u_char     *p, *end;
    nxt_int_t  ret;
    nxt_str_t  pattern;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"match\" pattern for \"uri\" "
                                   "must be a string.");
    }

    ret = nxt_conf_vldt_match_pattern(vldt, value);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    nxt_conf_get_string(value, &pattern);

    p = nxt_mp_nget(vldt->pool, pattern.length);
    if (nxt_slow_path(p == NULL)) {
        return NXT_ERROR;
    }

    end = nxt_decode_uri(p, pattern.start, pattern.length);
    if (nxt_slow_path(end == NULL)) {
        return nxt_conf_vldt_error(vldt, "The \"match\" pattern for \"uri\" "
                                   "is encoded but is invalid.");
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_match_addrs(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        return nxt_conf_vldt_array_iterator(vldt, value,
                                            &nxt_conf_vldt_match_addr);
    }

    return nxt_conf_vldt_match_addr(vldt, value);
}


static nxt_int_t
nxt_conf_vldt_match_addr(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    nxt_http_route_addr_pattern_t  pattern;

    switch (nxt_http_route_addr_pattern_parse(vldt->pool, &pattern, value)) {

    case NXT_OK:
        return NXT_OK;

    case NXT_ADDR_PATTERN_PORT_ERROR:
        return nxt_conf_vldt_error(vldt, "The \"address\" port an invalid "
                                         "port.");

    case NXT_ADDR_PATTERN_CV_TYPE_ERROR:
        return nxt_conf_vldt_error(vldt, "The \"match\" pattern for "
                                         "\"address\" must be a string.");

    case NXT_ADDR_PATTERN_LENGTH_ERROR:
        return nxt_conf_vldt_error(vldt, "The \"address\" is too short.");

    case NXT_ADDR_PATTERN_FORMAT_ERROR:
        return nxt_conf_vldt_error(vldt, "The \"address\" format is invalid.");

    case NXT_ADDR_PATTERN_RANGE_OVERLAP_ERROR:
        return nxt_conf_vldt_error(vldt, "The \"address\" range is "
                                         "overlapping.");

    case NXT_ADDR_PATTERN_CIDR_ERROR:
        return nxt_conf_vldt_error(vldt, "The \"address\" has an invalid CIDR "
                                         "prefix.");

    case NXT_ADDR_PATTERN_NO_IPv6_ERROR:
        return nxt_conf_vldt_error(vldt, "The \"address\" does not support "
                                         "IPv6 with your configuration.");

    default:
        return nxt_conf_vldt_error(vldt, "The \"address\" has an unknown "
                                         "format.");
    }
}


static nxt_int_t
nxt_conf_vldt_match_scheme_pattern(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    nxt_str_t  scheme;

    static const nxt_str_t  http = nxt_string("http");
    static const nxt_str_t  https = nxt_string("https");

    nxt_conf_get_string(value, &scheme);

    if (nxt_strcasestr_eq(&scheme, &http)
        || nxt_strcasestr_eq(&scheme, &https))
    {
        return NXT_OK;
    }

    return nxt_conf_vldt_error(vldt, "The \"scheme\" can either be "
                                     "\"http\" or \"https\".");
}


static nxt_int_t
nxt_conf_vldt_match_patterns_sets(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        return nxt_conf_vldt_array_iterator(vldt, value,
                                            &nxt_conf_vldt_match_patterns_set);
    }

    /* NXT_CONF_OBJECT */

    return nxt_conf_vldt_match_patterns_set(vldt, value);
}


static nxt_int_t
nxt_conf_vldt_match_patterns_set(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    if (nxt_conf_type(value) != NXT_CONF_OBJECT) {
        return nxt_conf_vldt_error(vldt, "The \"match\" patterns for "
                                   "\"arguments\", \"cookies\", and "
                                   "\"headers\" must be objects.");
    }

    return nxt_conf_vldt_object_iterator(vldt, value,
                                     &nxt_conf_vldt_match_patterns_set_member);
}


static nxt_int_t
nxt_conf_vldt_match_patterns_set_member(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value)
{
    if (name->length == 0) {
        return nxt_conf_vldt_error(vldt, "The \"match\" pattern objects must "
                                   "not contain empty member names.");
    }

    return nxt_conf_vldt_match_patterns(vldt, value, NULL);
}


#if (NXT_TLS)

static nxt_int_t
nxt_conf_vldt_certificate(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_str_t         name;
    nxt_conf_value_t  *cert;

    nxt_conf_get_string(value, &name);

    cert = nxt_cert_info_get(&name);

    if (cert == NULL) {
        return nxt_conf_vldt_error(vldt, "Certificate \"%V\" is not found.",
                                   &name);
    }

    return NXT_OK;
}

#endif


static nxt_int_t
nxt_conf_vldt_app_name(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_str_t         name;
    nxt_conf_value_t  *apps, *app;

    static nxt_str_t  apps_str = nxt_string("applications");

    nxt_conf_get_string(value, &name);

    apps = nxt_conf_get_object_member(vldt->conf, &apps_str, NULL);

    if (nxt_slow_path(apps == NULL)) {
        goto error;
    }

    app = nxt_conf_get_object_member(apps, &name, NULL);

    if (nxt_slow_path(app == NULL)) {
        goto error;
    }

    return NXT_OK;

error:

    return nxt_conf_vldt_error(vldt, "Listening socket is assigned for "
                                     "a non existing application \"%V\".",
                                     &name);
}


static nxt_int_t
nxt_conf_vldt_app(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    nxt_int_t              ret;
    nxt_str_t              type;
    nxt_thread_t           *thread;
    nxt_conf_value_t       *type_value;
    nxt_app_lang_module_t  *lang;

    static nxt_str_t  type_str = nxt_string("type");

    static struct {
        nxt_conf_vldt_handler_t  validator;
        nxt_conf_vldt_object_t   *members;

    } types[] = {
        { nxt_conf_vldt_object, nxt_conf_vldt_external_members },
        { nxt_conf_vldt_object, nxt_conf_vldt_python_members },
        { nxt_conf_vldt_php,    NULL },
        { nxt_conf_vldt_object, nxt_conf_vldt_perl_members },
        { nxt_conf_vldt_object, nxt_conf_vldt_ruby_members },
        { nxt_conf_vldt_object, nxt_conf_vldt_java_members },
    };

    ret = nxt_conf_vldt_type(vldt, name, value, NXT_CONF_VLDT_OBJECT);

    if (ret != NXT_OK) {
        return ret;
    }

    type_value = nxt_conf_get_object_member(value, &type_str, NULL);

    if (type_value == NULL) {
        return nxt_conf_vldt_error(vldt,
                           "Application must have the \"type\" property set.");
    }

    ret = nxt_conf_vldt_type(vldt, &type_str, type_value, NXT_CONF_VLDT_STRING);

    if (ret != NXT_OK) {
        return ret;
    }

    nxt_conf_get_string(type_value, &type);

    thread = nxt_thread();

    lang = nxt_app_lang_module(thread->runtime, &type);
    if (lang == NULL) {
        return nxt_conf_vldt_error(vldt,
                                   "The module to run \"%V\" is not found "
                                   "among the available application modules.",
                                   &type);
    }

    return types[lang->type].validator(vldt, value, types[lang->type].members);
}


static nxt_int_t
nxt_conf_vldt_object(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    uint32_t                index;
    nxt_int_t               ret;
    nxt_str_t               name;
    nxt_conf_value_t        *member;
    nxt_conf_vldt_object_t  *vals;

    vals = data;

    for ( ;; ) {
        if (vals->name.length == 0) {

            if (vals->data != NULL) {
                vals = vals->data;
                continue;
            }

            break;
        }

        if (vals->flags & NXT_CONF_VLDT_REQUIRED) {
            member = nxt_conf_get_object_member(value, &vals->name, NULL);

            if (member == NULL) {
                return nxt_conf_vldt_error(vldt, "Required parameter \"%V\" "
                                           "is missing.", &vals->name);
            }
        }

        vals++;
    }

    index = 0;

    for ( ;; ) {
        member = nxt_conf_next_object_member(value, &name, &index);

        if (member == NULL) {
            return NXT_OK;
        }

        vals = data;

        for ( ;; ) {
            if (vals->name.length == 0) {

                if (vals->data != NULL) {
                    vals = vals->data;
                    continue;
                }

                return nxt_conf_vldt_error(vldt, "Unknown parameter \"%V\".",
                                           &name);
            }

            if (!nxt_strstr_eq(&vals->name, &name)) {
                vals++;
                continue;
            }

            ret = nxt_conf_vldt_type(vldt, &name, member, vals->type);

            if (ret != NXT_OK) {
                return ret;
            }

            if (vals->validator != NULL) {
                ret = vals->validator(vldt, member, vals->data);

                if (ret != NXT_OK) {
                    return ret;
                }
            }

            break;
        }
    }
}


typedef struct {
    int64_t  spare;
    int64_t  max;
    int64_t  idle_timeout;
} nxt_conf_vldt_processes_conf_t;


static nxt_conf_map_t  nxt_conf_vldt_processes_conf_map[] = {
    {
        nxt_string("spare"),
        NXT_CONF_MAP_INT64,
        offsetof(nxt_conf_vldt_processes_conf_t, spare),
    },

    {
        nxt_string("max"),
        NXT_CONF_MAP_INT64,
        offsetof(nxt_conf_vldt_processes_conf_t, max),
    },

    {
        nxt_string("idle_timeout"),
        NXT_CONF_MAP_INT64,
        offsetof(nxt_conf_vldt_processes_conf_t, idle_timeout),
    },
};


static nxt_int_t
nxt_conf_vldt_processes(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    int64_t                         int_value;
    nxt_int_t                       ret;
    nxt_conf_vldt_processes_conf_t  proc;

    if (nxt_conf_type(value) == NXT_CONF_NUMBER) {
        int_value = nxt_conf_get_number(value);

        if (int_value < 1) {
            return nxt_conf_vldt_error(vldt, "The \"processes\" number must be "
                                       "equal to or greater than 1.");
        }

        if (int_value > NXT_INT32_T_MAX) {
            return nxt_conf_vldt_error(vldt, "The \"processes\" number must "
                                       "not exceed %d.", NXT_INT32_T_MAX);
        }

        return NXT_OK;
    }

    ret = nxt_conf_vldt_object(vldt, value, data);
    if (ret != NXT_OK) {
        return ret;
    }

    proc.spare = 0;
    proc.max = 1;
    proc.idle_timeout = 15;

    ret = nxt_conf_map_object(vldt->pool, value,
                              nxt_conf_vldt_processes_conf_map,
                              nxt_nitems(nxt_conf_vldt_processes_conf_map),
                              &proc);
    if (ret != NXT_OK) {
        return ret;
    }

    if (proc.spare < 0) {
        return nxt_conf_vldt_error(vldt, "The \"spare\" number must not be "
                                   "negative.");
    }

    if (proc.spare > NXT_INT32_T_MAX) {
        return nxt_conf_vldt_error(vldt, "The \"spare\" number must not "
                                   "exceed %d.", NXT_INT32_T_MAX);
    }

    if (proc.max < 1) {
        return nxt_conf_vldt_error(vldt, "The \"max\" number must be equal "
                                   "to or greater than 1.");
    }

    if (proc.max > NXT_INT32_T_MAX) {
        return nxt_conf_vldt_error(vldt, "The \"max\" number must not "
                                   "exceed %d.", NXT_INT32_T_MAX);
    }

    if (proc.max < proc.spare) {
        return nxt_conf_vldt_error(vldt, "The \"spare\" number must be "
                                   "less than or equal to \"max\".");
    }

    if (proc.idle_timeout < 0) {
        return nxt_conf_vldt_error(vldt, "The \"idle_timeout\" number must not "
                                   "be negative.");
    }

    if (proc.idle_timeout > NXT_INT32_T_MAX / 1000) {
        return nxt_conf_vldt_error(vldt, "The \"idle_timeout\" number must not "
                                   "exceed %d.", NXT_INT32_T_MAX / 1000);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_object_iterator(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    uint32_t                index;
    nxt_int_t               ret;
    nxt_str_t               name;
    nxt_conf_value_t        *member;
    nxt_conf_vldt_member_t  validator;

    validator = (nxt_conf_vldt_member_t) data;
    index = 0;

    for ( ;; ) {
        member = nxt_conf_next_object_member(value, &name, &index);

        if (member == NULL) {
            return NXT_OK;
        }

        ret = validator(vldt, &name, member);

        if (ret != NXT_OK) {
            return ret;
        }
    }
}


static nxt_int_t
nxt_conf_vldt_array_iterator(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    uint32_t                 index;
    nxt_int_t                ret;
    nxt_conf_value_t         *element;
    nxt_conf_vldt_element_t  validator;

    validator = (nxt_conf_vldt_element_t) data;

    for (index = 0; /* void */ ; index++) {
        element = nxt_conf_get_array_element(value, index);

        if (element == NULL) {
            return NXT_OK;
        }

        ret = validator(vldt, element);

        if (ret != NXT_OK) {
            return ret;
        }
    }
}


static nxt_int_t
nxt_conf_vldt_environment(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    nxt_str_t  str;

    if (name->length == 0) {
        return nxt_conf_vldt_error(vldt,
                                   "The environment name must not be empty.");
    }

    if (nxt_memchr(name->start, '\0', name->length) != NULL) {
        return nxt_conf_vldt_error(vldt, "The environment name must not "
                                   "contain null character.");
    }

    if (nxt_memchr(name->start, '=', name->length) != NULL) {
        return nxt_conf_vldt_error(vldt, "The environment name must not "
                                   "contain '=' character.");
    }

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" environment value must be "
                                   "a string.", name);
    }

    nxt_conf_get_string(value, &str);

    if (nxt_memchr(str.start, '\0', str.length) != NULL) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" environment value must "
                                   "not contain null character.", name);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_clone_namespaces(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    return nxt_conf_vldt_object(vldt, value, data);
}


static nxt_int_t
nxt_conf_vldt_isolation(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    return nxt_conf_vldt_object(vldt, value, data);
}


#if (NXT_HAVE_CLONE_NEWUSER)

typedef struct {
    nxt_int_t container;
    nxt_int_t host;
    nxt_int_t size;
} nxt_conf_vldt_clone_procmap_conf_t;


static nxt_conf_map_t nxt_conf_vldt_clone_procmap_conf_map[] = {
    {
        nxt_string("container"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_conf_vldt_clone_procmap_conf_t, container),
    },

    {
        nxt_string("host"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_conf_vldt_clone_procmap_conf_t, host),
    },

    {
        nxt_string("size"),
        NXT_CONF_MAP_INT32,
        offsetof(nxt_conf_vldt_clone_procmap_conf_t, size),
    },

};


static nxt_int_t
nxt_conf_vldt_clone_procmap(nxt_conf_validation_t *vldt, const char *mapfile,
        nxt_conf_value_t *value)
{
    nxt_int_t                           ret;
    nxt_conf_vldt_clone_procmap_conf_t  procmap;

    procmap.container = -1;
    procmap.host = -1;
    procmap.size = -1;

    ret = nxt_conf_map_object(vldt->pool, value,
                              nxt_conf_vldt_clone_procmap_conf_map,
                              nxt_nitems(nxt_conf_vldt_clone_procmap_conf_map),
                              &procmap);
    if (ret != NXT_OK) {
        return ret;
    }

    if (procmap.container == -1) {
        return nxt_conf_vldt_error(vldt, "The %s requires the "
                "\"container\" field set.", mapfile);
    }

    if (procmap.host == -1) {
        return nxt_conf_vldt_error(vldt, "The %s requires the "
                "\"host\" field set.", mapfile);
    }

    if (procmap.size == -1) {
        return nxt_conf_vldt_error(vldt, "The %s requires the "
                "\"size\" field set.", mapfile);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_clone_uidmap(nxt_conf_validation_t *vldt, nxt_conf_value_t *value)
{
    nxt_int_t  ret;

    if (nxt_conf_type(value) != NXT_CONF_OBJECT) {
        return nxt_conf_vldt_error(vldt, "The \"uidmap\" array "
                                   "must contain only object values.");
    }

    ret = nxt_conf_vldt_object(vldt, value,
                               (void *) nxt_conf_vldt_app_procmap_members);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    return nxt_conf_vldt_clone_procmap(vldt, "uid_map", value);
}


static nxt_int_t
nxt_conf_vldt_clone_gidmap(nxt_conf_validation_t *vldt, nxt_conf_value_t *value)
{
    nxt_int_t ret;

    if (nxt_conf_type(value) != NXT_CONF_OBJECT) {
        return nxt_conf_vldt_error(vldt, "The \"gidmap\" array "
                                   "must contain only object values.");
    }

    ret = nxt_conf_vldt_object(vldt, value,
                               (void *) nxt_conf_vldt_app_procmap_members);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }

    return nxt_conf_vldt_clone_procmap(vldt, "gid_map", value);
}

#endif


static nxt_int_t
nxt_conf_vldt_argument(nxt_conf_validation_t *vldt, nxt_conf_value_t *value)
{
    nxt_str_t  str;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"arguments\" array "
                                   "must contain only string values.");
    }

    nxt_conf_get_string(value, &str);

    if (nxt_memchr(str.start, '\0', str.length) != NULL) {
        return nxt_conf_vldt_error(vldt, "The \"arguments\" array must not "
                                   "contain strings with null character.");
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_php(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_conf_value_t  *targets;

    static nxt_str_t  targets_str = nxt_string("targets");

    targets = nxt_conf_get_object_member(value, &targets_str, NULL);

    if (targets != NULL) {
        return nxt_conf_vldt_object(vldt, value, nxt_conf_vldt_php_members);
    }

    return nxt_conf_vldt_object(vldt, value,
                                nxt_conf_vldt_php_notargets_members);
}


static nxt_int_t
nxt_conf_vldt_php_targets_exclusive(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    return nxt_conf_vldt_error(vldt, "The \"%s\" option is mutually exclusive "
                               "with the \"targets\" object.", data);
}


static nxt_int_t
nxt_conf_vldt_php_targets(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_uint_t  n;

    n = nxt_conf_object_members_count(value);

    if (n > 254) {
        return nxt_conf_vldt_error(vldt, "The \"targets\" object must not "
                                   "contain more than 254 members.");
    }

    return nxt_conf_vldt_object_iterator(vldt, value,
                                         &nxt_conf_vldt_php_target);
}


static nxt_int_t
nxt_conf_vldt_php_target(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    if (name->length == 0) {
        return nxt_conf_vldt_error(vldt,
                                   "The PHP target name must not be empty.");
    }

    if (nxt_conf_type(value) != NXT_CONF_OBJECT) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" PHP target must be "
                                   "an object.", name);
    }

    return nxt_conf_vldt_object(vldt, value, &nxt_conf_vldt_php_target_members);
}


static nxt_int_t
nxt_conf_vldt_php_option(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    if (name->length == 0) {
        return nxt_conf_vldt_error(vldt,
                                   "The PHP option name must not be empty.");
    }

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" PHP option must be "
                                   "a string.", name);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_java_classpath(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    nxt_str_t  str;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"classpath\" array "
                                   "must contain only string values.");
    }

    nxt_conf_get_string(value, &str);

    if (nxt_memchr(str.start, '\0', str.length) != NULL) {
        return nxt_conf_vldt_error(vldt, "The \"classpath\" array must not "
                                   "contain strings with null character.");
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_java_option(nxt_conf_validation_t *vldt, nxt_conf_value_t *value)
{
    nxt_str_t  str;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"options\" array "
                                   "must contain only string values.");
    }

    nxt_conf_get_string(value, &str);

    if (nxt_memchr(str.start, '\0', str.length) != NULL) {
        return nxt_conf_vldt_error(vldt, "The \"options\" array must not "
                                   "contain strings with null character.");
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_upstream(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    nxt_int_t         ret;
    nxt_conf_value_t  *conf;

    static nxt_str_t  servers = nxt_string("servers");

    ret = nxt_conf_vldt_type(vldt, name, value, NXT_CONF_VLDT_OBJECT);

    if (ret != NXT_OK) {
        return ret;
    }

    ret = nxt_conf_vldt_object(vldt, value, nxt_conf_vldt_upstream_members);

    if (ret != NXT_OK) {
        return ret;
    }

    conf = nxt_conf_get_object_member(value, &servers, NULL);
    if (conf == NULL) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" upstream must contain "
                                   "\"servers\" object value.", name);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_server(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    nxt_int_t       ret;
    nxt_sockaddr_t  *sa;

    ret = nxt_conf_vldt_type(vldt, name, value, NXT_CONF_VLDT_OBJECT);

    if (ret != NXT_OK) {
        return ret;
    }

    sa = nxt_sockaddr_parse(vldt->pool, name);

    if (sa == NULL) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" is not valid "
                                   "server address.", name);
    }

    return nxt_conf_vldt_object(vldt, value,
                                nxt_conf_vldt_upstream_server_members);
}


static nxt_int_t
nxt_conf_vldt_server_weight(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    double  num_value;

    num_value = nxt_conf_get_number(value);

    if (num_value < 0) {
        return nxt_conf_vldt_error(vldt, "The \"weight\" number must be "
                                   "positive.");
    }

    if (num_value > 1000000) {
        return nxt_conf_vldt_error(vldt, "The \"weight\" number must "
                                   "not exceed 1,000,000");
    }

    return NXT_OK;
}
