
/*
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 * Copyright 2024, Alejandro Colomar <alx@kernel.org>
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#include <nxt_cert.h>
#include <nxt_script.h>
#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_sockaddr.h>
#include <nxt_http_route_addr.h>
#include <nxt_regex.h>


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
    NXT_CONF_VLDT_REQUIRED  = 1 << 0,
    NXT_CONF_VLDT_TSTR      = 1 << 1,
} nxt_conf_vldt_flags_t;


typedef nxt_int_t (*nxt_conf_vldt_handler_t)(nxt_conf_validation_t *vldt,
                                             nxt_conf_value_t *value,
                                             void *data);
typedef nxt_int_t (*nxt_conf_vldt_member_t)(nxt_conf_validation_t *vldt,
                                            nxt_str_t *name,
                                            nxt_conf_value_t *value);
typedef nxt_int_t (*nxt_conf_vldt_element_t)(nxt_conf_validation_t *vldt,
                                             nxt_conf_value_t *value);


typedef struct nxt_conf_vldt_object_s  nxt_conf_vldt_object_t;

struct nxt_conf_vldt_object_s {
    nxt_str_t                     name;
    nxt_conf_vldt_type_t          type:32;
    nxt_conf_vldt_flags_t         flags:32;
    nxt_conf_vldt_handler_t       validator;

    union {
        nxt_conf_vldt_object_t    *members;
        nxt_conf_vldt_object_t    *next;
        nxt_conf_vldt_member_t    object;
        nxt_conf_vldt_element_t   array;
        const char                *string;
    } u;
};


#define NXT_CONF_VLDT_NEXT(next)  { .u.members = next }
#define NXT_CONF_VLDT_END         { .name = nxt_null_string }


static nxt_int_t nxt_conf_vldt_type(nxt_conf_validation_t *vldt,
    const nxt_str_t *name, nxt_conf_value_t *value, nxt_conf_vldt_type_t type);
static nxt_int_t nxt_conf_vldt_error(nxt_conf_validation_t *vldt,
    const char *fmt, ...);
static nxt_int_t nxt_conf_vldt_var(nxt_conf_validation_t *vldt,
    const nxt_str_t *name, nxt_str_t *value);
static nxt_int_t nxt_conf_vldt_if(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
nxt_inline nxt_int_t nxt_conf_vldt_unsupported(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
    NXT_MAYBE_UNUSED;

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
#if (NXT_HAVE_OPENSSL_CONF_CMD)
static nxt_int_t nxt_conf_vldt_object_conf_commands(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
#endif
static nxt_int_t nxt_conf_vldt_certificate_element(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_tls_cache_size(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_tls_timeout(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
#if (NXT_HAVE_OPENSSL_TLSEXT)
static nxt_int_t nxt_conf_vldt_ticket_key(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_ticket_key_element(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
#endif
#endif
static nxt_int_t nxt_conf_vldt_action(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_pass(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_return(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_share(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_share_element(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_proxy(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_python(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_python_path(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_python_path_element(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_python_protocol(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_python_prefix(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_listen_threads(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_threads(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_thread_stack_size(nxt_conf_validation_t *vldt,
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
static nxt_int_t nxt_conf_vldt_response_header(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_app_name(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_forwarded(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_listen_backlog(nxt_conf_validation_t *vldt,
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
static nxt_int_t nxt_conf_vldt_targets_exclusive(
    nxt_conf_validation_t *vldt, nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_targets(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_target(nxt_conf_validation_t *vldt,
    nxt_str_t *name, nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_argument(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_php(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
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
static nxt_int_t nxt_conf_vldt_access_log(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);

static nxt_int_t nxt_conf_vldt_isolation(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_clone_namespaces(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);

#if (NXT_HAVE_CLONE_NEWUSER)
static nxt_int_t nxt_conf_vldt_clone_uidmap(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
static nxt_int_t nxt_conf_vldt_clone_gidmap(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
#endif

#if (NXT_HAVE_CGROUP)
static nxt_int_t nxt_conf_vldt_cgroup_path(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data);
#endif

#if (NXT_HAVE_NJS)
static nxt_int_t nxt_conf_vldt_js_module(nxt_conf_validation_t *vldt,
     nxt_conf_value_t *value, void *data);
static nxt_int_t nxt_conf_vldt_js_module_element(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value);
#endif

#if (NXT_HAVE_OTEL)
nxt_inline nxt_int_t nxt_otel_validate_endpoint(nxt_conf_validation_t *vldt,
                                                nxt_conf_value_t *value,
                                                void *data);
nxt_int_t nxt_otel_validate_batch_size(nxt_conf_validation_t *vldt,
                                       nxt_conf_value_t *value,
                                       void *data);
nxt_int_t nxt_otel_validate_sample_ratio(nxt_conf_validation_t *vldt,
                                         nxt_conf_value_t *value,
                                         void *data);
nxt_int_t nxt_otel_validate_protocol(nxt_conf_validation_t *vldt,
                                     nxt_conf_value_t *value,
                                     void *data);
#endif


static nxt_conf_vldt_object_t  nxt_conf_vldt_setting_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_http_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_websocket_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_static_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_forwarded_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_client_ip_members[];
#if (NXT_TLS)
static nxt_conf_vldt_object_t  nxt_conf_vldt_tls_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_session_members[];
#endif
static nxt_conf_vldt_object_t  nxt_conf_vldt_match_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_python_target_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_php_common_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_php_options_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_php_target_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_wasm_access_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_common_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_app_limits_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_app_processes_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_app_isolation_members[];
static nxt_conf_vldt_object_t  nxt_conf_vldt_app_namespaces_members[];
#if (NXT_HAVE_CGROUP)
static nxt_conf_vldt_object_t  nxt_conf_vldt_app_cgroup_members[];
#endif
#if (NXT_HAVE_ISOLATION_ROOTFS)
static nxt_conf_vldt_object_t  nxt_conf_vldt_app_automount_members[];
#endif
static nxt_conf_vldt_object_t  nxt_conf_vldt_access_log_members[];


static nxt_conf_vldt_object_t  nxt_conf_vldt_root_members[] = {
    {
        .name       = nxt_string("settings"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_setting_members,
    }, {
        .name       = nxt_string("listeners"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object_iterator,
        .u.object   = nxt_conf_vldt_listener,
    }, {
        .name       = nxt_string("routes"),
        .type       = NXT_CONF_VLDT_ARRAY | NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_routes,
    }, {
        .name       = nxt_string("applications"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object_iterator,
        .u.object   = nxt_conf_vldt_app,
    }, {
        .name       = nxt_string("upstreams"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object_iterator,
        .u.object   = nxt_conf_vldt_upstream,
    }, {
        .name       = nxt_string("access_log"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_access_log,
    },

    NXT_CONF_VLDT_END
};



#if (NXT_HAVE_OTEL)
static nxt_conf_vldt_object_t nxt_conf_vldt_otel_members[] = {
    {
        .name      = nxt_string("endpoint"),
        .type      = NXT_CONF_VLDT_STRING,
        .validator = nxt_otel_validate_endpoint,
        .flags     = NXT_CONF_VLDT_REQUIRED
    }, {
        .name      = nxt_string("batch_size"),
        .type      = NXT_CONF_VLDT_INTEGER,
        .validator = nxt_otel_validate_batch_size,
    }, {
        .name      = nxt_string("protocol"),
        .type      = NXT_CONF_VLDT_STRING,
        .validator = nxt_otel_validate_protocol,
        .flags     = NXT_CONF_VLDT_REQUIRED
    }, {
        .name      = nxt_string("sampling_ratio"),
        .type      = NXT_CONF_VLDT_NUMBER,
        .validator = nxt_otel_validate_sample_ratio,
    },

    NXT_CONF_VLDT_END
};
#endif


static nxt_conf_vldt_object_t  nxt_conf_vldt_setting_members[] = {
    {
        .name       = nxt_string("listen_threads"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_listen_threads,
    }, {
        .name       = nxt_string("http"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_http_members,
#if (NXT_HAVE_OTEL)
    }, {
        .name       = nxt_string("telemetry"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_otel_members,
#endif
#if (NXT_HAVE_NJS)
    }, {
        .name       = nxt_string("js_module"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_js_module,
#endif
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_http_members[] = {
    {
        .name       = nxt_string("header_read_timeout"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("body_read_timeout"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("send_timeout"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("idle_timeout"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("large_header_buffer_size"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("large_header_buffers"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("body_buffer_size"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("max_body_size"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("body_temp_path"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("discard_unsafe_fields"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    }, {
        .name       = nxt_string("websocket"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_websocket_members,
    }, {
        .name       = nxt_string("static"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_static_members,
    }, {
        .name       = nxt_string("log_route"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    }, {
        .name       = nxt_string("server_version"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    }, {
        .name       = nxt_string("chunked_transform"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_websocket_members[] = {
    {
        .name       = nxt_string("read_timeout"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {

        .name       = nxt_string("keepalive_interval"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("max_frame_size"),
        .type       = NXT_CONF_VLDT_INTEGER,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_static_members[] = {
    {
        .name       = nxt_string("mime_types"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_mtypes,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_listener_members[] = {
    {
        .name       = nxt_string("pass"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_pass,
        .flags      = NXT_CONF_VLDT_TSTR,
    }, {
        .name       = nxt_string("application"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_app_name,
    }, {
        .name       = nxt_string("forwarded"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_forwarded,
    }, {
        .name       = nxt_string("client_ip"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_client_ip_members
    }, {
        .name       = nxt_string("backlog"),
        .type       = NXT_CONF_VLDT_NUMBER,
        .validator  = nxt_conf_vldt_listen_backlog,
    },

#if (NXT_TLS)
    {
        .name       = nxt_string("tls"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_tls_members,
    },
#endif

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_forwarded_members[] = {
    {
        .name       = nxt_string("client_ip"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("protocol"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("source"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_addrs,
        .flags      = NXT_CONF_VLDT_REQUIRED
    }, {
        .name       = nxt_string("recursive"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_client_ip_members[] = {
    {
        .name       = nxt_string("source"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_addrs,
        .flags      = NXT_CONF_VLDT_REQUIRED
    }, {
        .name       = nxt_string("header"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED
    }, {
        .name       = nxt_string("recursive"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },

    NXT_CONF_VLDT_END
};


#if (NXT_TLS)

static nxt_conf_vldt_object_t  nxt_conf_vldt_tls_members[] = {
    {
        .name       = nxt_string("certificate"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .flags      = NXT_CONF_VLDT_REQUIRED,
        .validator  = nxt_conf_vldt_certificate,
    }, {
        .name       = nxt_string("conf_commands"),
        .type       = NXT_CONF_VLDT_OBJECT,
#if (NXT_HAVE_OPENSSL_CONF_CMD)
        .validator  = nxt_conf_vldt_object_conf_commands,
#else
        .validator  = nxt_conf_vldt_unsupported,
        .u.string   = "conf_commands",
#endif
    }, {
        .name       = nxt_string("session"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_session_members,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_session_members[] = {
    {
        .name       = nxt_string("cache_size"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_tls_cache_size,
    }, {
        .name       = nxt_string("timeout"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_tls_timeout,
    }, {
        .name       = nxt_string("tickets"),
        .type       = NXT_CONF_VLDT_STRING
                     | NXT_CONF_VLDT_ARRAY
                     | NXT_CONF_VLDT_BOOLEAN,
#if (NXT_HAVE_OPENSSL_TLSEXT)
        .validator  = nxt_conf_vldt_ticket_key,
#else
        .validator  = nxt_conf_vldt_unsupported,
        .u.string   = "tickets",
#endif
    },

    NXT_CONF_VLDT_END
};


static nxt_int_t
nxt_conf_vldt_tls_cache_size(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    int64_t  cache_size;

    cache_size = nxt_conf_get_number(value);

    if (cache_size < 0) {
        return nxt_conf_vldt_error(vldt, "The \"cache_size\" number must not "
                                         "be negative.");
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_tls_timeout(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    int64_t  timeout;

    timeout = nxt_conf_get_number(value);

    if (timeout <= 0) {
        return nxt_conf_vldt_error(vldt, "The \"timeout\" number must be "
                                         "greater than zero.");
    }

    return NXT_OK;
}

#endif

#if (NXT_HAVE_OPENSSL_TLSEXT)

static nxt_int_t
nxt_conf_vldt_ticket_key(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_BOOLEAN) {
        return NXT_OK;
    }

    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        return nxt_conf_vldt_array_iterator(vldt, value,
                                            &nxt_conf_vldt_ticket_key_element);
    }

    /* NXT_CONF_STRING */

    return nxt_conf_vldt_ticket_key_element(vldt, value);
}


static nxt_int_t
nxt_conf_vldt_ticket_key_element(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    ssize_t    ret;
    nxt_str_t  key;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"key\" array must "
                                   "contain only string values.");
    }

    nxt_conf_get_string(value, &key);

    ret = nxt_base64_decode(NULL, key.start, key.length);
    if (ret == NXT_ERROR) {
        return nxt_conf_vldt_error(vldt, "Invalid Base64 format for the ticket "
                                   "key \"%V\".", &key);
    }

    if (ret != 48 && ret != 80) {
        return nxt_conf_vldt_error(vldt, "Invalid length %d of the ticket "
                                   "key \"%V\".  Must be 48 or 80 bytes.",
                                   ret, &key);
    }

    return NXT_OK;
}

#endif


static nxt_conf_vldt_object_t  nxt_conf_vldt_route_members[] = {
    {
        .name       = nxt_string("match"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_match_members,
    }, {
        .name       = nxt_string("action"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_action,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_match_members[] = {
    {
        .name       = nxt_string("method"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_patterns,
        .u.string   = "method",
    }, {
        .name       = nxt_string("scheme"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_match_scheme_pattern,
    }, {
        .name       = nxt_string("host"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_patterns,
        .u.string   = "host",
    }, {
        .name       = nxt_string("source"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_addrs,
    }, {
        .name       = nxt_string("destination"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_addrs,
    }, {
        .name       = nxt_string("uri"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_encoded_patterns,
        .u.string   = "uri"
    }, {
        .name       = nxt_string("query"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_encoded_patterns,
        .u.string   = "query"
    }, {
        .name       = nxt_string("arguments"),
        .type       = NXT_CONF_VLDT_OBJECT | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_encoded_patterns_sets,
    }, {
        .name       = nxt_string("headers"),
        .type       = NXT_CONF_VLDT_OBJECT | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_patterns_sets,
        .u.string   = "headers"
    }, {
        .name       = nxt_string("cookies"),
        .type       = NXT_CONF_VLDT_OBJECT | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_patterns_sets,
        .u.string   = "cookies"
    }, {
        .name       = nxt_string("if"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_if,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_action_common_members[] = {
    {
        .name       = nxt_string("rewrite"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_TSTR,
    },
    {
        .name       = nxt_string("response_headers"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object_iterator,
        .u.object   = nxt_conf_vldt_response_header,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_pass_action_members[] = {
    {
        .name       = nxt_string("pass"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_pass,
        .flags      = NXT_CONF_VLDT_TSTR,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_action_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_return_action_members[] = {
    {
        .name       = nxt_string("return"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_return,
    }, {
        .name       = nxt_string("location"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_TSTR,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_action_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_share_action_members[] = {
    {
        .name       = nxt_string("share"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_share,
    }, {
        .name       = nxt_string("index"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("types"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_match_patterns,
    }, {
        .name       = nxt_string("fallback"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_action,
    }, {
        .name       = nxt_string("chroot"),
        .type       = NXT_CONF_VLDT_STRING,
#if !(NXT_HAVE_OPENAT2)
        .validator  = nxt_conf_vldt_unsupported,
        .u.string   = "chroot",
#endif
        .flags      = NXT_CONF_VLDT_TSTR,
    }, {
        .name       = nxt_string("follow_symlinks"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
#if !(NXT_HAVE_OPENAT2)
        .validator  = nxt_conf_vldt_unsupported,
        .u.string   = "follow_symlinks",
#endif
    }, {
        .name       = nxt_string("traverse_mounts"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
#if !(NXT_HAVE_OPENAT2)
        .validator  = nxt_conf_vldt_unsupported,
        .u.string   = "traverse_mounts",
#endif
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_action_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_proxy_action_members[] = {
    {
        .name       = nxt_string("proxy"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_proxy,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_action_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_external_members[] = {
    {
        .name       = nxt_string("executable"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("arguments"),
        .type       = NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_array_iterator,
        .u.array    = nxt_conf_vldt_argument,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_python_common_members[] = {
    {
        .name       = nxt_string("home"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("path"),
        .type       = NXT_CONF_VLDT_STRING | NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_python_path,
    }, {
        .name       = nxt_string("protocol"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_python_protocol,
    }, {
        .name       = nxt_string("threads"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_threads,
    }, {
        .name       = nxt_string("thread_stack_size"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_thread_stack_size,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_common_members)
};

static nxt_conf_vldt_object_t  nxt_conf_vldt_python_members[] = {
    {
        .name       = nxt_string("module"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_targets_exclusive,
        .u.string   = "module",
    }, {
        .name       = nxt_string("callable"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_targets_exclusive,
        .u.string   = "callable",
    }, {
        .name       = nxt_string("factory"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
        .validator  = nxt_conf_vldt_targets_exclusive,
        .u.string   = "factory",
    }, {
        .name       = nxt_string("prefix"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_targets_exclusive,
        .u.string   = "prefix",
    }, {
        .name       = nxt_string("targets"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_targets,
        .u.members  = nxt_conf_vldt_python_target_members
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_python_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_python_target_members[] = {
    {
        .name       = nxt_string("module"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("callable"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("factory"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    }, {
        .name       = nxt_string("prefix"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_python_prefix,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_python_notargets_members[] = {
    {
        .name       = nxt_string("module"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("callable"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("factory"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    }, {
        .name       = nxt_string("prefix"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_python_prefix,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_python_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_php_members[] = {
    {
        .name       = nxt_string("root"),
        .type       = NXT_CONF_VLDT_ANY_TYPE,
        .validator  = nxt_conf_vldt_targets_exclusive,
        .u.string   = "root",
    }, {
        .name       = nxt_string("script"),
        .type       = NXT_CONF_VLDT_ANY_TYPE,
        .validator  = nxt_conf_vldt_targets_exclusive,
        .u.string   = "script",
    }, {
        .name       = nxt_string("index"),
        .type       = NXT_CONF_VLDT_ANY_TYPE,
        .validator  = nxt_conf_vldt_targets_exclusive,
        .u.string   = "index",
    }, {
        .name       = nxt_string("targets"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_targets,
        .u.members  = nxt_conf_vldt_php_target_members
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_php_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_php_common_members[] = {
    {
        .name       = nxt_string("options"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_php_options_members,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_php_options_members[] = {
    {
        .name       = nxt_string("file"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("admin"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object_iterator,
        .u.object   = nxt_conf_vldt_php_option,
    }, {
        .name       = nxt_string("user"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object_iterator,
        .u.object   = nxt_conf_vldt_php_option,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_php_target_members[] = {
    {
        .name       = nxt_string("root"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("script"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("index"),
        .type       = NXT_CONF_VLDT_STRING,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_php_notargets_members[] = {
    {
        .name       = nxt_string("root"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("script"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("index"),
        .type       = NXT_CONF_VLDT_STRING,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_php_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_perl_members[] = {
    {
        .name       = nxt_string("script"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("threads"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_threads,
    }, {
        .name       = nxt_string("thread_stack_size"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_thread_stack_size,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_ruby_members[] = {
    {
        .name       = nxt_string("script"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("threads"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_threads,
    }, {
        .name       = nxt_string("hooks"),
        .type       = NXT_CONF_VLDT_STRING
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_java_members[] = {
    {
        .name       = nxt_string("classpath"),
        .type       = NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_array_iterator,
        .u.array    = nxt_conf_vldt_java_classpath,
    }, {
        .name       = nxt_string("webapp"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("options"),
        .type       = NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_array_iterator,
        .u.array    = nxt_conf_vldt_java_option,
    }, {
        .name       = nxt_string("unit_jars"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("threads"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_threads,
    }, {
        .name       = nxt_string("thread_stack_size"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .validator  = nxt_conf_vldt_thread_stack_size,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_wasm_members[] = {
    {
        .name       = nxt_string("module"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("request_handler"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    },{
        .name       = nxt_string("malloc_handler"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("free_handler"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("module_init_handler"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("module_end_handler"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("request_init_handler"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("request_end_handler"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("response_end_handler"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("access"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_wasm_access_members,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_wasm_wc_members[] = {
    {
        .name       = nxt_string("component"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("access"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_wasm_access_members,
    },

    NXT_CONF_VLDT_NEXT(nxt_conf_vldt_common_members)
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_wasm_access_members[] = {
    {
        .name       = nxt_string("filesystem"),
        .type       = NXT_CONF_VLDT_ARRAY,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_common_members[] = {
    {
        .name       = nxt_string("type"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("limits"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_app_limits_members,
    }, {
        .name       = nxt_string("processes"),
        .type       = NXT_CONF_VLDT_INTEGER | NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_processes,
        .u.members  = nxt_conf_vldt_app_processes_members,
    }, {
        .name       = nxt_string("user"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("group"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("working_directory"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("environment"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object_iterator,
        .u.object   = nxt_conf_vldt_environment,
    }, {
        .name       = nxt_string("isolation"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_isolation,
        .u.members  = nxt_conf_vldt_app_isolation_members,
    }, {
        .name       = nxt_string("stdout"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("stderr"),
        .type       = NXT_CONF_VLDT_STRING,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_app_limits_members[] = {
    {
        .name       = nxt_string("timeout"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("requests"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("shm"),
        .type       = NXT_CONF_VLDT_INTEGER,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_app_processes_members[] = {
    {
        .name       = nxt_string("spare"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("max"),
        .type       = NXT_CONF_VLDT_INTEGER,
    }, {
        .name       = nxt_string("idle_timeout"),
        .type       = NXT_CONF_VLDT_INTEGER,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_app_isolation_members[] = {
    {
        .name       = nxt_string("namespaces"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_clone_namespaces,
        .u.members  = nxt_conf_vldt_app_namespaces_members,
    },

#if (NXT_HAVE_CLONE_NEWUSER)
    {
        .name       = nxt_string("uidmap"),
        .type       = NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_array_iterator,
        .u.array    = nxt_conf_vldt_clone_uidmap,
    }, {
        .name       = nxt_string("gidmap"),
        .type       = NXT_CONF_VLDT_ARRAY,
        .validator  = nxt_conf_vldt_array_iterator,
        .u.array    = nxt_conf_vldt_clone_gidmap,
    },
#endif

#if (NXT_HAVE_ISOLATION_ROOTFS)
    {
        .name       = nxt_string("rootfs"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("automount"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_app_automount_members,
    },
#endif

#if (NXT_HAVE_PR_SET_NO_NEW_PRIVS)
    {
        .name       = nxt_string("new_privs"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },
#endif

#if (NXT_HAVE_CGROUP)
    {
        .name       = nxt_string("cgroup"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object,
        .u.members  = nxt_conf_vldt_app_cgroup_members,
    },
#endif

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_app_namespaces_members[] = {

#if (NXT_HAVE_CLONE_NEWUSER)
    {
        .name       = nxt_string("credential"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },
#endif

#if (NXT_HAVE_CLONE_NEWPID)
    {
        .name       = nxt_string("pid"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },
#endif

#if (NXT_HAVE_CLONE_NEWNET)
    {
        .name       = nxt_string("network"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },
#endif

#if (NXT_HAVE_CLONE_NEWNS)
    {
        .name       = nxt_string("mount"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },
#endif

#if (NXT_HAVE_CLONE_NEWUTS)
    {
        .name       = nxt_string("uname"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },
#endif

#if (NXT_HAVE_CLONE_NEWCGROUP)
    {
        .name       = nxt_string("cgroup"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },
#endif

    NXT_CONF_VLDT_END
};


#if (NXT_HAVE_ISOLATION_ROOTFS)

static nxt_conf_vldt_object_t  nxt_conf_vldt_app_automount_members[] = {
    {
        .name       = nxt_string("language_deps"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    }, {
        .name       = nxt_string("tmpfs"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    }, {
        .name       = nxt_string("procfs"),
        .type       = NXT_CONF_VLDT_BOOLEAN,
    },

    NXT_CONF_VLDT_END
};

#endif


#if (NXT_HAVE_CGROUP)

static nxt_conf_vldt_object_t  nxt_conf_vldt_app_cgroup_members[] = {
    {
        .name       = nxt_string("path"),
        .type       = NXT_CONF_VLDT_STRING,
        .flags      = NXT_CONF_VLDT_REQUIRED,
        .validator  = nxt_conf_vldt_cgroup_path,
    },

    NXT_CONF_VLDT_END
};

#endif


#if (NXT_HAVE_CLONE_NEWUSER)

static nxt_conf_vldt_object_t nxt_conf_vldt_app_procmap_members[] = {
    {
        .name       = nxt_string("container"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("host"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    }, {
        .name       = nxt_string("size"),
        .type       = NXT_CONF_VLDT_INTEGER,
        .flags      = NXT_CONF_VLDT_REQUIRED,
    },

    NXT_CONF_VLDT_END
};

#endif


static nxt_conf_vldt_object_t  nxt_conf_vldt_upstream_members[] = {
    {
        .name       = nxt_string("servers"),
        .type       = NXT_CONF_VLDT_OBJECT,
        .validator  = nxt_conf_vldt_object_iterator,
        .u.object   = nxt_conf_vldt_server,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_upstream_server_members[] = {
    {
        .name       = nxt_string("weight"),
        .type       = NXT_CONF_VLDT_NUMBER,
        .validator  = nxt_conf_vldt_server_weight,
    },

    NXT_CONF_VLDT_END
};


static nxt_conf_vldt_object_t  nxt_conf_vldt_access_log_members[] = {
    {
        .name       = nxt_string("path"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("format"),
        .type       = NXT_CONF_VLDT_STRING,
    }, {
        .name       = nxt_string("if"),
        .type       = NXT_CONF_VLDT_STRING,
        .validator  = nxt_conf_vldt_if,
    },

    NXT_CONF_VLDT_END
};


nxt_int_t
nxt_conf_validate(nxt_conf_validation_t *vldt)
{
    nxt_int_t  ret;
    u_char     error[NXT_MAX_ERROR_STR];

    vldt->tstr_state = nxt_tstr_state_new(vldt->pool, 1);
    if (nxt_slow_path(vldt->tstr_state == NULL)) {
        return NXT_ERROR;
    }

    ret = nxt_conf_vldt_type(vldt, NULL, vldt->conf, NXT_CONF_VLDT_OBJECT);
    if (ret != NXT_OK) {
        return ret;
    }

    ret = nxt_conf_vldt_object(vldt, vldt->conf, nxt_conf_vldt_root_members);
    if (ret != NXT_OK) {
        return ret;
    }

    ret = nxt_tstr_state_done(vldt->tstr_state, error);
    if (ret != NXT_OK) {
        ret = nxt_conf_vldt_error(vldt, "%s", error);
        return ret;
    }

    return NXT_OK;
}


#define NXT_CONF_VLDT_ANY_TYPE_STR                                            \
    "either a null, a boolean, an integer, "                                  \
    "a number, a string, an array, or an object"



#if (NXT_HAVE_OTEL)
inline nxt_int_t
nxt_otel_validate_endpoint(nxt_conf_validation_t *vldt,
                           nxt_conf_value_t *value,
                           void *data)
{
    // This function is a stub for now
    return NXT_OK;
}


nxt_int_t
nxt_otel_validate_batch_size(nxt_conf_validation_t *vldt,
                             nxt_conf_value_t *value,
                             void *data)
{
    double batch_size;
    batch_size = nxt_conf_get_number(value);
    if (batch_size <= 0) {
      return NXT_ERROR;
    }

    return NXT_OK;
}

nxt_int_t
nxt_otel_validate_sample_ratio(nxt_conf_validation_t *vldt,
                               nxt_conf_value_t *value,
                               void *data)
{
    double sample_ratio;

    sample_ratio = nxt_conf_get_number(value);
    if (sample_ratio < 0 || sample_ratio > 1) {
        return NXT_ERROR;
    }

    return NXT_OK;
}

nxt_int_t
nxt_otel_validate_protocol(nxt_conf_validation_t *vldt,
                           nxt_conf_value_t *value,
                           void *data)
{
    nxt_str_t proto;

    nxt_conf_get_string(value, &proto);
    if (nxt_str_eq(&proto, "HTTP", 4) ||
        nxt_str_eq(&proto, "http", 4)) {
          goto happy;
    }

    if (nxt_str_eq(&proto, "GRPC", 4) ||
        nxt_str_eq(&proto, "grpc", 4)) {
        goto happy;
    }

    return NXT_ERROR;

 happy:
    return NXT_OK;
}
#endif


static nxt_int_t
nxt_conf_vldt_type(nxt_conf_validation_t *vldt, const nxt_str_t *name,
    nxt_conf_value_t *value, nxt_conf_vldt_type_t type)
{
    u_char      *p;
    nxt_str_t   expected;
    nxt_bool_t  comma;
    nxt_uint_t  value_type, n, t;
    u_char      buf[nxt_length(NXT_CONF_VLDT_ANY_TYPE_STR)];

    static const nxt_str_t  type_name[] = {
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


nxt_inline nxt_int_t
nxt_conf_vldt_unsupported(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    return nxt_conf_vldt_error(vldt, "Unit is built without the \"%s\" "
                                     "option support.", data);
}


static nxt_int_t
nxt_conf_vldt_var(nxt_conf_validation_t *vldt, const nxt_str_t *name,
    nxt_str_t *value)
{
    u_char  error[NXT_MAX_ERROR_STR];

    if (nxt_tstr_test(vldt->tstr_state, value, error) != NXT_OK) {
        return nxt_conf_vldt_error(vldt, "%s in the \"%V\" value.",
                                   error, name);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_if(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_str_t  str;

    static const nxt_str_t  if_str = nxt_string("if");

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"if\" must be a string");
    }

    nxt_conf_get_string(value, &str);

    if (str.length == 0) {
        return NXT_OK;
    }

    if (str.start[0] == '!') {
        str.start++;
        str.length--;
    }

    if (nxt_is_tstr(&str)) {
        return nxt_conf_vldt_var(vldt, &if_str, &str);
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
    nxt_str_t                   exten, *dup_type;
    nxt_conf_vldt_mtypes_ctx_t  *ctx;

    ctx = vldt->ctx;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" MIME type array must "
                                   "contain only strings.", ctx->type);
    }

    nxt_conf_get_string(value, &exten);

    if (exten.length == 0) {
        return nxt_conf_vldt_error(vldt, "An empty file extension for "
                                         "the \"%V\" MIME type.", ctx->type);
    }

    dup_type = nxt_http_static_mtype_get(&ctx->hash, &exten);

    if (dup_type->length != 0) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" file extension has been "
                                         "declared for \"%V\" and \"%V\" "
                                         "MIME types at the same time.",
                                         &exten, dup_type, ctx->type);
    }

    return nxt_http_static_mtypes_hash_add(ctx->pool, &ctx->hash, &exten,
                                           ctx->type);
}


static nxt_int_t
nxt_conf_vldt_listener(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    nxt_int_t       ret;
    nxt_str_t       str;
    nxt_sockaddr_t  *sa;

    if (nxt_slow_path(nxt_str_dup(vldt->pool, &str, name) == NULL)) {
        return NXT_ERROR;
    }

    sa = nxt_sockaddr_parse(vldt->pool, &str);
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

    static const struct {
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

    static const nxt_str_t  targets_str = nxt_string("targets");

    nxt_conf_get_string(value, &pass);

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
nxt_conf_vldt_share(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        if (nxt_conf_array_elements_count(value) == 0) {
            return nxt_conf_vldt_error(vldt, "The \"share\" array "
                                       "must contain at least one element.");
        }

        return nxt_conf_vldt_array_iterator(vldt, value,
                                            &nxt_conf_vldt_share_element);
    }

    /* NXT_CONF_STRING */

    return nxt_conf_vldt_share_element(vldt, value);
}


static nxt_int_t
nxt_conf_vldt_share_element(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    nxt_str_t  str;

    static const nxt_str_t  share = nxt_string("share");

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"share\" array must "
                                   "contain only string values.");
    }

    nxt_conf_get_string(value, &str);

    if (nxt_is_tstr(&str)) {
        return nxt_conf_vldt_var(vldt, &share, &str);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_proxy(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_str_t       name, *ret;
    nxt_sockaddr_t  *sa;

    ret = nxt_conf_get_string_dup(value, vldt->pool, &name);
    if (nxt_slow_path(ret == NULL)) {
        return NXT_ERROR;
    }

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
nxt_conf_vldt_python(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_conf_value_t  *targets;

    static const nxt_str_t  targets_str = nxt_string("targets");

    targets = nxt_conf_get_object_member(value, &targets_str, NULL);

    if (targets != NULL) {
        return nxt_conf_vldt_object(vldt, value, nxt_conf_vldt_python_members);
    }

    return nxt_conf_vldt_object(vldt, value,
                                nxt_conf_vldt_python_notargets_members);
}


static nxt_int_t
nxt_conf_vldt_python_path(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        return nxt_conf_vldt_array_iterator(vldt, value,
                                            &nxt_conf_vldt_python_path_element);
    }

    /* NXT_CONF_STRING */

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_python_path_element(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"path\" array must contain "
                                   "only string values.");
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_python_protocol(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    nxt_str_t  proto;

    static const nxt_str_t  wsgi = nxt_string("wsgi");
    static const nxt_str_t  asgi = nxt_string("asgi");

    nxt_conf_get_string(value, &proto);

    if (nxt_strstr_eq(&proto, &wsgi) || nxt_strstr_eq(&proto, &asgi)) {
        return NXT_OK;
    }

    return nxt_conf_vldt_error(vldt, "The \"protocol\" can either be "
                                     "\"wsgi\" or \"asgi\".");
}


static nxt_int_t
nxt_conf_vldt_python_prefix(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    nxt_str_t  prefix;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"prefix\" must be a string "
                                   "beginning with \"/\".");
    }

    nxt_conf_get_string(value, &prefix);

    if (!nxt_strchr_start(&prefix, '/')) {
        return nxt_conf_vldt_error(vldt, "The \"prefix\" must be a string "
                                   "beginning with \"/\".");
    }

    return NXT_OK;
}

static nxt_int_t
nxt_conf_vldt_listen_threads(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    int64_t  threads;

    threads = nxt_conf_get_number(value);

    if (threads < 1) {
        return nxt_conf_vldt_error(vldt, "The \"listen_threads\" number must "
                                   "be equal to or greater than 1.");
    }

    if (threads > NXT_INT32_T_MAX) {
        return nxt_conf_vldt_error(vldt, "The \"listen_threads\" number must "
                                   "not exceed %d.", NXT_INT32_T_MAX);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_threads(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    int64_t  threads;

    threads = nxt_conf_get_number(value);

    if (threads < 1) {
        return nxt_conf_vldt_error(vldt, "The \"threads\" number must be "
                                   "equal to or greater than 1.");
    }

    if (threads > NXT_INT32_T_MAX) {
        return nxt_conf_vldt_error(vldt, "The \"threads\" number must "
                                   "not exceed %d.", NXT_INT32_T_MAX);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_thread_stack_size(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    int64_t  size, min_size;

    size = nxt_conf_get_number(value);
    min_size = sysconf(_SC_THREAD_STACK_MIN);

    if (size < min_size) {
        return nxt_conf_vldt_error(vldt, "The \"thread_stack_size\" number "
                                   "must be equal to or greater than %d.",
                                   min_size);
    }

    if ((size % nxt_pagesize) != 0) {
        return nxt_conf_vldt_error(vldt, "The \"thread_stack_size\" number "
                             "must be a multiple of the system page size (%d).",
                             nxt_pagesize);
    }

    return NXT_OK;
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
    nxt_int_t  ret;

    vldt->ctx = data;

    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        ret = nxt_conf_vldt_array_iterator(vldt, value,
                                           &nxt_conf_vldt_match_pattern);

    } else {
        /* NXT_CONF_STRING */
        ret = nxt_conf_vldt_match_pattern(vldt, value);
    }

    vldt->ctx = NULL;

    return ret;
}


static nxt_int_t
nxt_conf_vldt_match_pattern(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    nxt_str_t        pattern;
    nxt_uint_t       i, first, last;
#if (NXT_HAVE_REGEX)
    nxt_regex_t      *re;
    nxt_regex_err_t  err;
#endif

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"match\" pattern for \"%s\" "
                                   "must be strings.", vldt->ctx);
    }

    nxt_conf_get_string(value, &pattern);

    if (pattern.length == 0) {
        return NXT_OK;
    }

    first = (pattern.start[0] == '!');

    if (first < pattern.length && pattern.start[first] == '~') {
#if (NXT_HAVE_REGEX)
        pattern.start += first + 1;
        pattern.length -= first + 1;

        re = nxt_regex_compile(vldt->pool, &pattern, &err);
        if (nxt_slow_path(re == NULL)) {
            if (err.offset < pattern.length) {
                return nxt_conf_vldt_error(vldt, "Invalid regular expression: "
                                           "%s at offset %d",
                                           err.msg, err.offset);
            }

            return nxt_conf_vldt_error(vldt, "Invalid regular expression: %s",
                                       err.msg);
        }

        return NXT_OK;
#else
        return nxt_conf_vldt_error(vldt, "Unit is built without support of "
                                   "regular expressions: \"--no-regex\" "
                                   "./configure option was set.");
#endif
    }

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

    /* NXT_CONF_OBJECT */

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

    return nxt_conf_vldt_match_encoded_patterns(vldt, value,
                                                (void *) "arguments");
}


static nxt_int_t
nxt_conf_vldt_match_encoded_patterns(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    nxt_int_t  ret;

    vldt->ctx = data;

    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        ret = nxt_conf_vldt_array_iterator(vldt, value,
                                          &nxt_conf_vldt_match_encoded_pattern);

    } else {
        /* NXT_CONF_STRING */
        ret = nxt_conf_vldt_match_encoded_pattern(vldt, value);
    }

    vldt->ctx = NULL;

    return ret;
}


static nxt_int_t
nxt_conf_vldt_match_encoded_pattern(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    u_char     *p, *end;
    nxt_int_t  ret;
    nxt_str_t  pattern;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"match\" pattern for \"%s\" "
                                   "must be a string.", vldt->ctx);
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
        return nxt_conf_vldt_error(vldt, "The \"match\" pattern for \"%s\" "
                                   "is encoded but is invalid.", vldt->ctx);
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

    case NXT_ADDR_PATTERN_NO_UNIX_ERROR:
        return nxt_conf_vldt_error(vldt, "The \"address\" does not support "
                                         "UNIX domain sockets with your "
                                         "configuration.");

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
    nxt_int_t  ret;

    vldt->ctx = data;

    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        ret = nxt_conf_vldt_array_iterator(vldt, value,
                                           &nxt_conf_vldt_match_patterns_set);

    } else {
        /* NXT_CONF_OBJECT */
        ret = nxt_conf_vldt_match_patterns_set(vldt, value);
    }

    vldt->ctx = NULL;

    return ret;
}


static nxt_int_t
nxt_conf_vldt_match_patterns_set(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    if (nxt_conf_type(value) != NXT_CONF_OBJECT) {
        return nxt_conf_vldt_error(vldt, "The \"match\" patterns for "
                                   "\"%s\" must be objects.", vldt->ctx);
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

    return nxt_conf_vldt_match_patterns(vldt, value, vldt->ctx);
}


#if (NXT_TLS)

static nxt_int_t
nxt_conf_vldt_certificate(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        if (nxt_conf_array_elements_count(value) == 0) {
            return nxt_conf_vldt_error(vldt, "The \"certificate\" array "
                                       "must contain at least one element.");
        }

        return nxt_conf_vldt_array_iterator(vldt, value,
                                            &nxt_conf_vldt_certificate_element);
    }

    /* NXT_CONF_STRING */

    return nxt_conf_vldt_certificate_element(vldt, value);
}


static nxt_int_t
nxt_conf_vldt_certificate_element(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    nxt_str_t         name;
    nxt_conf_value_t  *cert;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"certificate\" array must "
                                   "contain only string values.");
    }

    nxt_conf_get_string(value, &name);

    cert = nxt_cert_info_get(&name);

    if (cert == NULL) {
        return nxt_conf_vldt_error(vldt, "Certificate \"%V\" is not found.",
                                   &name);
    }

    return NXT_OK;
}


#if (NXT_HAVE_OPENSSL_CONF_CMD)

static nxt_int_t
nxt_conf_vldt_object_conf_commands(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    uint32_t          index;
    nxt_int_t         ret;
    nxt_str_t         name;
    nxt_conf_value_t  *member;

    index = 0;

    for ( ;; ) {
        member = nxt_conf_next_object_member(value, &name, &index);

        if (member == NULL) {
            break;
        }

        ret = nxt_conf_vldt_type(vldt, &name, member, NXT_CONF_VLDT_STRING);
        if (ret != NXT_OK) {
            return ret;
        }
    }

    return NXT_OK;
}

#endif

#endif


static nxt_int_t
nxt_conf_vldt_response_header(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    nxt_str_t   str;
    nxt_uint_t  type;

    static const nxt_str_t  content_length = nxt_string("Content-Length");

    if (name->length == 0) {
        return nxt_conf_vldt_error(vldt, "The response header name "
                                         "must not be empty.");
    }

    if (nxt_strstr_eq(name, &content_length)) {
        return nxt_conf_vldt_error(vldt, "The \"Content-Length\" response "
                                         "header value is not supported");
    }

    type = nxt_conf_type(value);

    if (type == NXT_CONF_NULL) {
        return NXT_OK;
    }

    if (type == NXT_CONF_STRING) {
        nxt_conf_get_string(value, &str);

        if (nxt_is_tstr(&str)) {
            return nxt_conf_vldt_var(vldt, name, &str);
        }

        return NXT_OK;
    }

    return nxt_conf_vldt_error(vldt, "The \"%V\" response header value "
                               "must either be a string or a null", name);
}


static nxt_int_t
nxt_conf_vldt_app_name(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_str_t         name;
    nxt_conf_value_t  *apps, *app;

    static const nxt_str_t  apps_str = nxt_string("applications");

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
nxt_conf_vldt_forwarded(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_conf_value_t  *client_ip, *protocol;

    static const nxt_str_t  client_ip_str = nxt_string("client_ip");
    static const nxt_str_t  protocol_str = nxt_string("protocol");

    client_ip = nxt_conf_get_object_member(value, &client_ip_str, NULL);
    protocol = nxt_conf_get_object_member(value, &protocol_str, NULL);

    if (client_ip == NULL && protocol == NULL) {
        return nxt_conf_vldt_error(vldt, "The \"forwarded\" object must have "
                                   "either \"client_ip\" or \"protocol\" "
                                   "option set.");
    }

    return nxt_conf_vldt_object(vldt, value, nxt_conf_vldt_forwarded_members);
}


static nxt_int_t
nxt_conf_vldt_listen_backlog(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    int64_t  backlog;

    backlog = nxt_conf_get_number(value);

    /*
     * POSIX allows this to be 0 and some systems use -1 to
     * indicate to use the OS's default value.
     */
    if (backlog < -1) {
        return nxt_conf_vldt_error(vldt, "The \"backlog\" number must be "
                                   "equal to or greater than -1.");
    }

    if (backlog > NXT_INT32_T_MAX) {
        return nxt_conf_vldt_error(vldt, "The \"backlog\" number must "
                                   "not exceed %d.", NXT_INT32_T_MAX);
    }

    return NXT_OK;
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

    static const nxt_str_t  type_str = nxt_string("type");

    static const struct {
        nxt_conf_vldt_handler_t  validator;
        nxt_conf_vldt_object_t   *members;

    } types[] = {
        { nxt_conf_vldt_object, nxt_conf_vldt_external_members },
        { nxt_conf_vldt_python, NULL },
        { nxt_conf_vldt_php,    NULL },
        { nxt_conf_vldt_object, nxt_conf_vldt_perl_members },
        { nxt_conf_vldt_object, nxt_conf_vldt_ruby_members },
        { nxt_conf_vldt_object, nxt_conf_vldt_java_members },
        { nxt_conf_vldt_object, nxt_conf_vldt_wasm_members },
        { nxt_conf_vldt_object, nxt_conf_vldt_wasm_wc_members },
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
    nxt_str_t               name, var;
    nxt_conf_value_t        *member;
    nxt_conf_vldt_object_t  *vals;

    vals = data;

    for ( ;; ) {
        if (vals->name.length == 0) {

            if (vals->u.members != NULL) {
                vals = vals->u.members;
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

                if (vals->u.members != NULL) {
                    vals = vals->u.members;
                    continue;
                }

                return nxt_conf_vldt_error(vldt, "Unknown parameter \"%V\".",
                                           &name);
            }

            if (!nxt_strstr_eq(&vals->name, &name)) {
                vals++;
                continue;
            }

            if (vals->flags & NXT_CONF_VLDT_TSTR
                && nxt_conf_type(member) == NXT_CONF_STRING)
            {
                nxt_conf_get_string(member, &var);

                if (nxt_is_tstr(&var)) {
                    ret = nxt_conf_vldt_var(vldt, &name, &var);
                    if (ret != NXT_OK) {
                        return ret;
                    }

                    break;
                }
            }

            ret = nxt_conf_vldt_type(vldt, &name, member, vals->type);
            if (ret != NXT_OK) {
                return ret;
            }

            if (vals->validator != NULL) {
                ret = vals->validator(vldt, member, vals->u.members);

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

    if (nxt_conf_type(value) == NXT_CONF_INTEGER) {
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

    if (memchr(name->start, '\0', name->length) != NULL) {
        return nxt_conf_vldt_error(vldt, "The environment name must not "
                                   "contain null character.");
    }

    if (memchr(name->start, '=', name->length) != NULL) {
        return nxt_conf_vldt_error(vldt, "The environment name must not "
                                   "contain '=' character.");
    }

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" environment value must be "
                                   "a string.", name);
    }

    nxt_conf_get_string(value, &str);

    if (memchr(str.start, '\0', str.length) != NULL) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" environment value must "
                                   "not contain null character.", name);
    }

    return NXT_OK;
}


static nxt_int_t
nxt_conf_vldt_targets_exclusive(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value, void *data)
{
    return nxt_conf_vldt_error(vldt, "The \"%s\" option is mutually exclusive "
                               "with the \"targets\" object.", data);
}


static nxt_int_t
nxt_conf_vldt_targets(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_int_t   ret;
    nxt_uint_t  n;

    n = nxt_conf_object_members_count(value);

    if (n > 254) {
        return nxt_conf_vldt_error(vldt, "The \"targets\" object must not "
                                   "contain more than 254 members.");
    }

    vldt->ctx = data;

    ret = nxt_conf_vldt_object_iterator(vldt, value, &nxt_conf_vldt_target);

    vldt->ctx = NULL;

    return ret;
}


static nxt_int_t
nxt_conf_vldt_target(nxt_conf_validation_t *vldt, nxt_str_t *name,
    nxt_conf_value_t *value)
{
    if (name->length == 0) {
        return nxt_conf_vldt_error(vldt,
                                   "The target name must not be empty.");
    }

    if (nxt_conf_type(value) != NXT_CONF_OBJECT) {
        return nxt_conf_vldt_error(vldt, "The \"%V\" target must be "
                                   "an object.", name);
    }

    return nxt_conf_vldt_object(vldt, value, vldt->ctx);
}


#if (NXT_HAVE_CGROUP)

static nxt_int_t
nxt_conf_vldt_cgroup_path(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    char       path[NXT_MAX_PATH_LEN];
    nxt_str_t  cgpath;

    nxt_conf_get_string(value, &cgpath);
    if (cgpath.length >= NXT_MAX_PATH_LEN - strlen(NXT_CGROUP_ROOT) - 1) {
        return nxt_conf_vldt_error(vldt, "The cgroup path \"%V\" is too long.",
                                   &cgpath);
    }

    sprintf(path, "/%*s/", (int) cgpath.length, cgpath.start);

    if (cgpath.length == 0 || strstr(path, "/../") != NULL) {
        return nxt_conf_vldt_error(vldt,
                                   "The cgroup path \"%V\" is invalid.",
                                   &cgpath);
    }

    return NXT_OK;
}

#endif


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

    return NXT_OK;
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

    return NXT_OK;
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

    if (memchr(str.start, '\0', str.length) != NULL) {
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

    static const nxt_str_t  targets_str = nxt_string("targets");

    targets = nxt_conf_get_object_member(value, &targets_str, NULL);

    if (targets != NULL) {
        return nxt_conf_vldt_object(vldt, value, nxt_conf_vldt_php_members);
    }

    return nxt_conf_vldt_object(vldt, value,
                                nxt_conf_vldt_php_notargets_members);
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

    if (memchr(str.start, '\0', str.length) != NULL) {
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

    if (memchr(str.start, '\0', str.length) != NULL) {
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

    static const nxt_str_t  servers = nxt_string("servers");

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
    nxt_str_t       str;
    nxt_sockaddr_t  *sa;

    ret = nxt_conf_vldt_type(vldt, name, value, NXT_CONF_VLDT_OBJECT);
    if (ret != NXT_OK) {
        return ret;
    }

    if (nxt_slow_path(nxt_str_dup(vldt->pool, &str, name) == NULL)) {
        return NXT_ERROR;
    }

    sa = nxt_sockaddr_parse(vldt->pool, &str);
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


#if (NXT_HAVE_NJS)

static nxt_int_t
nxt_conf_vldt_js_module(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    if (nxt_conf_type(value) == NXT_CONF_ARRAY) {
        return nxt_conf_vldt_array_iterator(vldt, value,
                                            &nxt_conf_vldt_js_module_element);
    }

    /* NXT_CONF_STRING */

    return nxt_conf_vldt_js_module_element(vldt, value);
}


static nxt_int_t
nxt_conf_vldt_js_module_element(nxt_conf_validation_t *vldt,
    nxt_conf_value_t *value)
{
    nxt_str_t         name;
    nxt_conf_value_t  *module;

    if (nxt_conf_type(value) != NXT_CONF_STRING) {
        return nxt_conf_vldt_error(vldt, "The \"js_module\" array must "
                                   "contain only string values.");
    }

    nxt_conf_get_string(value, &name);

    module = nxt_script_info_get(&name);
    if (module == NULL) {
        return nxt_conf_vldt_error(vldt, "JS module \"%V\" is not found.",
                                   &name);
    }

    return NXT_OK;
}

#endif


typedef struct {
    nxt_str_t  path;
    nxt_str_t  format;
} nxt_conf_vldt_access_log_conf_t;


static nxt_conf_map_t  nxt_conf_vldt_access_log_map[] = {
    {
        nxt_string("path"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_conf_vldt_access_log_conf_t, path),
    },

    {
        nxt_string("format"),
        NXT_CONF_MAP_STR,
        offsetof(nxt_conf_vldt_access_log_conf_t, format),
    },
};


static nxt_int_t
nxt_conf_vldt_access_log(nxt_conf_validation_t *vldt, nxt_conf_value_t *value,
    void *data)
{
    nxt_int_t                        ret;
    nxt_conf_vldt_access_log_conf_t  conf;

    static const nxt_str_t  format_str = nxt_string("format");

    if (nxt_conf_type(value) == NXT_CONF_STRING) {
        return NXT_OK;
    }

    ret = nxt_conf_vldt_object(vldt, value, nxt_conf_vldt_access_log_members);
    if (ret != NXT_OK) {
        return ret;
    }

    nxt_memzero(&conf, sizeof(nxt_conf_vldt_access_log_conf_t));

    ret = nxt_conf_map_object(vldt->pool, value,
                              nxt_conf_vldt_access_log_map,
                              nxt_nitems(nxt_conf_vldt_access_log_map),
                              &conf);
    if (ret != NXT_OK) {
        return ret;
    }

    if (conf.path.length == 0) {
        return nxt_conf_vldt_error(vldt,
                                   "The \"path\" string must not be empty.");
    }

    if (nxt_is_tstr(&conf.format)) {
        return nxt_conf_vldt_var(vldt, &format_str, &conf.format);
    }

    return NXT_OK;
}
