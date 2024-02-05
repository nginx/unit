
/*
 * Copyright (C) Max Romanov
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_APPLICATION_H_INCLUDED_
#define _NXT_APPLICATION_H_INCLUDED_


#include <nxt_conf.h>

#include <nxt_unit_typedefs.h>


typedef enum {
    NXT_APP_EXTERNAL,
    NXT_APP_PYTHON,
    NXT_APP_PHP,
    NXT_APP_PERL,
    NXT_APP_RUBY,
    NXT_APP_JAVA,
    NXT_APP_WASM,
    NXT_APP_WASM_WC,

    NXT_APP_UNKNOWN,
} nxt_app_type_t;


typedef struct nxt_app_module_s  nxt_app_module_t;
typedef nxt_int_t (*nxt_application_setup_t)(nxt_task_t *task,
    nxt_process_t *process, nxt_common_app_conf_t *conf);


typedef struct {
    nxt_app_type_t            type;
    u_char                    *version;
    char                      *file;
    nxt_app_module_t          *module;
    nxt_array_t               *mounts;    /* of nxt_fs_mount_t */
} nxt_app_lang_module_t;


typedef struct {
    char                       *executable;
    nxt_conf_value_t           *arguments;
} nxt_external_app_conf_t;


typedef struct {
    char                       *home;
    nxt_conf_value_t           *path;
    nxt_str_t                  protocol;
    uint32_t                   threads;
    uint32_t                   thread_stack_size;
    nxt_conf_value_t           *targets;
} nxt_python_app_conf_t;


typedef struct {
    nxt_conf_value_t           *targets;
    nxt_conf_value_t           *options;
} nxt_php_app_conf_t;


typedef struct {
    char       *script;
    uint32_t   threads;
    uint32_t   thread_stack_size;
} nxt_perl_app_conf_t;


typedef struct {
    nxt_str_t  script;
    uint32_t   threads;
    nxt_str_t  hooks;
} nxt_ruby_app_conf_t;


typedef struct {
    nxt_conf_value_t           *classpath;
    char                       *webapp;
    nxt_conf_value_t           *options;
    char                       *unit_jars;
    uint32_t                   threads;
    uint32_t                   thread_stack_size;
} nxt_java_app_conf_t;


typedef struct {
    const char        *module;

    const char        *request_handler;
    const char        *malloc_handler;
    const char        *free_handler;

    const char        *module_init_handler;
    const char        *module_end_handler;
    const char        *request_init_handler;
    const char        *request_end_handler;
    const char        *response_end_handler;

    nxt_conf_value_t  *access;
} nxt_wasm_app_conf_t;


typedef struct {
    const char        *component;

    nxt_conf_value_t  *access;
} nxt_wasm_wc_app_conf_t;


struct nxt_common_app_conf_s {
    nxt_str_t                  name;
    nxt_str_t                  type;
    nxt_str_t                  user;
    nxt_str_t                  group;

    char                       *stdout_log;
    char                       *stderr_log;

    char                       *working_directory;
    nxt_conf_value_t           *environment;

    nxt_conf_value_t           *isolation;
    nxt_conf_value_t           *limits;

    size_t                     shm_limit;
    uint32_t                   request_limit;

    nxt_fd_t                   shared_port_fd;
    nxt_fd_t                   shared_queue_fd;

    union {
        nxt_external_app_conf_t  external;
        nxt_python_app_conf_t    python;
        nxt_php_app_conf_t       php;
        nxt_perl_app_conf_t      perl;
        nxt_ruby_app_conf_t      ruby;
        nxt_java_app_conf_t      java;
        nxt_wasm_app_conf_t      wasm;
        nxt_wasm_wc_app_conf_t   wasm_wc;
    } u;

    nxt_conf_value_t           *self;
};


struct nxt_app_module_s {
    size_t                     compat_length;
    uint32_t                   *compat;

    nxt_str_t                  type;
    const char                 *version;

    const nxt_fs_mount_t       *mounts;
    nxt_uint_t                 nmounts;

    nxt_application_setup_t    setup;
    nxt_process_start_t        start;
};


nxt_app_lang_module_t *nxt_app_lang_module(nxt_runtime_t *rt, nxt_str_t *name);
nxt_app_type_t nxt_app_parse_type(u_char *p, size_t length);

NXT_EXPORT extern nxt_str_t  nxt_server;
extern nxt_app_module_t      nxt_external_module;

NXT_EXPORT nxt_int_t nxt_unit_default_init(nxt_task_t *task,
    nxt_unit_init_t *init, nxt_common_app_conf_t *conf);

NXT_EXPORT nxt_int_t nxt_app_set_logs(void);

#endif /* _NXT_APPLICATION_H_INCLIDED_ */
