
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

    NXT_APP_UNKNOWN,
} nxt_app_type_t;


typedef struct nxt_app_module_s  nxt_app_module_t;


typedef struct {
    nxt_app_type_t            type;
    u_char                    *version;
    char                      *file;
    nxt_app_module_t          *module;
} nxt_app_lang_module_t;


typedef struct nxt_common_app_conf_s nxt_common_app_conf_t;


typedef struct {
    char                       *executable;
    nxt_conf_value_t           *arguments;
} nxt_external_app_conf_t;


typedef struct {
    char       *home;
    nxt_str_t  path;
    nxt_str_t  module;
} nxt_python_app_conf_t;


typedef struct {
    char                       *root;
    nxt_str_t                  script;
    nxt_str_t                  index;
    nxt_conf_value_t           *options;
} nxt_php_app_conf_t;


typedef struct {
    char       *script;
} nxt_perl_app_conf_t;


typedef struct {
    nxt_str_t  script;
} nxt_ruby_app_conf_t;


typedef struct {
    nxt_conf_value_t           *classpath;
    char                       *webapp;
    nxt_conf_value_t           *options;
    char                       *unit_jars;
} nxt_java_app_conf_t;


struct nxt_common_app_conf_s {
    nxt_str_t                  name;
    nxt_str_t                  type;
    nxt_str_t                  user;
    nxt_str_t                  group;

    char                       *working_directory;
    nxt_conf_value_t           *environment;

    union {
        nxt_external_app_conf_t  external;
        nxt_python_app_conf_t    python;
        nxt_php_app_conf_t       php;
        nxt_perl_app_conf_t      perl;
        nxt_ruby_app_conf_t      ruby;
        nxt_java_app_conf_t      java;
    } u;
};


struct nxt_app_module_s {
    size_t                     compat_length;
    uint32_t                   *compat;

    nxt_str_t                  type;
    const char                 *version;

    nxt_int_t                  (*pre_init)(nxt_task_t *task,
                                    nxt_common_app_conf_t *conf);
    nxt_int_t                  (*init)(nxt_task_t *task,
                                    nxt_common_app_conf_t *conf);
};


nxt_app_lang_module_t *nxt_app_lang_module(nxt_runtime_t *rt, nxt_str_t *name);
nxt_app_type_t nxt_app_parse_type(u_char *p, size_t length);

NXT_EXPORT extern nxt_str_t  nxt_server;
extern nxt_app_module_t      nxt_external_module;

NXT_EXPORT nxt_int_t nxt_unit_default_init(nxt_task_t *task,
    nxt_unit_init_t *init);


#endif /* _NXT_APPLICATION_H_INCLIDED_ */
