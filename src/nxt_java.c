
/*
 * Copyright (C) NGINX, Inc.
 */


#include <jni.h>

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_router.h>
#include <nxt_unit.h>
#include <nxt_unit_field.h>
#include <nxt_unit_request.h>
#include <nxt_unit_response.h>
#include <nxt_unit_websocket.h>

#include <java/nxt_jni.h>

#include "java/nxt_jni_Thread.h"
#include "java/nxt_jni_Context.h"
#include "java/nxt_jni_Request.h"
#include "java/nxt_jni_Response.h"
#include "java/nxt_jni_InputStream.h"
#include "java/nxt_jni_OutputStream.h"
#include "java/nxt_jni_URLClassLoader.h"

#include "nxt_jars.h"

#include NXT_JAVA_MOUNTS_H

static nxt_int_t nxt_java_setup(nxt_task_t *task, nxt_process_t *process,
    nxt_common_app_conf_t *conf);
static nxt_int_t nxt_java_start(nxt_task_t *task,
    nxt_process_data_t *data);
static void nxt_java_request_handler(nxt_unit_request_info_t *req);
static void nxt_java_websocket_handler(nxt_unit_websocket_frame_t *ws);
static void nxt_java_close_handler(nxt_unit_request_info_t *req);
static int nxt_java_ready_handler(nxt_unit_ctx_t *ctx);
static void *nxt_java_thread_func(void *main_ctx);
static int nxt_java_init_threads(nxt_java_app_conf_t *c);
static void nxt_java_join_threads(nxt_unit_ctx_t *ctx,
    nxt_java_app_conf_t *c);

static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};

char  *nxt_java_modules;

static pthread_t       *nxt_java_threads;
static pthread_attr_t  *nxt_java_thread_attr;


#define NXT_STRING(x)   _NXT_STRING(x)
#define _NXT_STRING(x)  #x

NXT_EXPORT nxt_app_module_t  nxt_app_module = {
    sizeof(compat),
    compat,
    nxt_string("java"),
    NXT_STRING(NXT_JAVA_VERSION),
    nxt_java_mounts,
    nxt_nitems(nxt_java_mounts),
    nxt_java_setup,
    nxt_java_start,
};

typedef struct {
    JavaVM               *jvm;
    jobject              cl;
    jobject              ctx;
    nxt_java_app_conf_t  *conf;
} nxt_java_data_t;


static nxt_int_t
nxt_java_setup(nxt_task_t *task, nxt_process_t *process,
    nxt_common_app_conf_t *conf)
{
    char        *path, *relpath, *p, *rootfs;
    size_t      jars_dir_len, rootfs_len;
    const char  *unit_jars;

    rootfs = (char *) process->isolation.rootfs;
    rootfs_len = 0;

    unit_jars = conf->u.java.unit_jars;
    if (unit_jars == NULL) {
        if (rootfs != NULL) {
            unit_jars = "/";
        } else {
            unit_jars = NXT_JARS;
        }
    }

    relpath = strdup(unit_jars);
    if (nxt_slow_path(relpath == NULL)) {
        return NXT_ERROR;
    }

    if (rootfs != NULL) {
        jars_dir_len = strlen(unit_jars);
        rootfs_len = strlen(rootfs);

        path = nxt_malloc(jars_dir_len + rootfs_len + 1);
        if (nxt_slow_path(path == NULL)) {
            free(relpath);
            return NXT_ERROR;
        }

        p = nxt_cpymem(path, process->isolation.rootfs, rootfs_len);
        p = nxt_cpymem(p, relpath, jars_dir_len);
        *p = '\0';

        free(relpath);

    } else {
        path = relpath;
    }

    nxt_java_modules = realpath(path, NULL);
    if (nxt_java_modules == NULL) {
        nxt_alert(task, "realpath(\"%s\") failed %E", path, nxt_errno);
        goto free;
    }

    if (rootfs != NULL && strlen(path) > rootfs_len) {
        nxt_java_modules = path + rootfs_len;
    }

    nxt_debug(task, "JAVA MODULES: %s", nxt_java_modules);

    return NXT_OK;

free:

    nxt_free(path);

    return NXT_ERROR;
}


static char **
nxt_java_module_jars(const char *jars[], int jar_count)
{
    char        **res, *jurl;
    uint8_t     pathsep;
    nxt_int_t   modules_len, jlen, i;
    const char  **jar;

    res = nxt_malloc(jar_count * sizeof(char*));
    if (res == NULL) {
        return NULL;
    }

    modules_len = nxt_strlen(nxt_java_modules);

    pathsep = nxt_java_modules[modules_len - 1] == '/';

    for (i = 0, jar = jars; *jar != NULL; jar++) {
        jlen = nxt_length("file:") + modules_len
               + (!pathsep ? nxt_length("/") : 0)
               + nxt_strlen(*jar) + 1;

        jurl = nxt_malloc(jlen);
        if (jurl == NULL) {
            return NULL;
        }

        res[i++] = jurl;

        jurl = nxt_cpymem(jurl, "file:", nxt_length("file:"));
        jurl = nxt_cpymem(jurl, nxt_java_modules, modules_len);

        if (!pathsep) {
            *jurl++ = '/';
        }

        jurl = nxt_cpymem(jurl, *jar, nxt_strlen(*jar));
        *jurl++ = '\0';
    }

    return res;
}


static nxt_int_t
nxt_java_start(nxt_task_t *task, nxt_process_data_t *data)
{
    jint                   rc;
    char                   *opt, *real_path;
    char                   **classpath_arr, **unit_jars, **system_jars;
    JavaVM                 *jvm;
    JNIEnv                 *env;
    jobject                cl, classpath;
    nxt_str_t              str;
    nxt_int_t              opt_len, real_path_len;
    nxt_uint_t             i, unit_jars_count, classpath_count;
    nxt_uint_t             system_jars_count;
    JavaVMOption           *jvm_opt;
    JavaVMInitArgs         jvm_args;
    nxt_unit_ctx_t         *ctx;
    nxt_unit_init_t        java_init;
    nxt_java_data_t        java_data;
    nxt_conf_value_t       *value;
    nxt_java_app_conf_t    *c;
    nxt_common_app_conf_t  *app_conf;

    //setenv("ASAN_OPTIONS", "handle_segv=0", 1);

    jvm_args.version = JNI_VERSION_1_6;
    jvm_args.nOptions = 0;
    jvm_args.ignoreUnrecognized = 0;

    app_conf = data->app;
    c = &app_conf->u.java;

    if (c->options != NULL) {
        jvm_args.nOptions += nxt_conf_array_elements_count(c->options);
    }

    jvm_opt = nxt_malloc(jvm_args.nOptions * sizeof(JavaVMOption));
    if (jvm_opt == NULL) {
        nxt_alert(task, "failed to allocate jvm_opt");
        return NXT_ERROR;
    }

    jvm_args.options = jvm_opt;

    unit_jars_count = nxt_nitems(nxt_java_unit_jars) - 1;

    unit_jars = nxt_java_module_jars(nxt_java_unit_jars, unit_jars_count);
    if (unit_jars == NULL) {
        nxt_alert(task, "failed to allocate buffer for unit_jars array");

        return NXT_ERROR;
    }

    system_jars_count = nxt_nitems(nxt_java_system_jars) - 1;

    system_jars = nxt_java_module_jars(nxt_java_system_jars, system_jars_count);
    if (system_jars == NULL) {
        nxt_alert(task, "failed to allocate buffer for system_jars array");

        return NXT_ERROR;
    }

    if (c->options != NULL) {

        for (i = 0; /* void */ ; i++) {
            value = nxt_conf_get_array_element(c->options, i);
            if (value == NULL) {
                break;
            }

            nxt_conf_get_string(value, &str);

            opt = nxt_malloc(str.length + 1);
            if (opt == NULL) {
                nxt_alert(task, "failed to allocate jvm_opt");
                return NXT_ERROR;
            }

            memcpy(opt, str.start, str.length);
            opt[str.length] = '\0';

            jvm_opt[i].optionString = opt;
        }
    }

    if (c->classpath != NULL) {
        classpath_count = nxt_conf_array_elements_count(c->classpath);
        classpath_arr = nxt_malloc(classpath_count * sizeof(char *));

        for (i = 0; /* void */ ; i++) {
            value = nxt_conf_get_array_element(c->classpath, i);
            if (value == NULL) {
                break;
            }

            nxt_conf_get_string(value, &str);

            opt_len = str.length + 1;

            char *sc = memchr(str.start, ':', str.length);
            if (sc == NULL && str.start[0] == '/') {
                opt_len += nxt_length("file:");
            }

            opt = nxt_malloc(opt_len);
            if (opt == NULL) {
                nxt_alert(task, "failed to allocate classpath");
                return NXT_ERROR;
            }

            if (sc == NULL && str.start[0] != '/') {
                nxt_memcpy(opt, str.start, str.length);
                opt[str.length] = '\0';

                real_path = realpath(opt, NULL);
                if (real_path == NULL) {
                    nxt_alert(task, "realpath(%s) failed: %E", opt, nxt_errno);
                    return NXT_ERROR;
                }

                real_path_len = nxt_strlen(real_path);

                free(opt);

                opt_len = nxt_length("file:") + real_path_len + 1;

                opt = nxt_malloc(opt_len);
                if (opt == NULL) {
                    nxt_alert(task, "failed to allocate classpath");
                    return NXT_ERROR;
                }

            } else {
                real_path = (char *) str.start;  /* I love this cast! */
                real_path_len = str.length;
            }

            classpath_arr[i] = opt;

            if (sc == NULL) {
                opt = nxt_cpymem(opt, "file:", nxt_length("file:"));
            }

            opt = nxt_cpymem(opt, real_path, real_path_len);
            *opt = '\0';
        }

    } else {
        classpath_count = 0;
        classpath_arr = NULL;
    }

    rc = JNI_CreateJavaVM(&jvm, (void **) &env, &jvm_args);
    if (rc != JNI_OK) {
        nxt_alert(task, "failed to create Java VM: %d", (int) rc);
        return NXT_ERROR;
    }

    rc = nxt_java_initThread(env);
    if (rc != NXT_UNIT_OK) {
        nxt_alert(task, "nxt_java_initThread() failed");
        goto env_failed;
    }

    rc = nxt_java_initURLClassLoader(env);
    if (rc != NXT_UNIT_OK) {
        nxt_alert(task, "nxt_java_initURLClassLoader() failed");
        goto env_failed;
    }

    cl = nxt_java_newURLClassLoader(env, system_jars_count, system_jars);
    if (cl == NULL) {
        nxt_alert(task, "nxt_java_newURLClassLoader failed");
        goto env_failed;
    }

    nxt_java_setContextClassLoader(env, cl);

    cl = nxt_java_newURLClassLoader_parent(env, unit_jars_count, unit_jars, cl);
    if (cl == NULL) {
        nxt_alert(task, "nxt_java_newURLClassLoader_parent failed");
        goto env_failed;
    }

    nxt_java_setContextClassLoader(env, cl);

    rc = nxt_java_initContext(env, cl);
    if (rc != NXT_UNIT_OK) {
        nxt_alert(task, "nxt_java_initContext() failed");
        goto env_failed;
    }

    rc = nxt_java_initRequest(env, cl);
    if (rc != NXT_UNIT_OK) {
        nxt_alert(task, "nxt_java_initRequest() failed");
        goto env_failed;
    }

    rc = nxt_java_initResponse(env, cl);
    if (rc != NXT_UNIT_OK) {
        nxt_alert(task, "nxt_java_initResponse() failed");
        goto env_failed;
    }

    rc = nxt_java_initInputStream(env, cl);
    if (rc != NXT_UNIT_OK) {
        nxt_alert(task, "nxt_java_initInputStream() failed");
        goto env_failed;
    }

    rc = nxt_java_initOutputStream(env, cl);
    if (rc != NXT_UNIT_OK) {
        nxt_alert(task, "nxt_java_initOutputStream() failed");
        goto env_failed;
    }

    nxt_java_jni_init(env);
    if (rc != NXT_UNIT_OK) {
        nxt_alert(task, "nxt_java_jni_init() failed");
        goto env_failed;
    }

    classpath = nxt_java_newURLs(env, classpath_count, classpath_arr);
    if (classpath == NULL) {
        nxt_alert(task, "nxt_java_newURLs failed");
        goto env_failed;
    }

    java_data.jvm = jvm;
    java_data.cl = cl;
    java_data.ctx = nxt_java_startContext(env, c->webapp, classpath);
    java_data.conf = c;

    if ((*env)->ExceptionCheck(env)) {
        nxt_alert(task, "Unhandled exception in application start");
        (*env)->ExceptionDescribe(env);
        return NXT_ERROR;
    }

    rc = nxt_java_init_threads(c);
    if (nxt_slow_path(rc == NXT_UNIT_ERROR)) {
        return NXT_ERROR;
    }

    nxt_unit_default_init(task, &java_init, app_conf);

    java_init.callbacks.request_handler = nxt_java_request_handler;
    java_init.callbacks.websocket_handler = nxt_java_websocket_handler;
    java_init.callbacks.close_handler = nxt_java_close_handler;
    java_init.callbacks.ready_handler = nxt_java_ready_handler;
    java_init.request_data_size = sizeof(nxt_java_request_data_t);
    java_init.data = &java_data;
    java_init.ctx_data = env;

    ctx = nxt_unit_init(&java_init);
    if (nxt_slow_path(ctx == NULL)) {
        nxt_alert(task, "nxt_unit_init() failed");
        return NXT_ERROR;
    }

    rc = nxt_unit_run(ctx);

    nxt_java_join_threads(ctx, c);

    nxt_java_stopContext(env, java_data.ctx);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
    }

    nxt_unit_done(ctx);

    (*jvm)->DestroyJavaVM(jvm);

    exit(rc);

    return NXT_OK;

env_failed:

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
    }

    return NXT_ERROR;
}


static void
nxt_java_request_handler(nxt_unit_request_info_t *req)
{
    JNIEnv                   *env;
    jobject                  jreq, jresp;
    nxt_java_data_t          *java_data;
    nxt_java_request_data_t  *data;

    java_data = req->unit->data;
    env = req->ctx->data;
    data = req->data;

    jreq = nxt_java_newRequest(env, java_data->ctx, req);
    if (jreq == NULL) {
        nxt_unit_req_alert(req, "failed to create Request instance");

        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }

        nxt_unit_request_done(req, NXT_UNIT_ERROR);
        return;
    }

    jresp = nxt_java_newResponse(env, req);
    if (jresp == NULL) {
        nxt_unit_req_alert(req, "failed to create Response instance");

        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }

        (*env)->DeleteLocalRef(env, jreq);

        nxt_unit_request_done(req, NXT_UNIT_ERROR);
        return;
    }

    data->header_size = 10 * 1024;
    data->buf_size = 32 * 1024; /* from Jetty */
    data->jreq = jreq;
    data->jresp = jresp;
    data->buf = NULL;

    nxt_unit_request_group_dup_fields(req);

    nxt_java_service(env, java_data->ctx, jreq, jresp);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    if (!nxt_unit_response_is_init(req)) {
        nxt_unit_response_init(req, 200, 0, 0);
    }

    if (!nxt_unit_response_is_sent(req)) {
        nxt_unit_response_send(req);
    }

    if (data->buf != NULL) {
        nxt_unit_buf_send(data->buf);

        data->buf = NULL;
    }

    if (nxt_unit_response_is_websocket(req)) {
        data->jreq = (*env)->NewGlobalRef(env, jreq);
        data->jresp = (*env)->NewGlobalRef(env, jresp);

    } else {
        nxt_unit_request_done(req, NXT_UNIT_OK);
    }

    (*env)->DeleteLocalRef(env, jresp);
    (*env)->DeleteLocalRef(env, jreq);
}


static void
nxt_java_websocket_handler(nxt_unit_websocket_frame_t *ws)
{
    void                     *b;
    JNIEnv                   *env;
    jobject                  jbuf;
    nxt_java_request_data_t  *data;

    env = ws->req->ctx->data;
    data = ws->req->data;

    b = malloc(ws->payload_len);
    if (b != NULL) {
        nxt_unit_websocket_read(ws, b, ws->payload_len);

        jbuf = (*env)->NewDirectByteBuffer(env, b, ws->payload_len);
        if (jbuf != NULL) {
            nxt_java_Request_websocket(env, data->jreq, jbuf,
                                       ws->header->opcode, ws->header->fin);

            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
            }

            (*env)->DeleteLocalRef(env, jbuf);
        }

        free(b);
    }

    nxt_unit_websocket_done(ws);
}


static void
nxt_java_close_handler(nxt_unit_request_info_t *req)
{
    JNIEnv                   *env;
    nxt_java_request_data_t  *data;

    env = req->ctx->data;
    data = req->data;

    nxt_java_Request_close(env, data->jreq);

    (*env)->DeleteGlobalRef(env, data->jresp);
    (*env)->DeleteGlobalRef(env, data->jreq);

    nxt_unit_request_done(req, NXT_UNIT_OK);
}


static int
nxt_java_ready_handler(nxt_unit_ctx_t *ctx)
{
    int                  res;
    uint32_t             i;
    nxt_java_data_t      *java_data;
    nxt_java_app_conf_t  *c;

    java_data = ctx->unit->data;
    c = java_data->conf;

    if (c->threads <= 1) {
        return NXT_UNIT_OK;
    }

    for (i = 0; i < c->threads - 1; i++) {
        res = pthread_create(&nxt_java_threads[i], nxt_java_thread_attr,
                             nxt_java_thread_func, ctx);

        if (nxt_fast_path(res == 0)) {
            nxt_unit_debug(ctx, "thread #%d created", (int) (i + 1));

        } else {
            nxt_unit_alert(ctx, "thread #%d create failed: %s (%d)",
                           (int) (i + 1), strerror(res), res);

            return NXT_UNIT_ERROR;
        }
    }

    return NXT_UNIT_OK;
}


static void *
nxt_java_thread_func(void *data)
{
    int              rc;
    JavaVM           *jvm;
    JNIEnv           *env;
    nxt_unit_ctx_t   *main_ctx, *ctx;
    nxt_java_data_t  *java_data;

    main_ctx = data;

    nxt_unit_debug(main_ctx, "worker thread start");

    java_data = main_ctx->unit->data;
    jvm = java_data->jvm;

    rc = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL);
    if (rc != JNI_OK) {
        nxt_unit_alert(main_ctx, "failed to attach Java VM: %d", (int) rc);
        return NULL;
    }

    nxt_java_setContextClassLoader(env, java_data->cl);

    ctx = nxt_unit_ctx_alloc(main_ctx, env);
    if (nxt_slow_path(ctx == NULL)) {
        goto fail;
    }

    (void) nxt_unit_run(ctx);

    nxt_unit_done(ctx);

fail:

    (*jvm)->DetachCurrentThread(jvm);

    nxt_unit_debug(NULL, "worker thread end");

    return NULL;
}


static int
nxt_java_init_threads(nxt_java_app_conf_t *c)
{
    int                    res;
    static pthread_attr_t  attr;

    if (c->threads <= 1) {
        return NXT_UNIT_OK;
    }

    if (c->thread_stack_size > 0) {
        res = pthread_attr_init(&attr);
        if (nxt_slow_path(res != 0)) {
            nxt_unit_alert(NULL, "thread attr init failed: %s (%d)",
                           strerror(res), res);

            return NXT_UNIT_ERROR;
        }

        res = pthread_attr_setstacksize(&attr, c->thread_stack_size);
        if (nxt_slow_path(res != 0)) {
            nxt_unit_alert(NULL, "thread attr set stack size failed: %s (%d)",
                           strerror(res), res);

            return NXT_UNIT_ERROR;
        }

        nxt_java_thread_attr = &attr;
    }

    nxt_java_threads = nxt_unit_malloc(NULL,
                                       sizeof(pthread_t) * (c->threads - 1));
    if (nxt_slow_path(nxt_java_threads == NULL)) {
        nxt_unit_alert(NULL, "Failed to allocate thread id array");

        return NXT_UNIT_ERROR;
    }

    memset(nxt_java_threads, 0, sizeof(pthread_t) * (c->threads - 1));

    return NXT_UNIT_OK;
}


static void
nxt_java_join_threads(nxt_unit_ctx_t *ctx, nxt_java_app_conf_t *c)
{
    int       res;
    uint32_t  i;

    if (nxt_java_threads == NULL) {
        return;
    }

    for (i = 0; i < c->threads - 1; i++) {
        if ((uintptr_t) nxt_java_threads[i] == 0) {
            continue;
        }

        res = pthread_join(nxt_java_threads[i], NULL);

        if (nxt_fast_path(res == 0)) {
            nxt_unit_debug(ctx, "thread #%d joined", (int) i);

        } else {
            nxt_unit_alert(ctx, "thread #%d join failed: %s (%d)",
                           (int) i, strerror(res), res);
        }
    }

    nxt_unit_free(ctx, nxt_java_threads);
}


