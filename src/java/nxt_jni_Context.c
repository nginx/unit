
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_auto_config.h>

#include <nxt_unit.h>
#include <jni.h>

#include "nxt_jni.h"
#include "nxt_jni_Context.h"
#include "nxt_jni_URLClassLoader.h"


static jclass     nxt_java_Context_class;
static jmethodID  nxt_java_Context_start;
static jmethodID  nxt_java_Context_service;
static jmethodID  nxt_java_Context_stop;

static void JNICALL nxt_java_Context_log(JNIEnv *env, jclass cls,
    jlong ctx_ptr, jstring msg, jint msg_len);
static void JNICALL nxt_java_Context_trace(JNIEnv *env, jclass cls,
    jlong ctx_ptr, jstring msg, jint msg_len);


int
nxt_java_initContext(JNIEnv *env, jobject cl)
{
    int     res;
    jclass  cls;

    cls = nxt_java_loadClass(env, cl, "nginx.unit.Context");
    if (cls == NULL) {
        nxt_unit_warn(NULL, "nginx.unit.Context not found");
        return NXT_UNIT_ERROR;
    }

    nxt_java_Context_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);
    cls = nxt_java_Context_class;

    nxt_java_Context_start = (*env)->GetStaticMethodID(env, cls, "start",
                     "(Ljava/lang/String;[Ljava/net/URL;)Lnginx/unit/Context;");
    if (nxt_java_Context_start == NULL) {
        nxt_unit_warn(NULL, "nginx.unit.Context.start() not found");
        goto failed;
    }

    nxt_java_Context_service = (*env)->GetMethodID(env, cls, "service",
            "(Lnginx/unit/Request;Lnginx/unit/Response;)V");
    if (nxt_java_Context_service == NULL) {
        nxt_unit_warn(NULL, "nginx.unit.Context.service() not found");
        goto failed;
    }

    nxt_java_Context_stop = (*env)->GetMethodID(env, cls, "stop", "()V");
    if (nxt_java_Context_service == NULL) {
        nxt_unit_warn(NULL, "nginx.unit.Context.stop() not found");
        goto failed;
    }

    JNINativeMethod context_methods[] = {
        { (char *) "log",
          (char *) "(JLjava/lang/String;I)V",
          nxt_java_Context_log },

        { (char *) "trace",
          (char *) "(JLjava/lang/String;I)V",
          nxt_java_Context_trace },

    };

    res = (*env)->RegisterNatives(env, nxt_java_Context_class,
                                  context_methods,
                                  sizeof(context_methods)
                                      / sizeof(context_methods[0]));

    nxt_unit_debug(NULL, "registered Context methods: %d", res);

    if (res != 0) {
        nxt_unit_warn(NULL, "registering natives for Context failed");
        goto failed;
    }

    return NXT_UNIT_OK;

failed:

    (*env)->DeleteGlobalRef(env, cls);
    return NXT_UNIT_ERROR;
}


jobject
nxt_java_startContext(JNIEnv *env, const char *webapp, jobject classpaths)
{
    jstring webapp_str;

    webapp_str = (*env)->NewStringUTF(env, webapp);
    if (webapp_str == NULL) {
        return NULL;
    }

    return (*env)->CallStaticObjectMethod(env, nxt_java_Context_class,
                                          nxt_java_Context_start, webapp_str,
                                          classpaths);
}


void
nxt_java_service(JNIEnv *env, jobject ctx, jobject jreq, jobject jresp)
{
    (*env)->CallVoidMethod(env, ctx, nxt_java_Context_service, jreq, jresp);
}


void
nxt_java_stopContext(JNIEnv *env, jobject ctx)
{
    (*env)->CallVoidMethod(env, ctx, nxt_java_Context_stop);
}


static void JNICALL
nxt_java_Context_log(JNIEnv *env, jclass cls, jlong ctx_ptr, jstring msg,
    jint msg_len)
{
    const char      *msg_str;
    nxt_unit_ctx_t  *ctx;

    ctx = nxt_jlong2ptr(ctx_ptr);

    msg_str = (*env)->GetStringUTFChars(env, msg, NULL);
    if (msg_str == NULL) {
        return;
    }

    nxt_unit_log(ctx, NXT_UNIT_LOG_INFO, "%.*s", msg_len, msg_str);

    (*env)->ReleaseStringUTFChars(env, msg, msg_str);
}


static void JNICALL
nxt_java_Context_trace(JNIEnv *env, jclass cls, jlong ctx_ptr, jstring msg,
    jint msg_len)
{
#if (NXT_DEBUG)
    const char      *msg_str;
    nxt_unit_ctx_t  *ctx;

    ctx = nxt_jlong2ptr(ctx_ptr);

    msg_str = (*env)->GetStringUTFChars(env, msg, NULL);
    if (msg_str == NULL) {
        return;
    }

    nxt_unit_debug(ctx, "%.*s", msg_len, msg_str);

    (*env)->ReleaseStringUTFChars(env, msg, msg_str);
#endif
}
