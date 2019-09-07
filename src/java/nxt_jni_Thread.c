
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_unit.h>
#include <jni.h>

#include "nxt_jni_Thread.h"


static jclass     nxt_java_Thread_class;
static jmethodID  nxt_java_Thread_currentThread;
static jmethodID  nxt_java_Thread_getContextClassLoader;
static jmethodID  nxt_java_Thread_setContextClassLoader;


int
nxt_java_initThread(JNIEnv *env)
{
    jclass  cls;

    cls = (*env)->FindClass(env, "java/lang/Thread");
    if (cls == NULL) {
        nxt_unit_warn(NULL, "java.lang.Thread not found");
        return NXT_UNIT_ERROR;
    }

    nxt_java_Thread_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);
    cls = nxt_java_Thread_class;

    nxt_java_Thread_currentThread = (*env)->GetStaticMethodID(env, cls,
        "currentThread", "()Ljava/lang/Thread;");
    if (nxt_java_Thread_currentThread == NULL) {
        nxt_unit_warn(NULL, "java.lang.Thread.currentThread() not found");
        goto failed;
    }

    nxt_java_Thread_getContextClassLoader = (*env)->GetMethodID(env, cls,
        "getContextClassLoader", "()Ljava/lang/ClassLoader;");
    if (nxt_java_Thread_getContextClassLoader == NULL) {
        nxt_unit_warn(NULL, "java.lang.Thread.getContextClassLoader() "
                      "not found");
        goto failed;
    }

    nxt_java_Thread_setContextClassLoader = (*env)->GetMethodID(env, cls,
        "setContextClassLoader", "(Ljava/lang/ClassLoader;)V");
    if (nxt_java_Thread_setContextClassLoader == NULL) {
        nxt_unit_warn(NULL, "java.lang.Thread.setContextClassLoader() "
                      "not found");
        goto failed;
    }

    return NXT_UNIT_OK;

failed:

    (*env)->DeleteGlobalRef(env, cls);
    return NXT_UNIT_ERROR;
}

void
nxt_java_setContextClassLoader(JNIEnv *env, jobject cl)
{
    jobject thread;

    thread = (*env)->CallStaticObjectMethod(env, nxt_java_Thread_class,
                                            nxt_java_Thread_currentThread);

    if (thread == NULL) {
        return;
    }

    (*env)->CallVoidMethod(env, thread, nxt_java_Thread_setContextClassLoader,
                           cl);
}

jobject
nxt_java_getContextClassLoader(JNIEnv *env)
{
    jobject thread;

    thread = (*env)->CallStaticObjectMethod(env, nxt_java_Thread_class,
                                            nxt_java_Thread_currentThread);

    if (thread == NULL) {
        return NULL;
    }

    return (*env)->CallObjectMethod(env, thread,
                                    nxt_java_Thread_getContextClassLoader);
}
