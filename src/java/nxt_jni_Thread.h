
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_JAVA_THREAD_H_INCLUDED_
#define _NXT_JAVA_THREAD_H_INCLUDED_


#include <jni.h>


int nxt_java_initThread(JNIEnv *env);

void nxt_java_setContextClassLoader(JNIEnv *env, jobject cl);

jobject nxt_java_getContextClassLoader(JNIEnv *env);

#endif  /* _NXT_JAVA_THREAD_H_INCLUDED_ */

