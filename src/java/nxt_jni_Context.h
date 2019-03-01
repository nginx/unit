
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_JAVA_CONTEXT_H_INCLUDED_
#define _NXT_JAVA_CONTEXT_H_INCLUDED_


#include <jni.h>


int nxt_java_initContext(JNIEnv *env, jobject cl);

jobject nxt_java_startContext(JNIEnv *env, const char *webapp,
    jobject classpaths);

void nxt_java_service(JNIEnv *env, jobject ctx, jobject jreq, jobject jresp);

void nxt_java_stopContext(JNIEnv *env, jobject ctx);

#endif  /* _NXT_JAVA_CONTEXT_H_INCLUDED_ */

