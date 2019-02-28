
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_JAVA_OUTPUTSTREAM_H_INCLUDED_
#define _NXT_JAVA_OUTPUTSTREAM_H_INCLUDED_


#include <jni.h>


int nxt_java_initOutputStream(JNIEnv *env, jobject cl);

int nxt_java_OutputStream_flush_buf(JNIEnv *env, nxt_unit_request_info_t *req);

#endif  /* _NXT_JAVA_OUTPUTSTREAM_H_INCLUDED_ */
