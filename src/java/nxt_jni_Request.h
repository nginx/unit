
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_JAVA_REQUEST_H_INCLUDED_
#define _NXT_JAVA_REQUEST_H_INCLUDED_


#include <jni.h>
#include <nxt_unit_typedefs.h>


int nxt_java_initRequest(JNIEnv *env, jobject cl);

jobject nxt_java_newRequest(JNIEnv *env, jobject ctx, nxt_unit_request_info_t *req);

void nxt_java_Request_websocket(JNIEnv *env, jobject jreq, jobject jbuf,
    uint8_t opcode, uint8_t fin);

void nxt_java_Request_close(JNIEnv *env, jobject jreq);

#endif  /* _NXT_JAVA_REQUEST_H_INCLUDED_ */
