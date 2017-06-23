// +build !go1.7

/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

package nginext

import "C"
import "unsafe"

func getCBytes(p []byte) unsafe.Pointer {
	return unsafe.Pointer(C.CString(string(p))) // go <= 1.6
}
