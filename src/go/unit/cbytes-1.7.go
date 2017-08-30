// +build go1.7

/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

package unit

import "C"
import "unsafe"

func getCBytes(p []byte) unsafe.Pointer {
	return C.CBytes(p) // go >= 1.7
}
