/*
 * Copyright (C) NGINX, Inc.
 */

package unit

import (
	"sync"
)

type observable struct {
	sync.Mutex
	observers []chan int
}

func (o *observable) attach(c chan int) {
	o.Lock()
	defer o.Unlock()

	o.observers = append(o.observers, c)
}

func (o *observable) notify(e int) {
	o.Lock()
	defer o.Unlock()

	for _, v := range o.observers {
		v <- e
	}

	o.observers = nil
}
