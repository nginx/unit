#!/usr/bin/make

VERSION ?= $(shell grep 'define NXT_VERSION' ../src/nxt_main.h		\
		| sed -e 's/^.*"\(.*\)".*/\1/')

RELEASE ?= 1

default:
	@echo "available targets: rpm"

rpm:
	@cd rpm && VERSION=$(VERSION) RELEASE=$(RELEASE) make all

clean:
	@cd rpm && make clean

.PHONY: default rpm clean
