#!/usr/bin/make

VERSION ?= $(shell grep 'define NXT_VERSION' ../src/nxt_main.h		\
		| sed -e 's/^.*"\(.*\)".*/\1/')

RELEASE ?= 1

default:
	@echo "available targets: rpm deb docker"

rpm:
	@cd rpm && VERSION=$(VERSION) RELEASE=$(RELEASE) make all

deb:
	@cd deb && VERSION=$(VERSION) RELEASE=$(RELEASE) make all

docker:
	@cd docker && VERSION=$(VERSION) RELEASE=$(RELEASE) make all

clean:
	@cd rpm && make clean
	@cd deb && make clean
	@cd docker && make clean

.PHONY: default rpm deb docker clean
