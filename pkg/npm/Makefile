#!/usr/bin/make

include ../../version

VERSION ?= $(NXT_VERSION)
VERNUM ?= $(NXT_VERNUM)
NPM ?= npm

default:
	@echo "valid targets: all publish clean"

copy:
	cp -rp ../../src/nodejs/unit-http .
	echo '#define NXT_NODE_VERNUM ${VERNUM}' > unit-http/version.h
	mv unit-http/binding_pub.gyp unit-http/binding.gyp
	sed -e 's/"version"\s*:.*/"version": "${VERSION}.0",/' \
		unit-http/package.json > unit-http/package.json.tmp
	mv unit-http/package.json.tmp unit-http/package.json

publish: copy
	cd unit-http && $(NPM) publish

all: copy

clean:
	rm -rf unit-http

.PHONY: default all copy publish clean
