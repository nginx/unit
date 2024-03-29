#!/usr/bin/make

include ../version
include shasum.mak

VERSION ?= $(NXT_VERSION)
RELEASE ?= 1

default:
	@echo "available targets: dist rpm deb docker npm"

dist:
	rm -f unit-$(VERSION).tar.gz
	cd .. && git archive \
		--output pkg/unit-$(VERSION).tar.gz \
		--prefix unit-$(VERSION)/ \
		--worktree-attributes \
		$(VERSION) ./
	$(SHA512SUM) unit-$(VERSION).tar.gz > unit-$(VERSION).tar.gz.sha512

rpm:
	@cd rpm && VERSION=$(VERSION) RELEASE=$(RELEASE) make all

deb:
	@cd deb && VERSION=$(VERSION) RELEASE=$(RELEASE) make all

docker:
	@cd docker && VERSION=$(VERSION) RELEASE=$(RELEASE) make all

npm:
	@cd npm && VERSION=$(VERSION) RELEASE=$(RELEASE) make all

njs:
	@cd contrib && make .njs

clean:
	@cd rpm && make clean
	@cd deb && make clean
	@cd docker && make clean
	@cd npm && make clean
	@cd contrib && make clean
	rm -f unit-$(VERSION).tar.gz
	rm -f unit-$(VERSION).tar.gz.sha512

.PHONY: default rpm deb docker npm clean
