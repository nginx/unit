#!/usr/bin/make

include ../../version
include ../shasum.mak

DEFAULT_VERSION := $(NXT_VERSION)

VERSION ?= $(DEFAULT_VERSION)
PATCHLEVEL ?= 1

EXPORT_DIR := $(VERSION)

MODULES ?= go jsc node perl php python ruby minimal

VERSION_minimal ?=
CONTAINER_minimal ?= debian:bullseye-slim
CONFIGURE_minimal ?=
INSTALL_minimal ?=	version
RUN_minimal ?=		/bin/true

VERSION_go ?=		1.20
CONTAINER_go ?=		golang:$(VERSION_go)
CONFIGURE_go ?=		go --go-path=$$GOPATH
INSTALL_go ?=		go-install-src libunit-install
RUN_go ?=			/bin/true

VERSION_jsc ?=		11
CONTAINER_jsc ?=	eclipse-temurin:$(VERSION_jsc)-jdk
CONFIGURE_jsc ?=	java --jars=/usr/share/unit-jsc-common/
INSTALL_jsc ?=		java-shared-install java-install
RUN_jsc ?=	 		/bin/true

VERSION_node ?=		18
CONTAINER_node ?=	node:$(VERSION_node)
CONFIGURE_node ?=	nodejs --node-gyp=/usr/local/lib/node_modules/npm/bin/node-gyp-bin/node-gyp
INSTALL_node ?=		node node-install libunit-install
RUN_node ?=			/bin/true

VERSION_perl ?=		5.36
CONTAINER_perl ?=	perl:$(VERSION_perl)
CONFIGURE_perl ?=	perl
INSTALL_perl ?=		perl-install
RUN_perl ?=			/bin/true

VERSION_php ?=		8.2
CONTAINER_php ?=	php:$(VERSION_php)-cli
CONFIGURE_php ?=	php
INSTALL_php ?=		php-install
RUN_php ?=			ldconfig

VERSION_python ?=	3.11
CONTAINER_python ?=	python:$(VERSION_python)
CONFIGURE_python ?=	python --config=/usr/local/bin/python3-config
INSTALL_python ?=	python3-install
RUN_python ?=		/bin/true

VERSION_ruby ?=		3.2
CONTAINER_ruby ?=	ruby:$(VERSION_ruby)
CONFIGURE_ruby ?=	ruby
INSTALL_ruby ?=		ruby-install
RUN_ruby ?=			gem install rack

default:
	@echo "valid targets: all build dockerfiles clean"

MODVERSIONS = $(foreach module,$(MODULES),$(module)$(VERSION_$(module)))

modname = $(shell echo $1 | /usr/bin/tr -d '.01234567890-')

dockerfiles: $(addprefix Dockerfile., $(MODVERSIONS))
build: $(addprefix build-,$(MODVERSIONS))

Dockerfile.%: ../../version template.Dockerfile
	@echo "===> Building $@"
	cat template.Dockerfile | sed \
			-e 's,@@VERSION@@,$(VERSION),g' \
			-e 's,@@PATCHLEVEL@@,$(PATCHLEVEL),g' \
			-e 's,@@CONTAINER@@,$(CONTAINER_$(call modname, $*)),g' \
			-e 's,@@CONFIGURE@@,$(CONFIGURE_$(call modname, $*)),g' \
			-e 's,@@INSTALL@@,$(INSTALL_$(call modname, $*)),g' \
			-e 's,@@RUN@@,$(RUN_$(call modname, $*)),g' \
			> $@

build-%: Dockerfile.%
	docker pull $(CONTAINER_$(call modname, $*))
	docker build --no-cache -t unit:$(VERSION)-$* -f Dockerfile.$* .

library:
	@echo "# this file is generated via https://github.com/nginx/unit/blob/$(shell git describe --always --abbrev=0 HEAD)/pkg/docker/Makefile"
	@echo ""
	@echo "Maintainers: Unit Docker Maintainers <docker-maint@nginx.com> (@nginx)"
	@echo "GitRepo: https://github.com/nginx/unit.git"
	@for mod in $(MODVERSIONS); do \
		echo ""; \
		TAGS="$$mod $${mod%%.*} $$( echo $$mod | tr -d '.0123456789-' )"; \
		TAGS="$$(echo $$TAGS | tr " " "\n" | sort -u -r | tr "\n" "," | sed "s/,/, /g")"; \
		echo "Tags: $(VERSION)-$$mod, $${TAGS%, }"; \
		echo "Architectures: amd64, arm64v8"; \
		echo "GitFetch: refs/heads/branches/packaging"; \
		echo "GitCommit: $(shell git describe --always --abbrev=0 HEAD)"; \
		echo "Directory: pkg/docker"; \
		echo "File: Dockerfile.$$mod"; \
	done

all: $(addprefix Dockerfile., $(MODVERSIONS))

clean:
	rm -f $(addprefix Dockerfile., $(MODVERSIONS))
	rm -rf $(EXPORT_DIR)

.PHONY: default build dockerfiles clean library
