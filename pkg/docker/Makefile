#!/usr/bin/make

include ../../version
include ../shasum.mak

DEFAULT_VERSION := $(NXT_VERSION)

VERSION ?= $(DEFAULT_VERSION)
PATCHLEVEL ?= 1

MODULES ?= go jsc node perl php python ruby

VARIANT ?= bullseye

VERSIONS_minimal ?=
CONTAINER_minimal ?= debian:$(VARIANT)-slim
CONFIGURE_minimal ?=
INSTALL_minimal ?=	version
RUN_minimal ?=		/bin/true

VERSIONS_go ?=		1.20
VARIANT_go ?=		$(VARIANT)
$(foreach goversion, $(VERSIONS_go), $(eval CONTAINER_go$(goversion) = golang:$(goversion)-$(VARIANT_go)))
CONFIGURE_go ?=		go --go-path=$$GOPATH
INSTALL_go ?=		go-install-src libunit-install
RUN_go ?=			/bin/true

VERSIONS_jsc ?=		11
VARIANT_jsc ?=		jammy
$(foreach jscversion, $(VERSIONS_jsc), $(eval CONTAINER_jsc$(jscversion) = eclipse-temurin:$(jscversion)-jdk-$(VARIANT_jsc)))
CONFIGURE_jsc ?=	java --jars=/usr/share/unit-jsc-common/
INSTALL_jsc ?=		java-shared-install java-install
RUN_jsc ?=	 		/bin/true

VERSIONS_node ?=	18
VARIANT_node ?=		$(VARIANT)
$(foreach nodeversion, $(VERSIONS_node), $(eval CONTAINER_node$(nodeversion) = node:$(nodeversion)-$(VARIANT_node)))
CONFIGURE_node ?=	nodejs --node-gyp=/usr/local/lib/node_modules/npm/bin/node-gyp-bin/node-gyp
INSTALL_node ?=		node node-install libunit-install
RUN_node ?=			/bin/true

VERSIONS_perl ?=	5.36
VARIANT_perl ?=		$(VARIANT)
$(foreach perlversion, $(VERSIONS_perl), $(eval CONTAINER_perl$(perlversion) = perl:$(perlversion)-$(VARIANT_perl)))
CONFIGURE_perl ?=	perl
INSTALL_perl ?=		perl-install
RUN_perl ?=			/bin/true

VERSIONS_php ?=		8.2
VARIANT_php ?=		cli-$(VARIANT)
$(foreach phpversion, $(VERSIONS_php), $(eval CONTAINER_php$(phpversion) = php:$(phpversion)-$(VARIANT_php)))
CONFIGURE_php ?=	php
INSTALL_php ?=		php-install
RUN_php ?=			ldconfig

VERSIONS_python ?=  3.11
VARIANT_python ?=	$(VARIANT)
$(foreach pythonversion, $(VERSIONS_python), $(eval CONTAINER_python$(pythonversion) = python:$(pythonversion)-$(VARIANT_python)))
CONFIGURE_python ?=	python --config=/usr/local/bin/python3-config
INSTALL_python ?=	python3-install
RUN_python ?=		/bin/true

VERSIONS_ruby ?=	3.2
VARIANT_ruby ?=		$(VARIANT)
$(foreach rubyversion, $(VERSIONS_ruby), $(eval CONTAINER_ruby$(rubyversion) = ruby:$(rubyversion)-$(VARIANT_ruby)))
CONFIGURE_ruby ?=	ruby
INSTALL_ruby ?=		ruby-install
RUN_ruby ?=			gem install rack

default:
	@echo "valid targets: all build dockerfiles library clean"

MODVERSIONS = $(foreach module, $(MODULES), $(foreach modversion, $(shell for v in $(VERSIONS_$(module)); do echo $$v; done | sort -r), $(module)$(modversion))) minimal

modname = $(shell echo $1 | /usr/bin/tr -d '.01234567890-')

dockerfiles: $(addprefix Dockerfile., $(MODVERSIONS))
build: $(addprefix build-, $(MODVERSIONS))

Dockerfile.%: ../../version template.Dockerfile
	@echo "===> Building $@"
	cat template.Dockerfile | sed \
			-e 's,@@VERSION@@,$(VERSION),g' \
			-e 's,@@PATCHLEVEL@@,$(PATCHLEVEL),g' \
			-e 's,@@CONTAINER@@,$(CONTAINER_$*),g' \
			-e 's,@@CONFIGURE@@,$(CONFIGURE_$(call modname, $*)),g' \
			-e 's,@@INSTALL@@,$(INSTALL_$(call modname, $*)),g' \
			-e 's,@@RUN@@,$(RUN_$(call modname, $*)),g' \
			> $@

build-%: Dockerfile.%
	docker pull $(CONTAINER_$*)
	docker build --no-cache -t unit:$(VERSION)-$* -f Dockerfile.$* .

library:
	@echo "# this file is generated via https://github.com/nginx/unit/blob/$(shell git describe --always --abbrev=0 HEAD)/pkg/docker/Makefile"
	@echo ""
	@echo "Maintainers: Unit Docker Maintainers <docker-maint@nginx.com> (@nginx)"
	@echo "GitRepo: https://github.com/nginx/unit.git"
	@previous=""; \
	 for mod in $(MODVERSIONS); do \
		echo ""; \
		modname="$$( echo $$mod | tr -d '.0123456789-' )"; \
		TAGS="$$mod $${mod%%.*} $$modname" ; \
		TAGS="$$(echo $$TAGS | tr " " "\n" | sort -u -r | tr "\n" "," | sed "s/,/, /g")"; \
		if [ "$$previous" == "$$modname" ]; then \
			echo "Tags: $(VERSION)-$$mod, $$mod"; \
		else \
			echo "Tags: $(VERSION)-$$mod, $${TAGS%, }"; \
		fi; \
		echo "Architectures: amd64, arm64v8"; \
		echo "GitFetch: refs/heads/branches/packaging"; \
		echo "GitCommit: $(shell git describe --always --abbrev=0 HEAD)"; \
		echo "Directory: pkg/docker"; \
		echo "File: Dockerfile.$$mod"; \
		previous=$$(echo $$mod | tr -d '.0123456789-'); \
	done

all: $(addprefix Dockerfile., $(MODVERSIONS))

clean:
	rm -f Dockerfile.*

.PHONY: default build dockerfiles clean library
