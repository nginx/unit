#!/usr/bin/make

include ../../version
include ../shasum.mak

DEFAULT_VERSION := $(NXT_VERSION)

VERSION ?= $(DEFAULT_VERSION)

EXPORT_DIR := $(VERSION)

MODULES ?= go jsc node perl php python ruby minimal

VERSION_minimal ?=
CONTAINER_minimal ?= debian:buster-slim
CONFIGURE_minimal ?=
INSTALL_minimal ?=	version
define COPY_minimal
endef

VERSION_go ?=		1.15
CONTAINER_go ?=		golang:$(VERSION_go)
CONFIGURE_go ?=		go --go-path=$$GOPATH
INSTALL_go ?=		go-install-src libunit-install
define COPY_go
COPY --from=BUILDER /usr/lib/x86_64-linux-gnu/libunit.a /usr/lib/x86_64-linux-gnu/\n\$
COPY --from=BUILDER /usr/include/nxt_* /usr/include/\n\$
COPY --from=BUILDER /go/src/ /go/src/
endef

VERSION_jsc ?=		11
CONTAINER_jsc ?=	openjdk:$(VERSION_jsc)-jdk
CONFIGURE_jsc ?=	java --jars=/usr/share/unit-jsc-common/
INSTALL_jsc ?=		java-shared-install java-install
COPY_jsc =	 		COPY --from=BUILDER /usr/share/unit-jsc-common/ /usr/share/unit-jsc-common/

VERSION_node ?=		15
CONTAINER_node ?=	node:$(VERSION_node)
CONFIGURE_node ?=	nodejs --node-gyp=/usr/local/lib/node_modules/npm/bin/node-gyp-bin/node-gyp
INSTALL_node ?=		node node-install libunit-install
define COPY_node
COPY --from=BUILDER /usr/lib/x86_64-linux-gnu/libunit.a /usr/lib/x86_64-linux-gnu/\n\$
COPY --from=BUILDER /usr/include/nxt_* /usr/include/\n\$
COPY --from=BUILDER /usr/local/lib/node_modules/unit-http/ /usr/local/lib/node_modules/unit-http/
endef

VERSION_perl ?=		5.32
CONTAINER_perl ?=	perl:$(VERSION_perl)
CONFIGURE_perl ?=	perl
INSTALL_perl ?=		perl-install
COPY_perl =

VERSION_php ?=		8.0
CONTAINER_php ?=	php:$(VERSION_php)-cli
CONFIGURE_php ?=	php
INSTALL_php ?=		php-install
COPY_php =			RUN ldconfig

VERSION_python ?=	3.9
CONTAINER_python ?=	python:$(VERSION_python)
CONFIGURE_python ?=	python --config=/usr/local/bin/python3-config
INSTALL_python ?=	python3-install
COPY_python =

VERSION_ruby ?=		2.7
CONTAINER_ruby ?=	ruby:$(VERSION_ruby)
CONFIGURE_ruby ?=	ruby
INSTALL_ruby ?=		ruby-install
COPY_ruby =			RUN gem install rack

default:
	@echo "valid targets: all build dockerfiles push tag export clean"

MODVERSIONS = $(foreach module,$(MODULES),$(module)$(VERSION_$(module)))

modname = $(shell echo $1 | /usr/bin/tr -d '.01234567890-')

dockerfiles: $(addprefix Dockerfile., $(MODVERSIONS))
build: $(addprefix build-,$(MODVERSIONS))
tag: $(addprefix tag-,$(MODVERSIONS))
push: $(addprefix push-,$(MODVERSIONS))
export: $(addsuffix .tar.gz,$(addprefix $(EXPORT_DIR)/nginx-unit-$(VERSION)-,$(MODVERSIONS))) $(addsuffix .tar.gz.sha512, $(addprefix $(EXPORT_DIR)/nginx-unit-$(VERSION)-,$(MODVERSIONS)))

Dockerfile.%: ../../version
	@echo "===> Building $@"
	cat template.Dockerfile | sed \
			-e 's,@@VERSION@@,$(VERSION),g' \
			-e 's,@@CONTAINER@@,$(CONTAINER_$(call modname, $*)),g' \
			-e 's,@@CONFIGURE@@,$(CONFIGURE_$(call modname, $*)),g' \
			-e 's,@@INSTALL@@,$(INSTALL_$(call modname, $*)),g' \
			-e 's,@@COPY@@,$(COPY_$(call modname, $*)),g' \
			> $@

build-%: Dockerfile.%
	docker pull $(CONTAINER_$(call modname, $*))
	docker build --no-cache -t unit:$(VERSION)-$* -f Dockerfile.$* .

tag-%: build-%
	docker tag unit:$(VERSION)-$* nginx/unit:$(VERSION)-$*
	docker tag unit:$(VERSION)-$* public.ecr.aws/nginx/unit:$(VERSION)-$*

push-%: tag-%
	docker push nginx/unit:$(VERSION)-$*
	docker push public.ecr.aws/nginx/unit:$(VERSION)-$*

$(EXPORT_DIR):
	mkdir -p $@

$(EXPORT_DIR)/nginx-unit-$(VERSION)-%.tar.gz: $(EXPORT_DIR) tag-%
	docker save nginx/unit:$(VERSION)-$* | gzip > $@

$(EXPORT_DIR)/nginx-unit-$(VERSION)-%.tar.gz.sha512: $(EXPORT_DIR)/nginx-unit-$(VERSION)-%.tar.gz
	$(SHA512SUM) $< | sed 's,$(EXPORT_DIR)/,,' > $@

all: $(addprefix Dockerfile., $(MODVERSIONS))

clean:
	rm -f $(addprefix Dockerfile., $(MODVERSIONS))
	rm -rf $(EXPORT_DIR)

.PHONY: default build dockerfiles push tag export clean
