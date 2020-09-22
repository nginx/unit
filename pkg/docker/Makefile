#!/usr/bin/make

include ../../version
include ../shasum.mak

DEFAULT_RELEASE := 1

VERSION ?= $(NXT_VERSION)
RELEASE ?= $(DEFAULT_RELEASE)
CODENAME := buster

UNIT_VERSION = $(VERSION)-$(RELEASE)~$(CODENAME)

MODULES = python2.7 python3.7 php7.3 go1.11-dev perl5.28 ruby2.5 \
          jsc11 full minimal

MODULE_php7.3="unit=$${UNIT_VERSION} unit-php=$${UNIT_VERSION}"

MODULE_python2.7="unit=$${UNIT_VERSION} unit-python2.7=$${UNIT_VERSION}"

MODULE_python3.7="unit=$${UNIT_VERSION} unit-python3.7=$${UNIT_VERSION}"

MODULE_go1.11-dev="unit=$${UNIT_VERSION} unit-go=$${UNIT_VERSION} gcc"

MODULE_perl5.28="unit=$${UNIT_VERSION} unit-perl=$${UNIT_VERSION}"

MODULE_ruby2.5="unit=$${UNIT_VERSION} unit-ruby=$${UNIT_VERSION}"

MODULE_jsc11="unit=$${UNIT_VERSION} unit-jsc11=$${UNIT_VERSION}"

MODULE_full="unit=$${UNIT_VERSION} unit-php=$${UNIT_VERSION} unit-python2.7=$${UNIT_VERSION} unit-python3.7=$${UNIT_VERSION} unit-perl=$${UNIT_VERSION} unit-ruby=$${UNIT_VERSION} unit-jsc11=$${UNIT_VERSION}"

MODULE_minimal="unit=$${UNIT_VERSION}"

EXPORT_DIR := $(VERSION)

default:
	@echo "valid targets: all build dockerfiles push tag export clean"

dockerfiles: $(addprefix Dockerfile., $(MODULES))
build: $(addprefix build-,$(MODULES))
tag: $(addprefix tag-,$(MODULES))
push: $(addprefix push-,$(MODULES)) latest
export: $(addsuffix .tar.gz,$(addprefix $(EXPORT_DIR)/nginx-unit-$(VERSION)-,$(MODULES))) $(addsuffix .tar.gz.sha512, $(addprefix $(EXPORT_DIR)/nginx-unit-$(VERSION)-,$(MODULES)))

Dockerfile.%: ../../version
	@echo "===> Building $@"
	cat Dockerfile.tmpl | sed \
			-e 's,@@UNITPACKAGES@@,$(MODULE_$*),g' \
			-e 's,@@UNIT_VERSION@@,$(UNIT_VERSION),g' \
			> $@

build-%: Dockerfile.%
	docker build -t unit:$(VERSION)-$* -f Dockerfile.$* .

tag-%: build-%
	docker tag unit:$(VERSION)-$* nginx/unit:$(VERSION)-$*

push-%: tag-%
	docker push nginx/unit:$(VERSION)-$*

latest:
	docker tag nginx/unit:$(VERSION)-full nginx/unit:latest
	docker push nginx/unit:latest

$(EXPORT_DIR):
	mkdir -p $@

$(EXPORT_DIR)/nginx-unit-$(VERSION)-%.tar.gz: $(EXPORT_DIR) tag-%
	docker save nginx/unit:$(VERSION)-$* | gzip > $@

$(EXPORT_DIR)/nginx-unit-$(VERSION)-%.tar.gz.sha512: $(EXPORT_DIR)/nginx-unit-$(VERSION)-%.tar.gz
	$(SHA512SUM) $< | sed 's,$(EXPORT_DIR)/,,' > $@

all: $(addprefix Dockerfile., $(MODULES))

clean:
	rm -f $(addprefix Dockerfile., $(MODULES))
	rm -rf $(EXPORT_DIR)

.PHONY: default all build dockerfiles latest push tag export clean
