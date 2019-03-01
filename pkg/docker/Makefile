#!/usr/bin/make

include ../../version

DEFAULT_RELEASE := 1

VERSION ?= $(NXT_VERSION)
RELEASE ?= $(DEFAULT_RELEASE)
CODENAME := stretch

UNIT_VERSION = $(VERSION)-$(RELEASE)~$(CODENAME)

MODULES = python2.7 python3.5 php7.0 go1.7-dev go1.8-dev perl5.24 ruby2.3 \
          full minimal

MODULE_php7.0="unit=$${UNIT_VERSION} unit-php=$${UNIT_VERSION}"

MODULE_python2.7="unit=$${UNIT_VERSION} unit-python2.7=$${UNIT_VERSION}"

MODULE_python3.5="unit=$${UNIT_VERSION} unit-python3.5=$${UNIT_VERSION}"

MODULE_go1.7-dev="unit=$${UNIT_VERSION} unit-go1.7=$${UNIT_VERSION} gcc"

MODULE_go1.8-dev="unit=$${UNIT_VERSION} unit-go1.8=$${UNIT_VERSION} gcc"

MODULE_perl5.24="unit=$${UNIT_VERSION} unit-perl=$${UNIT_VERSION}"

MODULE_ruby2.3="unit=$${UNIT_VERSION} unit-ruby=$${UNIT_VERSION}"

MODULE_full="unit=$${UNIT_VERSION} unit-php=$${UNIT_VERSION} unit-python2.7=$${UNIT_VERSION} unit-python3.5=$${UNIT_VERSION} unit-perl=$${UNIT_VERSION} unit-ruby=$${UNIT_VERSION}"

MODULE_minimal="unit=$${UNIT_VERSION}"

export \
		MODULE_python2.7 \
 		MODULE_python3.5 \
 		MODULE_php7.0 \
 		MODULE_go1.7-dev \
 		MODULE_go1.8-dev \
 		MODULE_perl5.24 \
 		MODULE_ruby2.3 \
		MODULE_full \
 		MODULE_minimal

default:
	@echo "valid targets: all build dockerfiles push clean"

dockerfiles: $(addprefix Dockerfile., $(MODULES))
build: dockerfiles $(addprefix build-,$(MODULES))
push: build $(addprefix push-,$(MODULES)) latest

Dockerfile.%: ../../src/nxt_main.h
	@echo "===> Building $@"
	cat Dockerfile.tmpl | sed \
			-e 's,@@UNITPACKAGES@@,$(MODULE_$*),g' \
			-e 's,@@UNIT_VERSION@@,$(UNIT_VERSION),g' \
			> $@

build-%: Dockerfile.%
	docker build -t unit:$(VERSION)-$* -f Dockerfile.$* .

push-%:
	docker tag unit:$(VERSION)-$* nginx/unit:$(VERSION)-$*
	docker push nginx/unit:$(VERSION)-$*

latest:
	docker tag nginx/unit:$(VERSION)-full nginx/unit:latest
	docker push nginx/unit:latest

all: $(addprefix Dockerfile., $(MODULES))

clean:
	rm -f $(addprefix Dockerfile., $(MODULES))

.PHONY: default all build dockerfiles latest push clean
