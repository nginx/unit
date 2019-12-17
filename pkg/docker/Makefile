#!/usr/bin/make

include ../../version

DEFAULT_RELEASE := 1

VERSION ?= $(NXT_VERSION)
RELEASE ?= $(DEFAULT_RELEASE)
CODENAME := buster

UNIT_VERSION = $(VERSION)-$(RELEASE)~$(CODENAME)

MODULES = python2.7 python3.7 php7.3 go1.11-dev perl5.28 ruby2.5 \
          full minimal

MODULE_php7.3="unit=$${UNIT_VERSION} unit-php=$${UNIT_VERSION}"

MODULE_python2.7="unit=$${UNIT_VERSION} unit-python2.7=$${UNIT_VERSION}"

MODULE_python3.7="unit=$${UNIT_VERSION} unit-python3.7=$${UNIT_VERSION}"

MODULE_go1.11-dev="unit=$${UNIT_VERSION} unit-go1.11=$${UNIT_VERSION} gcc"

MODULE_perl5.28="unit=$${UNIT_VERSION} unit-perl=$${UNIT_VERSION}"

MODULE_ruby2.5="unit=$${UNIT_VERSION} unit-ruby=$${UNIT_VERSION}"

MODULE_full="unit=$${UNIT_VERSION} unit-php=$${UNIT_VERSION} unit-python2.7=$${UNIT_VERSION} unit-python3.7=$${UNIT_VERSION} unit-perl=$${UNIT_VERSION} unit-ruby=$${UNIT_VERSION}"

MODULE_minimal="unit=$${UNIT_VERSION}"

default:
	@echo "valid targets: all build dockerfiles push clean"

dockerfiles: $(addprefix Dockerfile., $(MODULES))
build: dockerfiles $(addprefix build-,$(MODULES))
push: build $(addprefix push-,$(MODULES)) latest

Dockerfile.%: ../../version
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
