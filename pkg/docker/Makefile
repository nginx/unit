#!/usr/bin/make

include ../../version
include ../shasum.mak

DEFAULT_VERSION := $(NXT_VERSION)

VERSION ?= $(DEFAULT_VERSION)
PATCHLEVEL ?= 1

MODULES ?= go jsc node perl php python ruby wasm

VARIANT ?= bullseye

VERSIONS_minimal ?=
CONTAINER_minimal ?= debian:$(VARIANT)-slim
CONFIGURE_minimal ?=
INSTALL_minimal ?=	version
RUN_minimal ?=		/bin/true
MODULE_PREBUILD_minimal ?= /bin/true

VERSIONS_go ?=		1.21 1.22
VARIANT_go ?=		$(VARIANT)
$(foreach goversion, $(VERSIONS_go), $(eval CONTAINER_go$(goversion) = golang:$(goversion)-$(VARIANT_go)))
CONFIGURE_go ?=		go --go-path=$$GOPATH
INSTALL_go ?=		go-install-src libunit-install
RUN_go ?=			/bin/true
MODULE_PREBUILD_go ?= /bin/true

VERSIONS_jsc ?=		11
VARIANT_jsc ?=		jammy
$(foreach jscversion, $(VERSIONS_jsc), $(eval CONTAINER_jsc$(jscversion) = eclipse-temurin:$(jscversion)-jdk-$(VARIANT_jsc)))
CONFIGURE_jsc ?=	java --jars=/usr/share/unit-jsc-common/
INSTALL_jsc ?=		java-shared-install java-install
RUN_jsc ?=	 		rm -rf /root/.m2
MODULE_PREBUILD_jsc ?= /bin/true

VERSIONS_node ?=	20 21
VARIANT_node ?=		$(VARIANT)
$(foreach nodeversion, $(VERSIONS_node), $(eval CONTAINER_node$(nodeversion) = node:$(nodeversion)-$(VARIANT_node)))
CONFIGURE_node ?=	nodejs --node-gyp=/usr/local/bin/node-gyp
INSTALL_node ?=		node node-install libunit-install
RUN_node ?=			rm -rf /root/.cache/ \&\& rm -rf /root/.npm
MODULE_PREBUILD_node ?=	npm -g install node-gyp

VERSIONS_perl ?=	5.36 5.38
VARIANT_perl ?=		$(VARIANT)
$(foreach perlversion, $(VERSIONS_perl), $(eval CONTAINER_perl$(perlversion) = perl:$(perlversion)-$(VARIANT_perl)))
CONFIGURE_perl ?=	perl
INSTALL_perl ?=		perl-install
RUN_perl ?=			/bin/true
MODULE_PREBUILD_perl ?=	/bin/true

VERSIONS_php ?=		8.2 8.3
VARIANT_php ?=		cli-$(VARIANT)
$(foreach phpversion, $(VERSIONS_php), $(eval CONTAINER_php$(phpversion) = php:$(phpversion)-$(VARIANT_php)))
CONFIGURE_php ?=	php
INSTALL_php ?=		php-install
RUN_php ?=			ldconfig
MODULE_PREBUILD_php ?= /bin/true

VERSIONS_python ?=  3.11 3.12
VARIANT_python ?=	$(VARIANT)
$(foreach pythonversion, $(VERSIONS_python), $(eval CONTAINER_python$(pythonversion) = python:$(pythonversion)-$(VARIANT_python)))
CONFIGURE_python ?=	python --config=/usr/local/bin/python3-config
INSTALL_python ?=	python3-install
RUN_python ?=		/bin/true
MODULE_PREBUILD_python ?= /bin/true

VERSIONS_ruby ?=	3.2 3.3
VARIANT_ruby ?=		$(VARIANT)
$(foreach rubyversion, $(VERSIONS_ruby), $(eval CONTAINER_ruby$(rubyversion) = ruby:$(rubyversion)-$(VARIANT_ruby)))
CONFIGURE_ruby ?=	ruby
INSTALL_ruby ?=		ruby-install
RUN_ruby ?=			gem install rack \&\& rm -rf /root/.local
MODULE_PREBUILD_ruby ?=	/bin/true

VERSIONS_wasm ?=
CONTAINER_wasm ?= debian:$(VARIANT)-slim
CONFIGURE_wasm ?= wasm --include-path=\`pwd\`/pkg/contrib/wasmtime/crates/c-api/include --lib-path=/usr/lib/\$$(dpkg-architecture -q DEB_HOST_MULTIARCH)/ \&\& ./configure wasm-wasi-component
INSTALL_wasm ?=   wasm-install wasm-wasi-component-install
RUN_wasm ?=       /bin/true

define MODULE_PREBUILD_wasm
apt-get install --no-install-recommends --no-install-suggests -y libclang-dev \\\n \
\ \ \ \&\& export RUST_VERSION=1.76.0 \\\n \
\ \ \ \&\& export RUSTUP_HOME=/usr/src/unit/rustup \\\n \
\ \ \ \&\& export CARGO_HOME=/usr/src/unit/cargo \\\n    \
\ \ \ \&\& export PATH=/usr/src/unit/cargo/bin:\$$PATH \\\n \
\ \ \ \&\& dpkgArch="\$$\(dpkg --print-architecture\)" \\\n \
\ \ \ \&\& case "\$${dpkgArch##*-}" in \\\n \
\ \ \ \ \ \ amd64\) rustArch="x86_64-unknown-linux-gnu"; rustupSha256="0b2f6c8f85a3d02fde2efc0ced4657869d73fccfce59defb4e8d29233116e6db" ;; \\\n \
\ \ \ \ \ \ arm64\) rustArch="aarch64-unknown-linux-gnu"; rustupSha256="673e336c81c65e6b16dcdede33f4cc9ed0f08bde1dbe7a935f113605292dc800" ;; \\\n \
\ \ \ \ \ \ *\) echo \>\&2 "unsupported architecture: \$${dpkgArch}"; exit 1 ;; \\\n \
\ \ \ \esac \\\n \
\ \ \ \&\& url="https://static.rust-lang.org/rustup/archive/1.26.0/\$${rustArch}/rustup-init" \\\n \
\ \ \ \&\& curl -L -O "\$$url" \\\n \
\ \ \ \&\& echo "\$${rustupSha256} *rustup-init" | sha256sum -c - \\\n \
\ \ \ \&\& chmod +x rustup-init \\\n \
\ \ \ \&\& ./rustup-init -y --no-modify-path --profile minimal --default-toolchain \$$RUST_VERSION --default-host \$${rustArch} \\\n \
\ \ \ \&\& rm rustup-init \\\n \
\ \ \ \&\& rustup --version \\\n \
\ \ \ \&\& cargo --version \\\n \
\ \ \ \&\& rustc --version \\\n \
\ \ \ \&\& make -C pkg/contrib .wasmtime \\\n \
\ \ \ \&\& install -pm 755 pkg/contrib/wasmtime/target/release/libwasmtime.so /usr/lib/\$$\(dpkg-architecture -q DEB_HOST_MULTIARCH\)/
endef

default:
	@echo "valid targets: all build dockerfiles library clean"

MODVERSIONS = $(foreach module, $(MODULES), $(foreach modversion, $(shell for v in $(VERSIONS_$(module)); do echo $$v; done | sort -r), $(module)$(modversion))) wasm minimal

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
			-e 's,@@MODULE_PREBUILD@@,$(MODULE_PREBUILD_$(call modname, $*)),g' \
			-e 's,@@MODULE@@,$*,g' \
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
		if [ "$$previous" = "$$modname" ]; then \
			echo "Tags: $(VERSION)-$$mod, $$mod"; \
		else \
			if [ "$$mod" = "minimal" ]; then \
				echo "Tags: $(VERSION)-$$mod, $${TAGS%, }, latest"; \
			else \
				echo "Tags: $(VERSION)-$$mod, $${TAGS%, }"; \
			fi; \
		fi; \
		echo "Architectures: amd64, arm64v8"; \
		echo "GitFetch: refs/heads/branches/packaging"; \
		echo "GitCommit: $(shell git describe --always --abbrev=0 HEAD)"; \
		echo "Directory: pkg/docker"; \
		echo "File: Dockerfile.$$mod"; \
		previous=$$(echo $$mod | tr -d '.0123456789-'); \
	done

diff: $(addprefix diff-, $(MODVERSIONS))

diff-%:
	@echo container-diff diff --type file daemon://$(CONTAINER_$*) daemon://unit:$(VERSION)-$*

all: $(addprefix Dockerfile., $(MODVERSIONS))

clean:
	rm -f Dockerfile.*

.PHONY: default build dockerfiles clean library
