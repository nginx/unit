MAKE_MAJOR_VER    := $(shell echo $(MAKE_VERSION) | cut -d'.' -f1)

ifneq ($(shell test $(MAKE_MAJOR_VER) -gt 3; echo $$?),0)
$(error Make version $(MAKE_VERSION) not supported, please install GNU Make 4.x)
endif

GREP               ?= $(shell command -v ggrep 2> /dev/null || command -v grep 2> /dev/null)
SED                ?= $(shell command -v gsed 2> /dev/null || command -v sed 2> /dev/null)
AWK                ?= $(shell command -v gawk 2> /dev/null || command -v awk 2> /dev/null)
RUSTUP             ?= $(shell command -v rustup 2> /dev/null)
ifeq ($(RUSTUP),)
$(error Please install Rustup)
endif

RPM_ARCH           := $(shell uname -m)
VERSION            ?= $(shell $(GREP) -Po '^version\s+=\s+"\K.*?(?=")' $(CURDIR)/unitctl/Cargo.toml)
SRC_REPO           := https://github.com/nginxinc/unit-rust-sdk
DEFAULT_TARGET     ?= $(shell $(RUSTUP) toolchain list | $(GREP) '(default)' | cut -d' ' -f1 | cut -d- -f2-)
SHELL              := /bin/bash
OUTPUT_BINARY      ?= unitctl
PACKAGE_NAME       ?= unitctl
CARGO              ?= cargo
DOCKER             ?= docker
DOCKER_BUILD_FLAGS ?= --load
CHECKSUM           ?= sha256sum
OPENAPI_GENERATOR_VERSION ?= 6.6.0

# Define platform targets based off of the current host OS
# If running MacOS, then build for MacOS platform targets installed in rustup
# If running Linux, then build for Linux platform targets installed in rustup
ifeq ($(shell uname -s),Darwin)
	TARGETS       := $(sort $(shell $(RUSTUP) target list | \
						$(GREP) '(installed)' | \
						$(GREP) 'apple' | \
						cut -d' ' -f1))
else ifeq ($(shell uname -s),Linux)
	TARGETS       := $(sort $(shell $(RUSTUP) target list | \
						$(GREP) '(installed)' | \
						$(GREP) 'linux' | \
						cut -d' ' -f1))
else
	TARGETS       := $(DEFAULT_TARGET)
endif

RELEASE_BUILD_FLAGS ?= --quiet --release --bin $(OUTPUT_BINARY)

Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

.PHONY: help
help:
	@$(GREP) --no-filename -E '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		$(AWK) 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-28s\033[0m %s\n", $$1, $$2}' | \
		sort

.PHONY: clean
clean: ; $(info $(M) cleaning...)@ ## Cleanup everything
	$Q rm -rf $(CURDIR)/target

.PHONY: list-targets
list-targets: ## List all available platform targets
	$Q echo $(TARGETS) | $(SED) -e 's/ /\n/g'

.PHONY: all
all: $(TARGETS) ## Build all available platform targets [see: list-targets]

.PHONY: $(TARGETS)
.ONESHELL: $(TARGETS)
$(TARGETS): openapi-generate
	$Q if [ ! -f "$(CURDIR)/target/$(@)/release/$(OUTPUT_BINARY)" ]; then
		echo "$(M) building $(OUTPUT_BINARY) with flags [$(RELEASE_BUILD_FLAGS) --target $(@)]"
		$(CARGO) build $(RELEASE_BUILD_FLAGS) --target $@
	fi

target target/debug:
	$Q mkdir -p $@

.PHONY: debug
debug: target/debug/$(OUTPUT_BINARY)

target/debug/$(OUTPUT_BINARY): openapi-generate
	$Q echo "$(M) building $(OUTPUT_BINARY) in debug mode for the current platform"
	$Q $(CARGO) build --bin $(OUTPUT_BINARY)

.PHONY: release
release: target/release/$(OUTPUT_BINARY)

target/release/$(OUTPUT_BINARY): openapi-generate
	$Q echo "$(M) building $(OUTPUT_BINARY) in release mode for the current platform"
	$Q $(CARGO) build $(RELEASE_BUILD_FLAGS)

.PHONY: test
test: ## Run tests
	$Q $(CARGO) test

.ONESHELL: target/man/$(OUTPUT_BINARY).1.gz
target/man/$(OUTPUT_BINARY).1.gz:
	$Q $(info $(M) building distributable manpage)
	mkdir -p target/man
	$(SED) 's/%%VERSION%%/$(VERSION)/' \
		man/$(OUTPUT_BINARY).1 > $(CURDIR)/target/man/$(OUTPUT_BINARY).1
	gzip $(CURDIR)/target/man/$(OUTPUT_BINARY).1

target/gz:
	$Q mkdir -p target/gz

.PHONY: manpage
manpage: target/man/$(OUTPUT_BINARY).1.gz ## Builds man page

.openapi_cache:
	$Q mkdir -p $@

## Generate (or regenerate) UNIT API access code via a OpenAPI spec
.PHONY: openapi-generate
openapi-generate: .openapi_cache
	$Q if [ ! -f "$(CURDIR)/unit-openapi/src/models/mod.rs" ]; then
		echo "$(M) generating UNIT API access code via a OpenAPI spec"
		OPENAPI_GENERATOR_VERSION="$(OPENAPI_GENERATOR_VERSION)" \
		OPENAPI_GENERATOR_DOWNLOAD_CACHE_DIR="$(CURDIR)/.openapi_cache" \
		$(CURDIR)/build/openapi-generator-cli.sh \
			generate \
			--input-spec "$(CURDIR)/../../docs/unit-openapi.yaml" \
			--config "$(CURDIR)/openapi-config.json" \
			--template-dir "$(CURDIR)/unit-openapi/openapi-templates" \
			--output "$(CURDIR)/unit-openapi" \
			--generator-name rust
		echo "mod error;" >> "$(CURDIR)/unit-openapi/src/apis/mod.rs"
		$(SED) -i '1i #![allow(clippy::all)]' "$(CURDIR)/unit-openapi/src/lib.rs"
		$(CARGO) fmt
	fi

.PHONY: openapi-clean
openapi-clean: ## Clean up generated OpenAPI files
	$Q $(info $(M) cleaning up generated OpenAPI documentation)
	$Q rm -rf "$(CURDIR)/unit-openapi/docs/*"
	$Q $(info $(M) cleaning up generated OpenAPI api code)
	$Q find "$(CURDIR)/unit-openapi/src/apis" \
		! -name 'error.rs' -type f -exec rm -f {} +
	$Q $(info $(M) cleaning up generated OpenAPI models code)
	$Q rm -rf "$(CURDIR)/unit-openapi/src/models/*"

include $(CURDIR)/build/package.mk
include $(CURDIR)/build/container.mk
include $(CURDIR)/build/release.mk
include $(CURDIR)/build/github.mk
