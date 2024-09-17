.PHONY: install-packaging-deb
install-packaging-deb:
	$Q if ! command -v cargo-deb > /dev/null; then \
		$(CARGO) install --quiet cargo-deb; \
	fi

.PHONY: install-packaging-rpm
install-packaging-rpm:
	$Q if ! command -v cargo-generate-rpm > /dev/null; then \
		$(CARGO) install --quiet cargo-generate-rpm; \
	fi

## Installs tools needed for building distributable packages
.PHONY: install-packaging-tools
install-packaging-tools:
	$Q $(CARGO) install --quiet cargo-deb cargo-generate-rpm

target/dist:
	$Q mkdir -p $@

## Builds all packages for all targets
.PHONY: all-packages
all-packages: deb-packages rpm-packages gz-packages

target/dist/SHA256SUMS: target/dist
	$Q cd target/dist && $(CHECKSUM) * > SHA256SUMS

.PHONY: checksums
checksums: target/dist/SHA256SUMS ## Generates checksums for all packages

################################################################################
### Debian Packages
################################################################################

to_debian_arch = $(shell echo $(1) | \
	$(SED) -e 's/x86_64/amd64/' -e 's/aarch64/arm64/' -e 's/armv7/armhf/')
DEBIAN_PACKAGE_TARGETS := \
	$(foreach t, $(TARGETS), target/$(t)/debian/$(PACKAGE_NAME)_$(VERSION)_$(call to_debian_arch, $(firstword $(subst -,  , $(t)))).deb)

.ONESHELL: $(DEBIAN_PACKAGE_TARGETS)
.NOTPARALLEL: $(DEBIAN_PACKAGE_TARGETS)
$(DEBIAN_PACKAGE_TARGETS): $(TARGETS) target/man/$(OUTPUT_BINARY).1.gz target/dist
	$Q TARGET="$(word 2, $(subst /,  , $(dir $@)))"
	# Skip building debs for musl targets
	if echo "$(@)" | $(GREP) -q 'musl\|apple'; then \
		exit 0
	fi
	if [ ! -f "$(CURDIR)/$(@)" ]; then
		if [ -d "$(CURDIR)/target/release" ]; then \
			echo "$(M) removing existing release directory: $(CURDIR)/target/release"
			rm -rf "$(CURDIR)/target/release"
		fi
		echo "$(M) copying target architecture [$${TARGET}] build to target/release directory"
		cp -r "$(CURDIR)/target/$${TARGET}/release" "$(CURDIR)/target/release"
		echo "$(M) building debian package for target [$${TARGET}]: $(@)"
		$(CARGO) deb --package unitctl --no-build --target "$${TARGET}" --output "$(CURDIR)/$(@)"
		ln -f "$(CURDIR)/$(@)" "$(CURDIR)/target/dist/"
	fi

## Creates a debian package for the current platform
.PHONY: deb-packages
deb-packages: install-packaging-deb $(TARGETS) manpage $(DEBIAN_PACKAGE_TARGETS)

################################################################################
### RPM Packages
################################################################################

RPM_PACKAGE_TARGETS := $(foreach t, $(TARGETS), target/$(t)/generate-rpm/$(PACKAGE_NAME)_$(VERSION)_$(firstword $(subst -,  , $(t))).rpm)

.ONESHELL: $(RPM_PACKAGE_TARGETS)
.NOTPARALLEL: $(RPM_PACKAGE_TARGETS)
$(RPM_PACKAGE_TARGETS): $(TARGETS) target/man/$(OUTPUT_BINARY).1.gz target/dist
	$Q TARGET="$(word 2, $(subst /,  , $(dir $@)))"
	ARCH="$(firstword $(subst -,  , $(word 2, $(subst /,  , $(dir $@)))))"
	# Skip building rpms for musl targets
	if echo "$(@)" | $(GREP) -q 'musl\|apple'; then \
		exit 0
	fi
	if [ ! -f "$(CURDIR)/$(@)" ]; then
		if [ -d "$(CURDIR)/target/release" ]; then \
			echo "$(M) removing existing release directory: $(CURDIR)/target/release"
			rm -rf "$(CURDIR)/target/release"
		fi
		echo "$(M) copying target architecture [$${ARCH}] build to target/release directory"
		cp -r "$(CURDIR)/target/$${TARGET}/release" "$(CURDIR)/target/release"
		echo "$(M) building rpm package: $(@)"
		$(CARGO) generate-rpm --package unitctl --arch "$${ARCH}" --target "$${TARGET}" --output "$(CURDIR)/$(@)"
		rm -rf "$(CURDIR)/target/release"
		ln -f "$(CURDIR)/$(@)" "$(CURDIR)/target/dist/"
	fi

## Creates a rpm package for the current platform
.PHONY: rpm-packages
rpm-packages: install-packaging-rpm $(TARGETS) manpage $(RPM_PACKAGE_TARGETS)

################################################################################
### Homebrew Packages
################################################################################

## Modifies the homebrew formula to point to the latest release
.PHONY: homebrew-packages
.ONESHELL: homebrew-packages
homebrew-packages: target/dist/SHA256SUMS
ifdef NEW_VERSION
	VERSION=$(NEW_VERSION)
endif
	$Q \
	VERSION="$(VERSION)" \
    PACKAGE_NAME="$(PACKAGE_NAME)" \
    SRC_REPO="$(SRC_REPO)" \
	AARCH64_UNKNOWN_LINUX_GNU_SHA256="$$($(GREP) $(PACKAGE_NAME)_v$(VERSION)_aarch64-unknown-linux-gnu.tar.gz $(CURDIR)/target/dist/SHA256SUMS | cut -d ' ' -f 1)" \
	X86_64_UNKNOWN_LINUX_GNU_SHA256="$$($(GREP) $(PACKAGE_NAME)_v$(VERSION)_x86_64-unknown-linux-gnu.tar.gz $(CURDIR)/target/dist/SHA256SUMS | cut -d ' ' -f 1)" \
	X86_64_APPLE_DARWIN_SHA256="$$($(GREP) $(PACKAGE_NAME)_v$(VERSION)_x86_64-apple-darwin.tar.gz $(CURDIR)/target/dist/SHA256SUMS | cut -d ' ' -f 1)" \
    AARCH64_APPLE_DARWIN_SHA256="$$($(GREP) $(PACKAGE_NAME)_v$(VERSION)_aarch64-apple-darwin.tar.gz $(CURDIR)/target/dist/SHA256SUMS | cut -d ' ' -f 1)" \
	envsubst < $(CURDIR)/pkg/brew/$(PACKAGE_NAME).rb.template > $(CURDIR)/pkg/brew/$(PACKAGE_NAME).rb


################################################################################
### Tarball Packages
################################################################################

GZ_PACKAGE_TARGETS = $(foreach t, $(TARGETS), target/gz/$(t)/$(PACKAGE_NAME)_$(VERSION)_$(firstword $(subst -,  , $(t))).tar.gz)

.ONESHELL: $(GZ_PACKAGE_TARGETS)
$(GZ_PACKAGE_TARGETS): $(TARGETS) target/man/$(PACKAGE_NAME).1.gz target/dist
	$Q mkdir -p "$(CURDIR)/target/gz"
	TARGET="$(word 3, $(subst /,  , $(dir $@)))"
	PACKAGE="$(CURDIR)/target/gz/$(PACKAGE_NAME)_v$(VERSION)_$${TARGET}.tar.gz"
	if [ ! -f "$${PACKAGE}}" ]; then
		tar -cz -f $${PACKAGE} \
			-C $(CURDIR)/target/man $(PACKAGE_NAME).1.gz \
			-C $(CURDIR)/target/$${TARGET}/release $(PACKAGE_NAME) \
			-C $(CURDIR) LICENSE.txt
		ln -f "$${PACKAGE}" "$(CURDIR)/target/dist/"
	fi

## Creates a gzipped tarball all target platforms
.PHONE: gz-packages
gz-packages: $(GZ_PACKAGE_TARGETS)
