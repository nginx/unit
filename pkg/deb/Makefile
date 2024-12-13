#!/usr/bin/make

include ../../version

DEFAULT_VERSION := $(NXT_VERSION)
DEFAULT_RELEASE := 1

VERSION ?= $(DEFAULT_VERSION)
RELEASE ?= $(DEFAULT_RELEASE)

PACKAGE_VENDOR = NGINX Packaging <nginx-packaging@f5.com>

SRCDIR=	unit-$(VERSION)

CODENAME = $(shell lsb_release -cs)

BUILD_DEPENDS_unit = build-essential debhelper devscripts fakeroot libxml2-utils lintian lsb-release xsltproc libssl-dev clang llvm
BUILD_DEPENDS = $(BUILD_DEPENDS_unit)

MODULES=

# Ubuntu 24.04
ifeq ($(CODENAME),noble)
include Makefile.php
include Makefile.python312
include Makefile.go
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc11
include Makefile.jsc17
include Makefile.jsc21
include Makefile.wasm
endif

# Ubuntu 23.10
ifeq ($(CODENAME),mantic)
include Makefile.php
include Makefile.python311
include Makefile.python312
include Makefile.go
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc11
include Makefile.jsc17
include Makefile.jsc19
include Makefile.jsc20
include Makefile.jsc21
include Makefile.wasm
endif

# Ubuntu 22.04
ifeq ($(CODENAME),jammy)
include Makefile.php
include Makefile.python27
include Makefile.python310
include Makefile.go
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc11
include Makefile.jsc17
include Makefile.jsc18
include Makefile.wasm
endif

# Ubuntu 20.04
ifeq ($(CODENAME),focal)
include Makefile.php
include Makefile.python27
include Makefile.python38
include Makefile.go
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc11
include Makefile.wasm
endif

# Debian 12
ifeq ($(CODENAME),bookworm)
include Makefile.php
include Makefile.python311
include Makefile.go
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc17
include Makefile.wasm
endif

# Debian 11
ifeq ($(CODENAME),bullseye)
include Makefile.php
include Makefile.python27
include Makefile.python39
include Makefile.go
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc11
include Makefile.wasm
endif

CONFIGURE_ARGS_COMMON=\
	--prefix=/usr \
	--statedir=/var/lib/unit \
	--control="unix:/var/run/control.unit.sock" \
	--runstatedir=/var/run \
	--pid=/var/run/unit.pid \
	--logdir=/var/log \
	--log=/var/log/unit.log \
	--tmpdir=/var/tmp \
	--user=unit \
	--group=unit \
	--tests \
	--openssl

CONFIGURE_ARGS=\
	$(CONFIGURE_ARGS_COMMON) \
	--njs \
	--otel

export CR=\\n

default:
	@echo "valid targets: all modules unit $(addprefix unit-, $(MODULES)) test test-debug clean"

all: check-build-depends-all unit modules

modules: $(addprefix unit-, $(MODULES))

check-build-depends-%:
	@{ \
	case "$*" in \
		all) pkgs="$(BUILD_DEPENDS)" ;; \
		unit) pkgs="$(BUILD_DEPENDS_unit)" ;; \
		*) pkgs="$(BUILD_DEPENDS_unit) $(BUILD_DEPENDS_$*)" ;; \
	esac ; \
	not_installed= ; \
	for pkg in $${pkgs}; do \
		i=$$(dpkg-query -f '$${db:Status-Status}' -W $${pkg}:$$(dpkg --print-architecture) 2>/dev/null) ; \
		if [ $$? -ne 0 -o "$${i}" != "installed" ]; then \
			i=$$(dpkg-query -f '$${db:Status-Status}' -W $${pkg}:all 2>/dev/null) ; \
			if [ $$? -ne 0 -o "$${i}" != "installed" ]; then \
				not_installed="$${not_installed} $${pkg}" ; \
			fi; \
		fi ; \
	done ; \
	if test -n "$${not_installed}" ; then \
		echo "" >&2 ; \
		echo "The following packages are required in order to proceed:" >&2 ; \
		echo "" >&2 ; \
		echo $${not_installed} >&2 ; \
		echo "" >&2 ; \
		exit 1 ; \
	fi \
	}
	touch $@

debuild/$(SRCDIR)/debian:
	@{ \
	set -e ; \
	mkdir -p debuild/$(SRCDIR) ; \
	cp -pr debian debuild/$(SRCDIR) ; \
	echo '11' > debuild/$(SRCDIR)/debian/compat ; \
	mkdir -p debuild/$(SRCDIR)/debian/source ; \
	echo '3.0 (quilt)' > debuild/$(SRCDIR)/debian/source/format ; \
	cat debian/control.in | sed \
		-e "s#%%PACKAGE_VENDOR%%#$(PACKAGE_VENDOR)#g" \
		-e "s#%%UNIT_VERSION%%#$(VERSION)#g" \
	> debuild/$(SRCDIR)/debian/control ; \
        cat debian/rules.in | sed \
                -e "s#%%CONFIGURE_ARGS%%#$(CONFIGURE_ARGS)#g" \
        > debuild/$(SRCDIR)/debian/rules ; \
	chmod +x debuild/$(SRCDIR)/debian/rules ; \
	}

debuild/$(SRCDIR)/debian/changelog: ../../docs/changes.xml | debuild/$(SRCDIR)/debian
	cd ../../docs && make ../build/unit.deb-changelog
ifneq ($(DEFAULT_VERSION)$(DEFAULT_RELEASE), $(VERSION)$(RELEASE))
	cat ../../build/unit.deb-changelog | sed \
		-e "s/unit ($(DEFAULT_VERSION)-$(DEFAULT_RELEASE)~/unit ($(VERSION)-$(RELEASE)~/" \
		-e "s#%%CODENAME%%#$(CODENAME)#g" \
		> debuild/$(SRCDIR)/debian/changelog
else
	cat ../../build/unit.deb-changelog | sed \
		-e "s#%%CODENAME%%#$(CODENAME)#g" \
		> debuild/$(SRCDIR)/debian/changelog
endif

debuild/unit_$(VERSION).orig.tar.gz: | debuild/$(SRCDIR)/debian
	cd ../.. && tar -czf pkg/deb/debuild/$(SRCDIR).tar.gz \
		--transform "s#^#$(SRCDIR)/#" \
		LICENSE NOTICE CHANGES README.md CONTRIBUTING.md configure auto src \
		test tools version go pkg/contrib docs/man/man8/unitd.8.in
	mv debuild/$(SRCDIR).tar.gz debuild/unit_$(VERSION).orig.tar.gz
	cd debuild && tar zxf unit_$(VERSION).orig.tar.gz

unit: check-build-depends-unit debuild/unit_$(VERSION).orig.tar.gz debuild/$(SRCDIR)/debian/changelog
	@echo "===> Building $@ package"
	cd debuild/$(SRCDIR) && debuild --preserve-envvar PATH --preserve-envvar RUSTUP_HOME -us -uc
	mkdir -p debs
	find debuild/ -maxdepth 1 -type f -exec cp {} debs/ \;
	ln -s debuild/$(SRCDIR)/build $@

debuild-%: debuild/unit_$(VERSION).orig.tar.gz ../../docs/changes.xml
	mkdir $@
	cp debuild/unit_$(VERSION).orig.tar.gz debuild-$*/unit-$(MODULE_SUFFIX_$*)_$(VERSION).orig.tar.gz
	cd $@ && tar zxf unit-$(MODULE_SUFFIX_$*)_$(VERSION).orig.tar.gz
	mkdir $@/$(SRCDIR)/debian
	echo '11' > $@/$(SRCDIR)/debian/compat
	mkdir $@/$(SRCDIR)/debian/source
	echo '3.0 (quilt)' > $@/$(SRCDIR)/debian/source/format
	cd ../../docs && make ../build/unit-$(MODULE_SUFFIX_$*).deb-changelog
ifneq ($(DEFAULT_VERSION)$(DEFAULT_RELEASE), $(VERSION)$(RELEASE))
	cat ../../build/unit-$(MODULE_SUFFIX_$*).deb-changelog | sed \
		-e "s/unit-$* ($(DEFAULT_VERSION)-$(DEFAULT_RELEASE)~/unit-$* ($(VERSION)-$(RELEASE)~/" \
		-e "s#%%CODENAME%%#$(CODENAME)#g" \
		> $@/$(SRCDIR)/debian/changelog
else
	cat ../../build/unit-$(MODULE_SUFFIX_$*).deb-changelog | sed \
		-e "s#%%CODENAME%%#$(CODENAME)#g" \
		> $@/$(SRCDIR)/debian/changelog
endif
	if [ -f debian.module/copyright.unit-$(MODULE_SUFFIX_$*) ]; then \
		cp debian.module/copyright.unit-$(MODULE_SUFFIX_$*) debuild-$*/$(SRCDIR)/debian/copyright ; \
	else \
		cp debian/copyright debuild-$*/$(SRCDIR)/debian/ ; \
	fi
	@{ \
	set -e ; \
	for src in $(MODULE_SOURCES_$*); do \
		cp debian.module/$${src} $@/$(SRCDIR)/debian/ ; \
	done ; \
	definitions=`echo "$$MODULE_DEFINITIONS_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	prebuild=`echo "$$MODULE_PREBUILD_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	preinstall=`echo "$$MODULE_PREINSTALL_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	postinstall=`echo "$$MODULE_POSTINSTALL_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	post=`echo "$$MODULE_POST_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	cat debian.module/$(if $(MODULE_NOARCH_$*),control-noarch.in,control.in) | sed \
                -e "s#%%NAME%%#unit-$(MODULE_SUFFIX_$*)#g" \
                -e "s#%%SUMMARY%%#$(MODULE_SUMMARY_$*)#g" \
                -e "s#%%CODENAME%%#$(CODENAME)#g" \
                -e "s#%%UNIT_VERSION%%#$(VERSION)#g" \
                -e "s#%%UNIT_RELEASE%%#$(RELEASE)#g" \
                -e "s#%%VERSION%%#$(MODULE_VERSION_$*)#g" \
                -e "s#%%RELEASE%%#$(MODULE_RELEASE_$*)#g" \
                -e "s#%%PACKAGE_VENDOR%%#$(PACKAGE_VENDOR)#g" \
                -e "s#%%MODULE_BUILD_DEPENDS%%#$(MODULE_BUILD_DEPENDS_$*)#g" \
                -e "s#%%MODULE_DEPENDS%%#$(MODULE_DEPENDS_$*)#g" \
        > $@/$(SRCDIR)/debian/control ; \
        cat debian.module/$(if $(MODULE_NOARCH_$*),rules-noarch.in,rules.in) | sed \
                -e "s#%%NAME%%#unit-$(MODULE_SUFFIX_$*)#g" \
                -e "s#%%CODENAME%%#$(CODENAME)#g" \
                -e "s#%%UNIT_VERSION%%#$(VERSION)#g" \
                -e "s#%%UNIT_RELEASE%%#$(RELEASE)#g" \
                -e "s#%%CONFIGURE_ARGS%%#$(CONFIGURE_ARGS_COMMON)#g" \
                -e "s#%%MODULE_CONFARGS%%#$(MODULE_CONFARGS_$*)#g" \
                -e "s#%%MODULE_MAKEARGS%%#$(MODULE_MAKEARGS_$*)#g" \
                -e "s#%%MODULE_INSTARGS%%#$(MODULE_INSTARGS_$*)#g" \
                -e "s#%%MODULE_DEFINITIONS%%#$${definitions}#g" \
                -e "s#%%MODULE_PREBUILD%%#$${prebuild}#g" \
                -e "s#%%MODULE_PREINSTALL%%#$${preinstall}#g" \
                -e "s#%%MODULE_POSTINSTALL%%#$${postinstall}#g" \
        > $@/$(SRCDIR)/debian/rules ; \
        cat debian.module/preinst.in | sed \
                -e "s#%%MODULE_POST%%#$$post#g" \
        > $@/$(SRCDIR)/debian/preinst ; \
        chmod +x $@/$(SRCDIR)/debian/rules ; \
	}

unit-%: check-build-depends-% | debuild-%
	@echo "===> Building $@ package"
	cd debuild-$*/$(SRCDIR) && debuild --preserve-envvar PATH --preserve-envvar RUSTUP_HOME -us -uc
	mkdir -p debs
	find debuild-$*/ -maxdepth 1 -type f -exec cp {} debs/ \;
	ln -s debuild-$*/$(SRCDIR)/build $@

test: unit modules
	@{ \
	for so in `find debuild-*/unit-$(VERSION)/debian/build-unit/ -type f \( -name "*.so" -o -name "*.jar" \)`; do \
		soname=`basename $${so}` ; \
		test "$${soname}" = "java.unit.so" && continue ; \
		test -h debuild/unit-$(VERSION)/debian/build-unit/build/lib/$${soname} || \
		ln -fs `pwd`/$${so} debuild/unit-$(VERSION)/debian/build-unit/build/lib/$${soname} ; \
	done ; \
	( cd debuild/unit-$(VERSION)/debian/build-unit && env python3 -m pytest --user=nobody $(PYTEST_ARGS) ) ; \
	}

test-debug: unit modules
	@{ \
	for so in `find debuild-*/unit-$(VERSION)/debian/build-unit-debug/ -type f \( -name "*.so" -o -name "*.jar" \)`; do \
		soname=`basename $${so}` ; \
		test "$${soname}" = "java.unit.so" && continue ; \
		test -h debuild/unit-$(VERSION)/debian/build-unit-debug/build/lib/$${soname} || \
		ln -fs `pwd`/$${so} debuild/unit-$(VERSION)/debian/build-unit-debug/build/lib/$${soname} ; \
	done ; \
	( cd debuild/unit-$(VERSION)/debian/build-unit-debug && env python3 -m pytest --user=nobody $(PYTEST_ARGS) ) ; \
	}

clean:
	rm -rf debuild debuild-* debs ../../build
	rm -f check-build-depends-*
	find . -maxdepth 1 -type l -delete

.PHONY: default all modules test test-debug clean

.SECONDARY: $(addprefix check-build-depends-, $(MODULES)) $(addprefix debuild-, $(MODULES))
