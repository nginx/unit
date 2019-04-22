#!/usr/bin/make

include ../../version

DEFAULT_RELEASE := 1

VERSION ?= $(NXT_VERSION)
RELEASE ?= $(DEFAULT_RELEASE)

SRCDIR=	unit-$(VERSION)

CODENAME = $(shell lsb_release -cs)

BUILD_DEPENDS_unit = build-essential debhelper devscripts fakeroot libxml2-utils lintian lsb-release xsltproc libssl-dev
BUILD_DEPENDS = $(BUILD_DEPENDS_unit)

MODULES=

# Ubuntu 19.04
ifeq ($(CODENAME),disco)
include Makefile.php
include Makefile.python27
include Makefile.python37
include Makefile.go110
include Makefile.go111
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc11
endif

# Ubuntu 18.10
ifeq ($(CODENAME),cosmic)
include Makefile.php
include Makefile.python27
include Makefile.python36
include Makefile.python37
include Makefile.go19
include Makefile.go110
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc8
include Makefile.jsc11
endif

# Ubuntu 18.04
ifeq ($(CODENAME),bionic)
include Makefile.php
include Makefile.python27
include Makefile.python36
include Makefile.go19
include Makefile.go110
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc8
include Makefile.jsc10
endif

# Ubuntu 16.04
ifeq ($(CODENAME),xenial)
include Makefile.php
include Makefile.python27
include Makefile.python35
include Makefile.go
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc8
endif

# Ubuntu 14.04
ifeq ($(CODENAME),trusty)
include Makefile.php
include Makefile.python
include Makefile.perl
endif

# Debian 9
ifeq ($(CODENAME),stretch)
include Makefile.php
include Makefile.python27
include Makefile.python35
include Makefile.go17
include Makefile.go18
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc8
endif

# Debian 8
ifeq ($(CODENAME),jessie)
include Makefile.php
include Makefile.python27
include Makefile.python34
include Makefile.perl
include Makefile.ruby
endif

CONFIGURE_ARGS=\
	--prefix=/usr \
	--state=/var/lib/unit \
	--control="unix:/var/run/control.unit.sock" \
	--pid=/var/run/unit.pid \
	--log=/var/log/unit.log \
	--tests \
	--openssl

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
		dpkg -s $${pkg} >/dev/null 2>&1 ; \
		if [ $$? -ne 0 ]; then \
			not_installed="$${not_installed} $${pkg}" ; \
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
	echo '9' > debuild/$(SRCDIR)/debian/compat ; \
	mkdir -p debuild/$(SRCDIR)/debian/source ; \
	echo '3.0 (quilt)' > debuild/$(SRCDIR)/debian/source/format ; \
        cat debian/rules.in | sed \
                -e "s#%%CONFIGURE_ARGS%%#$(CONFIGURE_ARGS)#g" \
        > debuild/$(SRCDIR)/debian/rules ; \
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
		LICENSE NOTICE CHANGES README configure auto src test version
	mv debuild/$(SRCDIR).tar.gz debuild/unit_$(VERSION).orig.tar.gz
	cd debuild && tar zxf unit_$(VERSION).orig.tar.gz

unit: check-build-depends-unit debuild/unit_$(VERSION).orig.tar.gz debuild/$(SRCDIR)/debian/changelog
	@echo "===> Building $@ package"
	cd debuild/$(SRCDIR) && debuild -us -uc
	mkdir -p debs
	find debuild/ -maxdepth 1 -type f -exec cp {} debs/ \;
	ln -s debuild/$(SRCDIR)/build $@

debuild-%: debuild/unit_$(VERSION).orig.tar.gz ../../docs/changes.xml
	mkdir $@
	cp debuild/unit_$(VERSION).orig.tar.gz debuild-$*/unit-$(MODULE_SUFFIX_$*)_$(VERSION).orig.tar.gz
	cd $@ && tar zxf unit-$(MODULE_SUFFIX_$*)_$(VERSION).orig.tar.gz
	mkdir $@/$(SRCDIR)/debian
	echo '9' > $@/$(SRCDIR)/debian/compat
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
                -e "s#%%MODULE_BUILD_DEPENDS%%#$(MODULE_BUILD_DEPENDS_$*)#g" \
                -e "s#%%MODULE_DEPENDS%%#$(MODULE_DEPENDS_$*)#g" \
        > $@/$(SRCDIR)/debian/control ; \
        cat debian.module/$(if $(MODULE_NOARCH_$*),rules-noarch.in,rules.in) | sed \
                -e "s#%%NAME%%#unit-$(MODULE_SUFFIX_$*)#g" \
                -e "s#%%CODENAME%%#$(CODENAME)#g" \
                -e "s#%%UNIT_VERSION%%#$(VERSION)#g" \
                -e "s#%%UNIT_RELEASE%%#$(RELEASE)#g" \
                -e "s#%%CONFIGURE_ARGS%%#$(CONFIGURE_ARGS)#g" \
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
	cd debuild-$*/$(SRCDIR) && debuild -us -uc
	mkdir -p debs
	find debuild-$*/ -maxdepth 1 -type f -exec cp {} debs/ \;
	ln -s debuild-$*/$(SRCDIR)/build $@

test: unit modules
	@{ \
	for so in `find debuild-*/unit-$(VERSION)/debian/build-unit/ -type f \( -name "*.so" -o -name "*.jar" \)`; do \
		soname=`basename $${so}` ; \
		test "$${soname}" = "java.unit.so" && continue ; \
		test -h debuild/unit-$(VERSION)/debian/build-unit/build/$${soname} || \
		ln -fs `pwd`/$${so} debuild/unit-$(VERSION)/debian/build-unit/build/$${soname} ; \
	done ; \
	( cd debuild/unit-$(VERSION)/debian/build-unit && ./test/run.py ) ; \
	}

test-debug: unit modules
	@{ \
	for so in `find debuild-*/unit-$(VERSION)/debian/build-unit-debug/ -type f \( -name "*.so" -o -name "*.jar" \)`; do \
		soname=`basename $${so}` ; \
		test "$${soname}" = "java.unit.so" && continue ; \
		test -h debuild/unit-$(VERSION)/debian/build-unit-debug/build/$${soname} || \
		ln -fs `pwd`/$${so} debuild/unit-$(VERSION)/debian/build-unit-debug/build/$${soname} ; \
	done ; \
	( cd debuild/unit-$(VERSION)/debian/build-unit-debug && ./test/run.py ) ; \
	}

clean:
	rm -rf debuild debuild-* debs ../../build
	rm -f check-build-depends-*
	find . -maxdepth 1 -type l -delete

.PHONY: default all modules test test-debug clean

.SECONDARY: $(addprefix check-build-depends-, $(MODULES)) $(addprefix debuild-, $(MODULES))
