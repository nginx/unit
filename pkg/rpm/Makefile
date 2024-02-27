#!/usr/bin/make

include ../../version

DEFAULT_VERSION := $(NXT_VERSION)
DEFAULT_RELEASE := 1

VERSION ?= $(DEFAULT_VERSION)
RELEASE ?= $(DEFAULT_RELEASE)

PACKAGE_VENDOR = NGINX Packaging <nginx-packaging@f5.com>

ifeq ($(shell test `rpm --eval '0%{?rhel} -eq 7 -a 0%{?amzn} -eq 0'`; echo $$?), 0)
OSVER = centos7
else ifeq ($(shell rpm --eval "%{?rhel}"), 8)
OSVER = centos8
else ifeq ($(shell rpm --eval "%{?rhel}"), 9)
OSVER = centos9
else ifeq ($(shell rpm --eval "%{?amzn}"), 2)
OSVER = amazonlinux2
else ifeq ($(shell rpm --eval "%{?amzn}"), 2023)
OSVER = amazonlinux2023
else ifeq ($(shell test `rpm --eval '0%{?fedora} -ge 35 -a 0%{?fedora} -le 36'`; echo $$?),0)
OSVER = fedora
else ifeq ($(shell test `rpm --eval '0%{?fedora} -ge 37 -a 0%{?fedora} -le 38'`; echo $$?),0)
OSVER = fedora37
else ifeq ($(shell test `rpm --eval '0%{?fedora} -ge 39'`; echo $$?),0)
OSVER = fedora39
endif

BUILD_DEPENDS_unit = gcc rpm-build rpmlint

ifeq ($(OSVER), centos7)
BUILD_DEPENDS_unit += which
endif

ifneq (,$(findstring $(OSVER),amazonlinux2))
BUILD_DEPENDS_unit += libxml2 libxslt openssl11-devel
else
BUILD_DEPENDS_unit += libxml2 libxslt openssl-devel
endif

BUILD_DEPENDS = $(BUILD_DEPENDS_unit)

MODULES=

ifeq ($(OSVER), centos7)
include Makefile.php
include Makefile.python27
include Makefile.python36
include Makefile.go
include Makefile.perl
include Makefile.jsc-common
include Makefile.jsc8
include Makefile.jsc11
endif

ifeq ($(OSVER), centos8)
include Makefile.php
include Makefile.python27
include Makefile.python36
include Makefile.python38
include Makefile.python39
include Makefile.go
include Makefile.perl
include Makefile.jsc-common
include Makefile.jsc8
include Makefile.jsc11
include Makefile.wasm
endif

ifeq ($(OSVER), centos9)
include Makefile.php
include Makefile.python39
include Makefile.go
include Makefile.perl
include Makefile.jsc-common
include Makefile.jsc8
include Makefile.jsc11
include Makefile.wasm
endif

ifeq ($(OSVER), amazonlinux2)
include Makefile.php
include Makefile.python27
include Makefile.python37
include Makefile.go
include Makefile.perl
include Makefile.jsc-common
include Makefile.jsc8
include Makefile.wasm
endif

ifeq ($(OSVER), amazonlinux2023)
include Makefile.php
include Makefile.python39
include Makefile.python311
include Makefile.go
include Makefile.perl
include Makefile.jsc-common
include Makefile.jsc17
include Makefile.wasm
endif

ifeq ($(OSVER), fedora)
include Makefile.php
include Makefile.python310
include Makefile.go
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc8
include Makefile.jsc11
include Makefile.wasm
endif

ifeq ($(OSVER), fedora37)
include Makefile.php
include Makefile.python311
include Makefile.go
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc8
include Makefile.jsc11
include Makefile.wasm
endif

ifeq ($(OSVER), fedora39)
include Makefile.php
include Makefile.python312
include Makefile.go
include Makefile.perl
include Makefile.ruby
include Makefile.jsc-common
include Makefile.jsc17
include Makefile.wasm
endif


CONFIGURE_ARGS_COMMON=\
	--prefix=/usr \
	--statedir=%{_sharedstatedir}/unit \
	--control="unix:/var/run/unit/control.sock" \
	--runstatedir=/var/run \
	--pid=/var/run/unit/unit.pid \
	--logdir=/var/log \
	--log=/var/log/unit/unit.log \
	--tmpdir=/var/tmp \
	--user=unit \
	--group=unit \
	--tests \
	--openssl

CONFIGURE_ARGS=\
	$(CONFIGURE_ARGS_COMMON) \
	--njs

export CR=\\n

default:
	@echo "valid targets: all modules unit $(addprefix unit-, $(MODULES)) rpmlint specs test test-debug clean"

all: check-build-depends-all unit modules

modules: $(addprefix unit-, $(MODULES))

specs: rpmbuild/SPECS/unit.spec $(addsuffix .spec, $(addprefix rpmbuild/SPECS/unit-, $(MODULES)))

check-build-depends-%:
	@{ \
	case "$*" in \
		all) pkgs="$(BUILD_DEPENDS)" ;; \
		unit) pkgs="$(BUILD_DEPENDS_unit)" ;; \
		*) pkgs="$(BUILD_DEPENDS_unit) $(BUILD_DEPENDS_$*)" ;; \
	esac ; \
	not_installed= ; \
	for pkg in $${pkgs}; do \
		rpm -qi --whatprovides $${pkg} >/dev/null 2>&1 ; \
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

rpmbuild/SPECS:
	mkdir -p rpmbuild/SPECS

rpmbuild/SPECS/unit.spec: unit.spec.in ../../docs/changes.xml | rpmbuild/SPECS
	cat unit.spec.in | \
		sed -e "s#%%VERSION%%#$(VERSION)#g" \
		    -e "s#%%RELEASE%%#$(RELEASE)#g" \
		    -e "s#%%CONFIGURE_ARGS%%#$(CONFIGURE_ARGS)#g" \
		    -e "s#%%PACKAGE_VENDOR%%#$(PACKAGE_VENDOR)#g" \
		> rpmbuild/SPECS/unit.spec
	cd ../../docs && make ../build/unit.rpm-changelog
ifneq ($(DEFAULT_VERSION)$(DEFAULT_RELEASE), $(VERSION)$(RELEASE))
	cat ../../build/unit.rpm-changelog | sed -e \
		"s/> - $(DEFAULT_VERSION)-$(DEFAULT_RELEASE)/> - $(VERSION)-$(RELEASE)/" \
		>> rpmbuild/SPECS/unit.spec
else
	cat ../../build/unit.rpm-changelog >> rpmbuild/SPECS/unit.spec
endif

rpmbuild/SOURCES/unit-$(VERSION).tar.gz:
	cd ../.. && tar -czf pkg/rpm/rpmbuild/SOURCES/unit-$(VERSION).tar.gz \
		--transform "s#^#unit-$(VERSION)/#" \
		LICENSE NOTICE CHANGES README.md CONTRIBUTING.md configure auto src \
		test tools version go pkg/contrib docs/man/man8/unitd.8.in

unit: check-build-depends-unit rpmbuild/SPECS/unit.spec rpmbuild/SOURCES/unit-$(VERSION).tar.gz
	@echo "===> Building $@ package" ; \
	rpmbuild -D "_topdir `pwd`/rpmbuild" -ba --noclean rpmbuild/SPECS/unit.spec && \
	ln -s rpmbuild/BUILD/$@-$(VERSION)/build $@

rpmlint:
	find rpmbuild/ -name "*.rpm" -print -exec rpmlint {} \;

rpmbuild/SPECS/unit-%.spec: unit.module.spec.in ../../docs/changes.xml | rpmbuild/SPECS
	@echo "===> Creating $@"
	@{ \
	set -e ; \
	i=100 ; \
	sources= ; \
	for src in $(MODULE_SOURCES_$*); do \
		s="`printf "Source%d: %s\n" $${i} $${src}`" ; \
		sources="$${sources}\n$${s}" ; \
		i=$$(($${i}+1)) ; \
	done ; \
	pkgname=$(shell echo $@ | cut -d '/' -f 3 | tr '_' '-' | cut -d '.' -f 1) ; \
	definitions=`echo "$$MODULE_DEFINITIONS_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	prebuild=`echo "$$MODULE_PREBUILD_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	preinstall=`echo "$$MODULE_PREINSTALL_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	postinstall=`echo "$$MODULE_POSTINSTALL_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	files=`echo "$$MODULE_FILES_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	post=`echo "$$MODULE_POST_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	cat unit.module.spec.in | sed \
		-e "s#%%NAME%%#$${pkgname}#g" \
		-e "s#%%SUMMARY%%#$(MODULE_SUMMARY_$*)#g" \
		-e "s#%%VERSION%%#$(MODULE_VERSION_$*)#g" \
		-e "s#%%RELEASE%%#$(MODULE_RELEASE_$*)#g" \
		-e "s#%%UNIT_VERSION%%#$(VERSION)#g" \
		-e "s#%%UNIT_RELEASE%%#$(RELEASE)#g" \
		-e "s#%%PACKAGE_VENDOR%%#$(PACKAGE_VENDOR)#g" \
		-e "s#%%MODULE_SOURCES%%#$${sources}#g" \
		-e "s#%%CONFIGURE_ARGS%%#$(CONFIGURE_ARGS_COMMON)#g" \
		-e "s#%%MODULE_CONFARGS%%#$(MODULE_CONFARGS_$*)#g" \
		-e "s#%%MODULE_MAKEARGS%%#$(MODULE_MAKEARGS_$*)#g" \
		-e "s#%%MODULE_INSTARGS%%#$(MODULE_INSTARGS_$*)#g" \
		-e "s#%%MODULE_DEFINITIONS%%#$${definitions}#g" \
		-e "s#%%MODULE_PREBUILD%%#$${prebuild}#g" \
		-e "s#%%MODULE_PREINSTALL%%#$${preinstall}#g" \
		-e "s#%%MODULE_POSTINSTALL%%#$${postinstall}#g" \
		-e "s#%%MODULE_FILES%%#$${files}#g" \
		-e "s#%%MODULE_POST%%#$${post}#g" \
		> $@.tmp ; \
	}
	cd ../../docs && make ../build/unit-$(MODULE_SUFFIX_$*).rpm-changelog
	cat ../../build/unit-$(MODULE_SUFFIX_$*).rpm-changelog | sed -e \
		"s/> - $(DEFAULT_VERSION)-$(DEFAULT_RELEASE)/> - $(MODULE_VERSION_$*)-$(MODULE_RELEASE_$*)/" \
		>> $@.tmp
	mv $@.tmp $@

unit-%: check-build-depends-% rpmbuild/SPECS/unit-%.spec rpmbuild/SOURCES/unit-$(VERSION).tar.gz
	@echo "===> Building $(subst _,-,$@) package" ; \
	rpmbuild -D "_topdir `pwd`/rpmbuild" -ba --noclean rpmbuild/SPECS/$@.spec && \
	ln -s rpmbuild/BUILD/$(subst _,-,$@)-$(VERSION)/build $@

test: unit modules
	@{ \
	for so in `find rpmbuild/BUILD/*/build-nodebug/ -type f \( -name "*.so" -o -name "*.jar" \)`; do \
		soname=`basename $${so}` ; \
		test "$${soname}" = "java.unit.so" && continue ; \
		test -h rpmbuild/BUILD/unit-$(VERSION)/build-nodebug/$${soname} || \
		ln -fs `pwd`/$${so} rpmbuild/BUILD/unit-$(VERSION)/build-nodebug/$${soname} ; \
	done ; \
	( cd rpmbuild/BUILD/unit-$(VERSION) && rm -f build && ln -s build-nodebug build && env python3 -m pytest --user=nobody $(PYTEST_ARGS) ) ; \
	}

test-debug: unit modules
	@{ \
	for so in `find rpmbuild/BUILD/*/build-debug/ -type f \( -name "*.so" -o -name "*.jar" \)`; do \
		soname=`basename $${so}` ; \
		test "$${soname}" = "java.unit.so" && continue ; \
		test -h rpmbuild/BUILD/unit-$(VERSION)/build-debug/$${soname} || \
		ln -fs `pwd`/$${so} rpmbuild/BUILD/unit-$(VERSION)/build-debug/$${soname} ; \
	done ; \
	( cd rpmbuild/BUILD/unit-$(VERSION) && rm -f build && ln -s build-debug build && env python3 -m pytest --user=nobody $(PYTEST_ARGS) ) ; \
	}

clean:
	rm -rf rpmbuild/SPECS rpmbuild/BUILD rpmbuild/BUILDROOT rpmbuild/RPMS rpmbuild/SRPMS ../../build
	rm -f rpmbuild/SOURCES/unit-*.tar.gz check-build-depends-*
	find . -maxdepth 1 -type l -delete

.PHONY: default all modules specs rpmlint test test-debug clean

.SECONDARY: $(addprefix check-build-depends-, $(MODULES))
