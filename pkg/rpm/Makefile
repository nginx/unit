#!/usr/bin/make

DEFAULT_VERSION := $(shell grep 'define NXT_VERSION' ../../src/nxt_main.h \
			| sed -e 's/^.*"\(.*\)".*/\1/')

DEFAULT_RELEASE := 1

VERSION ?= $(DEFAULT_VERSION)
RELEASE ?= $(DEFAULT_RELEASE)

ifeq ($(shell rpm --eval "%{?rhel}"), 6)
OSVER = centos6
else ifeq ($(shell rpm --eval "%{?rhel}"), 7)
OSVER = centos7
else ifeq ($(shell rpm --eval "%{?amzn}"), 1)
OSVER = amazonlinux1
else ifeq ($(shell rpm --eval "%{?amzn}"), 2)
OSVER = amazonlinux2
else ifeq ($(shell test `rpm --eval '0%{?suse_version} -ge 1315 -a 0%{?suse_version} -lt 1330 -a 0%{?is_opensuse} -eq 1'`; echo $$?), 0)
OSVER = opensuse-leap
else ifeq ($(shell test `rpm --eval '0%{?suse_version} -ge 1330 -a 0%{?is_opensuse} -eq 1'`; echo $$?), 0)
OSVER = opensuse-tumbleweed
else ifeq ($(shell test `rpm --eval '0%{?suse_version} -ge 1315 -a 0%{?is_opensuse} -eq 0'`; echo $$?), 0)
OSVER = sles
else ifeq ($(shell test `rpm --eval '0%{?fedora} -ge 26'`; echo $$?),0)
OSVER = fedora
endif

BUILD_DEPENDS_unit = gcc rpm-build rpmlint

ifeq ($(OSVER), centos7)
BUILD_DEPENDS_unit += which
endif

ifeq ($(OSVER), amazonlinux1)
BUILD_DEPENDS_unit += system-rpm-config
endif

ifneq (,$(findstring $(OSVER),opensuse-leap opensuse-tumbleweed sles))
BUILD_DEPENDS_unit += libxml2-tools libxslt1 libopenssl-devel
else
BUILD_DEPENDS_unit += libxml2 libxslt openssl-devel
endif

BUILD_DEPENDS = $(BUILD_DEPENDS_unit)

MODULES=

ifeq ($(OSVER), centos6)
include Makefile.php
include Makefile.python
include Makefile.go
endif

ifneq (,$(findstring $(OSVER),centos7 amazonlinux2))
include Makefile.php
include Makefile.python
include Makefile.go
include Makefile.perl
endif

ifeq ($(OSVER), amazonlinux1)
include Makefile.php
include Makefile.python27
include Makefile.python34
include Makefile.python35
include Makefile.python36
include Makefile.go
include Makefile.perl
endif

ifeq ($(OSVER), opensuse-leap)
include Makefile.python27
include Makefile.python34
include Makefile.go
include Makefile.perl
include Makefile.ruby
endif

ifeq ($(OSVER), opensuse-tumbleweed)
include Makefile.php
include Makefile.python27
include Makefile.python36
include Makefile.go
include Makefile.perl
include Makefile.ruby
endif

ifeq ($(OSVER), sles)
include Makefile.python27
include Makefile.python34
include Makefile.perl
endif

ifeq ($(OSVER), fedora)
include Makefile.php
include Makefile.python27
ifeq ($(shell test `rpm --eval '0%{?fedora} -ge 29'`; echo $$?),0)
include Makefile.python37
else
include Makefile.python36
endif
include Makefile.go
include Makefile.perl
include Makefile.ruby
endif

CONFIGURE_ARGS=\
	--prefix=/usr \
	--state=%{_sharedstatedir}/unit \
	--control="unix:/var/run/unit/control.sock" \
	--pid=/var/run/unit.pid \
	--log=/var/log/unit.log \
	--tests \
	--openssl

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
		rpm -qi $${pkg} >/dev/null 2>&1 ; \
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
		LICENSE NOTICE CHANGES README configure auto src test

unit: check-build-depends-unit rpmbuild/SPECS/unit.spec rpmbuild/SOURCES/unit-$(VERSION).tar.gz
	@echo "===> Building $@ package" ; \
	rpmbuild -D "_topdir `pwd`/rpmbuild" -ba rpmbuild/SPECS/unit.spec && \
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
	pkgname=$(shell echo $@ | cut -d '/' -f 3 | cut -d '.' -f 1) ; \
	definitions=`echo "$$MODULE_DEFINITIONS_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	preinstall=`echo "$$MODULE_PREINSTALL_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	files=`echo "$$MODULE_FILES_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	post=`echo "$$MODULE_POST_$*" | sed -e ':a' -e 'N' -e '$$!ba' -e "s/\n/\$$CR/g"` ; \
	cat unit.module.spec.in | sed \
		-e "s#%%NAME%%#$${pkgname}#g" \
		-e "s#%%SUMMARY%%#$(MODULE_SUMMARY_$*)#g" \
		-e "s#%%VERSION%%#$(MODULE_VERSION_$*)#g" \
		-e "s#%%RELEASE%%#$(MODULE_RELEASE_$*)#g" \
		-e "s#%%UNIT_VERSION%%#$(VERSION)#g" \
		-e "s#%%UNIT_RELEASE%%#$(RELEASE)#g" \
		-e "s#%%MODULE_SOURCES%%#$${sources}#g" \
		-e "s#%%CONFIGURE_ARGS%%#$(CONFIGURE_ARGS)#g" \
		-e "s#%%MODULE_CONFARGS%%#$(MODULE_CONFARGS_$*)#g" \
		-e "s#%%MODULE_MAKEARGS%%#$(MODULE_MAKEARGS_$*)#g" \
		-e "s#%%MODULE_INSTARGS%%#$(MODULE_INSTARGS_$*)#g" \
		-e "s#%%MODULE_DEFINITIONS%%#$${definitions}#g" \
		-e "s#%%MODULE_PREINSTALL%%#$${preinstall}#g" \
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
	@echo "===> Building $@ package" ; \
	rpmbuild -D "_topdir `pwd`/rpmbuild" -ba rpmbuild/SPECS/$@.spec && \
	ln -s rpmbuild/BUILD/$@-$(VERSION)/build $@

test: unit modules
	@{ \
	for so in `find rpmbuild/BUILD/*/build-nodebug/ -type f -name "*.so"`; do \
		soname=`basename $${so}` ; \
		test -h rpmbuild/BUILD/unit-$(VERSION)/build-nodebug/$${soname} || \
		ln -fs `pwd`/$${so} rpmbuild/BUILD/unit-$(VERSION)/build-nodebug/$${soname} ; \
	done ; \
	( cd rpmbuild/BUILD/unit-$(VERSION) && rm -f build && ln -s build-nodebug build && ./test/run.py ) ; \
	}

test-debug: unit modules
	@{ \
	for so in `find rpmbuild/BUILD/*/build-debug/ -type f -name "*.so"`; do \
		soname=`basename $${so}` ; \
		test -h rpmbuild/BUILD/unit-$(VERSION)/build-debug/$${soname} || \
		ln -fs `pwd`/$${so} rpmbuild/BUILD/unit-$(VERSION)/build-debug/$${soname} ; \
	done ; \
	( cd rpmbuild/BUILD/unit-$(VERSION) && rm -f build && ln -s build-debug build && ./test/run.py ) ; \
	}

clean:
	rm -rf rpmbuild/SPECS rpmbuild/BUILD rpmbuild/BUILDROOT rpmbuild/RPMS rpmbuild/SRPMS ../../build
	rm -f rpmbuild/SOURCES/unit-*.tar.gz check-build-depends-*
	find . -maxdepth 1 -type l -delete

.PHONY: default all modules specs rpmlint test test-debug clean

.SECONDARY: $(addprefix check-build-depends-, $(MODULES))
