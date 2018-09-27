MODULES+=		ruby
MODULE_SUFFIX_ruby=	ruby

MODULE_SUMMARY_ruby=	Ruby module for NGINX Unit

MODULE_VERSION_ruby=	$(VERSION)
MODULE_RELEASE_ruby=	1

MODULE_CONFARGS_ruby=	ruby
MODULE_MAKEARGS_ruby=	ruby
MODULE_INSTARGS_ruby=	ruby-install

MODULE_SOURCES_ruby=	unit.example-ruby-app \
			unit.example-ruby-config

ifeq ($(OSVER), opensuse-leap)
RACK_PACKAGE=	ruby2.1-rubygem-rack
else ifeq ($(OSVER), opensuse-tumbleweed)
RACK_PACKAGE=	ruby2.5-rubygem-rack
else
RACK_PACKAGE=	rubygem-rack
endif

BUILD_DEPENDS_ruby=	ruby-devel $(RACK_PACKAGE)
BUILD_DEPENDS+=		$(BUILD_DEPENDS_ruby)

define MODULE_DEFINITIONS_ruby
BuildRequires: $(BUILD_DEPENDS_ruby)
Requires: $(RACK_PACKAGE)
endef
export MODULE_DEFINITIONS_ruby

define MODULE_PREINSTALL_ruby
%{__mkdir} -p %{buildroot}%{_datadir}/doc/unit-ruby/examples
%{__install} -m 644 -p %{SOURCE100} \
    %{buildroot}%{_datadir}/doc/unit-ruby/examples/ruby-app.ru
%{__install} -m 644 -p %{SOURCE101} \
    %{buildroot}%{_datadir}/doc/unit-ruby/examples/unit.config
endef
export MODULE_PREINSTALL_ruby

define MODULE_FILES_ruby
%{_libdir}/unit/modules/*
%{_libdir}/unit/debug-modules/*
endef
export MODULE_FILES_ruby

define MODULE_POST_ruby
cat <<BANNER
----------------------------------------------------------------------

The $(MODULE_SUMMARY_ruby) has been installed.

To check the sample app, run these commands:

 sudo service unit start
 cd /usr/share/doc/%{name}/examples
 sudo curl -X PUT --data-binary @unit.config --unix-socket /var/run/control.unit.sock :/config
 curl http://localhost:8700/

Online documentation is available at https://unit.nginx.org

----------------------------------------------------------------------
BANNER
endef
export MODULE_POST_ruby
