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

BUILD_DEPENDS_ruby=	ruby-dev ruby-rack
BUILD_DEPENDS+=         $(BUILD_DEPENDS_ruby)

MODULE_BUILD_DEPENDS_ruby=,ruby-dev,ruby-rack

MODULE_DEPENDS_ruby=,ruby-rack

define MODULE_PREINSTALL_ruby
	mkdir -p debian/unit-ruby/usr/share/doc/unit-ruby/examples
	install -m 644 -p debian/unit.example-ruby-app debian/unit-ruby/usr/share/doc/unit-ruby/examples/ruby-app.ru
	install -m 644 -p debian/unit.example-ruby-config debian/unit-ruby/usr/share/doc/unit-ruby/examples/unit.config
endef
export MODULE_PREINSTALL_ruby

define MODULE_POST_ruby
cat <<BANNER
----------------------------------------------------------------------

The $(MODULE_SUMMARY_ruby) has been installed.

To check out the sample app, run these commands:

 sudo service unit restart
 sudo service unit loadconfig /usr/share/doc/unit-ruby/examples/unit.config
 curl http://localhost:8700/

Online documentation is available at https://unit.nginx.org

----------------------------------------------------------------------
BANNER
endef
export MODULE_POST_ruby
