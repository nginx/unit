MODULES+=		php
MODULE_SUFFIX_php=	php

MODULE_SUMMARY_php=	PHP module for NGINX Unit

MODULE_VERSION_php=	$(VERSION)
MODULE_RELEASE_php=	1

MODULE_CONFARGS_php=	php
MODULE_MAKEARGS_php=	php
MODULE_INSTARGS_php=	php-install

MODULE_SOURCES_php=	unit.example-php-app \
			unit.example-php-config

ifneq (,$(findstring $(CODENAME),trusty jessie))
BUILD_DEPENDS_php=	php5-dev libphp5-embed
MODULE_BUILD_DEPENDS_php=,php5-dev,libphp5-embed
MODULE_DEPENDS_php=,libphp5-embed
else
BUILD_DEPENDS_php=	php-dev libphp-embed
MODULE_BUILD_DEPENDS_php=,php-dev,libphp-embed
MODULE_DEPENDS_php=,libphp-embed
endif

BUILD_DEPENDS+=		$(BUILD_DEPENDS_php)

define MODULE_PREINSTALL_php
	mkdir -p debian/unit-php/usr/share/doc/unit-php/examples/phpinfo-app
	install -m 644 -p debian/unit.example-php-app debian/unit-php/usr/share/doc/unit-php/examples/phpinfo-app/index.php
	install -m 644 -p debian/unit.example-php-config debian/unit-php/usr/share/doc/unit-php/examples/unit.config
endef
export MODULE_PREINSTALL_php

define MODULE_POST_php
cat <<BANNER
----------------------------------------------------------------------

The $(MODULE_SUMMARY_php) has been installed.

To check out the sample app, run these commands:

 sudo service unit restart
 cd /usr/share/doc/unit-$(MODULE_SUFFIX_php)/examples
 sudo curl -X PUT --data-binary @unit.config --unix-socket /var/run/control.unit.sock :/config
 curl http://localhost:8300/

Online documentation is available at https://unit.nginx.org

----------------------------------------------------------------------
BANNER
endef
export MODULE_POST_php
