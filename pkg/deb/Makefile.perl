MODULES+=		perl
MODULE_SUFFIX_perl=	perl

MODULE_SUMMARY_perl=	Perl module for NGINX Unit

MODULE_VERSION_perl=	$(VERSION)
MODULE_RELEASE_perl=	1

MODULE_CONFARGS_perl=	perl
MODULE_MAKEARGS_perl=	perl
MODULE_INSTARGS_perl=	perl-install

MODULE_SOURCES_perl=	unit.example-perl-app \
			unit.example-perl-config

BUILD_DEPENDS_perl=	libperl-dev
BUILD_DEPENDS+=         $(BUILD_DEPENDS_perl)

MODULE_BUILD_DEPENDS_perl=,libperl-dev

define MODULE_PREINSTALL_perl
	mkdir -p debian/unit-perl/usr/share/doc/unit-perl/examples/perl-app
	install -m 644 -p debian/unit.example-perl-app debian/unit-perl/usr/share/doc/unit-perl/examples/perl-app/index.pl
	install -m 644 -p debian/unit.example-perl-config debian/unit-perl/usr/share/doc/unit-perl/examples/unit.config
endef
export MODULE_PREINSTALL_perl

define MODULE_POST_perl
cat <<BANNER
----------------------------------------------------------------------

The $(MODULE_SUMMARY_perl) has been installed.

To check out the sample app, run these commands:

 sudo service unit restart
 cd /usr/share/doc/unit-$(MODULE_SUFFIX_perl)/examples
 sudo curl -X PUT --data-binary @unit.config --unix-socket /var/run/control.unit.sock http://localhost/config
 curl http://localhost:8600/

Online documentation is available at https://unit.nginx.org

----------------------------------------------------------------------
BANNER
endef
export MODULE_POST_perl
