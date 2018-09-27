MODULES+=		go
MODULE_SUFFIX_go=	go

MODULE_SUMMARY_go=	Go module for NGINX Unit

MODULE_VERSION_go=	$(VERSION)
MODULE_RELEASE_go=	1

MODULE_CONFARGS_go=	go --go-path=/usr/share/gocode
MODULE_MAKEARGS_go=	go
MODULE_INSTARGS_go=	go-install

MODULE_SOURCES_go=	unit.example-go-app \
			unit.example-go-config

BUILD_DEPENDS_go=	golang
BUILD_DEPENDS+=		$(BUILD_DEPENDS_go)

MODULE_BUILD_DEPENDS_go=,golang
MODULE_DEPENDS_go=,golang

MODULE_NOARCH_go=	true

define MODULE_PREINSTALL_go
	mkdir -p debian/unit-go/usr/share/doc/unit-go/examples/go-app
	install -m 644 -p debian/unit.example-go-app debian/unit-go/usr/share/doc/unit-go/examples/go-app/let-my-people.go
	install -m 644 -p debian/unit.example-go-config debian/unit-go/usr/share/doc/unit-go/examples/unit.config
endef
export MODULE_PREINSTALL_go

define MODULE_POST_go
cat <<BANNER
----------------------------------------------------------------------

The $(MODULE_SUMMARY_go) has been installed.

To check out the sample app, run these commands:

 GOPATH=/usr/share/gocode go build -o /tmp/go-app /usr/share/doc/unit-$(MODULE_SUFFIX_go)/examples/go-app/let-my-people.go
 sudo service unit restart
 cd /usr/share/doc/unit-$(MODULE_SUFFIX_go)/examples
 sudo curl -X PUT --data-binary @unit.config --unix-socket /var/run/control.unit.sock :/config
 curl http://localhost:8500/

Online documentation is available at https://unit.nginx.org

----------------------------------------------------------------------
BANNER
endef
export MODULE_POST_go
