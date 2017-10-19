MODULES+=		go
MODULE_SUFFIX_go=	go

MODULE_SUMMARY_go=	Go module for NGINX Unit

MODULE_VERSION_go=	$(VERSION)
MODULE_RELEASE_go=	1

MODULE_CONFARGS_go=	go --go-path=\$$(GOROOT)
MODULE_MAKEARGS_go=	go
MODULE_INSTARGS_go=	go-install

MODULE_SOURCES_go=	unit.example-go-app \
			unit.example-go-config

BUILD_DEPENDS+=		golang

MODULE_BUILD_DEPENDS_go=,golang
MODULE_DEPENDS_go=,golang

define MODULE_DEFINITIONS_go
GOROOT = $(shell go env GOROOT)
endef
export MODULE_DEFINITIONS_go

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

 go build -o /tmp/go-app /usr/share/doc/unit-go/examples/go-app/let-my-people.go
 sudo service unit restart
 sudo service unit loadconfig /usr/share/doc/unit-go/examples/unit.config
 curl http://localhost:8500/

Online documentation is available at https://unit.nginx.org

----------------------------------------------------------------------
BANNER
endef
export MODULE_POST_go
