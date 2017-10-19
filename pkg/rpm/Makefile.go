MODULES+=		go

MODULE_SUMMARY_go=	Go module for NGINX Unit

MODULE_VERSION_go=	$(VERSION)
MODULE_RELEASE_go=	1

MODULE_CONFARGS_go=	go --go-path=%{goroot}
MODULE_MAKEARGS_go=	go
MODULE_INSTARGS_go=	go-install

MODULE_SOURCES_go=	unit.example-go-app \
			unit.example-go-config

BUILD_DEPENDS+=		golang

define MODULE_DEFINITIONS_go
%define goroot %(go env GOROOT)
%define goos %(go env GOOS)
%define goarch %(go env GOARCH)

BuildRequires: golang
endef
export MODULE_DEFINITIONS_go

define MODULE_PREINSTALL_go
QA_SKIP_BUILD_ROOT=1
export QA_SKIP_BUILD_ROOT

%{__mkdir} -p %{buildroot}%{_datadir}/doc/unit-go/examples/go-app
%{__install} -m 644 -p %{SOURCE100} \
    %{buildroot}%{_datadir}/doc/unit-go/examples/go-app/let-my-people.go
%{__install} -m 644 -p %{SOURCE101} \
    %{buildroot}%{_datadir}/doc/unit-go/examples/unit.config
endef
export MODULE_PREINSTALL_go

define MODULE_FILES_go
%dir %{goroot}/src/unit
%{goroot}/src/unit/*
%{goroot}/pkg/%{goos}_%{goarch}/unit.a
endef
export MODULE_FILES_go

define MODULE_POST_go
cat <<BANNER
----------------------------------------------------------------------

The $(MODULE_SUMMARY_go) has been installed.

To check the sample app, run these commands:

 go build -o /tmp/go-app /usr/share/doc/unit-go/examples/go-app/let-my-people.go
 sudo service unit start
 sudo service unit loadconfig /usr/share/doc/unit-go/examples/unit.config
 curl http://localhost:8500/

Online documentation is available at https://unit.nginx.org

----------------------------------------------------------------------
BANNER
endef
export MODULE_POST_go
