#/bin/sh -x

DIR=`dirname $0`
DISTRO="$1"; shift;

# package management helpers
PACKAGE_MANAGER_INSTALL_yum="yum --setopt=skip_missing_names_on_install=False install -y"
PACKAGE_MANAGER_REMOVE_yum="yum erase -y"
PACKAGE_DEBUG_SUFFIX_yum="debuginfo"
PACKAGE_DEVEL_SUFFIX_yum="devel"
PACKAGE_MANAGER_INSTALL_apt="apt-get install -y --force-yes -q "
PACKAGE_MANAGER_REMOVE_apt="apt-get remove -y --force-yes -q --purge"
PACKAGE_DEBUG_SUFFIX_apt="dbg"
PACKAGE_DEVEL_SUFFIX_apt="dev"
LANGUAGES_COMMON="go perl php"
PACKAGES_PREREQUISITES="curl git"

case "$DISTRO" in
    amazon-lts)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_yum
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_yum
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_yum"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_yum"
        languages="$LANGUAGES_COMMON wasm"
        python_versions="2.7 3.7"
        java_versions="1.8"
        distroversion="amzn/2"
        ;;
    amazonlinux-2023)
        PACKAGES_PREREQUISITES="git"
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_yum
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_yum
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_yum"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_yum"
        languages="$LANGUAGES_COMMON wasm"
        python_versions="3.9 3.11"
        java_versions="17"
        distroversion="amzn/2023"
        ;;
    centos-7|centos-74|rhel-7|ol-7)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_yum
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_yum
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_yum"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_yum"
        languages="$LANGUAGES_COMMON"
        python_versions="2.7 3.6"
        java_versions="1.8 11"
        distroversion="centos/7"
        ;;
    rhel-8|alma-8|rocky-8|ol-8)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_yum
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_yum
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_yum"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_yum"
        languages="$LANGUAGES_COMMON wasm"
        python_versions="2.7 3.6 3.8 3.9"
        java_versions="1.8 11"
        distroversion="centos/8"
        ;;
    rhel-9|alma-9|rocky-9|ol-9)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_yum
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_yum
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_yum"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_yum"
        languages="$LANGUAGES_COMMON wasm"
        python_versions="3.9"
        java_versions="1.8 11"
        distroversion="centos/9"
        ;;
    fedora-38)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_yum
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_yum
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_yum"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_yum"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="3.11"
        java_versions="1.8 11"
        distroversion="fedora/38"
        ;;
    fedora-39)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_yum
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_yum
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_yum"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_yum"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="3.12"
        java_versions="17"
        distroversion="fedora/39"
        ;;
    ubuntu-18.04)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_apt
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_apt
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_apt"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_apt"
        PACKAGES_PREREQUISITES="curl apt-transport-https lsb-release ca-certificates"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="2.7 3.6 3.7 3.8"
        java_versions="1.8 11"
        distroversion="ubuntu/18.04"
        ;;
    ubuntu-20.04)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_apt
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_apt
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_apt"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_apt"
        PACKAGES_PREREQUISITES="curl apt-transport-https lsb-release ca-certificates"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="2.7 3.8"
        java_versions="11"
        distroversion="ubuntu/20.04"
        ;;
    ubuntu-21.10)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_apt
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_apt
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_apt"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_apt"
        PACKAGES_PREREQUISITES="curl apt-transport-https lsb-release ca-certificates"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="2.7 3.9 3.10"
        java_versions="11 16 17 18"
        distroversion="ubuntu/21.10"
        ;;
    ubuntu-22.04)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_apt
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_apt
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_apt"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_apt"
        PACKAGES_PREREQUISITES="curl apt-transport-https lsb-release ca-certificates"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="2.7 3.10"
        java_versions="11 17 18"
        distroversion="ubuntu/22.04"
        ;;
    ubuntu-22.10)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_apt
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_apt
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_apt"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_apt"
        PACKAGES_PREREQUISITES="curl apt-transport-https lsb-release ca-certificates"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="2.7 3.10"
        java_versions="11 17 18 19"
        distroversion="ubuntu/22.10"
        ;;
    ubuntu-23.04)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_apt
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_apt
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_apt"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_apt"
        PACKAGES_PREREQUISITES="curl apt-transport-https lsb-release ca-certificates"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="3.11"
        java_versions="11 17 18 19 20"
        distroversion="ubuntu/23.04"
        ;;
    ubuntu-23.10)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_apt
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_apt
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_apt"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_apt"
        PACKAGES_PREREQUISITES="curl apt-transport-https lsb-release ca-certificates"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="3.12"
        java_versions="11 17 19 20 21"
        distroversion="ubuntu/23.10"
        ;;
    debian-10)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_apt
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_apt
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_apt"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_apt"
        PACKAGES_PREREQUISITES="curl apt-transport-https lsb-release ca-certificates"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="2.7 3.7"
        java_versions="11"
        distroversion="debian/10"
        ;;
    debian-11)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_apt
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_apt
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_apt"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_apt"
        PACKAGES_PREREQUISITES="curl apt-transport-https lsb-release ca-certificates"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="2.7 3.9"
        java_versions="11"
        distroversion="debian/11"
        ;;
    debian-12)
        PACKAGE_MANAGER_INSTALL=$PACKAGE_MANAGER_INSTALL_apt
        PACKAGE_MANAGER_REMOVE=$PACKAGE_MANAGER_REMOVE_apt
        PACKAGE_DEBUG_SUFFIX="$PACKAGE_DEBUG_SUFFIX_apt"
        PACKAGE_DEVEL_SUFFIX="$PACKAGE_DEVEL_SUFFIX_apt"
        PACKAGES_PREREQUISITES="curl apt-transport-https lsb-release ca-certificates"
        languages="$LANGUAGES_COMMON ruby wasm"
        python_versions="3.11"
        java_versions="17"
        distroversion="debian/12"
        ;;
    alpine*)
        PACKAGE_MANAGER_INSTALL="apk add "
        PACKAGE_MANAGER_REMOVE="apk del "
        ;;
        
    *)
        echo "Unknown distro: $DISTRO, exiting"
        exit 1
        ;;
esac

x_wait_apt_lock() {
    if [ -f "/var/lib/apt/lists/lock" ]; then
        while fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
            echo "Waiting for apt lists lock to be free"
            sleep 5
        done
        while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
            echo "Waiting for dpkg lock to be free"
            sleep 5
        done
    fi
}
# try to install the packages for five times
# sleep for five seconds between attempts
x_install_package()
{
    if [ -f "/var/lib/apt/lists/lock" ]; then
        x_wait_apt_lock
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y --no-allow-insecure-repositories
        systemctl stop unattended-upgrades.service || :
        systemctl disable unattended-upgrades.service || :
    fi
    case "$DISTRO" in
        alpine*)
            apk update
            ;;
    esac
    retry=1
    try=1
    while [ -n "$retry" ] && [ "$try" -le 5 ]; do
        retry=
        if $PACKAGE_MANAGER_INSTALL $@; then
            rc=0
        else
            rc=$?
            try=$((try + 1))
            retry=1
            x_wait_apt_lock
            sleep 1
            continue
        fi
    done
    return "$rc"
}

family=`echo $DISTRO | cut -f 1 -d -`
PKGS=`cat $DIR/pkglists/$family $DIR/pkglists/$DISTRO`
x_install_package $PACKAGES_PREREQUISITES $PKGS

