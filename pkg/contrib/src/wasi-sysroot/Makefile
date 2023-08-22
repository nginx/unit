# wasi-sysroot

include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/version
WASI_SYSROOT_URL := https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-$(WASI_SYSROOT_VERSION_MAJOR)/wasi-sysroot-$(WASI_SYSROOT_VERSION_MAJOR).$(WASI_SYSROOT_VERSION_MINOR).tar.gz

PKGS += wasi-sysroot

$(TARBALLS)/wasi-sysroot-$(WASI_SYSROOT_VERSION_MAJOR).$(WASI_SYSROOT_VERSION_MINOR).tar.gz:
	$(call download_pkg,$(WASI_SYSROOT_URL),wasi-sysroot)

.sum-wasi-sysroot: wasi-sysroot-$(WASI_SYSROOT_VERSION_MAJOR).$(WASI_SYSROOT_VERSION_MINOR).tar.gz

wasi-sysroot: wasi-sysroot-$(WASI_SYSROOT_VERSION_MAJOR).$(WASI_SYSROOT_VERSION_MINOR).tar.gz .sum-wasi-sysroot
	$(UNPACK)

.wasi-sysroot: wasi-sysroot
	touch $@
