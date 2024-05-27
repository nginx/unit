# libunit-wasm

include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/version
LIBUNIT_WASM_URL := https://github.com/nginx/unit-wasm.git

PKGS += libunit-wasm

DEPS_libunit-wasm = wasi-sysroot $(DEPS_wasi-sysroot)

$(TARBALLS)/libunit-wasm-$(LIBUNIT_WASM_GITHASH).tar.xz:
	$(call download_git,$(LIBUNIT_WASM_URL),,$(LIBUNIT_WASM_GITHASH))

.sum-libunit-wasm: libunit-wasm-$(LIBUNIT_WASM_GITHASH).tar.xz
	$(call check_githash,$(LIBUNIT_WASM_GITHASH))
	touch $@

libunit-wasm: libunit-wasm-$(LIBUNIT_WASM_GITHASH).tar.xz
	$(UNPACK)
	$(MOVE)

.libunit-wasm: libunit-wasm
	cd $< && CFLAGS= make WASI_SYSROOT=$(TOPSRC)wasi-sysroot V=1 libunit-wasm
	touch $@
