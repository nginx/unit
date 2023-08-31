# wasmtime

include $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/version
WASMTIME_URL := https://github.com/bytecodealliance/wasmtime/releases/download/v$(WASMTIME_VERSION)/wasmtime-v$(WASMTIME_VERSION)-src.tar.gz

PKGS += wasmtime

ifeq ($(shell which cargo >/dev/null 2>&1 || echo FAIL),)
CARGO = cargo
else
CARGO = $(error Cargo (Rust package manager) not found)
endif

ifeq ($(shell uname -s),Linux)
WASMTIME_ARGS=-Clink-arg=-Wl,-soname,libwasmtime.so
endif

$(TARBALLS)/wasmtime-v$(WASMTIME_VERSION)-src.tar.gz:
	$(call download_pkg,$(WASMTIME_URL),wasmtime)

.sum-wasmtime: wasmtime-v$(WASMTIME_VERSION)-src.tar.gz

wasmtime: wasmtime-v$(WASMTIME_VERSION)-src.tar.gz .sum-wasmtime
	$(UNPACK)
	$(MOVE)

.wasmtime: wasmtime
	cd $< && $(CARGO) rustc --release -p wasmtime-c-api -- $(WASMTIME_ARGS)
	cp $</crates/c-api/wasm-c-api/include/wasm.h $</crates/c-api/include/
	touch $@
