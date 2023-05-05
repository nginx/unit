SYSROOT	= /demo/wasi-sysroot

CC	= clang
CFLAGS	= -Wall -Wextra -Wdeclaration-after-statement -Wvla -std=gnu11 \
	  -fno-strict-aliasing --target=wasm32-wasi --sysroot=$(SYSROOT) \
	  -Iinclude
LDFLAGS	= -Wl,--no-entry,--export=__heap_base,--export=__data_end,--export=malloc,--export=free,--stack-first,-z,stack-size=$$((8*1024*1024)) \
	  -mexec-model=reactor --rtlib=compiler-rt

all: luw-echo-request luw-upload-reflector libunit-wasm.a

libunit-wasm.o: libunit-wasm.c include/unit/unit-wasm.h
	$(CC) $(CFLAGS) -fvisibility=hidden -c $<

libunit-wasm.a: libunit-wasm.o
	llvm-ar rcs $@ $<

luw-echo-request: luw-echo-request.c libunit-wasm.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@.wasm $< libunit-wasm.o

luw-upload-reflector: luw-upload-reflector.c libunit-wasm.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@.wasm $< libunit-wasm.o

crate: libunit-wasm.a rust/libunit-wasm/build.rs rust/libunit-wasm/src/lib.rs rust/libunit-wasm/Cargo.toml
	bindgen include/unit/unit-wasm.h -o rust/libunit-wasm/src/bindings.rs \
	 --allowlist-function '^luw_.*' --allowlist-var '^luw_.*' \
	 --allowlist-type '^luw_.*' -- --target=wasm32-wasi
	cd rust/libunit-wasm; cargo build --target=wasm32-wasi

unit-wasm-raw.o: unit-wasm-raw.c unit-wasm-raw.h
	$(CC) $(CFLAGS) -c $<

echo-request-raw: echo-request-raw.c unit-wasm-raw.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@.wasm $< unit-wasm-raw.o

upload-reflector-raw: upload-reflector-raw.c unit-wasm-raw.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@.wasm $< unit-wasm-raw.o

clean:
	rm -f *.wasm *.o *.a *.gch
