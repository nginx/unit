FROM unit:wasm AS build
WORKDIR /demo

# Get all the build tools we need
#
RUN apt update && apt install -y wget build-essential clang lld
RUN cd /usr/lib/llvm-11/lib/clang/11.0.1 && wget -O- https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-20/libclang_rt.builtins-wasm32-wasi-20.0.tar.gz | tar zxvf -
RUN wget -O- https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-20/wasi-sysroot-20.0.tar.gz | tar zxfv -

# Copy-in the demo application source code and build into a .wasm module
#
ADD src/ /demo/
RUN make

# Copy the .wasm modules and Unit configuration to the final Docker image
# that will run the demo application.
#
FROM unit:wasm
COPY --from=build /demo/*.wasm /demo/
ADD wasm-conf.json /docker-entrypoint.d
