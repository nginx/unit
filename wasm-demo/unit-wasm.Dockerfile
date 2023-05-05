# Start with the minimal Docker Official Image so we can use the same defaults
#
FROM unit:minimal AS build
WORKDIR /src

# Get all the build tools we need, including Wasmtime
#
#RUN apt update && apt install -y wget git build-essential clang lld libpcre2-dev libssl-dev
RUN apt update && apt install -y wget git build-essential libpcre2-dev libssl-dev
RUN wget -O- https://github.com/bytecodealliance/wasmtime/releases/download/v11.0.0/wasmtime-v11.0.0-$(arch)-linux-c-api.tar.xz \
    | tar Jxfv - && \
    mkdir /usr/lib/wasmtime && \
    cp /src/wasmtime-v11.0.0-$(arch)-linux-c-api/lib/* /usr/lib/wasmtime

# Build NGINX JavaScript (njs) so that we have a feature-complete Unit
#
RUN git clone https://github.com/nginx/njs.git && \
    cd njs && \
    ./configure --no-libxml2 --no-zlib && \
    make

# Build Unit with the Wasm module, copying the configure arguments from the
# official image.
#
RUN git clone https://github.com/nginx/unit.git && \
    cd unit && \
    wget -O- https://github.com/nginx/unit/pull/902.patch | patch -p1 && \
    ./configure $(unitd --version 2>&1 | tr ' ' '\n' | grep ^-- | grep -v opt=) \
                --cc-opt="-I/src/njs/src -I/src/njs/build" --ld-opt=-L/src/njs/build && \
    ./configure wasm --include-path=/src/wasmtime-v11.0.0-$(arch)-linux-c-api/include \
                     --lib-path=/usr/lib/wasmtime --rpath && \
    make

# Create a clean final image by copying over only Wasmtime, the new unitd
# binary, and the Wasm module.
#
FROM unit:minimal
COPY --from=build /src/unit/build/sbin/unitd /usr/sbin
COPY --from=build /src/unit/build/lib/unit/modules/wasm.unit.so /usr/lib/unit/modules
COPY --from=build /usr/lib/wasmtime/*.so /usr/lib/wasmtime/
