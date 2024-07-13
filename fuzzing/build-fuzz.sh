#!/usr/bin/env bash

export CC=clang
export CXX=clang++
export CFLAGS="-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fsanitize=fuzzer-no-link"
export CXXFLAGS="-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address,undefined -fsanitize=fuzzer-no-link"
export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"

./configure --no-regex --no-pcre2 --fuzz=$LIB_FUZZING_ENGINE
make fuzz -j$(nproc)

mkdir -p build/fuzz_basic_seed
mkdir -p build/fuzz_http_controller_seed
mkdir -p build/fuzz_http_h1p_seed
mkdir -p build/fuzz_http_h1p_peer_seed
mkdir -p build/fuzz_json_seed

echo ""
echo "Run: ./build/\${fuzzer} build/\${fuzzer}_seed fuzzing/\${fuzzer}_seed_corpus"
echo ""
