# Fuzzing unit

These tests are generally advised to run only on GNU/Linux.

## Build fuzzers using libFuzzer.

Running `sh fuzzing/build-fuzz.sh` can build all the fuzzers with standard
`ASan` and `UBSan`.

### More comprehensive How-to Guide.

#### Export flags that are to be used by Unit for fuzzing.

Note that in `CFLAGS` and `CXXFLAGS`, any type of sanitizers can be added.

- [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html),
    [ThreadSanitizer](https://clang.llvm.org/docs/ThreadSanitizer.html),
    [MemorySanitizer](https://clang.llvm.org/docs/MemorySanitizer.html),
    [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html),
    [LeakSanitizer](https://clang.llvm.org/docs/LeakSanitizer.html).

```shell
$ export CC=clang
$ export CXX=clang++
$ export CFLAGS="-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link"
$ export CXXFLAGS="-g -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION  -fsanitize=fuzzer-no-link"
$ export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
```

#### Build Unit for Fuzzing.

```shell
$ ./configure --no-regex --no-pcre2 --fuzz=$LIB_FUZZING_ENGINE
$ make fuzz -j$(nproc)
```

#### Running fuzzers.

```shell
$ mkdir -p build/fuzz_basic_seed
$ mkdir -p build/fuzz_http_controller_seed
$ mkdir -p build/fuzz_http_h1p_seed
$ mkdir -p build/fuzz_http_h1p_peer_seed
$ mkdir -p build/fuzz_json_seed

$ ./build/fuzz_basic            build/fuzz_basic_seed            fuzzing/fuzz_basic_seed_corpus
$ ./build/fuzz_http_controller  build/fuzz_http_controller_seed  fuzzing/fuzz_http_seed_corpus
$ ./build/fuzz_http_h1p         build/fuzz_http_h1p_seed         fuzzing/fuzz_http_seed_corpus
$ ./build/fuzz_http_h1p_peer    build/fuzz_http_h1p_peer_seed    fuzzing/fuzz_http_seed_corpus
$ ./build/fuzz_json             build/fuzz_json_seed             fuzzing/fuzz_json_seed_corpus
```

Here is more information about [LibFuzzer](https://llvm.org/docs/LibFuzzer.html).

## Build fuzzers using other fuzzing engines.

- [Honggfuzz](https://github.com/google/honggfuzz/blob/master/docs/PersistentFuzzing.md).
- [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/aflpp_driver/README.md).


## Requirements.

You will likely need at least the following packages installed (package names
may vary).

```
clang, llvm & compiler-rt
```
