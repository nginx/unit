#!/bin/bash -eu

# Build unit
./configure --no-regex --no-pcre2 --fuzz="$LIB_FUZZING_ENGINE"
make fuzz -j"$(nproc)"

# Copy all fuzzers.
cp build/fuzz_* $OUT/

# cd into fuzzing dir
pushd fuzzing/
cp fuzz_http.dict $OUT/fuzz_http_controller.dict
cp fuzz_http.dict $OUT/fuzz_http_h1p.dict
cp fuzz_http.dict $OUT/fuzz_http_h1p_peer.dict

# Create temporary directories.
cp -r fuzz_http_seed_corpus/ fuzz_http_controller_seed_corpus/
cp -r fuzz_http_seed_corpus/ fuzz_http_h1p_seed_corpus/
cp -r fuzz_http_seed_corpus/ fuzz_http_h1p_peer_seed_corpus/

zip -r $OUT/fuzz_basic_seed_corpus.zip fuzz_basic_seed_corpus/
zip -r $OUT/fuzz_http_controller_seed_corpus.zip  fuzz_http_controller_seed_corpus/
zip -r $OUT/fuzz_http_h1p_seed_corpus.zip  fuzz_http_h1p_seed_corpus/
zip -r $OUT/fuzz_http_h1p_peer_seed_corpus.zip  fuzz_http_h1p_peer_seed_corpus/
zip -r $OUT/fuzz_json_seed_corpus.zip fuzz_json_seed_corpus/

# Delete temporary directories.
rm -r fuzz_http_controller_seed_corpus/ fuzz_http_h1p_seed_corpus/ fuzz_http_h1p_peer_seed_corpus/
popd
