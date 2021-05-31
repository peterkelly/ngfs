#!/bin/bash
set -eu
SCRIPT_DIR="$(dirname -- "$0")"
cd "$SCRIPT_DIR/.."

BASES="
    base16 \
    base32 \
    base32pad \
    base58flickr \
    base58btc \
    base64 \
    base64pad \
    base64url \
    base64urlpad \
    "

mkdir -p temp
rm -rf temp/test_multibase
mkdir -p temp/test_multibase
mkdir -p temp/test_multibase/expected
mkdir -p temp/test_multibase/actual
node testdata/multihash/generate.js temp/test_multibase/expected


for B in $BASES; do
    echo base $B
    target/debug/test_multibase temp/test_multibase/expected/numbers.txt $B > temp/test_multibase/actual/$B
done
