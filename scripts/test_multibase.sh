#!/bin/bash
set -eu
SCRIPT_DIR="$(dirname -- "$0")"
cd "$SCRIPT_DIR/.."

BASES="
    base16 \
    base16upper \
    base32 \
    base32upper \
    base32pad \
    base32padupper \
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
    target/debug/test_multibase temp/test_multibase/expected/numbers.txt "$B" > "temp/test_multibase/actual/$B.txt"
    if diff -qr "temp/test_multibase/expected/$B.txt" "temp/test_multibase/actual/$B.txt" >/dev/null 2>/dev/null; then
        # echo "base $B: PASS"
        printf "%-20s %s\n" "$B" "PASS"
    else
        # echo "base $B: FAIL"
        printf "%-20s %s\n" "$B" "FAIL"
    fi
done
