#!/bin/bash
set -eu
OPENSSL=/opt/homebrew/Cellar/openssl\@1.1/1.1.1s/bin/openssl
OUTNAME=certsample
"$OPENSSL" req \
    -new \
    -newkey rsa:2048 \
    -keyout "$OUTNAME.key" \
    -nodes \
    -x509 \
    -out "$OUTNAME.crt.pem" \
    -subj "/CN=localhost" \
    -addext '1.3.6.1.4.1.53594.1.1=ASN1:BITSTRING:abcdef1234556789'


#    -addext '1.3.6.1.4.1.53594.1.1=critical,ASN1:UTF8String:Some random data'
"$OPENSSL" x509 -in "$OUTNAME.crt.pem" -out "$OUTNAME.crt.der" -outform der
"$OPENSSL" x509 -in "$OUTNAME.crt.pem" -noout -text > "$OUTNAME.crt.txt"
