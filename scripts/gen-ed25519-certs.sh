#!/bin/bash
set -eu
OPENSSL=/opt/homebrew/Cellar/openssl\@1.1/1.1.1s/bin/openssl
OUTDIR=certificates/ed25519
#OUTNAME=certsample

"$OPENSSL" genpkey -algorithm ed25519 -out "$OUTDIR/ca.key"
"$OPENSSL" genpkey -algorithm ed25519 -out "$OUTDIR/client.key"
"$OPENSSL" genpkey -algorithm ed25519 -out "$OUTDIR/server.key"

#"$OPENSSL" pkey -in "$OUTDIR/ca-private-key.pem" -out "$OUTDIR/ca-public-key.pem" -pubout

# Generate self-signed certificate for the certificate authority
"$OPENSSL" req \
    -x509 \
    -new \
    -nodes \
    -key "$OUTDIR/ca.key" \
    -sha256 \
    -days 1825 \
    -out "$OUTDIR/ca.crt" \
    -subj '/C=US/O=My Certificate Authority'

# Generate client certificate
"$OPENSSL" req \
    -new \
    -key \
    "$OUTDIR/client.key" \
    -out "$OUTDIR/client.csr" \
    -subj '/C=US/O=Client'

"$OPENSSL" x509 \
    -req \
    -in "$OUTDIR/client.csr" \
    -CA "$OUTDIR/ca.crt" \
    -CAkey "$OUTDIR/ca.key" \
    -CAcreateserial \
    -out "$OUTDIR/client.crt" \
    -days 825 \
    -sha256

rm -f "$OUTDIR/client.csr"

# Generate server certificate
"$OPENSSL" req \
    -new \
    -key \
    "$OUTDIR/server.key" \
    -out "$OUTDIR/server.csr" \
    -subj '/C=US/O=Server'

"$OPENSSL" x509 \
    -req \
    -in "$OUTDIR/server.csr" \
    -CA "$OUTDIR/ca.crt" \
    -CAkey "$OUTDIR/ca.key" \
    -CAcreateserial \
    -out "$OUTDIR/server.crt" \
    -days 825 \
    -sha256

rm -f "$OUTDIR/server.csr"
