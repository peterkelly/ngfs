Generate certificate authority

# Certificate authority

openssl ecparam -name prime256v1 -genkey -noout -out ec-ca-private-key.pem
openssl ec -in ec-ca-private-key.pem -pubout -out ec-ca-public-key.pem
openssl req -x509 -new -nodes -key ec-ca-private-key.pem -sha256 -days 1825 -out ec-ca-certificate.pem

# Server certificate

openssl ecparam -name prime256v1 -genkey -noout -out ec-server-private-key.pem
openssl req -new -key ec-server-private-key.pem -out ec-server-certificate-request.pem
openssl x509 \
    -req \
    -in ec-server-certificate-request.pem \
    -CA ec-ca-certificate.pem \
    -CAkey ec-ca-private-key.pem \
    -CAcreateserial \
    -out ec-server-certificate.pem \
    -days 825 \
    -sha256 \
    -extfile ec-server.ext

ec-server.ext

authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = DNS:localhost

# Client certificate

openssl ecparam -name prime256v1 -genkey -noout -out ec-client-private-key.pem
openssl req -new -key ec-client-private-key.pem -out ec-client-certificate-request.pem
openssl x509 \
    -req \
    -in ec-client-certificate-request.pem \
    -CA ec-ca-certificate.pem \
    -CAkey ec-ca-private-key.pem \
    -CAcreateserial \
    -out ec-client-certificate.pem \
    -days 825 \
    -sha256
