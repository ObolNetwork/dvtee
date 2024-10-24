#!/bin/bash

# Generate a password-protected self-signed certifiacte and the corresponding known 
# client file as described in https://docs.web3signer.consensys.io/how-to/configure-tls

mkdir -p w3s_tls && cd w3s_tls

# First generate an x509 certificate
openssl ecparam -name prime256v1 -genkey -noout -out privatekey.pem
openssl req -new -x509 -key privatekey.pem -out certificate.pem -days 365 -subj "/O=client/CN=client"

# Then export it to a password-encrypted PKCS12 keystore
openssl rand -base64 16 > password.txt
openssl pkcs12 -export -out client_keystore.p12 -inkey privatekey.pem -in certificate.pem -passout pass:$(cat password.txt)

# Finally generate the known client file which embeds the Common Name along with the SHA256 digest of the keystore
echo -n "client " > knownClient.txt
echo -n $(openssl x509 -in certificate.pem -noout -fingerprint -sha256 | awk -F'=' '{print $2}') >> knownClient.txt

# Remove .pem files
rm *.pem

cd ..