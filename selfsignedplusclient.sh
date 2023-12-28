#!/bin/bash

# Configuration
ROOT_KEY="ecc_root.key"
ROOT_CERT="ecc_root.crt"
ROOT_CONFIG="root_openssl.cnf"
CLIENT_CONFIG="client_openssl.cnf"
CLIENTS=10
IP="192.168.253"

# Write config
echo "[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
x509_extensions    = v3_ca
prompt             = no

[ req_distinguished_name ]
# Empty fields except for the IP
CN                 = ${IP}.1

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
" > $ROOT_CONFIG

# Generate ECC-521 root key
openssl ecparam -name secp521r1 -genkey -out $ROOT_KEY

# Create a self-signed root certificate
openssl req -new -x509 -sha512 -key $ROOT_KEY -out $ROOT_CERT -days 365 -config $ROOT_CONFIG


# Generate client certificates
for i in $(seq 2 $CLIENTS); do
echo "[ req ]
default_bits       = 4096
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
CN                 = ${IP}.${i}

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
" > $CLIENT_CONFIG
    CLIENT_KEY="client_${i}.key"
    CLIENT_CSR="client_${i}.csr"
    CLIENT_CERT="client_${i}.crt"

    # Generate a client key
    openssl ecparam -name secp521r1 -genkey -out $CLIENT_KEY

    # Generate a CSR for the client
    openssl req -new -key $CLIENT_KEY -out $CLIENT_CSR -config $CLIENT_CONFIG

    # Generate a client certificate signed with the root certificate
    openssl x509 -req -days 365 -in $CLIENT_CSR -CA $ROOT_CERT -CAkey $ROOT_KEY -CAcreateserial -out $CLIENT_CERT
done
rm $ROOT_CONFIG
rm $CLIENT_CONFIG
rm *.csr
