#!/bin/bash -x

:<< COMMENTS
1. self-signed certificate
2. MSYS_NO_PATHCONV=1
   [MINGW issue] do not treat '\' as escape character on MINGW
COMMENTS

:<< HELP
    RSA     - RSA certificate (RSA3072)
    ECDSA   - ECDSA certificate (P-384)
    P-256
    P-384
    P-521
    MLDSA   - MLDSA certificate (ML-DSA-65)
    MLDSA44
    MLDSA65
    MLDSA87
    EDDSA   - EDDSA Certificate (ED25519)
    ED25519
    ED448
    clean   - delete certificate files (and then exit)
HELP

set -euo pipefail

certtype="ecdsa"

args=("$@")

if [ ${#args[@]} -ne 0 ]; then
    for arg in "${args[@]}"; do
        item=$(echo "$arg" | tr '[:upper:]' '[:lower:]')
        if [ "$item" = "ecdsa" ]; then
            certtype=$item
        elif [ "$item" = "p-256" ]; then
            certtype=$item
        elif [ "$item" = "p-384" ]; then
            certtype=$item
        elif [ "$item" = "p-521" ]; then
            certtype=$item
        elif [ "$item" = "rsa" ]; then
            certtype=$item
        elif [ "$item" = "mldsa" ]; then
            certtype=$item
        elif [ "$item" = "mldsa44" ]; then
            certtype=$item
        elif [ "$item" = "mldsa65" ]; then
            certtype=$item
        elif [ "$item" = "mldsa87" ]; then
            certtype=$item
        elif [ "$item" = "eddsa" ]; then
            certtype=$item
        elif [ "$item" = "ed25519" ]; then
            certtype=$item
        elif [ "$item" = "ed448" ]; then
            certtype=$item
        elif [ "$item" = "clean" ]; then
            rm -f root-* server-* *.srl *.pem
            exit
        else
            exit
        fi
    done
fi

algorithm=""
pkeyopt=()
digest=""

# root.key
if [ "${certtype}" = "ecdsa" ]; then
    algorithm="ec"
    pkeyopt=( -pkeyopt ec_paramgen_curve:P-384 )
    digest="-sha384"
elif [ "${certtype}" = "p-256" ]; then
    algorithm="ec"
    pkeyopt=( -pkeyopt ec_paramgen_curve:P-256 )
    digest="-sha256"
elif [ "${certtype}" = "p-384" ]; then
    algorithm="ec"
    pkeyopt=( -pkeyopt ec_paramgen_curve:P-384 )
    digest="-sha384"
elif [ "${certtype}" = "p-521" ]; then
    algorithm="ec"
    pkeyopt=( -pkeyopt ec_paramgen_curve:P-521 )
    digest="-sha512"
elif [ "${certtype}" = "mldsa" ]; then
    # ML-DSA-44 ML-DSA-65 ML-DSA-87
    algorithm="ML-DSA-65"
elif [ "${certtype}" = "mldsa44" ]; then
    algorithm="ML-DSA-44"
elif [ "${certtype}" = "mldsa65" ]; then
    algorithm="ML-DSA-65"
elif [ "${certtype}" = "mldsa87" ]; then
    algorithm="ML-DSA-87"
elif [ "${certtype}" = "rsa" ]; then
    algorithm="rsa"
    pkeyopt=( -pkeyopt rsa_keygen_bits:3072 )
    digest="-sha256"
elif [ "${certtype}" = "eddsa" ]; then
    algorithm="Ed25519"
elif [ "${certtype}" = "ed25519" ]; then
    algorithm="Ed25519"
elif [ "${certtype}" = "ed448" ]; then
    algorithm="Ed448"
else
    exit
fi
openssl genpkey -algorithm "${algorithm}" "${pkeyopt[@]}" -out root-${certtype}.key

# root.csr
MSYS_NO_PATHCONV=1 openssl req -new ${digest} -key root-${certtype}.key -out root-${certtype}.csr -subj '/C=KR/ST=KN/L=GJ/O=Test/OU=Test/CN=Test Root'
# review root.csr
openssl req -in root-${certtype}.csr -noout -text
# root.ext
cat << EOF > root-${certtype}.ext
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
# root.crt
openssl x509 -req -days 3650 -in root-${certtype}.csr -signkey root-${certtype}.key -extfile root-${certtype}.ext -out root-${certtype}.crt
# review root.crt
openssl x509 -text -in root-${certtype}.crt

# server-encrypted.key
openssl genpkey -algorithm ${algorithm} "${pkeyopt[@]}" -out server-${certtype}-tmp.key
openssl pkey -aes256 -in server-${certtype}-tmp.key -out server-${certtype}-encrypted.key

rm -f server-${certtype}-tmp.key 

# server.key
openssl pkey -in server-${certtype}-encrypted.key -out server-${certtype}.key
# server.csr
MSYS_NO_PATHCONV=1 openssl req -new ${digest} -key server-${certtype}.key -out server-${certtype}.csr -subj '/C=KR/ST=KN/L=GJ/O=Test/OU=Test/CN=test.com'
# server.ext
if [ "${certtype}" = "rsa" ]; then
    KU="digitalSignature, keyEncipherment"
else
    KU="digitalSignature"
fi
cat << EOF > server-${certtype}.ext
basicConstraints = CA:FALSE
keyUsage = ${KU}
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[alt_names]
DNS.1 = test.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
# server.crt
openssl x509 -req -days 365 -in server-${certtype}.csr -extfile server-${certtype}.ext -CA root-${certtype}.crt -CAkey root-${certtype}.key -CAcreateserial -out server-${certtype}.crt
# review server.crt
# openssl x509 -noout -text -in server-${certtype}.crt
openssl verify -CAfile root-${certtype}.crt server-${certtype}.crt
