#!/bin/bash -x

:<< COMMENTS
1. self-signed certificate
2. MSYS_NO_PATHCONV=1
   [MINGW issue] do not treat '\' as escape character on MINGW
COMMENTS

:<< HELP
    RSA   - RSA certificate
    ECDSA - ECDSA certificate
    MLDSA - ML DSA certificate
    clean - delete certificate files (and then exit)
HELP

certtype="ecdsa"

args=("$@")

if [ ${#args[@]} -ne 0 ]; then
    for arg in ${args[@]}; do
        item=`echo "$arg" | tr '[:upper:]' '[:lower:]'`
        if [ $item = 'ecdsa' ]; then
            certtype=$item
        elif [ $item = 'rsa' ]; then
            certtype=$item
        elif [ $item = 'mldsa' ]; then
            certtype=$item
        elif [ $item = 'clean' ]; then
            rm -f *.ext *.crt *.csr *.key *.srl
            exit
        fi
    done
fi

# root.key
if [ ${certtype} = 'ecdsa' ]; then
    openssl ecparam -name prime256v1 -genkey -out root-${certtype}.key
elif [ ${certtype} = 'rsa' ]; then
    openssl genrsa -out root-${certtype}.key 2048
elif [ ${certtype} = 'mldsa' ]; then
    # ML-DSA-44 ML-DSA-65 ML-DSA-87
    openssl genpkey -algorithm ML-DSA-65 -out root-${certtype}.key
else
    exit
fi

# root.csr
MSYS_NO_PATHCONV=1 openssl req -new -key root-${certtype}.key -out root-${certtype}.csr -subj '/C=KR/ST=KN/L=GJ/O=Test/OU=Test/CN=Test Root'
# review root.csr
openssl req -in root-${certtype}.csr -noout -text
# root.ext
echo "basicConstraints = CA:TRUE" > root-${certtype}.ext
# root.crt
openssl x509 -req -days 3650 -in root-${certtype}.csr -signkey root-${certtype}.key -extfile root-${certtype}.ext -out root-${certtype}.crt
# review root.crt
openssl x509 -text -in root-${certtype}.crt

# server-encrypted.key
openssl genrsa -aes256 -out server-${certtype}-encrypted.key 2048
# server.key
openssl rsa -in server-${certtype}-encrypted.key -out ${certtype}.key
# server.csr
MSYS_NO_PATHCONV=1 openssl req -new -key ${certtype}.key -out server-${certtype}.csr -subj '/C=KR/ST=KN/L=GJ/O=Test/OU=Test/CN=Test'
# server.ext
cat << EOF > server-${certtype}.ext
subjectAltName = @alt_names

[alt_names]
DNS = test.com
EOF
# server.crt
openssl x509 -req -days 365 -in server-${certtype}.csr -extfile server-${certtype}.ext -CA root-${certtype}.crt -CAkey root-${certtype}.key -CAcreateserial -out ${certtype}.crt
# review server.crt
openssl x509 -text -in ${certtype}.crt
