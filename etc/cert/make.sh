#!/bin/bash -x

:<< COMMENTS
1. self-signed certificate
2. MSYS_NO_PATHCONV=1
   [MINGW issue] do not treat '\' as escape character on MINGW
COMMENTS

:<< HELP
    RSA   - RSA certificate
    ECDSA - ECDSA certificate
    clean - delete certificate files (and then exit)
HELP

CERTTYPE='ECDSA'

args=("$@")

if [ ${#args[@]} -ne 0 ]; then
    for arg in ${args[@]}; do
        item=`echo "$arg" | tr '[:upper:]' '[:lower:]'`
        if [ $item = 'ecdsa' ]; then
            CERTTYPE=ECDSA
        elif [ $item = 'rsa' ]; then
            CERTTYPE=RSA
        elif [ $item = 'clean' ]; then
            rm -f *.ext *.crt *.csr *.key *.srl
            exit
        fi
    done
fi

# root.key
if [ $CERTTYPE = 'ECDSA' ]; then
    openssl ecparam -name prime256v1 -genkey -out root.key
elif [ $CERTTYPE = 'RSA' ]; then
    openssl genrsa -aes256 -genkey -out root.key 2048
else
    exit
fi

# root.csr
MSYS_NO_PATHCONV=1 openssl req -new -key root.key -out root.csr -subj '/C=KR/ST=KN/L=GJ/O=Test/OU=Test/CN=Test Root'
# review root.csr
openssl req -in root.csr -noout -text
# root.ext
echo "basicConstraints = CA:TRUE" > root.ext
# root.crt
openssl x509 -req -days 3650 -in root.csr -signkey root.key -extfile root.ext -out root.crt
# review root.crt
openssl x509 -text -in root.crt

# server-encrypted.key
openssl genrsa -aes256 -out server-encrypted.key 2048
# server.key
openssl rsa -in server-encrypted.key -out server.key
# server.csr
MSYS_NO_PATHCONV=1 openssl req -new -key server.key -out server.csr -subj '/C=KR/ST=GG/L=YI/O=Test/OU=Test/CN=Test'
# server.ext
cat << EOF > server.ext
subjectAltName = @alt_names

[alt_names]
DNS = test.com
EOF
# server.crt
openssl x509 -req -days 365 -in server.csr -extfile server.ext -CA root.crt -CAkey root.key -CAcreateserial -out server.crt
# review server.crt
openssl x509 -text -in server.crt

if [ $CERTTYPE = 'ECDSA' ]; then
    cp server.crt ecdsa.crt
    cp server.key ecdsa.key
elif [ $CERTTYPE = 'RSA' ]; then
    cp server.crt rsa.crt
    cp server.key rsa.key
fi
