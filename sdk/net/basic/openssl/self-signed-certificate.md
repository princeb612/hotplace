## Publication

```text
┌──────────────────────────────────────────────┐
│ hotplace source tree                         │
│ Edition 1 · Revision 1104                    │
│ Documented with GPT-6                        │
│ — source structure, implementation & tests   │
└──────────────────────────────────────────────┘
```
# self-signed certificate

## 1. Role

This document identifies the module or protocol area represented by this file.

## 2. Model

see test/cert/make.sh

```
#!/bin/bash

# root.key (RSA)
openssl genrsa -aes256 -out root.key 2048
# root.key (ECDSA)
openssl ecparam -name prime256v1 -genkey -out root.key

# root.csr
openssl req -new -key root.key -out root.csr -subj '/C=KR/ST=GG/L=YI/O=Test/OU=Test/CN=Test Root'
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
openssl req -new -key server.key -out server.csr -subj '/C=KR/ST=GG/L=YI/O=Test/OU=Test/CN=Test'
# server.ext
cat << EOF > server.ext
subjectAltName = @alt_names

[alt_names]
DNS = test.princeb612.pe
EOF
# server.crt
openssl x509 -req -days 365 -in server.csr -extfile server.ext -CA root.crt -CAkey root.key -CAcreateserial -out server.crt
# review server.crt
openssl x509 -text -in server.crt
```

## 3. Important behavior and lifetime

Implementation details and behavior are described where the existing source-tree notes provide evidence.

## 4. Example from the source tests

See the referenced testcase sources for concrete examples. Where no direct test is identified, this is not evidence of runtime verification.

## 5. Relationships

Related implementation areas and protocol boundaries are recorded here where identified.

## 6. References

Source references and related documents are retained here where available.
