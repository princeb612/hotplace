# hotplace

* Research on personal interests
* ![cmake workflow](https://github.com/princeb612/hotplace/actions/workflows/build.yml/badge.svg)
* powered by
  * ![openssl](https://img.shields.io/badge/openssl-1.1.1/3.0/3.2/3.3/3.4/3.5-green)
  * ![jansson](https://img.shields.io/badge/jansson-2.14-green)
  * ![zlib](https://img.shields.io/badge/zlb-1.3.1-green)
* language
  * ![c++](https://img.shields.io/badge/c++-c++11-green)
  * ![gcc](https://img.shields.io/badge/gcc->=4.7-green)
  * ![cmake](https://img.shields.io/badge/cmake->=2.6-green)
* platform
  * ![MSYS2](https://img.shields.io/badge/MSYS2-MINGW64-green)
  * ![UBUNTU](https://img.shields.io/badge/UBUNTU-green)
  * ![RHEL](https://img.shields.io/badge/RHEL-green)
* status
  * JOSE ![implemented](https://img.shields.io/badge/implemented+SDK-green)
  * CBOR,COSE ![implemented](https://img.shields.io/badge/implemented+SDK-green)
  * HTTP/1.1 ![implemented](https://img.shields.io/badge/implemented+SDK-green)
  * HTTP/2 ![implemented](https://img.shields.io/badge/implemented+SDK-green)
  * TLS over TCP ![implemented](https://img.shields.io/badge/implemented+SDK-green)
  * DTLS over UDP ![implemented](https://img.shields.io/badge/implemented+SDK-green)
  * QUIC ![studying](https://img.shields.io/badge/studying-magenta)
  * HTTP/3 ![studying](https://img.shields.io/badge/studying-magenta)
  * ASN.1 ![studying](https://img.shields.io/badge/studying-magenta)
* link
  * [changelog](CHANGELOG.md)
  * [devnotes](DEVNOTES.md)
  * [implemented](#implemented)
  * [applied](#applied)
  * [not applied](#not-applied)
  * [studying](#studying)
  * [next time](#next-time)
  * [build](#build)
  * [custom toolchain](#custom-toolchain)
  * [link](#link)

## implemented

* TLS,DTLS,QUIC
  * RFC 2246 The TLS Protocol Version 1.0
  * RFC 4346 The Transport Layer Security (TLS) Protocol Version 1.1
    * deprecated
  * RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
  * RFC 6347 Datagram Transport Layer Security Version 1.2
  * RFC 7627 Transport Layer Security (TLS) Session Hash and Extended Master Secret Extension
  * RFC 7905 ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)
  * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
  * RFC 8448 Example Handshake Traces for TLS 1.3
  * RFC 9147 The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
    * sdk/net/tls/tls/
    * test/tls/
  * RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
  * RFC 9001 Using TLS to Secure QUIC
  * RFC 9369 QUIC Version 2
    * sdk/net/tls/quic/
    * test/quic/
  * ML-KEM Post-Quantum Key Agreement for TLS 1.3
    * [draft-ietf-tls-mlkem-05](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/)
    * [draft-ietf-tls-ecdhe-mlkem-03](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
    * test/tls/
* CBOR
  * RFC 7049 Concise Binary Object Representation (CBOR)
  * RFC 8949 Concise Binary Object Representation (CBOR)
    * sdk/io/cbor/
    * test/cbor/
* COSE
  * RFC 8152 CBOR Object Signing and Encryption (COSE)
  * RFC 8230 Using RSA Algorithms with CBOR Object Signing and Encryption (COSE) Messages
  * RFC 8392 CBOR Web Token (CWT)
  * RFC 8812 CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms
  * RFC 9052 CBOR Object Signing and Encryption (COSE): Structures and Process
  * RFC 9053 CBOR Object Signing and Encryption (COSE): Initial Algorithms
  * RFC 9338 CBOR Object Signing and Encryption (COSE): Countersignatures
    * sdk/crypto/cose/
    * test/cose/
* JOSE
  * RFC 7515 JSON Web Signature (JWS)
  * RFC 7516 JSON Web Encryption (JWE)
  * RFC 7517 JSON Web Key (JWK)
  * RFC 7518 JSON Web Algorithms (JWA)
  * RFC 7520 Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
  * RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
    * sdk/crypto/jose/
    * test/jose/
* HTTP/1.1
  * RFC 1945 Hypertext Transfer Protocol -- HTTP/1.0
  * RFC 2068 Hypertext Transfer Protocol -- HTTP/1.1
  * RFC 2069 An Extension to HTTP : Digest Access Authentication
  * RFC 2396 Uniform Resource Identifiers (URI): Generic Syntax
  * RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
  * RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
  * RFC 6749 OAuth 2.0
  * RFC 6750 The OAuth 2.0 Authorization Framework: Bearer Token Usage
  * RFC 7616 HTTP Digest Access Authentication
    * sdk/net/http/
    * test/httpserver1/
    * test/httpauth/
    * test/httptest/
* HTTP/2
  * RFC 7541 HPACK: Header Compression for HTTP/2
    * sdk/net/http/http2/
    * test/hpack/
    * test/httpserver2/
  * RFC 7540 Hypertext Transfer Protocol Version 2 (HTTP/2)
  * RFC 7838 HTTP Alternative Services
  * RFC 9113 HTTP/2
    * sdk/net/http/http2/
    * sdk/net/basic/tls/
    * test/payload/
    * test/hpack/
    * test/httpaltsvc/
    * test/httpserver2/
* HTTP/3
  * RFC 9204 QPACK: Field Compression for HTTP/3
    * test/qpack/
* BASE16, BASE64, BASE64URL
  * RFC 4648 The Base16, Base32, and Base64 Data Encodings
    * sdk/base/basic/
    * test/encode/
* HOTP, TOTP
  * RFC 4226 HOTP: An HMAC-Based One-Time Password Algorithm
  * RFC 6238 TOTP: Time-Based One-Time Password Algorithm
    * sdk/crypto/basic/
    * test/hash/
* Pattern Search
  * KMP algorithm
  * Trie
  * Suffix Tree
  * Ukkonen algorithm
  * Aho-Corasick algorithm (wildcard)
    * sdk/base/pattern/
    * test/pattern/
    * test/parser/
* Graph
  * BFS, DFS, Djkstra
    * sdk/base/graph/
    * test/graph/
* Authenticode
  * Digital Certificate verification (plugin_msi, plugin_cabinet excluded)
    * sdk/crypto/authenticode/
    * test/authenticode/

## applied

* OpenSSL
  * RFC 2144 The CAST-128 Encryption Algorithm (May 1997)
  * RFC 2612 The CAST-256 Encryption Algorithm (June 1999)
  * RFC 3217 Triple-DES and RC2 Key Wrapping (December 2001)
  * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm (September 2002)
  * RFC 3610 Counter with CBC-MAC (CCM)
  * RFC 4615 The Advanced Encryption Standard-Cipher-based Message Authentication Code-Pseudo-Random Function-128 (AES-CMAC-PRF-128) Algorithm for the Internet Key Exchange Protocol (IKE)
  * RFC 4772 Security Implications of Using the Data Encryption Standard (DES) (December 2006)
  * RFC 5649 Advanced Encryption Starndard (AES) Key Wrap with Padding Algorithm (September 2009)
  * RFC 5794 A Description of the ARIA Encryption Algorithm (March 2010)
  * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
  * RFC 6070 PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors
  * RFC 7539 ChaCha20 and Poly1305 for IETF Protocols
  * RFC 7914 The scrypt Password-Based Key Derivation Function
  * RFC 8017 PKCS #1: RSA Cryptography Specifications Version 2.2
  * RFC 8439 ChaCha20 and Poly1305 for IETF Protocols
  * RFC 9106 Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
  * [Authenticated Encryption with AES-CBC and HMAC-SHA](https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt)
    * sdk/crypto/basic/
    * sdk/crypto/crypto/
    * test/crypto/
    * test/kdf/

  * RFC 2104 HMAC: Keyed-Hashing for Message Authentication
  * RFC 4231 HMAC-SHA Identifiers and Test Vectors December 2005
  * RFC 4493 The AES-CMAC Algorithm
  * RFC 6979 Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)
  * [NIST CAVP (Cryptographic Algorithm Validation Program) ECDSA](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/digital-signatures)
    * sdk/crypto/basic/
    * sdk/crypto/crypto/
    * test/hash/
    * test/sign/

  * RFC 4347 Datagram Transport Layer Security
  * RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
  * RFC 6347 Datagram Transport Layer Security Version 1.2
  * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
  * RFC 8996 Deprecating TLS 1.0 and TLS 1.1
  * RFC 9147 The Datagram Transport Layer Security (DTLS) Protocol Version 1.3
    * sdk/net/basic/tls/
    * test/tlsserver/
    * test/dtlsserver/

* Compression
  * RFC 1951 DEFLATE Compressed Data Format Specification version 1.3
  * RFC 1952 GZIP file format specification version 4.3
    * Accept-Encoding, Content-Encoding
    * test/httpserver1/
    * test/httpserver2/

* JOSE
  * RFC 7638 3.1.  Example JWK Thumbprint Computation
    * test/jose/

* IEEE 754
  * half/single/double precision floating point
    * test/ieee754/

* TLS
  * Post-quantum hybrid ECDHE-MLKEM Key Agreement for TLSv1.3
    * [draft-ietf-tls-ecdhe-mlkem-01](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/01/)
    * test/pqc/

## not applied


## studying

* HTTP/1.1
  * RFC 2817 Upgrading to TLS Within HTTP/1.1
* HTTP/3
  * RFC 9000 QUIC: A UDP-Based Multiplexed and Secure Transport
  * RFC 9001 Using TLS to Secure QUIC
  * RFC 9002 QUIC Loss Detection and Congestion Control
  * RFC 9114 HTTP/3
  * RFC 9368 Compatible Version Negotiation for QUIC
* TLS,DTLS
  * RFC 5746 Transport Layer Security (TLS) Renegotiation Indication Extension
  * RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
  * RFC 6347 Datagram Transport Layer Security Version 1.2
  * RFC 6797 HTTP Strict Transport Security (HSTS)
  * RFC 7301 Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension
  * RFC 7520 Using Raw Public Keys in Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
  * RFC 7685 A Transport Layer Security (TLS) ClientHello Padding Extension
  * RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
  * RFC 8422 Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS) Versions 1.2 and Earlier
  * RFC 9325 Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)

* ASN.1
  * ITU-T X.680-X.699
    * [X.680-X.693 : Information Technology - Abstract Syntax Notation One (ASN.1) & ASN.1 encoding rules](https://www.itu.int/rec/T-REC-X.680-X.693-202102-I/en)
      * Recommendation X.680-X.693 (02/21)
    * [ASN.1 (Abstract Syntax Notation One) is the international standard for representing data types and structures.](https://obj-sys.com/asn1tutorial/asn1only.html)
      * ITU-T X.680 ISO/IEC 8824-1 Abstract Syntax Notation One (ASN.1): Specification of basic notation
      * ITU-T X.681 ISO/IEC 8824-2 Abstract Syntax Notation One (ASN.1): Information object specification
      * ITU-T X.682 ISO/IEC 8824-3 Abstract Syntax Notation One (ASN.1): Constraint specification
      * ITU-T X.683 ISO/IEC 8824-4 Abstract Syntax Notation One (ASN.1): Parameterization of ASN.1 specifications
      * ITU-T X.690 ISO/IEC 8825-1 ASN.1 encoding rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
      * ITU-T X.691 ISO/IEC 8825-2 ASN.1 encoding rules: Specification of Packed Encoding Rules (PER)
      * ITU-T X.692 ISO/IEC 8825-3 ASN.1 encoding rules: Specification of Encoding Control Notation (ECN)
      * ITU-T X.693 ISO/IEC 8825-4 ASN.1 encoding rules: XML Encoding Rules (XER)
* Neural Networks / Machine Learning
  * sketch repository (private, spin off, in progress)

## next time

* Compression
  * RFC 7932 Brotli Compressed Data Format
  * RFC 8478 Zstandard Compression and the application/zstd Media Type
  * RFC 8878 Zstandard Compression and the 'application/zstd' Media Type
* COSE
  * RFC 8778 Use of the HSS/LMS Hash-Based Signature Algorithm with CBOR Object Signing and Encryption (COSE)
  * RFC 9021 Use of the Walnut Digital Signature Algorithm with CBOR Object Signing and Encryption (COSE)
  * RFC 9054 CBOR Object Signing and Encryption (COSE): Hash Algorithms
  * RFC 9360 CBOR Object Signing and Encryption (COSE): Header Parameters for Carrying and Referencing X.509 Certificates

## build

* platform support - mingw, linux
  * ubuntu
    * source env.ubuntu && install_packages
  * MINGW64
    * source env.mingw64 && install_packages
  * packages to install
    * gcc, g++, binutils, cmake, gdb
    * openssl-devel jansson-devel zlib-devel unixodbc (MINGW)
    * openssl-devel jansson zlib-devel unixodbc-devel (Rocky/CentOS/RHEL)
    * libssl-dev libjansson-dev zlib1g-dev unixodbc-dev (ubuntu)
    * valgrind (linux)
    * clang-tools-extra
* build script
  * cd hotplace
  * ./make.sh debug pch
* os support (x64)
  * tested
    * RHEL 7 and newer, (including CentOS, Rocky Linux)
    * ubuntu 20.04 and newer
    * mingw x64
    * Fedora Core release 4 (Stentz) w/ custom toolchain (GCC 4.8)

## custom toolchain

### openssl

* important
  * openssl 1.1.1 or newer
    * RSA-OAEP-256
    * Ed25519 Ed448 X25519 X448
    * sha3
  * openssl 3.0, 3.1
    * EVP_CIPHER_fetch/EVP_CIPHER_free, EVP_MD_fetch/EVP_MD_free
    * truncated sha ("sha2-512/224", "sha2-512/256")
    * failed to load PEM file containing HMAC private key
  * openssl 3.2
    * argon2d, argon2i, argon2id
  * custom build required in RHEL (RHEL, centos, rocky) and older version
    * -fPIC required
    * algoritm test, random SEGV, ctr_update SEGV (older linux), ...

* how to custom build
  * build custom openssl (example)
    * install perl
      * $ sudo yum install perl
  * cd thirdparty ; ./make.sh

### jansson

* build custom jansson (example)
  * see https://github.com/akheron/jansson
  * cd thirdparty ; ./make.sh

### FC4 custom toolchain

* toolchain dependencies
  * cmake (2.8.10.2)
  * perl (5.10.0)
  * m4 (1.4.13)
  * autoconf (2.65)
  * automake (1.16.4)
  * libtool (1.5.2)
  * make (3.80)
  * gmp (4.3.2)
  * mpfr (2.4.2)
  * mpc (1.0.3)
  * isl (0.10)
  * binutils (2.18)
  * gcc (4.8.5)

# link

 * https://github.com/princeb612/hotplace
 * https://www.facebook.com/princeb612
