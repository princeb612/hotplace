# hotplace

 * Research on personal interests
 * ![cmake workflow](https://github.com/princeb612/hotplace/actions/workflows/build.yml/badge.svg)
 * ![codeql workflow](https://github.com/princeb612/hotplace/actions/workflows/codeql.yml/badge.svg)
 * powered by
   * ![openssl](https://img.shields.io/badge/openssl-1.1.1/3.0/3.1/3.2-green)
   * ![jansson](https://img.shields.io/badge/jansson-latest-green)
   * ![zlib](https://img.shields.io/badge/zlb-latest-green)
 * badge
   * ![c++11](https://img.shields.io/badge/c++11-green) ![gcc](https://img.shields.io/badge/gcc-green) ![cmake](https://img.shields.io/badge/cmake-green)
   * ![mingw64](https://img.shields.io/badge/mingw64-green) ![ubuntu](https://img.shields.io/badge/ubuntu-green) ![RHEL](https://img.shields.io/badge/RHEL-green)
 * status
   * JOSE ![implemented](https://img.shields.io/badge/implemented-green)
   * CBOR ![implemented](https://img.shields.io/badge/implemented-green)
   * COSE ![implemented](https://img.shields.io/badge/implemented-green)
   * HTTP/1.1,2,3 ![studying](https://img.shields.io/badge/studying-magenta)

## implemented

 * RFC 7049 Concise Binary Object Representation (CBOR)
 * RFC 8949 Concise Binary Object Representation (CBOR)
   * sdk/io/cbor/
   * test/cbor/

 * RFC 7515 JSON Web Signature (JWS)
 * RFC 7516 JSON Web Encryption (JWE)
 * RFC 7517 JSON Web Key (JWK)
 * RFC 7518 JSON Web Algorithms (JWA)
 * RFC 7520 Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
 * RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
   * sdk/crypto/jose/
   * test/jose/

 * RFC 8152 CBOR Object Signing and Encryption (COSE)
 * RFC 8230 Using RSA Algorithms with CBOR Object Signing and Encryption (COSE) Messages
 * RFC 8392 CBOR Web Token (CWT)
 * RFC 8812 CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms
 * RFC 9052 CBOR Object Signing and Encryption (COSE): Structures and Process
 * RFC 9053 CBOR Object Signing and Encryption (COSE): Initial Algorithms
 * RFC 9338 CBOR Object Signing and Encryption (COSE): Countersignatures
   * sdk/crypto/cose/
   * test/cose/

 * RFC 7541 HPACK: Header Compression for HTTP/2
   * sdk/net/http/http2
   * test/hpack
   * test/httpserver2

## applied

 * RFC 4648 The Base16, Base32, and Base64 Data Encodings
   * sdk/io/basic/
   * test/encode/

 * RFC 4226 HOTP: An HMAC-Based One-Time Password Algorithm
 * RFC 6238 TOTP: Time-Based One-Time Password Algorithm
   * sdk/crypto/basic/
   * test/crypto/

 * RFC 2144 The CAST-128 Encryption Algorithm (May 1997)
 * RFC 2612 The CAST-256 Encryption Algorithm (June 1999)
 * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm (September 2002)
 * RFC 5649 Advanced Encryption Starndard (AES) Key Wrap with Padding Algorithm (September 2009)
 * RFC 5794 A Description of the ARIA Encryption Algorithm (March 2010)
 * RFC 5869 HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 * RFC 7539 ChaCha20 and Poly1305 for IETF Protocols
 * RFC 7914 The scrypt Password-Based Key Derivation Function
 * RFC 8017 PKCS #1: RSA Cryptography Specifications Version 2.2
 * RFC 8439 ChaCha20 and Poly1305 for IETF Protocols
 * RFC 9106 Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
   * sdk/crypto/basic/
   * test/crypto/
   * test/kdf/
 * Authenticated Encryption with AES-CBC and HMAC-SHA
   * https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
   * test/crypto/

 * RFC 4231 HMAC-SHA Identifiers and Test Vectors December 2005
 * RFC 4493 The AES-CMAC Algorithm
 * NIST CAVP (Cryptographic Algorithm Validation Program) ECDSA
   * https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/digital-signatures
   * sdk/crypto/basic/
   * test/hash/

 * RFC 1951 DEFLATE Compressed Data Format Specification version 1.3
 * RFC 1952 GZIP file format specification version 4.3
 * RFC 1945 Hypertext Transfer Protocol -- HTTP/1.0
 * RFC 2068 Hypertext Transfer Protocol -- HTTP/1.1
 * RFC 2069 An Extension to HTTP : Digest Access Authentication
 * RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
 * RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
 * RFC 6749 OAuth 2.0
 * RFC 7616 HTTP Digest Access Authentication
   * sdk/net/http/
   * test/httpserver/
   * test/httpauth/
   * test/httptest/

 * RFC 7540 Hypertext Transfer Protocol Version 2 (HTTP/2)
 * RFC 7301 Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension
   * sdk/net/http/http2/
   * sdk/net/tls/
   * test/payload/
   * test/hpack/
   * test/httpserver2/

 * RFC 7638 3.1.  Example JWK Thumbprint Computation
   * test/jose/

 * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 * RFC 8996 Deprecating TLS 1.0 and TLS 1.1
   * sdk/net/tls/
   * test/tlsserver/

## not applied


## studying

 * RFC 2817 Upgrading to TLS Within HTTP/1.1
 * RFC 9114 HTTP/3

 * RFC 1951 DEFLATE Compressed Data Format Specification version 1.3
 * RFC 1952 GZIP file format specification version 4.3
 * RFC 7932 Brotli Compressed Data Format
 * RFC 8478 Zstandard Compression and the application/zstd Media Type
 * RFC 8878 Zstandard Compression and the 'application/zstd' Media Type

 * ITU-T X.680-X.699

 * Neural Networks
 * Machine Learning
   * sketch repository (private, spin off, in progress)

## next time

 * RFC 8778 Use of the HSS/LMS Hash-Based Signature Algorithm with CBOR Object Signing and Encryption (COSE)
 * RFC 9021 Use of the Walnut Digital Signature Algorithm with CBOR Object Signing and Encryption (COSE)
 * RFC 9054 CBOR Object Signing and Encryption (COSE): Hash Algorithms
 * RFC 9360 CBOR Object Signing and Encryption (COSE): Header Parameters for Carrying and Referencing X.509 Certificates

## build

 * platform support - mingw, linux
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
 * os support
   * tested
     * RHEL 7 and newer, (including CentOS, Rocky Linux)
     * ubuntu 20.04 and newer
     * mingw
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
     * download openssl
       * $ wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz
     * extract and unzip
       * $ tar xvfz openssl-1.1.1w.tar.gz
     * cd
       * $ cd openssl-1.1.1v
     * prefix variable
       * **never overwrite system libraries (must not set install_dir=/usr)**
       * *RHEL openssl package customized (krb, kdf ??)*
       * $ install_dir=somewhere/thirdparty
     * configure linux ex.
       * $ ./Configure linux-x86_64 enable-idea enable-bf enable-seed --prefix=${install_dir} --with-rand-seed=devrandom -D__USE_UNIX98=1 -D_GNU_SOURCE=1 no-egd shared
     * configure mingw ex.
       * $ ./Configure mingw64 enable-idea enable-bf enable-seed --prefix=${install_dir} --with-rand-seed=os -D__USE_UNIX98=1 -D_GNU_SOURCE=1 no-egd shared
     * make
       * $ make
     * openssl SEGV ctr_update - FC4, centos5
       * $ touch crypto/rand/drbg_ctr.c
       * $ make
     * no thanks man pages
       * $ make install_sw install_ssldirs

### jansson

   * build custom jansson (example)
     * see https://github.com/akheron/jansson
     * aclocal; autoheader; autoconf;
     * libtoolize --automake --copy --force
     * automake --foreign --copy --add-missing
     * $ install_dir=somewhere/thirdparty
     * ./configure --prefix=${install_dir} --enable-static --enable-shared CPPFLAGS="-fPIC"
     * make
     * make install

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
