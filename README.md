
# hotplace


## build

 * platform support - mingw, linux
 * packages to install
   * gcc, g++, binutils, cmake, gdb
   * openssl-devel jansson-devel zlib-devel (MINGW)
   * openssl-devel jansson zlib-devel (RHEL)
   * libssl-dev libjansson-dev zlib1g-dev (ubuntu)
   * valgrind (linux)
 * important
   * openssl 1.1.1 or newer
     * RSA-OAEP-256
     * Ed25519 Ed448 X25519 X448
     * sha3
   * openssl 3.0, 3.1
     * failed to load PEM file containing private key
   * custom build required in RHEL (RHEL, centos, rocky) and older version
     * -fPIC required
     * algoritm test, random SEGV, ctr_update SEGV (older linux), ...
 * how to custom build
   * build custom openssl (example)
     * install perl
       * $ sudo yum install perl
     * download openssl
       * $ wget https://www.openssl.org/source/openssl-1.1.1v.tar.gz
     * extract and unzip
       * $ tar xvfz openssl-1.1.1v.tar.gz
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
   * build custom jansson (example)
     * see https://github.com/akheron/jansson
     * aclocal; autoheader; autoconf;
     * libtoolize --automake --copy --force
     * automake --foreign --copy --add-missing
     * $ install_dir=somewhere/thirdparty
     * ./configure --prefix=${install_dir} --enable-static --enable-shared CPPFLAGS="-fPIC"
     * make
     * make install
 * make sure root directory hotplace (not hotplace-master nor etc ...)
   * $ hotplace ./make.sh
 * os support
   * linux x86-64 minimum version FC4 (libc 2.3.5, ft. gcc 4.8 toolchain, since unicorn project)

## implemented

 * RFC 4648 The Base16, Base32, and Base64 Data Encodings
   * sdk/io/basic/
 * RFC 4226 HOTP: An HMAC-Based One-Time Password Algorithm
 * RFC 6238 TOTP: Time-Based One-Time Password Algorithm
   * sdk/crypto/basic/
   * test/crypto/
 * RFC 7049 Concise Binary Object Representation (CBOR)
 * RFC 8949 Concise Binary Object Representation (CBOR)
   * sdk/io/cbor/
   * test/cbor/
 * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm
 * RFC 7515 JSON Web Signature (JWS)
 * RFC 7516 JSON Web Encryption (JWE)
 * RFC 7517 JSON Web Key (JWK)
 * RFC 7518 JSON Web Algorithms (JWA)
 * RFC 7520 Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
 * RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
   * sdk/crypto/jose/
   * test/jose/

## preparing


## appliying

 * RFC 2144 The CAST-128 Encryption Algorithm (May 1997)
 * RFC 2612 The CAST-256 Encryption Algorithm (June 1999)
 * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm (September 2002)
 * RFC 5649 Advanced Encryption Starndard (AES) Key Wrap with Padding Algorithm (September 2009)
 * RFC 5794 A Description of the ARIA Encryption Algorithm (March 2010)
   * sdk/crypto/basic/
 * RFC 1951 : DEFLATE Compressed Data Format Specification version 1.3
 * RFC 1952 : GZIP file format specification version 4.3
 * RFC 1945 Hypertext Transfer Protocol -- HTTP/1.0
 * RFC 2068 Hypertext Transfer Protocol -- HTTP/1.1
 * RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
   * test/httpserver/
 * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm
   * test/crypto/
 * RFC 4231 HMAC-SHA Identifiers and Test Vectors December 2005
   * test/crypto/
 * RFC 7638 3.1.  Example JWK Thumbprint Computation
   * test/jose/
 * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 * RFC 8996 Deprecating TLS 1.0 and TLS 1.1
   * sdk/net/tls/x509.cpp

## not applied

  * RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
  * RFC 2069 An Extension to HTTP : Digest Access Authentication
  * RFC 2617 HTTP Authentication: Basic and Digest Access Authentication
    * merlin project

## personal projects

| code name | period                | platform      | disclosure | comments            |
| --        | --                    | --            | --         | --                  |
| merlin(1) | 2007.04.08~           | windows       | private    | no comments         |
| merlin(2) | 2010.03.24~2017.03.31 | windows/linux | private    | no comments         |
| grape     | 2017.05.31~2019.10.24 | linux         | private    | no comments         |
| unicorn   | 2019.11.21~2023.07.04 | mingw/linux   | private    | no comments         |
| hotplace  | 2023.08.12~           | mingw/linux   | public     | RFC-related         |
