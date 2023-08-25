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
   * custom build required in RHEL (RHEL, centos, rocky) and older version
     * -fPIC required
     * algoritm test, random SEGV, ...
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

 * RFC 4226 HOTP: An HMAC-Based One-Time Password Algorithm
 * RFC 4648 The Base16, Base32, and Base64 Data Encodings
 * RFC 6238 TOTP: Time-Based One-Time Password Algorithm
 * RFC 7049 Concise Binary Object Representation (CBOR)
 * RFC 7515 JSON Web Signature (JWS)
 * RFC 7516 JSON Web Encryption (JWE)
 * RFC 7517 JSON Web Key (JWK)
 * RFC 7518 JSON Web Algorithms (JWA)
 * RFC 7520 Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)
 * RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)

## references

 * RFC 1341 MIME  (Multipurpose Internet Mail Extensions)
 * RFC 1521 MIME (Multipurpose Internet Mail Extensions) Part One:
                      Mechanisms for Specifying and Describing
                      the Format of Internet Message Bodies
 * RFC 1945 Hypertext Transfer Protocol -- HTTP/1.0
 * RFC 1951 : DEFLATE Compressed Data Format Specification version 1.3
 * RFC 1952 : GZIP file format specification version 4.3
 * RFC 2068 Hypertext Transfer Protocol -- HTTP/1.1
 * RFC 2144 The CAST-128 Encryption Algorithm
 * RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1
 * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm
 * RFC 4231 HMAC-SHA Identifiers and Test Vectors December 2005
 * RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3

## personal projects

| code name | period                | platform      | disclosure | comments            |
| --        | --                    | --            | --         | --                  |
| merlin(1) | 2007.04.08~           | windows       | private    | no comments         |
| merlin(2) | 2010.03.24~2017.03.31 | windows/linux | private    | no comments         |
| grape     | 2017.05.31~2019.10.24 | linux         | private    | no comments         |
| unicorn   | 2019.11.21~2023.07.04 | mingw/linux   | private    | no comments         |
| hotplace  | 2023.08.12~           | mingw/linux   | public     | unrelated to my job |
