### thirdparty

* build
  ./make.sh debug

* thirdparty

| OSS          | brief       | description                                                              |
| --           | --          | --                                                                       |
| openssl      | CRYPTO, TLS | general-purpose cryptography and secure communication                    |
| jansson      | JSON        | encoding, decoding and manipulating JSON data                            |
| zlib         | compression | A Massively Spiffy Yet Delicately Unobtrusive Compression Library        |
| liboqs       | PQC         | quantum-safe cryptographic algorithms                                    |
| oqs-provider | PQC         | quantum-safe cryptography (QSC) in a standard OpenSSL (3.x) distribution |

* summary
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
  * openssl 3.5
    * ML-KEM, ML-DSA

* comments
  * openssl
    * MSVC
      * [MUST] manual build
    * 3.5.5, 3.6.1
      * [# 3.6.1 fails to build with MSYS2 (MingW64) on Windows 11.](https://github.com/openssl/openssl/issues/29818)

* old platforms
  * bash 3.x to 4 or later
    * https://ftp.kaist.ac.kr/gnu/bash/bash-4.4.tar.gz
    * https://ftp.kaist.ac.kr/gnu/bash/bash-5.3.tar.gz
  * cmake 2.8 to 3.16
    * # manual build (step by step 2.8 -> 3.1 -> 3.16)
    * declare -A oss_cmake301=([name]=cmake [url]=https://github.com/Kitware/CMake/archive/refs/tags/v3.1.0.tar.gz [dir]=CMake-3.1.0 [build]=build_tool [buildscript]=)
    * declare -A oss_cmake310=([name]=cmake [url]=https://github.com/Kitware/CMake/archive/refs/tags/v3.10.0.tar.gz [dir]=CMake-3.10.0 [build]=build_tool [buildscript]=)
    * # -j parallel (3.12.?)
    * declare -A oss_cmake312=([name]=cmake [url]=https://github.com/Kitware/CMake/archive/refs/tags/v3.12.0.tar.gz [dir]=CMake-3.10.0 [build]=build_tool [buildscript]=)
    * # Unknown CMake command "target_link_options".
    * declare -A oss_cmake313=([name]=cmake [url]=https://github.com/Kitware/CMake/archive/refs/tags/v3.13.0.tar.gz [dir]=CMake-3.13.0 [build]=build_tool [buildscript]=)
    * # -B option   (3.13.?)
    * # Unknown CMake command "target_precompile_headers".
    * declare -A oss_cmake316=([name]=cmake [url]=https://github.com/Kitware/CMake/archive/refs/tags/v3.16.0.tar.gz [dir]=CMake-3.16.0 [build]=build_tool [buildscript]=)
