### thirdparty

> Source base : Revision 1132

* build
  * From this directory: `./make.sh debug`

* Active dependency selection

The current `thirdparty/dependency` array selects `oss_openssl40`, `oss_jansson`, `oss_zlib`, and `oss_yaml`. The resolved package definitions are OpenSSL 4.0.3, Jansson 2.15.0, zlib 1.3.2, and yaml-cpp 0.9.0. This is the default dependency array used by `thirdparty/make.sh`.

| OSS | Current default selection | Description |
| -- | -- | -- |
| openssl | Selected: 4.0.3 | General-purpose cryptography and secure communication |
| jansson | Selected: 2.15.0 | JSON encoding, decoding and manipulation |
| zlib | Selected: 1.3.2 | Compression library |
| yaml-cpp | Selected: 0.9.0 | YAML parser |
| liboqs | Declared, not selected | Optional quantum-safe cryptographic algorithms |
| oqs-provider | Declared, not selected | External OpenSSL provider for quantum-safe algorithms |

`liboqs` and `oqs-provider` have package definitions in `thirdparty/dependency`, but neither appears in the active `dependency` array. The `SUPPORT_OQS` option controls inclusion of hotplace's OQS adapter/test sources; it does not add these two packages to the third-party build. An OQS-enabled runtime still requires an independently installed and loadable `oqsprovider` module.

* Historical OpenSSL compatibility notes
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

* historical build comments
  * openssl
    * MSVC
      * [MUST] manual build
    * 3.5.5, 3.6.1
      * [# 3.6.1 fails to build with MSYS2 (MingW64) on Windows 11.](https://github.com/openssl/openssl/issues/29818)
    * mininum version
      |  |  |
      |--|--|
      | 3.0 | EVP_PKEY_CTX_new_from_name, EVP_PKEY_get0_type_name |
      | 3.2 | BIO_err_is_non_fatal, OSSL_HPKE_seal, OSSL_set_max_threads |
      | 3.3 | OPENSSL_LH_set_thunks |
      | 3.4 | EVP_MD_CTX_get_size_ex |

* historical platform notes
  * bash 3.x to 4 or later
    * https://ftp.kaist.ac.kr/gnu/bash/bash-4.4.tar.gz
    * https://ftp.kaist.ac.kr/gnu/bash/bash-5.3.tar.gz
  * cmake 2.8 to 3.16
    * manual build (step by step 2.8 -> 3.1 -> 3.16)
      * declare -A oss_cmake301=([name]=cmake [url]=https://github.com/Kitware/CMake/archive/refs/tags/v3.1.0.tar.gz [dir]=CMake-3.1.0 [build]=build_tool [buildscript]=)
      * declare -A oss_cmake310=([name]=cmake [url]=https://github.com/Kitware/CMake/archive/refs/tags/v3.10.0.tar.gz [dir]=CMake-3.10.0 [build]=build_tool [buildscript]=)
    * -j parallel (3.12.?)
      * declare -A oss_cmake312=([name]=cmake [url]=https://github.com/Kitware/CMake/archive/refs/tags/v3.12.0.tar.gz [dir]=CMake-3.10.0 [build]=build_tool [buildscript]=)
    * Unknown CMake command "target_link_options".
      * declare -A oss_cmake313=([name]=cmake [url]=https://github.com/Kitware/CMake/archive/refs/tags/v3.13.0.tar.gz [dir]=CMake-3.13.0 [build]=build_tool [buildscript]=)
    * -B option   (3.13.?)
    * Unknown CMake command "target_precompile_headers".
      * declare -A oss_cmake316=([name]=cmake [url]=https://github.com/Kitware/CMake/archive/refs/tags/v3.16.0.tar.gz [dir]=CMake-3.16.0 [build]=build_tool [buildscript]=)

