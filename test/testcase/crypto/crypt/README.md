### Encryption and AEAD testcases

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `testcase_aead_ccm.cpp`
* `testcase_cipher_encrypt.cpp`
* `testcase_crypto_aead.cpp`
* `testcase_crypto_encrypt.cpp`
* `testcase_openssl_crypt.cpp`
* `testvector_cavp_blockciphers.cpp`
* `testvector_cbc_hmac_jose.cpp`
* `testvector_cbc_hmac_tls.cpp`
* `testvector_rfc3394.cpp`
* `testvector_rfc7539.cpp`

#### test data / build files

* `testvector_cavp_blockciphers.yml`
* `testvector_cbc_hmac_jose.yml`
* `testvector_cbc_hmac_tls.yml`
* `testvector_rfc3394.yml`
* `testvector_rfc7539.yml`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.
