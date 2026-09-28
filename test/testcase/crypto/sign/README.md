### Signature and MAC testcases

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `testcase_crypto_sign.cpp`
* `testcase_ecdsa.cpp`
* `testcase_hmac.cpp`
* `testcase_mldsa.cpp`
* `testcase_rsassa.cpp`
* `testcase_slhdsa.cpp`
* `testcase_x509.cpp`
* `testvector_dsa.cpp`
* `testvector_ecdsa.cpp`
* `testvector_rsassa.cpp`

#### test data / build files

* `testvector_dsa.yml`
* `testvector_ecdsa.yml`
* `testvector_rsassa.yml`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.
