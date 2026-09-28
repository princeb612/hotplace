### Key and key-exchange testcases

This directory contains the tests/samples for the corresponding hotplace module.

#### test sources

* `testcase_crypto_key.cpp`
* `testcase_curves.cpp`
* `testcase_der.cpp`
* `testcase_dh.cpp`
* `testcase_ec.cpp`
* `testcase_hpke.cpp`
* `testcase_key_dsa.cpp`
* `testcase_key_ffdhe.cpp`
* `testcase_key_mlkem.cpp`
* `testcase_key_rsa.cpp`
* `testcase_keyexchange.cpp`
* `testcase_keygen.cpp`
* `testvector_keygen.cpp`
* `testvector_keyshare.cpp`
* `testvector_rfc7919.cpp`

#### test data / build files

* `testvector_keygen.yml`
* `testvector_keyshare.yml`
* `testvector_rfc7919.yml`

The directory is organized around the concrete testcase sources present here; detailed protocol or implementation notes belong to the corresponding `sdk` documentation.
