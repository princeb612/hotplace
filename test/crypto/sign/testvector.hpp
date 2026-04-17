/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_CRYPTO_SIGN__
#define __HOTPLACE_TEST_CRYPTO_SIGN__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct test_vector_nist_cavp_rsa_key_t {
    const char* kid;
    const char* n;
    const char* e;
    const char* d;
};
extern const test_vector_nist_cavp_rsa_key_t test_vector_nist_cavp_rsa_fips186_4_keys[];
extern const size_t sizeof_test_vector_nist_cavp_rsa_fips186_4_keys;

struct test_vector_nist_cavp_rsa_t {
    const char* kid;
    hash_algorithm_t alg;
    const char* msg;
    const char* s;
    const char* salt;
};
extern const test_vector_nist_cavp_rsa_t test_vector_nist_cavp_rsa_fips186_4_signgen15_186_3[];
extern const size_t sizeof_test_vector_nist_cavp_rsa_fips186_4_signgen15_186_3;
extern const test_vector_nist_cavp_rsa_t test_vector_nist_cavp_rsa_fips186_4_signgenpss_186_3[];
extern const size_t sizeof_test_vector_nist_cavp_rsa_fips186_4_signgenpss_186_3;

struct test_vector_nist_cavp_ecdsa_t {
    int nid;
    hash_algorithm_t alg;
    const char* msg;
    const char* d;
    const char* x;
    const char* y;
    const char* k;
    const char* r;
    const char* s;
};

// NIST CAVP ECDSA
extern const test_vector_nist_cavp_ecdsa_t test_vector_nist_cavp_ecdsa_fips186_4_signgen[];
extern const size_t sizeof_test_vector_nist_cavp_ecdsa_fips186_4_signgen;
extern const test_vector_nist_cavp_ecdsa_t test_vector_nist_cavp_ecdsa_fips186_4_truncated_shas[];
extern const size_t sizeof_test_vector_nist_cavp_ecdsa_fips186_4_truncated_shas;
extern const test_vector_nist_cavp_ecdsa_t test_vector_nist_cavp_ecdsa_fips186_2_signgen[];
extern const size_t sizeof_test_vector_nist_cavp_ecdsa_fips186_2_signgen;
// RFC6979 ECDSA
extern const test_vector_nist_cavp_ecdsa_t test_vector_rfc6979[];
extern const size_t sizeof_test_vector_rfc6979;

struct test_vector_nist_cavp_dsa_param_t {
    const char* param;
    const char* p;
    const char* q;
    const char* g;
};
extern const test_vector_nist_cavp_dsa_param_t test_vector_nist_cavp_dsa_param[];
extern size_t sizeof_test_vector_nist_cavp_dsa_param;

struct test_vector_nist_cavp_dsa_t {
    const char* param;
    hash_algorithm_t hashalg;
    const char* msg;
    const char* x;
    const char* y;
    const char* k;
    const char* r;
    const char* s;
};
extern const test_vector_nist_cavp_dsa_t test_vector_nist_cavp_dsa_fips186_3_signgen[];
extern const size_t sizeof_test_vector_nist_cavp_dsa_fips186_3_signgen;

#endif
