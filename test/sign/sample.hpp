#ifndef __HOTPLACE_TEST_SIGN__
#define __HOTPLACE_TEST_SIGN__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

#include "sample.hpp"

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

typedef struct _OPTION {
    bool verbose;
    bool debug;
    int log;
    int time;
    bool dump_keys;

    _OPTION() : verbose(false), debug(false), log(0), time(0), dump_keys(false) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_hash_hmac_sign();
void test_nist_cavp_ecdsa();
void test_rfc6979_ecdsa();
void test_crypto_sign();
void test_nist_cavp_rsa();
void test_x509_sign();
void check_ecdsa_size();
void test_rsassa();

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

#endif
