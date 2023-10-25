#ifndef __HOTPLACE_TEST_HASH__
#define __HOTPLACE_TEST_HASH__

#include <hotplace/sdk/sdk.hpp>

using namespace hotplace::crypto;

typedef struct _nist_cavp_ecdsa_test_vector_t {
    int nid;
    hash_algorithm_t alg;
    const char* msg;
    const char* d;
    const char* x;
    const char* y;
    const char* k;
    const char* r;
    const char* s;
} test_vector_nist_cavp_ecdsa_t;

// NIST CAVP ECDSA
extern const test_vector_nist_cavp_ecdsa_t test_vector_nist_cavp_ecdsa[];
extern const size_t sizeof_test_vector_nist_cavp_ecdsa;
// RFC6079 ECDSA
extern const test_vector_nist_cavp_ecdsa_t test_vector_rfc6079[];
extern const size_t sizeof_test_vector_rfc6079;

#endif
