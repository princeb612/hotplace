#ifndef __HOTPLACE_TEST_CRYPTO__
#define __HOTPLACE_TEST_CRYPTO__

#include <hotplace/sdk/sdk.hpp>

using namespace hotplace::crypto;

typedef struct _test_vector_nist_cavp_blockcipher_t {
    const char* desc;
    const char* alg;
    const char* key;
    const char* iv;
    const char* plaintext;
    const char* ciphertext;
} test_vector_nist_cavp_blockcipher_t;

extern const test_vector_nist_cavp_blockcipher_t test_vector_nist_cavp_blockcipher[];
extern const size_t sizeof_test_vector_nist_cavp_blockcipher;

typedef struct _test_vector_rfc3394_t {
    crypt_algorithm_t alg;
    const char* kek;
    const char* key;
    const char* expect;
    const char* message;
} test_vector_rfc3394_t;

extern const test_vector_rfc3394_t test_vector_rfc3394[];
extern const size_t sizeof_test_vector_rfc3394;

#endif
