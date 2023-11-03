#ifndef __HOTPLACE_TEST_CRYPTO__
#define __HOTPLACE_TEST_CRYPTO__

#include <sdk/sdk.hpp>

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

// Authenticated Encryption with AES-CBC and HMAC-SHA
typedef struct _test_vector_aead_aes_cbc_hmac_sha2_t {
    const char* text;
    const char* enc_alg;
    const char* mac_alg;
    const char* k;  // mac_key || enc_key
    const char* p;
    const char* iv;
    const char* a;
    const char* q;
    const char* s;  // validation
    const char* t;  // validation
    const char* c;  // validation
} test_vector_aead_aes_cbc_hmac_sha2_t;

extern const test_vector_aead_aes_cbc_hmac_sha2_t test_vector_aead_aes_cbc_hmac_sha2[];
extern const size_t sizeof_test_vector_aead_aes_cbc_hmac_sha2;

typedef struct _test_vector_rfc7539_t {
    const char* text;
    const char* alg;
    const char* key;
    int counter;
    const char* iv;
    const char* msg;
    const char* aad;
    const char* expect;
} test_vector_rfc7539_t;

extern const test_vector_rfc7539_t test_vector_rfc7539[];
extern const size_t sizeof_test_vector_rfc7539;

#endif
