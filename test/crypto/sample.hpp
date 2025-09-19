#ifndef __HOTPLACE_TEST_CRYPTO__
#define __HOTPLACE_TEST_CRYPTO__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_features();

void validate_openssl_crypt();
void test_openssl_crypt(uint32 cooltime, uint32 unitsize);
void test_keywrap_rfc3394();
void test_chacha20_rfc7539();
void test_chacha20_rfc7539_crypto_aead();
void test_cbc_hmac_rfc7516();
void test_cipher_encrypt();
void test_crypto_encrypt();
void test_validate_resources();
void test_crypto_aead();
void test_cbc_hmac_tls_mte();
void test_cbc_hmac_tls_etm();
void test_aead_ccm();

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
    const char* algname;
    const char* kek;
    const char* key;
    const char* expect;
    const char* message;
} test_vector_rfc3394_t;

extern const test_vector_rfc3394_t test_vector_rfc3394[];
extern const size_t sizeof_test_vector_rfc3394;

// CBC-HMAC JOSE
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
    const char* tag;
    const char* expect;
} test_vector_rfc7539_t;

extern const test_vector_rfc7539_t test_vector_rfc7539[];
extern const size_t sizeof_test_vector_rfc7539;

// CBC-HMAC TLS
struct test_vector_cbchmac_tls_t {
    const char* desc;
    uint16 flag;
    hash_algorithm_t hashalg;
    const char* key;
    const char* iv;
    const char* mackey;
    const char* aad;
    const char* plaintext;
    const char* cbcmaced;
};

extern test_vector_cbchmac_tls_t test_vector_tls_mte[];
extern const size_t sizeof_test_vector_tls_mte;
extern test_vector_cbchmac_tls_t test_vector_tls_etm[];
extern const size_t sizeof_test_vector_tls_etm;

#endif
