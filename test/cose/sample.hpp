#ifndef __HOTPLACE_TEST_CRYPTO__
#define __HOTPLACE_TEST_CRYPTO__

#include <sdk/sdk.hpp>

typedef struct _test_vector_github_cose_wg_t {
    const char* keysetname;  // crypto_key* key;
    const char* file;
    const char* cbor;
    struct {
        const char* external;
        const char* iv_hex;
        const char* apu_id;
        const char* apu_nonce;
        const char* apu_other;
        const char* apv_id;
        const char* apv_nonce;
        const char* apv_other;
        const char* pub_other;
        const char* priv;
    } shared;
    struct {
        const char* aad_hex;
        const char* cek_hex;
        const char* tomac_hex;
    } enc;
    int skip;
    int untagged;
    int debug;
} test_vector_github_cose_wg_t;

extern const test_vector_github_cose_wg_t test_vector_github_cose_wg[];
extern const size_t sizeof_test_vector_github_cose_wg;

#endif
