#ifndef __HOTPLACE_TEST_COSE__
#define __HOTPLACE_TEST_COSE__

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;

typedef struct _OPTION {
    bool verbose;
    bool debug;
    int log;
    int time;
    bool dump_keys;
    bool dump_diagnostic;
    bool skip_cbor_basic;
    bool skip_validate;
    bool skip_gen;

    _OPTION()
        : verbose(false), log(0), debug(0), time(0), dump_keys(false), dump_diagnostic(false), skip_cbor_basic(false), skip_validate(false), skip_gen(false) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

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

extern crypto_key rfc8152_privkeys;
extern crypto_key rfc8152_pubkeys;
extern crypto_key rfc8152_privkeys_c4;

// part 0 .. try to decode
void test_rfc8152_read_cbor();

// part 1 .. following cases
// encode and decode
// Test Vector comparison
return_t dump_test_data(const char* text, basic_stream& diagnostic);
return_t dump_test_data(const char* text, const binary_t& cbor);
void dump_crypto_key(crypto_key_object* key, void*);
void test_rfc8152_b();
void test_rfc8152_c_1_1();
void test_rfc8152_c_1_2();
void test_rfc8152_c_1_3();
void test_rfc8152_c_1_4();
void test_rfc8152_c_2_1();
void test_rfc8152_c_3_1();
void test_rfc8152_c_3_2();
void test_rfc8152_c_3_3();
void test_rfc8152_c_3_4();
void test_rfc8152_c_4_1();
void test_rfc8152_c_4_2();
void test_rfc8152_c_5_1();
void test_rfc8152_c_5_2();
void test_rfc8152_c_5_3();
void test_rfc8152_c_5_4();
void test_rfc8152_c_6_1();
void test_rfc8152_c_7_1();
void test_rfc8152_c_7_2();

// part 2 .. test JWK, CWK compatibility
void test_jose_from_cwk();

// part 3 https://github.com/cose-wg/Examples
void test_github_example();

// part 4 encrypt/sign/mac
void test_keygen(crypto_key* key);
void test_selfgen(crypto_key* key);
void test_cose(crypto_key* key);

// part 5 CWT
void test_cwt_rfc8392();

#endif
