/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_COSE__
#define __HOTPLACE_TEST_COSE__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    bool dump_keys;
    bool dump_diagnostic;
    bool skip_cbor_basic;
    bool skip_validate;
    bool skip_gen;

    OPTION() : CMDLINEOPTION(), dump_keys(false), dump_diagnostic(false), skip_cbor_basic(false), skip_validate(false), skip_gen(false) {}
};

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

// validate resources
void testcase_resources();

// part 0 .. try to decode
void testcase_rfc8152_read_cbor();

// part 1 .. following cases
// part 2 .. test JWK, CWK compatibility
// encode and decode
// Test Vector comparison
return_t dump_test_data(const char* text, basic_stream& diagnostic);
return_t dump_test_data(const char* text, const binary_t& cbor);
void dump_crypto_key(crypto_key_object* key, void*);
void testcase_rfc8152();

// part 3 https://github.com/cose-wg/Examples
void testcase_examples();

// part 4 encrypt/sign/mac
void testcase_cose();

// part 5 CWT
void testcase_rfc8392();

#endif
