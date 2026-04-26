/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   sample.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_COSE__
#define __HOTPLACE_TEST_COSE__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/testcase/test.hpp>

struct OPTION : public CMDLINEOPTION {
    bool dump_keys;
    bool dump_diagnostic;
    bool skip_cbor_basic;
    bool skip_gen;

    OPTION() : CMDLINEOPTION(), dump_keys(false), dump_diagnostic(false), skip_cbor_basic(false), skip_gen(false) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

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
void testcase_testvector_cose_examples();

// part 4 encrypt/sign/mac
void testcase_cose();

// part 5 CWT
void testcase_rfc8392();

#endif
