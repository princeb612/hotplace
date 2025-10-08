/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_HASH__
#define __HOTPLACE_TEST_HASH__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    bool dump_keys;

    OPTION() : CMDLINEOPTION(), dump_keys(false) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_hash_routine(hash_algorithm_t algorithm, const byte_t* key_data, unsigned key_size, byte_t* data, size_t size);
return_t test_hash_routine(hash_algorithm_t algorithm, binary_t key, binary_t data, binary_t expect, const char* text);

void test_openssl_hash();
void test_hmacsha_rfc4231();
void test_cmac_rfc4493();
uint32 test_hotp_rfc4226();
uint32 test_totp_rfc6238(hash_algorithm_t algorithm);
void test_transcript_hash();

#endif
