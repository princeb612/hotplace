/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_KDF__
#define __HOTPLACE_TEST_KDF__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    bool test_slow_kdf;

    OPTION() : CMDLINEOPTION(), test_slow_kdf(false) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_kdf_hkdf();
void test_kdf_pbkdf2_rfc6070();
void test_kdf_pbkdf2_rfc7914();
void test_kdf_scrypt_rfc7914();
void test_kdf_argon_rfc9106();
void test_kdf_extract_expand_rfc5869();
void test_ckdf_rfc4615();

#endif
