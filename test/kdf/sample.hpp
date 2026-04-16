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
    bool test_argon2;

    OPTION() : CMDLINEOPTION(), test_slow_kdf(false), test_argon2(false) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_kdf_hkdf();
void test_rfc6070();  // PBKDF2
void test_rfc7914();  // PBKDF2, scrypt
void test_rfc9106();  // argon
void test_rfc5869();  // extract, expand
void test_rfc4615();  // CKDF

#endif
