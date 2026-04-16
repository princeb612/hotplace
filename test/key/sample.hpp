/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_CRYPTOKEY__
#define __HOTPLACE_TEST_CRYPTOKEY__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    int test_ffdhe;

    OPTION() : CMDLINEOPTION(), test_ffdhe(0) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_crypto_key();
void test_rsa();
void test_ec();
void test_ffdhe();
void test_der();
void test_dsa();
void test_dh();
void test_curves();
void test_hpke();
void test_mlkem();
void test_keyexchange();

#endif
