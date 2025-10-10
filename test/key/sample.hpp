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

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_crypto_key();
void test_rsa();
void test_eckey_compressed();
void test_ffdhe();
void test_ffdhe_dh();
void test_der();
void test_dsa();
void test_dh_rfc7748();
void test_hpke();
void test_mlkem();

#endif
