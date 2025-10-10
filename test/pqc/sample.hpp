/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */
#ifndef __HOTPLACE_TEST_PQC__
#define __HOTPLACE_TEST_PQC__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {
    bool dump_keys;

    OPTION() : CMDLINEOPTION(), dump_keys(false) {}
};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

void test_ossl_encode();
void test_ossl_kem();
void test_ossl_dsa();

void test_oqs_encode();
void test_oqs_kem();
void test_oqs_dsa();

#endif
