/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/crypto/sample.hpp>

void test_pqc_dsa() {
    _test_case.begin("openssl-3.5 DSA");

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    // TODO
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}

void testcase_pqc_dsa() { test_pqc_dsa(); }
