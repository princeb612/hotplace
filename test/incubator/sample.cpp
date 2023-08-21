/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;
using namespace hotplace::crypto;
using namespace hotplace::net;

test_case _test_case;

void test_x509 ()
{
    return_t ret = errorcode_t::success;
    x509_t* x509 = nullptr;

    ret = x509_open_pem (&x509, "server.crt", "server.key", "", "ca.crt");
    x509_close (x509);
    _test_case.test (ret, __FUNCTION__, "x509");
}

int main ()
{
    _test_case.begin ("x509");

    openssl_startup ();

    test_x509 ();

    openssl_cleanup ();

    _test_case.report ();
    return _test_case.result ();
}
