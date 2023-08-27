/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  mingw
 *      ./test-authenticate /c/windows/explorer.exe
 *  linux
 *      copy explorer.exe by using scp
 *      ./test-authenticate explorer.exe
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

test_case _test_case;

return_t test1 (int argc, char** argv)
{
    return_t ret = errorcode_t::success;
    authenticode_verifier verifier;
    authenticode_context_t* handle = NULL;
    uint32 result = 0;

    __try2
    {
        _test_case.begin ("authenticode verification test - file");
        verifier.open (&handle);
        int option = 0;
        verifier.set (handle, authenticode_ctrl_t::set_crl, &option, sizeof (option));
        verifier.add_trusted_rootcert (handle, "trust.crt", NULL);
        ret = verifier.verify (handle, argv[1], authenticode_flag_t::flag_separated, result);
        printf ("file verification : %08x\n", ret);
    }
    __finally2
    {
        verifier.close (handle);
        _test_case.test (ret, __FUNCTION__, "trust file");
    }
    return ret;
}

int main (int argc, char** argv)
{
    openssl_startup ();

    __try2
    {
        if (argc < 2) {
            printf ("[help] %s file\n", argv[0]);
            __leave2;
        }

        test1 (argc, argv);
    }
    __finally2
    {
        // do nothing
    }

    openssl_cleanup ();

    _test_case.report (5);
    return _test_case.result ();
}
