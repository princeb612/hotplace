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

test_case _test_case;

int main ()
{
    _test_case.test (errorcode_t::success, "function1", "case desc 1");                                 // pass
    _test_case.test (errorcode_t::invalid_parameter, "function2", "case desc 2 - intentional fail");    // fail
    _test_case.test (errorcode_t::not_supported, "function3", "case desc 4");                           // skip
    _test_case.test (errorcode_t::low_security, "function4", "case desc 5");                            // low

    _test_case.begin ("test case 1");

    _test_case.pause_time ();
    printf ("pause and resume and estimate time\n");
    msleep (1000);
    _test_case.resume_time ();

    _test_case.test (errorcode_t::success, "function5", "case 1 desc 1");                       // pass
    _test_case.test (errorcode_t::unexpected, "function6", "case 1 desc 2 - intentional fail"); // fail

    _test_case.begin ("test case 2");
    _test_case.test (errorcode_t::success, "function7", "case 2 desc 1");           // pass
    _test_case.assert (true, "function8", "case 2 desc 2");                         // pass
    _test_case.assert (false, "function9", "case 2 desc 3 - intentional fail");     // fail

    _test_case.report (5);
    return _test_case.result ();
}
