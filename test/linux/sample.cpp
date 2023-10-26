/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  MINGW COM
 *      ATL-related issues (heavily MSVC-dependent)
 *          INetFwPolicy2 (Windows Firewall implementation)
 *          IWbemClassObject (WMI implementation)
 *      hard to apply CComVariant
 *          failed ... Community/VC/Tools/MSVC/14.37.32822/atlmfc/include
 *          not tested ... https://github.com/reactos/reactos/tree/master/sdk/lib/atl
 *
 *  MINGW backtrace
 *      GetSymFromAddr, SymGetLineFromAddr
 *      libbfd link error
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <iostream>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

void test_trace() {
    _test_case.begin("debug_trace");
    return_t ret = errorcode_t::success;
    ansi_string stream;
    ret = debug_trace(&stream);
    std::cout << stream.c_str() << std::endl;
    _test_case.test(ret, __FUNCTION__, "debug_trace");
}

int main(int argc, char** argv) {
    test_trace();

    _test_case.report(5);
    return _test_case.result();
}
