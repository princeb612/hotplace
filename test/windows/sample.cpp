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

return_t enum_modules_handler(uint32 type, uint32 count, void* data[], CALLBACK_CONTROL* control, void* parameter) {
    switch (type) {
        case enum_modules_t::enum_toolhelp: {
            MODULEENTRY32* entry = (MODULEENTRY32*)data[0];
            printf(_T ("module [%s]\n"), entry->szExePath);
        } break;
        case enum_modules_t::enum_psapi: {
            HMODULE module_handle = (HMODULE)data[0];
            MODULEINFO* module_info = (MODULEINFO*)data[1];
            // ...
        } break;
    }
    return errorcode_t::success;
}

void test_enum_modules() {
    _test_case.begin("enum_modules");
    return_t ret = errorcode_t::success;

    ret = enum_modules(GetCurrentProcess(), enum_modules_handler, nullptr);
    _test_case.test(ret, __FUNCTION__, "enum_modules");
}

void test_trace() {
    _test_case.begin("debug_trace");
    return_t ret = errorcode_t::success;
    debug_trace_context_t* handle = nullptr;
    debug_trace dbg;
    CONTEXT rtlcontext;
    ansi_string stream;

    dbg.open(&handle);
    dbg.capture(&rtlcontext);
    ret = dbg.trace(handle, &rtlcontext, &stream);
    dbg.close(handle);

    {
        test_case_notimecheck notimecheck(_test_case);

        std::cout << stream.c_str() << std::endl;
    }

    _test_case.test(ret, __FUNCTION__, "debug_trace");
}

int main(int argc, char** argv) {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    test_enum_modules();
    test_trace();

    _test_case.report(5);
    return _test_case.result();
}
