/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/stream/stream.hpp>
#include <hotplace/sdk/io/stream/string.hpp>
#include <hotplace/sdk/io/system/sdk.hpp>
#include <cxxabi.h>
#include <dlfcn.h>      // dladdr
#include <execinfo.h>   // backtrace
#include <iostream>

namespace hotplace {
namespace io {

return_t trace (return_t errorcode)
{
    return_t ret = errorcode_t::success;

    if (errorcode_t::success != errorcode) {
        uint32 option = get_trace_option ();
        if (trace_option_t::trace_bt & option) {
            ansi_string stream;
            debug_trace (&stream);
            std::cout << stream.c_str () << std::endl;
        }
    }
    return ret;
}

return_t debug_trace (stream_t* stream)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        std::vector<void*> callstack;
        callstack.resize (256);
        int nptrs = backtrace (&callstack[0], callstack.size ());
        char** symbols = backtrace_symbols (&callstack[0], nptrs);
        if (NULL != symbols) {
            for (int i = 0; i < nptrs; i++) {
                stream->printf ("#%d 0x%08x ", i, callstack[i]);

                Dl_info info;
                int res = dladdr (callstack[i], &info);
                if (0 != res) {
                    size_t length = 0;
                    int status = 0;
                    char* function_name = abi::__cxa_demangle (info.dli_sname, NULL, &length, &status);
                    const char* disp = function_name ? function_name : info.dli_sname;

                    if (NULL == disp) {
                        stream->printf ("%s ", symbols[i]);
                    } else {
                        stream->printf ("%s!%s + 0x%x ", info.dli_fname, disp, (unsigned long) callstack[i] - (unsigned long) info.dli_saddr);
                    }
                    free (function_name);
                }
                stream->printf ("\n");
            }
            free (symbols);
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

void set_trace_exception ()
{
}

void reset_trace_exception ()
{
}

}
} // namespace
