/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2010.12.21   Soo Han, Kim        backtrace x86 implemented (merlin)
 * 2014.11.06   Soo Han, Kim        backtrace x64 implemented (merlin)
 * 2023.08.30   Soo Han, Kim        trying bfd
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_DEBUGTRACE__
#define __HOTPLACE_SDK_IO_SYSTEM_WINDOWS_DEBUGTRACE__

#include <hotplace/sdk/io/system/windows/sdk.hpp>

namespace hotplace {
namespace io {

struct _debug_trace_context_t {};
typedef struct _debug_trace_context_t debug_trace_context_t;

class debug_trace
{
public:
    debug_trace ();
    ~debug_trace ();

    return_t open (debug_trace_context_t** handle);
    return_t close (debug_trace_context_t* handle);

    return_t capture (CONTEXT* rtlcontext);
    return_t trace (debug_trace_context_t* handle, CONTEXT* rtlcontext, stream_t* stream);

    return_t trace (debug_trace_context_t* handle, EXCEPTION_POINTERS* exception, stream_t* stream);
protected:
};

LONG __stdcall exception_handler (struct _EXCEPTION_POINTERS * exception_ptr);

}
}  // namespace

#endif
