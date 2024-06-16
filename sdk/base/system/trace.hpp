/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_TRACE__
#define __HOTPLACE_SDK_BASE_SYSTEM_TRACE__

#include <sdk/base/charset.hpp>
#include <sdk/base/error.hpp>
#include <sdk/base/syntax.hpp>
#include <sdk/base/types.hpp>

namespace hotplace {

enum trace_option_t {
    trace_bt = 1,
    trace_except = 2,
};
uint32 set_trace_option(uint32 option);
uint32 get_trace_option();

return_t trace(return_t errorcode);

void set_trace_exception();
void reset_trace_exception();

}  // namespace hotplace

#endif
