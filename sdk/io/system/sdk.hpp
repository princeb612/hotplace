/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_SDK__
#define __HOTPLACE_SDK_IO_SYSTEM_SDK__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>

namespace hotplace {
namespace io {

enum trace_option_t {
    trace_bt        = 1,
    trace_except    = 2,
};
uint32 set_trace_option (uint32 option);
uint32 get_trace_option ();

return_t trace (return_t errorcode);

void set_trace_exception ();
void reset_trace_exception ();

}
}  // namespace

#endif
