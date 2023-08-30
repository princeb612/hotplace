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

#if defined __linux__
return_t debug_trace (stream_t* stream);
#endif

}
}  // namespace

#endif
