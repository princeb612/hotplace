/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_SYSTEM_TYPES__
#define __HOTPLACE_SDK_IO_SYSTEM_TYPES__

#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/io/types.hpp>

namespace hotplace {
namespace io {

#if defined __SIZEOF_INT128__

int128 atoi128(const std::string& in);
uint128 atou128(const std::string& in);

#endif

}  // namespace io
}  // namespace hotplace

#endif
