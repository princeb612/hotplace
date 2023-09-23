
/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_TYPES__
#define __HOTPLACE_SDK_IO_TYPES__

#include <hotplace/sdk/base.hpp>

namespace hotplace {
namespace io {

void binary_load (binary_t& bn, uint32 bnlen, byte_t* data, uint32 len);

}
} // namespace

#endif
