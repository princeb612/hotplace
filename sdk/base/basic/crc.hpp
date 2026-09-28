/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crc.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_CRC__
#define __HOTPLACE_SDK_BASE_BASIC_CRC__

#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {

/**
 * @sa  parsing table binary format
 */
uint32 crc32(const unsigned char* octets, size_t len);
/**
 * @sa  radix64
 */
uint32 crc24(const unsigned char* octets, size_t len);

}  // namespace hotplace

#endif
