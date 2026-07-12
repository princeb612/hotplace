/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   base128.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_ENCODING_BASE128__
#define __HOTPLACE_SDK_BASE_ENCODING_BASE128__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>

namespace hotplace {

return_t base128_encode(uint64 value, binary_t& bin);
return_t base128_decode(const byte_t* stream, size_t size, size_t& pos, uint64& value);

return_t base128_encode(const byte_t* stream, size_t size, binary_t& bin);
return_t base128_decode(const byte_t* stream, size_t size, size_t& pos, binary_t& value);

return_t base128_encode(const bignumber& value, binary_t& bin);
return_t base128_decode(const binary_t& bin, bignumber& value);
return_t base128_decode(const byte_t* stream, size_t size, size_t& pos, bignumber& value);

}  // namespace hotplace

#endif
