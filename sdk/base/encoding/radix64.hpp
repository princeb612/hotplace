/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   radix64.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2020.02.06   Soo Han, Kim        codename.unicorn Revision 49
 * 2026.09.04   Soo Han, Kim        codename.hotplace Revision 1070
 *
 */

#ifndef __HOTPLACE_SDK_BASE_ENCODING_RADIX64__
#define __HOTPLACE_SDK_BASE_ENCODING_RADIX64__

#include <hotplace/sdk/base/encoding/base64.hpp>
#include <hotplace/sdk/base/encoding/decoder_stream.hpp>
#include <hotplace/sdk/base/encoding/encoder_stream.hpp>
#include <string>

namespace hotplace {

uint32 crc24(const unsigned char* octets, size_t len);

#define radix64_encode base64_encode
#define radix64_decode base64_decode
#define radix64_encode_multiline base64_encode_multiline
#define radix64_decode_multiline base64_decode_multiline

/**
 * @param const byte_t* data [in]
 * @param size_t data_size
 * @param std::string& encoded [out]
 * @param std::string& crc [out]
 */
return_t radix64_armor_encode(const byte_t* data, size_t data_size, std::string& encoded, std::string& crc);
/**
 * @param const char* encoded [in]
 * @param size_t encoded_size [in]
 * @param const char* armor [in]
 * @param size_t armor_size [in]
 * @param binary_t& decoded [out]
 */
return_t radix64_armor_decode(const char* encoded, size_t encoded_size, const char* armor, size_t armor_size, binary_t& decoded);

}  // namespace hotplace

#endif
