/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   base64.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 4648 The Base16, Base32, and Base64 Data Encodings
 *  RFC 7515 JSON Web Signature (JWS)
 *           Appendix C.  Notes on Implementing base64url Encoding without Padding
 *
 * Revision History
 * Date         Name                Description
 *
 * @example
 *          const char* sample1 = "We don't playing because we grow old; we grow old because we stop playing.";
 *          auto encoded = base64_encode(sample1);
 *          auto decoded = base64_decode(encoded);
 *          _logger->write([&](basic_stream& bs) -> void {
 *              valist va;
 *              va << encoded << decoded;
 *              bs.vaprintln("encoded {1}", va);
 *              bs.vaprintln("decoded {2:s}", va);  // printable data
 *          });
 */

#ifndef __HOTPLACE_SDK_BASE_ENCODING_LOWLEVEL_BASE64__
#define __HOTPLACE_SDK_BASE_ENCODING_LOWLEVEL_BASE64__

#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {
namespace lowlevel {

return_t base64_encode(const byte_t* source, size_t source_size, char* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);
return_t base64_encode(const binary_t& source, char* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);
return_t base64_encode(const char* source, size_t source_size, char* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);
return_t base64_encode(const std::string& source, char* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);

return_t base64_decode(const char* source, size_t source_size, byte_t* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);
return_t base64_decode(const std::string& source, byte_t* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);
return_t base64_decode(const byte_t* source, size_t source_size, byte_t* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);
return_t base64_decode(const binary_t& source, byte_t* buffer, size_t* buffer_size, encoding_t encoding = encoding_t::encoding_base64);

}  // namespace lowlevel
}  // namespace hotplace

#endif
