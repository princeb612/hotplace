/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   base16.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 4648 The Base16, Base32, and Base64 Data Encodings
 *
 * Revision History
 * Date         Name                Description
 *
 * @example
 *          const char* sample1 = "We don't playing because we grow old; we grow old because we stop playing.";
 *          auto encoded = base16_encode(sample1);
 *          auto decoded = base16_decode(encoded);
 *          _logger->write([&](basic_stream& bs) -> void {
 *              valist va;
 *              va << encoded << decoded;
 *              bs.vaprintln("encoded {1}", va);
 *              bs.vaprintln("decoded {2:s}", va);  // printable data
 *          });
 */

#ifndef __HOTPLACE_SDK_BASE_ENCODING_LOWLEVEL_BASE16__
#define __HOTPLACE_SDK_BASE_ENCODING_LOWLEVEL_BASE16__

#include <hotplace/sdk/base/basic/types.hpp>

namespace hotplace {
namespace lowlevel {

return_t base16_encode(const byte_t* source, size_t size, char* buf, size_t* buflen, uint32 flags = 0);
return_t base16_encode(const binary_t& source, char* buf, size_t* buflen, uint32 flags = 0);
return_t base16_encode(const char* source, size_t size, char* buf, size_t* buflen, uint32 flags = 0);
return_t base16_encode(const std::string& source, char* buf, size_t* buflen, uint32 flags = 0);

return_t base16_decode(const char* source, size_t size, byte_t* buf, size_t* buflen);
return_t base16_decode(const std::string& source, byte_t* buf, size_t* buflen);
return_t base16_decode(const byte_t* source, size_t size, byte_t* buf, size_t* buflen);
return_t base16_decode(const binary_t source, byte_t* buf, size_t* buflen);

}  // namespace lowlevel
}  // namespace hotplace

#endif
