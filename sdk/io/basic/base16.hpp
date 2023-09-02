/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 4648 The Base16, Base32, and Base64 Data Encodings
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_BASE16__
#define __HOTPLACE_SDK_IO_BASIC_BASE16__

#include <hotplace/sdk/base.hpp>

namespace hotplace {
namespace io {

/**
 * @brief base16
 * @example
 *  const char* message = "sample";
 *  std::string hex;
 *  binary_t bin;
 *  base16_encode (message, 6, hex);
 *  std::cout << hex.c_str () << std::endl;
 *  base16_decode (hex, bin);
 *  buffer_stream bs;
 *  dump_memory (&bin[0], bin.size (), &bs);
 *  printf ("%s\n", bs.c_str ());
 */

return_t base16_encode (const byte_t* source, size_t size, std::string& outpart);
return_t base16_encode (binary_t source, std::string& outpart);
std::string base16_encode (binary_t source);
return_t base16_decode (const char* source, size_t size, binary_t& outpart);
return_t base16_decode (std::string source, binary_t& outpart);
binary_t base16_decode (const char* source);
binary_t base16_decode (std::string source);

}
}  // namespace

#endif
