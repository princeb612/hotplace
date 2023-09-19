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

#ifndef __HOTPLACE_SDK_BASE_BASIC_BASE16__
#define __HOTPLACE_SDK_BASE_BASIC_BASE16__

#include <hotplace/sdk/base/error.hpp>
#include <hotplace/sdk/base/stream.hpp>

namespace hotplace {

/**
 * @brief   encode
 * @desc
 *          no 0x prefix
 * @example
 *          const char* message = "sample";
 *          std::string hex;
 *          binary_t bin;
 *          base16_encode (message, 6, hex);
 *          std::cout << hex.c_str () << std::endl;
 *          base16_decode (hex, bin);
 *          buffer_stream bs;
 *          dump_memory (&bin[0], bin.size (), &bs);
 *          printf ("%s\n", bs.c_str ());
 */

return_t base16_encode (const byte_t* source, size_t size, char* buf, size_t* buflen);
return_t base16_encode (const byte_t* source, size_t size, std::string& outpart);
return_t base16_encode (const byte_t* source, size_t size, stream_t* stream);
return_t base16_encode (binary_t const& source, char* buf, size_t* buflen);
return_t base16_encode (binary_t const& source, std::string& outpart);
return_t base16_encode (binary_t const& source, stream_t* stream);
std::string base16_encode (binary_t const& source);

/**
 * @brief   decode
 * @desc
 *          support 0x prefix
 * @example
 *          const char* encoded1 = "01020304";
 *          bin1 = base16_decode (encoded1);
 *          const char* encoded2 = "0x01020304";
 *          bin2 = base16_decode (encoded2);
 */
return_t base16_decode (const char* source, size_t size, binary_t& outpart);
return_t base16_decode (const char* source, size_t size, stream_t* stream);
return_t base16_decode (std::string const& source, binary_t& outpart);
return_t base16_decode (std::string const& source, stream_t* stream);
binary_t base16_decode (const char* source);
binary_t base16_decode (const char* source, size_t size);
binary_t base16_decode (std::string const& source);

}  // namespace

#endif
