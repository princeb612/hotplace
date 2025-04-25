/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 4648 The Base16, Base32, and Base64 Data Encodings
 *  RFC 7515 JSON Web Signature (JWS)
 *           Appendix C.  Notes on Implementing base64url Encoding without Padding
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_BASE64__
#define __HOTPLACE_SDK_BASE_BASIC_BASE64__

#include <sdk/base/basic/types.hpp>

namespace hotplace {

/**
 * encode   base64 and base64url (fill padding)
 * @param   const byte_t* sources [in]
 * @param   size_t source_size [in]
 * @param   byte_t* buffer [out]
 * @param   size_t* buffer_size [inout]
 * @param   int encoding [inopt] see encoding_t
 * @return  error code (see error.hpp)
 * @remarks
 *          source        eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
 *          BASE64 (E)    ZXlKMGVYQWlPaUpLVjFRaUxBMEtJQ0poYkdjaU9pSklVekkxTmlKOQ==
 *          BASE64URL (E) ZXlKMGVYQWlPaUpLVjFRaUxBMEtJQ0poYkdjaU9pSklVekkxTmlKOQ
 *          BASE64 (D)    {"typ":"JWT",\n "alg":"HS256"}
 * @example
 *          binary_t buffer;
 *          size_t size = 0;
 *          bse64_encode(source, source_size, &buffer[0], &size); // size in=0 out=56
 *          buffer.resize(size);
 *          bse64_encode(source, source_size, &buffer[0], &size); // size in=56 out=56
 *          buffer.resize(size);
 */
return_t base64_encode(const byte_t* source, size_t source_size, byte_t* buffer, size_t* buffer_size, int encoding = encoding_t::encoding_base64);

/**
 * @brief   encode
 * @param   const byte_t* source [in]
 * @param   size_t source_size [in]
 * @param   binary_t& encoded [out]
 * @param   int encoding [inopt] see encoding_t
 */
return_t base64_encode(const byte_t* source, size_t source_size, binary_t& encoded, int encoding = encoding_t::encoding_base64);
/**
 * @brief   encode
 * @param   const byte_t* source [in]
 * @param   size_t source_size [in]
 * @param   std::string& encoded [out]
 * @param   int encoding [inopt] see encoding_t
 */
return_t base64_encode(const byte_t* source, size_t source_size, std::string& encoded, int encoding = encoding_t::encoding_base64);
/**
 * @brief   encode
 * @param   const byte_t* source [in]
 * @param   size_t source_size [in]
 * @param   int encoding [inopt] see encoding_t
 */
std::string base64_encode(const byte_t* source, size_t source_size, int encoding = encoding_t::encoding_base64);
/**
 * @brief   encode
 * @param   const binary_t& source [in]
 * @param   int encoding [inopt] see encoding_t
 */
std::string base64_encode(const binary_t& source, int encoding = encoding_t::encoding_base64);
/**
 * @brief   encode
 * @param   const std::string& source [in]
 * @param   int encoding [inopt] see encoding_t
 */
std::string base64_encode(const std::string& source, int encoding = encoding_t::encoding_base64);

/**
 * decode   base64 and base64url
 * @param   const byte_t* sources [in]
 * @param   size_t source_size [in]
 * @param   byte_t* buffer [out]
 * @param   size_t* buffer_size [inout]
 * @param   int encoding [inopt] see encoding_t
 * @return  error code (see error.hpp)
 * @example
 *          binary_t buffer;
 *          size_t size = 0;
 *          bse64_decode(source, source_size, &buffer[0], &size, encoding_t::encoding_base64url); // size in=0 out=42
 *          buffer.resize(size);
 *          bse64_decode(source, source_size, &buffer[0], &size, encoding_t::encoding_base64url); // size out=42 out=40
 *          buffer.resize(size);
 */
return_t base64_decode(const byte_t* source, size_t source_size, byte_t* buffer, size_t* buffer_size, int encoding = encoding_t::encoding_base64);
/**
 * @brief   decode
 * @param   const char* source [in]
 * @param   size_t source_size [in]
 * @param   binary_t& decoded [out]
 * @param   int encoding [inopt] see encoding_t
 */
return_t base64_decode(const char* source, size_t source_size, binary_t& decoded, int encoding = encoding_t::encoding_base64);
/**
 * @brief   decode
 * @param   const std::string& source [in]
 * @param   binary_t& decoded [out]
 * @param   int encoding [in] see encoding_t
 */
return_t base64_decode(const std::string& source, binary_t& decoded, int encoding = encoding_t::encoding_base64);
/**
 * @brief   decode
 * @param   const char* source [in]
 * @param   size_t source_size [in]
 * @param   int encoding [inopt] see encoding_t
 */
binary_t base64_decode(const char* source, size_t source_size, int encoding = encoding_t::encoding_base64);
/**
 * @brief   decode
 * @param   const binary_t& source [in]
 * @param   int encoding [inopt] see encoding_t
 */
binary_t base64_decode(const binary_t& source, int encoding = encoding_t::encoding_base64);
/**
 * @brief   decode
 * @param   const std::string& source [in]
 * @param   int encoding [inopt] see encoding_t
 */
binary_t base64_decode(const std::string& source, int encoding = encoding_t::encoding_base64);
/**
 * @brief   decode
 * @param   const std::string& source [in]
 * @param   int encoding [inopt] see encoding_t
 */
std::string base64_decode_careful(const std::string& source, int encoding = encoding_t::encoding_base64);
/**
 * @brief   decode
 * @param   const char* source [in]
 * @param   size_t source_size [in]
 * @param   int encoding [inopt] see encoding_t
 */
std::string base64_decode_careful(const char* source, size_t source_size, int encoding = encoding_t::encoding_base64);

}  // namespace hotplace

#endif
