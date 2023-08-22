/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * @remakrs
 *  RFC 4648 The Base16, Base32, and Base64 Data Encodings
 *  RFC 7515 JSON Web Signature (JWS)
 *           Appendix C.  Notes on Implementing base64url Encoding without Padding
 */

#ifndef __HOTPLACE_SDK_IO_ENCODER_BASE64__
#define __HOTPLACE_SDK_IO_ENCODER_BASE64__

#include <hotplace/sdk/base.hpp>

namespace hotplace {
namespace io {

enum base64_encoding_t {
    base64_encoding     = 0,    /* + / */
    base64url_encoding  = 1,    /* - _ without padding */
};

/*
 * encode base64 and base64url (fill padding)
 * @param const byte_t* sources [in]
 * @param size_t source_size [in]
 * @param byte_t* buffer [out]
 * @param size_t* buffer_size [inout]
 * @param int encoding [inopt] base64_encoding_t::base64_encoding, base64_encoding_t::base64url_encoding
 * @return error code (see error.hpp)
 * @remarks
 *  source        eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
 *  BASE64 (E)    ZXlKMGVYQWlPaUpLVjFRaUxBMEtJQ0poYkdjaU9pSklVekkxTmlKOQ==
 *  BASE64URL (E) ZXlKMGVYQWlPaUpLVjFRaUxBMEtJQ0poYkdjaU9pSklVekkxTmlKOQ
 *  BASE64 (D)    {"typ":"JWT",\n "alg":"HS256"}
 * @sample
 *        binary_t buffer;
 *        size_t size = 0;
 *        bse64_encode(source, source_size, &buffer[0], &size); // size in=0 out=56
 *        buffer.resize(size);
 *        bse64_encode(source, source_size, &buffer[0], &size); // size in=56 out=56
 *        buffer.resize(size);
 */
return_t base64_encode (const byte_t* source, size_t source_size, byte_t* buffer, size_t* buffer_size, int encoding = base64_encoding_t::base64_encoding);

return_t base64_encode (const byte_t* source, size_t source_size, binary_t& encoded, int encoding = base64_encoding_t::base64_encoding);
return_t base64_encode (const byte_t* source, size_t source_size, std::string& encoded, int encoding = base64_encoding_t::base64_encoding);
std::string base64_encode (const byte_t* source, size_t source_size, int encoding = base64_encoding_t::base64_encoding);
std::string base64_encode (binary_t source, int encoding = base64_encoding_t::base64_encoding);
std::string base64_encode (std::string source, int encoding = base64_encoding_t::base64_encoding);

/*
 * decode base64 and base64url
 * @param const byte_t* sources [in]
 * @param size_t source_size [in]
 * @param byte_t* buffer [out]
 * @param size_t* buffer_size [inout]
 * @param int encoding [inopt] base64_encoding_t::base64_encoding, base64_encoding_t::base64url_encoding
 * @return error code (see error.hpp)
 * @sample
 *        binary_t buffer;
 *        size_t size = 0;
 *        bse64_decode(source, source_size, &buffer[0], &size, base64_encoding_t::base64url_encoding); // size in=0 out=42
 *        buffer.resize(size);
 *        bse64_decode(source, source_size, &buffer[0], &size, base64_encoding_t::base64url_encoding); // size out=42 out=40
 *        buffer.resize(size);
 */
return_t base64_decode (const byte_t* source, size_t source_size, byte_t *buffer, size_t * buffer_size, int encoding = base64_encoding_t::base64_encoding);

return_t base64_decode (const char* source, size_t source_size, binary_t& decoded, int encoding = base64_encoding_t::base64_encoding);
return_t base64_decode (std::string source, binary_t& decoded, int encoding = base64_encoding_t::base64_encoding);
binary_t base64_decode (const char* source, size_t source_size, int encoding = base64_encoding_t::base64_encoding);
binary_t base64_decode (binary_t source, int encoding = base64_encoding_t::base64_encoding);
binary_t base64_decode (std::string source, int encoding = base64_encoding_t::base64_encoding);
std::string base64_decode_careful (std::string source, int encoding = base64_encoding_t::base64_encoding);
std::string base64_decode_careful (const char* source, size_t source_size, int encoding = base64_encoding_t::base64_encoding);

}
}  // namespace

#endif
