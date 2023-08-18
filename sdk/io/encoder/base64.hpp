/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.16   Soo Han, Kim        fix : base64_encode encoded size
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

enum BASE64_FLAG {
    BASE64_ENCODING     = 0,    /* + / */
    BASE64URL_ENCODING  = 1,    /* - _ without padding */
};

/*
 * encode base64 and base64url (fill padding)
 * @param const byte_t* sources [in]
 * @param size_t source_size [in]
 * @param byte_t* buffer [out]
 * @param size_t* buffer_size [inout]
 * @param int encoding [inopt] BASE64_ENCODING, BASE64URL_ENCODING
 * @return error code (see error.hpp)
 * @remarks
 *  source                 eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
 *  BASE64_ENCODING (E)    ZXlKMGVYQWlPaUpLVjFRaUxBMEtJQ0poYkdjaU9pSklVekkxTmlKOQ==
 *  BASE64URL_ENCODING (E) ZXlKMGVYQWlPaUpLVjFRaUxBMEtJQ0poYkdjaU9pSklVekkxTmlKOQ
 *  BASE64_ENCODING (D)    {"typ":"JWT",\n "alg":"HS256"}
 * @sample
 *        binary_t buffer;
 *        size_t size = 0;
 *        bse64_encode(source, source_size, &buffer[0], &size); // size in=0 out=56
 *        buffer.resize(size);
 *        bse64_encode(source, source_size, &buffer[0], &size); // size in=56 out=56
 *        buffer.resize(size);
 */
return_t base64_encode (const byte_t* source, size_t source_size, byte_t* buffer, size_t* buffer_size, int encoding = BASE64_ENCODING);

return_t base64_encode (const byte_t* source, size_t source_size, binary_t& encoded, int encoding = BASE64_ENCODING);

/*
 * decode base64 and base64url
 * @param const byte_t* sources [in]
 * @param size_t source_size [in]
 * @param byte_t* buffer [out]
 * @param size_t* buffer_size [inout]
 * @param int encoding [inopt] BASE64_ENCODING, BASE64URL_ENCODING
 * @return error code (see error.hpp)
 * @sample
 *        binary_t buffer;
 *        size_t size = 0;
 *        bse64_decode(source, source_size, &buffer[0], &size, BASE64URL_ENCODING); // size in=0 out=42
 *        buffer.resize(size);
 *        bse64_decode(source, source_size, &buffer[0], &size, BASE64URL_ENCODING); // size out=42 out=40
 *        buffer.resize(size);
 */
return_t base64_decode (const byte_t *source, size_t source_size, byte_t *buffer, size_t * buffer_size, int encoding = BASE64_ENCODING);

return_t base64_decode (const byte_t *source, size_t source_size, binary_t& decoded, int encoding = BASE64_ENCODING);

}
}  // namespace

#endif
