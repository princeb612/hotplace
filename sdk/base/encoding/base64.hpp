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

#ifndef __HOTPLACE_SDK_BASE_ENCODING_BASE64__
#define __HOTPLACE_SDK_BASE_ENCODING_BASE64__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/encoding/lowlevel/base64.hpp>
#include <hotplace/sdk/base/nostd/traits_encoder.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>

namespace hotplace {

/**
 * @remarks
 *          source        eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
 *          BASE64 (E)    ZXlKMGVYQWlPaUpLVjFRaUxBMEtJQ0poYkdjaU9pSklVekkxTmlKOQ==
 *          BASE64URL (E) ZXlKMGVYQWlPaUpLVjFRaUxBMEtJQ0poYkdjaU9pSklVekkxTmlKOQ
 *          BASE64 (D)    {"typ":"JWT",\n "alg":"HS256"}
 */

template <typename T, typename std::enable_if<custom::encoder_stream_traits<T>::value, int>::type = 0>
return_t base64_encode(const byte_t* source, size_t size, T& streambuf, encoding_t encoding = encoding_t::encoding_base64, uint32 flags = 0) {
    typedef custom::encoder_stream_traits<T> traits;
    typedef typename traits::value_type value_type;
    return_t ret = errorcode_t::success;

    if (encoding_t::encoding_base64 == encoding || encoding_t::encoding_base64url == encoding) {
        if (0 == (encoding_notrunc & flags)) {
            traits::trunc(streambuf);
        }
        size_t size_reserve = 0;
        ret = lowlevel::base64_encode(source, size, nullptr, &size_reserve, encoding);         // required size
        if (errorcode_t::insufficient_buffer == ret) {                                         // how many size required
            value_type* buf = traits::reserve(streambuf, size_reserve);                        // reserve
            size_t size_written = size_reserve;                                                //
            ret = lowlevel::base64_encode(source, size, (char*)buf, &size_written, encoding);  // encode
            if (errorcode_t::success == ret) {                                                 //
                traits::commit(streambuf, size_reserve, size_written);                         // shrink
            }
        }
    }
    return ret;
};

template <typename T, typename std::enable_if<custom::encoder_stream_traits<T>::value, int>::type = 0>
return_t base64_encode(const binary_t& source, T& streambuf, encoding_t encoding = encoding_t::encoding_base64, uint32 flags = 0) {
    return base64_encode(source.data(), source.size(), streambuf, encoding, flags);
}

std::string base64_encode(const char* source, encoding_t encoding = encoding_t::encoding_base64);
std::string base64_encode(const byte_t* source, size_t size, encoding_t encoding = encoding_t::encoding_base64);
std::string base64_encode(const std::string& source, encoding_t encoding = encoding_t::encoding_base64);
std::string base64_encode(const binary_t& source, encoding_t encoding = encoding_t::encoding_base64);
std::string base64_encode(const basic_stream& source, encoding_t encoding = encoding_t::encoding_base64);

template <typename T, typename std::enable_if<custom::encoder_stream_traits<T>::value, int>::type = 0>
return_t base64_decode(const char* source, size_t size, T& streambuf, encoding_t encoding = encoding_t::encoding_base64, uint32 flags = 0) {
    typedef custom::encoder_stream_traits<T> traits;
    typedef typename traits::value_type value_type;
    return_t ret = errorcode_t::success;

    if (encoding_t::encoding_base64 == encoding || encoding_t::encoding_base64url == encoding) {
        if (0 == (encoding_notrunc & flags)) {
            traits::trunc(streambuf);
        }
        size_t size_reserve = 0;
        ret = lowlevel::base64_decode(source, size, nullptr, &size_reserve, encoding);           // required size
        if (errorcode_t::insufficient_buffer == ret) {                                           // how many size required
            value_type* buf = traits::reserve(streambuf, size_reserve);                          // reserve
            size_t size_written = size_reserve;                                                  //
            ret = lowlevel::base64_decode(source, size, (byte_t*)buf, &size_written, encoding);  // decode
            if (errorcode_t::success == ret) {                                                   //
                traits::commit(streambuf, size_reserve, size_written);                           // shrink
            }
        }
    }
    return ret;
};

template <typename T, typename std::enable_if<custom::encoder_stream_traits<T>::value, int>::type = 0>
return_t base64_decode(const std::string& source, T& streambuf, encoding_t encoding = encoding_t::encoding_base64, uint32 flags = 0) {
    return base64_decode(source.c_str(), source.size(), streambuf, encoding, flags);
}

binary_t base64_decode(const char* source, encoding_t encoding = encoding_t::encoding_base64);
binary_t base64_decode(const char* source, size_t size, encoding_t encoding = encoding_t::encoding_base64);
binary_t base64_decode(const byte_t* source, size_t size, encoding_t encoding = encoding_t::encoding_base64);
binary_t base64_decode(const std::string& source, encoding_t encoding = encoding_t::encoding_base64);
binary_t base64_decode(const binary_t& source, encoding_t encoding = encoding_t::encoding_base64);
binary_t base64_decode(const basic_stream& source, encoding_t encoding = encoding_t::encoding_base64);

/**
 * @brief   decode (use this only if the original source is a string)
 * @param   const std::string& source [in]
 * @param   encoding_t encoding [inopt] see encoding_t
 */
std::string base64_decode_careful(const std::string& source, encoding_t encoding = encoding_t::encoding_base64);
/**
 * @brief   decode (use this only if the original source is a string)
 * @param   const char* source [in]
 * @param   size_t source_size [in]
 * @param   encoding_t encoding [inopt] see encoding_t
 */
std::string base64_decode_careful(const char* source, size_t source_size, encoding_t encoding = encoding_t::encoding_base64);

}  // namespace hotplace

#endif
