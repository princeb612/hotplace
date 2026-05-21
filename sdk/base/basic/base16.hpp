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

#ifndef __HOTPLACE_SDK_BASE_BASIC_BASE16__
#define __HOTPLACE_SDK_BASE_BASIC_BASE16__

#include <hotplace/sdk/base/basic/types.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>

namespace hotplace {

namespace implementation {

return_t base16_encode(const byte_t* source, size_t size, char* buf, size_t* buflen, uint32 flags = 0);
return_t base16_encode(const binary_t& source, char* buf, size_t* buflen, uint32 flags = 0);
return_t base16_encode(const char* source, size_t size, char* buf, size_t* buflen, uint32 flags = 0);
return_t base16_encode(const std::string& source, char* buf, size_t* buflen, uint32 flags = 0);

return_t base16_decode(const char* source, size_t size, byte_t* buf, size_t* buflen);
return_t base16_decode(const std::string& source, byte_t* buf, size_t* buflen);
return_t base16_decode(const byte_t* source, size_t size, byte_t* buf, size_t* buflen);
return_t base16_decode(const binary_t source, byte_t* buf, size_t* buflen);

}  // namespace implementation

template <typename T>
return_t base16_encode(const byte_t* source, size_t size, T& streambuf, uint32 flags = 0) {
    typedef encoder_stream_traits<T> traits;
    typedef typename traits::value_type value_type;
    return_t ret = errorcode_t::success;

    if (0 == (base16_notrunc & flags)) {
        traits::trunc(streambuf);
    }
    size_t size_reserve = 0;
    ret = implementation::base16_encode(source, size, nullptr, &size_reserve, flags);         // required size
    if (errorcode_t::insufficient_buffer == ret) {                                            // how many size required
        value_type* buf = traits::reserve(streambuf, size_reserve);                           // reserve
        size_t size_written = size_reserve;                                                   //
        ret = implementation::base16_encode(source, size, (char*)buf, &size_written, flags);  // encode
        if (errorcode_t::success == ret) {                                                    //
            traits::commit(streambuf, size_reserve, size_written);                            // shrink
        }
    }
    return ret;
};

template <typename T>
return_t base16_encode(const binary_t& source, T& streambuf, uint32 flags = 0) {
    return base16_encode(source.data(), source.size(), streambuf, flags);
}

std::string base16_encode(const char* source, uint32 flags = 0);
std::string base16_encode(const byte_t* source, size_t size, uint32 flags = 0);
std::string base16_encode(const std::string& source, uint32 flags = 0);
std::string base16_encode(const binary_t& source, uint32 flags = 0);
std::string base16_encode(const basic_stream& source, uint32 flags = 0);

template <typename T>
return_t base16_decode(const char* source, size_t size, T& streambuf, uint32 flags = 0) {
    typedef encoder_stream_traits<T> traits;
    typedef typename traits::value_type value_type;
    return_t ret = errorcode_t::success;

    if (0 == (base16_notrunc & flags)) {
        traits::trunc(streambuf);
    }
    size_t size_reserve = 0;
    ret = implementation::base16_decode(source, size, nullptr, &size_reserve);           // required size
    if (errorcode_t::insufficient_buffer == ret) {                                       // how many size required
        value_type* buf = traits::reserve(streambuf, size_reserve);                      // reserve
        size_t size_written = size_reserve;                                              //
        ret = implementation::base16_decode(source, size, (byte_t*)buf, &size_written);  // decode
        if (errorcode_t::success == ret) {                                               //
            traits::commit(streambuf, size_reserve, size_written);                       // shrink
        }
    }
    return ret;
};

template <typename T>
return_t base16_decode(const std::string& source, T& streambuf, uint32 flags = 0) {
    return base16_decode(source.c_str(), source.size(), streambuf, flags);
}

binary_t base16_decode(const char* source);
binary_t base16_decode(const char* source, size_t size);
binary_t base16_decode(const byte_t* source, size_t size);
binary_t base16_decode(const std::string& source);
binary_t base16_decode(const binary_t& source);
binary_t base16_decode(const basic_stream& source);

/**
 * @brief   encode (support various rfc-style)
 * @param   const std::string& source [in]
 * @return  std::string
 * @example
 *      // RFC 7516
 *      // Initialization Vector [227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]
 *      std::string iv = base16_encode_rfc("[227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]");
 *      // RFC 7539
 *      // Key = 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
 *      std::string key = base16_encode_rfc("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f");
 *      //  000  80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f  ................
 *      //  016  90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f  ................
 *      binary_t key = base16_encode_rfc("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f"
 *                                       "90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f");
 */
std::string base16_encode_rfc(const std::string& source);
/**
 * @brief   decode
 * @param   const std::string& source [in]
 * @return  binary_t
 * @sample  base16_encode_rfc
 */
binary_t base16_decode_rfc(const std::string& source);
/**
 * @param   const char* source [in]
 * @example
 *          binary_t key = std::move(base16_decode_rfc("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f"));
 * @sample  base16_encode_rfc
 */
binary_t base16_decode_rfc(const char* source);

bool base16_compare(const std::string& lhs, const std::string& rhs);
bool base16_compare(const char* lhs, const char* rhs);

}  // namespace hotplace

#endif
