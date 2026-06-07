/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   decoder_stream.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_DECODERSTREAM__
#define __HOTPLACE_SDK_BASE_STREAM_DECODERSTREAM__

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/types.hpp>
#include <string>

namespace hotplace {

/**
 * @brief   decoder stream
 */
class decoder_stream {
   public:
    /**
     * @brief   ctor
     * @param   encoding_t enc
     *          encoding_base16     // BASE16
     *          encoding_base64     // BASE64    + /
     *          encoding_base64url  // BASE64URL - _ without padding
     *          encoding_base16rfc  // see base16_encode_rfc, base16_decode_rfc
     *          encoding_h2hcodes   // HTTP/2 huffman coding
     */
    decoder_stream(encoding_t enc);

    /**
     * copy/move
     */
    decoder_stream(const decoder_stream& other) = default;
    decoder_stream(decoder_stream&& other) = default;
    decoder_stream& operator=(const decoder_stream& other) = default;
    decoder_stream& operator=(decoder_stream&& other) = default;

    decoder_stream& set_maxsize(size_t size);
    size_t get_maxsize();
    encoding_t get_encoding();

    binary_t data();

    /**
     * @remarks max buffer size 32K
     *          to change max buffer, use set_maxsize
     */
    return_t write(const char* data, size_t size);
    return_t write(const byte_t* data, size_t size);

    decoder_stream& add(const char* data, size_t size);
    decoder_stream& add(const byte_t* data, size_t size);

    /**
     * delegation
     */
    template <typename T>
    decoder_stream& add(T&& value) {
        return *this << std::forward<T>(value);
    }

    /**
     * delegation
     */
    template <typename T>
    decoder_stream& operator+=(T&& value) {
        return *this << std::forward<T>(value);
    }

    /**
     * stream implementation
     */
    decoder_stream& operator<<(const char* value);
    decoder_stream& operator<<(const std::string& value);
    decoder_stream& operator<<(const basic_stream& value);

   protected:
    return_t flush();

   private:
    struct encbuf_t {
        char buf[5];
        uint8 len;  // [0..4]

        encbuf_t() : len(0) {}
        uint8 unitsize(encoding_t encoding) {
            switch (encoding) {
                case encoding_t::encoding_base16:
                    return 2;
                case encoding_t::encoding_base64:
                case encoding_t::encoding_base64url:
                    return 4;
                default:
                    return 0;
            }
        }
        uint8 free_space(encoding_t encoding) {
            switch (encoding) {
                case encoding_t::encoding_base16:
                    return 2 - len;  // MUST managed as [0..2]
                case encoding_t::encoding_base64:
                case encoding_t::encoding_base64url:
                    return 4 - len;  // MUST managed as [0..4]
                default:
                    return 0;
            }
        }
        void reset() { len = 0; }
    };

    encoding_t _encoding;
    size_t _maxsize;
    binary_t _buffer;
    encbuf_t _encbuf;      // base16, base64
    std::string _huffbuf;  // huffman coding
};

}  // namespace hotplace

#endif
