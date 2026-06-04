/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   encoder_stream.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_ENCODERSTREAM__
#define __HOTPLACE_SDK_BASE_STREAM_ENCODERSTREAM__

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/nostd/traits.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/types.hpp>
#include <string>

namespace hotplace {

/**
 * @brief   encoder stream
 * @example
 *          encoder_stream encoder(encoding_base16, true);  // base16, big endian
 *          encoder.add("hello world").add(uint32(value));
 *          auto result = encoder.str();
 */
class encoder_stream {
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
    encoder_stream(encoding_t enc, bool use_bigendian = true);

    /**
     * copy/move
     */
    encoder_stream(const encoder_stream& other) = default;
    encoder_stream(encoder_stream&& other) = default;
    encoder_stream& operator=(const encoder_stream& other) = default;
    encoder_stream& operator=(encoder_stream&& other) = default;

    encoder_stream& set_maxsize(size_t size);
    size_t get_maxsize();
    encoding_t get_encoding();
    encoder_stream& set_endian(bool use_bigendian);
    bool is_bigendian();

    encoder_stream& clear();

    std::string str();
    binary_t bin();

    /**
     * @remarks max buffer size 32K
     *          to change max buffer, use set_maxsize
     */
    return_t write(const byte_t* data, size_t size);

    encoder_stream& add(const byte_t* data, size_t size) {
        write(data, size);
        return *this;
    }

    /**
     * delegation
     */
    template <typename T>
    encoder_stream& add(T&& value) {
        return *this << std::forward<T>(value);
    }

    /**
     * operator +=
     * delegation
     */
    template <typename T>
    encoder_stream& operator+=(T&& value) {
        return *this << std::forward<T>(value);
    }

    /**
     * operator <<
     * stream implementation
     * is_integral
     * !bool
     */
    template <typename T, typename std::enable_if<custom::is_integral<T>::value && !std::is_same<T, bool>::value, int>::type = 0>
    encoder_stream& operator<<(T value) {
        if (is_bigendian()) {
            auto final_value = convert_endian(value);
            write((byte_t*)&final_value, sizeof(T));
        } else {
            write((byte_t*)&value, sizeof(T));
        }
        return *this;
    }
    /**
     * operator <<
     * stream implementation
     * bool
     * !is_integral
     */
    encoder_stream& operator<<(bool value);
    encoder_stream& operator<<(const char* value);
    encoder_stream& operator<<(const std::string& value);
    encoder_stream& operator<<(const binary_t& value);
    encoder_stream& operator<<(const basic_stream& value);

   protected:
    return_t flush();

   private:
    struct encbuf_t {
        byte_t buf[3];
        uint8 len;  // [0..3]

        encbuf_t() : len(0) {}
        uint8 unitsize(encoding_t encoding) {
            switch (encoding) {
                case encoding_t::encoding_base64:
                case encoding_t::encoding_base64url:
                    return 3;
                default:
                    return 0;
            }
        }
        uint8 free_space(encoding_t encoding) {
            switch (encoding) {
                case encoding_t::encoding_base64:
                case encoding_t::encoding_base64url:
                    return 3 - len;  // MUST managed as [0..3]
                default:
                    return 0;
            }
        }
        void reset() { len = 0; }
    };
    struct bitbuf_t {
        uint8 buf;
        uint8 len;

        bitbuf_t() : buf(0), len(0) {}
        void reset() {
            buf = 0;
            len = 0;
        }
    };

    encoding_t _encoding;
    bool _use_bigendian;
    size_t _maxsize;
    std::string _buffer;
    binary_t _bin;
    encbuf_t _encbuf;
    bitbuf_t _bitbuf;
};

}  // namespace hotplace

#endif
