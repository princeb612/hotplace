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

    encoder_stream(const encoder_stream& other) = default;
    encoder_stream(encoder_stream&& other) = default;

    encoder_stream& operator=(const encoder_stream& other) = default;
    encoder_stream& operator=(encoder_stream&& other) = default;

    encoder_stream& set_maxsize(size_t size);
    encoding_t get_encoding();
    encoder_stream& set_endian(bool use_bigendian);
    bool is_bigendian();

    /**
     * @remarks max buffer size 4K
     *          to change max buffer, use set_maxsize
     */
    return_t write(const byte_t* data, size_t size);

    encoder_stream& operator<<(const char* value);
    encoder_stream& operator<<(const std::string& value);
    encoder_stream& operator<<(const binary_t& value);
    encoder_stream& operator<<(const basic_stream& value);

    encoder_stream& add(const char* value);
    encoder_stream& add(const byte_t* data, size_t size);
    encoder_stream& add(const std::string& value);
    encoder_stream& add(const binary_t& value);
    encoder_stream& add(const basic_stream& value);

    encoder_stream& add(int8 value);
    encoder_stream& add(int16 value);
    encoder_stream& add(int32 value);
    encoder_stream& add(int64 value);
#if defined __SIZEOF_INT128__
    encoder_stream& add(int128 value);
#endif
    encoder_stream& add(uint8 value);
    encoder_stream& add(uint16 value);
    encoder_stream& add(uint32 value);
    encoder_stream& add(uint64 value);
#if defined __SIZEOF_INT128__
    encoder_stream& add(uint128 value);
#endif

    encoder_stream& clear();

    std::string str();

   protected:
    return_t flush();

   private:
    struct encbuf_t {
        byte_t buf[3];
        uint8 len;  // [0..3]

        encbuf_t() : len(0) {}
        uint8 unitsize(encoding_t encoding) {
            switch (encoding) {
                case encoding_base64:
                case encoding_base64url:
                    return 3;
                default:
                    return 0;
            }
        }
        uint8 free_space(encoding_t encoding) {
            switch (encoding) {
                case encoding_base64:
                case encoding_base64url:
                    return 3 - len;  // MUST managed as [0..3]
                default:
                    return 0;
            }
        }
        void reset() { len = 0; }
    };

    encoding_t _encoding;
    bool _use_bigendian;
    size_t _maxsize;
    std::string _buffer;
    encbuf_t _encbuf;
};

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

    decoder_stream(const decoder_stream& other) = default;
    decoder_stream(decoder_stream&& other) = default;

    decoder_stream& operator=(const decoder_stream& other) = default;
    decoder_stream& operator=(decoder_stream&& other) = default;

    encoding_t get_encoding();

    return_t write(const char* data, size_t size);

    decoder_stream& operator<<(const char* value);
    decoder_stream& operator<<(const std::string& value);
    decoder_stream& operator<<(const basic_stream& value);

    decoder_stream& add(const char* value);
    decoder_stream& add(const std::string& value);
    decoder_stream& add(const basic_stream& value);

    binary_t data();

   protected:
    return_t flush();

   private:
    struct encbuf_t {
        char buf[5];
        uint8 len;  // [0..4]

        encbuf_t() : len(0) {}
        uint8 unitsize(encoding_t encoding) {
            switch (encoding) {
                case encoding_base16:
                    return 2;
                case encoding_base64:
                case encoding_base64url:
                    return 4;
                default:
                    return 0;
            }
        }
        uint8 free_space(encoding_t encoding) {
            switch (encoding) {
                case encoding_base16:
                    return 2 - len;  // MUST managed as [0..2]
                case encoding_base64:
                case encoding_base64url:
                    return 4 - len;  // MUST managed as [0..4]
                default:
                    return 0;
            }
        }
        void reset() { len = 0; }
    };

    encoding_t _encoding;
    binary_t _buffer;
    encbuf_t _encbuf;
};

}  // namespace hotplace

#endif
