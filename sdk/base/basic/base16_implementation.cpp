/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   base16_implementation.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 4648 The Base16, Base32, and Base64 Data Encodings
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.13   Soo Han, Kim        reboot : bin2hex, hex2bin
 */

#include <string.h>

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/string/string.hpp>

namespace hotplace {

namespace implementation {

inline byte_t conv_fast(char c) {
    const unsigned char uc = static_cast<unsigned char>(c);
    if (uc >= '0' && uc <= '9') {
        return static_cast<byte_t>(uc - '0');
    }
    if (uc >= 'A' && uc <= 'F') {
        return static_cast<byte_t>(uc - 'A' + 10);
    }
    if (uc >= 'a' && uc <= 'f') {
        return static_cast<byte_t>(uc - 'a' + 10);
    }
    return 0;
}

inline const char* hex_digits(bool uppercase) { return uppercase ? "0123456789ABCDEF" : "0123456789abcdef"; }

return_t base16_encode(const byte_t* source, size_t size, char* buf, size_t* buflen, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == source || nullptr == buflen) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_buf = *buflen;
        size_t size_necessary = (size << 1);

        *buflen = size_necessary;

        if (size_buf < size_necessary) {
            ret = errorcode_t::insufficient_buffer;
            __leave2;
        }

        if (nullptr == buf) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // direct copy instead of snprintf
        const bool capital = (encoding_flag_t::encoding_base16_capital & flags);
        const char* digits = hex_digits(capital);
        for (size_t i = 0; i < size; ++i) {
            const byte_t v = source[i];
            buf[(i << 1) + 0] = digits[(v >> 4) & 0x0F];
            buf[(i << 1) + 1] = digits[v & 0x0F];
        }
    }
    __finally2 {}
    return ret;
}

return_t base16_encode(const binary_t& source, char* buf, size_t* buflen, uint32 flags) {
    return_t ret = errorcode_t::success;
    ret = base16_encode(source.data(), source.size(), buf, buflen, flags);
    return ret;
}

return_t base16_encode(const char* source, size_t size, char* buf, size_t* buflen, uint32 flags) {
    return_t ret = errorcode_t::success;
    if (source) {
        ret = base16_encode((byte_t*)source, size, buf, buflen, flags);
    }
    return ret;
}

return_t base16_encode(const std::string& source, char* buf, size_t* buflen, uint32 flags) { return base16_encode(source.c_str(), source.size(), buf, buflen, flags); }

return_t base16_decode(const char* source, size_t size, byte_t* buf, size_t* buflen) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == source || nullptr == buflen) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_buf = *buflen;

        size_t cur = 0;
        /* ignore 0x prefix*/
        if ((size > 2) && (0 == strnicmp(source, "0x", 2))) {
            cur = 2;
        }

        /* reserve expected output size to reduce reallocations. */
        {
            const size_t hex_len = (size > cur) ? (size - cur) : 0;
            const size_t expected = (hex_len + 1) >> 1;  // supports odd sizes
            *buflen = expected;

            if (size_buf < expected) {
                ret = errorcode_t::insufficient_buffer;
                __leave2;
            }
        }

        if (nullptr == buf) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t pos = 0;
        /* case of an odd size - NIST CAVP test vector */
        if (size % 2) {
            buf[pos++] = conv_fast(source[cur++]);
        }

        /* octet */
        for (; cur < size; cur += 2) {
            byte_t i = 0;
            i = conv_fast(source[cur]) << 4;
            i += conv_fast(source[cur + 1]);
            buf[pos++] = i;
        }
    }
    __finally2 {}
    return ret;
}

return_t base16_decode(const std::string& source, byte_t* buf, size_t* buflen) { return base16_decode(source.c_str(), source.size(), buf, buflen); }

return_t base16_decode(const byte_t* source, size_t size, byte_t* buf, size_t* buflen) { return base16_decode((char*)source, size, buf, buflen); }

return_t base16_decode(const binary_t source, byte_t* buf, size_t* buflen) { return base16_decode((char*)source.data(), source.size(), buf, buflen); }

}  // namespace implementation

}  // namespace hotplace
