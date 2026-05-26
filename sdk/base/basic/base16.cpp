/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   base16.cpp
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

namespace implementation {

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

std::string base16_encode(const char* source, uint32 flags) {
    std::string res;
    if (source) {
        auto size = strlen(source);
        base16_encode((byte_t*)source, size, res, flags);
    }
    return res;
}

std::string base16_encode(const byte_t* source, size_t size, uint32 flags) {
    std::string res;
    if (source) {
        base16_encode(source, size, res, flags);
    }
    return res;
}

std::string base16_encode(const std::string& source, uint32 flags) {
    std::string res;
    base16_encode((byte_t*)source.c_str(), source.size(), res, flags);
    return res;
}

std::string base16_encode(const binary_t& source, uint32 flags) {
    std::string res;
    base16_encode(source.data(), source.size(), res, flags);
    return res;
}

std::string base16_encode(const basic_stream& source, uint32 flags) {
    std::string res;
    base16_encode(source.data(), source.size(), res, flags);
    return res;
}

binary_t base16_decode(const char* source) {
    binary_t res;
    if (source) {
        auto size = strlen(source);
        base16_decode(source, size, res);
    }
    return res;
}

binary_t base16_decode(const char* source, size_t size) {
    binary_t res;
    if (source) {
        base16_decode(source, size, res);
    }
    return res;
}

binary_t base16_decode(const byte_t* source, size_t size) {
    binary_t res;
    base16_decode((char*)source, size, res);
    return res;
}

binary_t base16_decode(const std::string& source) {
    binary_t res;
    base16_decode(source.c_str(), source.size(), res);
    return res;
}

binary_t base16_decode(const binary_t& source) {
    binary_t res;
    base16_decode((char*)source.data(), source.size(), res);
    return res;
}
binary_t base16_decode(const basic_stream& source) {
    binary_t res;
    base16_decode(source.c_str(), source.size(), res);
    return res;
}

std::string base16_encode_rfc(const std::string& source) {
    std::string outpart;

    if (false == source.empty()) {
        std::string inpart = source;
        ltrim(rtrim(inpart));

        // pattern 1 [ decimal, decimal, ..., decimal ]
        if (('[' == inpart[0]) && ends_with(inpart, "]")) {
            replace(inpart, "[", "");
            replace(inpart, "]", "");
            replace(inpart, " ", "");
            replace(inpart, "\t", "");
            replace(inpart, "\r", "");
            replace(inpart, "\n", "");
            replace(inpart, "-", "");
            split_context_t* handle = nullptr;
            std::string data;
            binary_t temp;
            split_begin(&handle, inpart.c_str(), ",");
            auto lambda = [&](const std::string& item) -> void {
                int value = atoi(data.c_str());
                if (value < 256) {
                    temp.push_back((byte_t)value);
                }
            };
            split_foreach(handle, lambda);
            split_end(handle);
            outpart = std::move(base16_encode(temp));
        }
        // pattern 2 hex:hex:...:hex
        else {
            // single phase
            for (auto e : inpart) {
                if (('9' >= e && e >= '0') || ('f' >= e && e >= 'a') || ('F' >= e && e >= 'A') || ('x' == e)) {
                    outpart.push_back(e);
                }
            }
        }
    }
    return outpart;
}

binary_t base16_decode_rfc(const std::string& source) {
    binary_t outpart;

    if (false == source.empty()) {
        std::string inpart = source;
        ltrim(rtrim(inpart));

        // pattern 1 [ decimal, decimal, ..., decimal ]
        if (('[' == inpart[0]) && ends_with(inpart, "]")) {
            replace(inpart, "[", "");
            replace(inpart, "]", "");
            replace(inpart, " ", "");
            replace(inpart, "\t", "");
            replace(inpart, "\r", "");
            replace(inpart, "\n", "");
            replace(inpart, "-", "");
            split_context_t* handle = nullptr;
            size_t count = 0;
            std::string data;
            split_begin(&handle, inpart.c_str(), ",");
            split_count(handle, count);
            for (unsigned int i = 0; i < count; i++) {
                split_get(handle, i, data);
                int value = atoi(data.c_str());
                if (value < 256) {
                    outpart.push_back((byte_t)value);
                }
            }
            split_end(handle);
        }
        // pattern 2 hex:hex:...:hex
        // pattern 3 hex hex ... hex\nhex hex
        else {
            // single phase
            std::string temp;
            for (auto e : inpart) {
                if (('9' >= e && e >= '0') || ('F' >= e && e >= 'A') || ('f' >= e && e >= 'a') || ('x' == e)) {
                    temp.push_back(e);
                }
            }
            outpart = std::move(base16_decode(temp));
        }
    }
    return outpart;
}

binary_t base16_decode_rfc(const char* source) {
    std::string input;
    if (source) {
        input = source;
    }
    return base16_decode_rfc(input);
}

bool base16_compare(const std::string& lhs, const std::string& rhs) { return base16_compare(lhs.c_str(), rhs.c_str()); }

bool base16_compare(const char* lhs, const char* rhs) {
    bool ret = false;
    binary_t lbin = base16_decode_rfc(lhs);
    binary_t rbin = base16_decode_rfc(rhs);
    while (false == lbin.empty()) {
        if (0 == lbin.front()) {
            lbin.erase(lbin.begin());
        }
    }
    while (false == rbin.empty()) {
        if (0 == rbin.front()) {
            rbin.erase(rbin.begin());
        }
    }
    ret = (lbin == rbin);
    return ret;
}

}  // namespace hotplace
