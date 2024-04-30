/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 4648 The Base16, Base32, and Base64 Data Encodings
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.13   Soo Han, Kim        reboot : bin2hex, hex2bin
 */

#include <string.h>

#include <sdk/base/basic/base16.hpp>
#include <sdk/base/charset.hpp>
#include <sdk/base/string/string.hpp>

namespace hotplace {

return_t base16_encode(const byte_t* source, size_t size, char* buf, size_t* buflen) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == source || nullptr == buflen) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        size_t size_buf = *buflen;
        size_t size_necessary = (size << 1) + 1;

        *buflen = size_necessary;

        if (size_buf < size_necessary) {
            ret = errorcode_t::insufficient_buffer;
            __leave2;
        }

        if (nullptr == buf) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const byte_t* p = source;
        char* target = buf;
        size_t cur = 0;
        for (; cur < size; p++, target += 2, cur++) {
            snprintf(target, 3, "%02x", *p);
        }
        *target = 0;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t base16_encode(const byte_t* source, size_t size, std::string& outpart, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (0 == (base16_flag_t::base16_notrunc & flags)) {
            outpart.clear();
        }

        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        char buf[3];
        size_t buflen = sizeof(buf);
        for (size_t cur = 0; cur < size; cur++) {
            byte_t item = source[cur];
            if (base16_flag_t::base16_capital & flags) {
                snprintf(buf, buflen, "%02X", item);
            } else {
                snprintf(buf, buflen, "%02x", item);
            }
            outpart += buf[0];
            outpart += buf[1];
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t base16_encode(const byte_t* source, size_t size, stream_t* stream, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == source || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == (base16_flag_t::base16_notrunc & flags)) {
            stream->clear();
        }

        for (size_t cur = 0; cur < size; cur++) {
            byte_t item = source[cur];
            if (base16_flag_t::base16_capital & flags) {
                stream->printf("%02X", item);
            } else {
                stream->printf("%02x", item);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t base16_encode(binary_t const& source, char* buf, size_t* buflen) { return base16_encode(&source[0], source.size(), buf, buflen); }

return_t base16_encode(binary_t const& source, std::string& outpart, uint32 flags) { return base16_encode(&source[0], source.size(), outpart, flags); }

std::string base16_encode(binary_t const& source) {
    std::string outpart;

    base16_encode(source, outpart);
    return outpart;
}

return_t base16_encode(binary_t const& source, stream_t* stream) { return base16_encode(&source[0], source.size(), stream); }

std::string base16_encode(const char* source) {
    std::string outpart;
    if (source) {
        base16_encode((const byte_t*)source, strlen(source), outpart);
    }
    return outpart;
}

return_t base16_encode(const char* source, std::string& outpart) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        base16_encode((const byte_t*)source, strlen(source), outpart);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t base16_encode(const char* source, binary_t& outpart) {
    return_t ret = errorcode_t::success;
    if (source) {
        size_t slen = strlen(source);
        size_t dlen = 0;
        ret = base16_encode((const byte_t*)source, slen, (char*)&outpart[0], &dlen);
        outpart.resize(dlen);
        ret = base16_encode((const byte_t*)source, slen, (char*)&outpart[0], &dlen);
    }
    return ret;
}

return_t base16_encode(std::string const& source, binary_t& outpart) { return base16_encode(source.c_str(), outpart); }

static byte_t conv(char c) {
    byte_t ret = 0;

    if (('0' <= c) && (c <= '9')) {
        ret = c - '0';  // 0~9
    }
    if (('A' <= c) && (c <= 'F')) {
        ret = c - 'A' + 10;  // 10~15
    }
    if (('a' <= c) && (c <= 'f')) {
        ret = c - 'a' + 10;  // 10~15
    }
    return ret;
}

return_t base16_decode(const char* source, size_t size, binary_t& outpart, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == (base16_flag_t::base16_notrunc & flags)) {
            outpart.clear();
        }

        size_t cur = 0;
        if ((size > 2) && (0 == strnicmp(source, "0x", 2))) {
            cur = 2;
        }

        /* case of an odd size - NIST CAVP test vector */
        if (size % 2) {
            byte_t i = conv(source[cur++]);
            outpart.push_back(i);
        }

        /* octet */
        for (; cur < size; cur += 2) {
            byte_t i = 0;
            i = conv(source[cur]) << 4;
            i += conv(source[cur + 1]);
            outpart.push_back(i);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t base16_decode(const char* source, size_t size, stream_t* stream, uint32 flags) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == source || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (0 == (base16_flag_t::base16_notrunc & flags)) {
            stream->clear();
        }

        size_t cur = 0;
        if ((size > 2) && (0 == strnicmp(source, "0x", 2))) {
            cur = 2;
        }

        if (size % 2) { /* support NIST CAVP test vector */
            byte_t i = 0;
            i += conv(source[cur++]);
            stream->printf("%c", i);
        }
        for (; cur < size; cur += 2) {
            byte_t i = 0;
            i = conv(source[cur]) << 4;
            i += conv(source[cur + 1]);
            stream->printf("%c", i);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t base16_decode(std::string const& source, binary_t& outpart, uint32 flags) { return base16_decode(source.c_str(), source.size(), outpart, flags); }

return_t base16_decode(std::string const& source, stream_t* stream, uint32 flags) { return base16_decode(source.c_str(), source.size(), stream, flags); }

binary_t base16_decode(const char* source) {
    binary_t outpart;
    if (source) {
        outpart = base16_decode(source, strlen(source));
    }
    return outpart;
}

binary_t base16_decode(const char* source, size_t size) {
    binary_t outpart;

    base16_decode(source, size, outpart);
    return outpart;
}

binary_t base16_decode(std::string const& source) {
    binary_t outpart;

    base16_decode(source, outpart);
    return outpart;
}

std::string base16_encode_rfc(std::string const& source) {
    std::string inpart = source;
    std::string outpart;

    if (false == inpart.empty()) {
        ltrim(rtrim(inpart));

        // pattern 1 [ decimal, decimal, ..., decimal ]
        if (('[' == inpart[0]) && ends_with(inpart, "]")) {
            replace(inpart, "[", "");
            replace(inpart, "]", "");
            replace(inpart, " ", "");
            replace(inpart, "\t", "");
            replace(inpart, "\r", "");
            replace(inpart, "\n", "");
            split_context_t* handle = nullptr;
            size_t count = 0;
            std::string data;
            split_begin(&handle, inpart.c_str(), ",");
            split_count(handle, count);
            binary_t temp;
            for (size_t i = 0; i < count; i++) {
                split_get(handle, i, data);
                int value = atoi(data.c_str());
                if (value < 256) {
                    temp.push_back((byte_t)value);
                }
            }
            split_end(handle);
            outpart = base16_encode(temp);
        }
        // pattern 2 hex:hex:...:hex
        else {
            replace(inpart, ":", "");
            replace(inpart, " ", "");
            replace(inpart, "\t", "");
            replace(inpart, "\r", "");
            replace(inpart, "\n", "");
            outpart = inpart;
        }
    }
    return outpart;
}

binary_t base16_decode_rfc(std::string const& source) {
    std::string inpart = source;
    binary_t outpart;

    if (false == inpart.empty()) {
        ltrim(rtrim(inpart));

        // pattern 1 [ decimal, decimal, ..., decimal ]
        if (('[' == inpart[0]) && ends_with(inpart, "]")) {
            replace(inpart, "[", "");
            replace(inpart, "]", "");
            replace(inpart, " ", "");
            replace(inpart, "\t", "");
            replace(inpart, "\r", "");
            replace(inpart, "\n", "");
            split_context_t* handle = nullptr;
            size_t count = 0;
            std::string data;
            split_begin(&handle, inpart.c_str(), ",");
            split_count(handle, count);
            for (size_t i = 0; i < count; i++) {
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
            replace(inpart, ":", "");
            replace(inpart, " ", "");
            replace(inpart, "\t", "");
            replace(inpart, "\r", "");
            replace(inpart, "\n", "");
            outpart = base16_decode(inpart);
        }
    }
    return outpart;
}

}  // namespace hotplace
