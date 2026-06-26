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

#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/string/string.hpp>

namespace hotplace {

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
