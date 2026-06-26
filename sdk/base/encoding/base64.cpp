/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   base64.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 4648 The Base16, Base32, and Base64 Data Encodings
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.16   Soo Han, Kim        fix : base64_encode encoded size
 * 2023.08.20   Soo Han, Kim        fix : base64_encode source access range
 */

#include <hotplace/sdk/base/encoding/base64.hpp>

namespace hotplace {

std::string base64_encode(const char* source, encoding_t encoding) {
    std::string res;
    if (source) {
        auto size = strlen(source);
        base64_encode((byte_t*)source, size, res, encoding);
    }
    return res;
}

std::string base64_encode(const byte_t* source, size_t size, encoding_t encoding) {
    std::string res;
    if (source) {
        base64_encode((byte_t*)source, size, res, encoding);
    }
    return res;
}

std::string base64_encode(const std::string& source, encoding_t encoding) {
    std::string res;
    base64_encode((byte_t*)source.data(), source.size(), res, encoding);
    return res;
}

std::string base64_encode(const binary_t& source, encoding_t encoding) {
    std::string res;
    base64_encode(source.data(), source.size(), res, encoding);
    return res;
}

std::string base64_encode(const basic_stream& source, encoding_t encoding) {
    std::string res;
    base64_encode(source.data(), source.size(), res, encoding);
    return res;
}

binary_t base64_decode(const char* source, encoding_t encoding) {
    binary_t res;
    if (source) {
        auto size = strlen(source);
        base64_decode(source, size, res, encoding);
    }
    return res;
}

binary_t base64_decode(const char* source, size_t size, encoding_t encoding) {
    binary_t res;
    if (source) {
        base64_decode(source, size, res, encoding);
    }
    return res;
}

binary_t base64_decode(const byte_t* source, size_t size, encoding_t encoding) {
    binary_t res;
    if (source) {
        base64_decode((char*)source, size, res, encoding);
    }
    return res;
}

binary_t base64_decode(const std::string& source, encoding_t encoding) {
    binary_t res;
    base64_decode(source.c_str(), source.size(), res, encoding);
    return res;
}

binary_t base64_decode(const binary_t& source, encoding_t encoding) {
    binary_t res;
    base64_decode((char*)source.data(), source.size(), res, encoding);
    return res;
}

binary_t base64_decode(const basic_stream& source, encoding_t encoding) {
    binary_t res;
    base64_decode(source.c_str(), source.size(), res, encoding);
    return res;
}

std::string base64_decode_careful(const std::string& source, encoding_t encoding) {
    std::string res;
    base64_decode(source.c_str(), source.size(), res, encoding);
    return res;
}

std::string base64_decode_careful(const char* source, size_t source_size, encoding_t encoding) {
    std::string res;
    base64_decode(source, source_size, res, encoding);
    return res;
}

}  // namespace hotplace
