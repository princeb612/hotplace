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

#include <algorithm>
#include <hotplace/sdk/base/encoding/base64.hpp>
#include <hotplace/sdk/base/encoding/decoder_stream.hpp>
#include <hotplace/sdk/base/encoding/encoder_stream.hpp>
#include <hotplace/sdk/base/string/string.hpp>

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

return_t base64_encode_multiline(const byte_t* data, size_t data_size, uint16 column, std::string& encoded) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        encoder_stream encoder(encoding_t::encoding_base64);
        ret = encoder.write(data, data_size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        auto res = encoder.str();
        std::string out;
        // if 0 == column do not wrap
        if (column && (column < res.size())) {
            size_t cursor = 0;
            for (const auto& ch : res) {
                out.push_back(ch);
                if (++cursor == column) {
                    out.push_back('\n');
                    cursor = 0;
                }
            }
            encoded = std::move(out);
        } else {
            encoded = std::move(res);
        }
    }
    __finally2 {}
    return ret;
}

return_t base64_decode_multiline(const char* encoded, size_t encoded_size, binary_t& decoded) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == encoded) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        decoder_stream decoder(encoding_t::encoding_base64);

        size_t pos = 0;
        size_t brk = 0;
        while (errorcode_t::success == scan(encoded, encoded_size, pos, &brk, "\n")) {
            // trim (line may contain CR and NL)
            auto tbrk = brk;
            auto tpos = pos;
            while (std::isspace(*(encoded + tpos))) ++tpos;
            if (tbrk > 0) {
                while (std::isspace(*(encoded + tbrk - 1))) --tbrk;
            }

            if (tbrk < tpos) {
                // case only whitespace "  "
                ret = errorcode_t::empty;
                break;
            }
            decoder.write(encoded + tpos, tbrk - tpos);

            pos = brk + 1;
        }

        auto res = decoder.data();
        decoded = std::move(res);
    }
    __finally2 {}
    return ret;
}

}  // namespace hotplace
