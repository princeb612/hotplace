/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   base16rfc.cpp
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

}  // namespace hotplace
