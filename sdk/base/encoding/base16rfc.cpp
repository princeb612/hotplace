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
#include <hotplace/sdk/base/string/split.hpp>
#include <hotplace/sdk/base/string/string.hpp>

namespace hotplace {

std::string base16_encode_rfc(const std::string& source) {
    std::string outpart;

    if (false == source.empty()) {
        std::string inpart = source;
        ltrim(rtrim(inpart));

        // pattern 1 [ decimal, decimal, ..., decimal ]
        if (('[' == inpart[0]) && ends_with(inpart, "]")) {
            // refine
            replace(inpart, "[", "");
            replace(inpart, "]", "");
            replace(inpart, " ", "");
            replace(inpart, "\t", "");
            replace(inpart, "\r", "");
            replace(inpart, "\n", "");
            replace(inpart, "-", "");

            split_context_t* handle = nullptr;
            binary_t temp;
            split_begin(&handle, inpart.c_str(), ",");
            auto lambda = [&temp](const std::string& item) -> bool {
                int value = atoi(item.c_str());
                // if empty 0
                // else if [..., 300, ...]
                if (value >= 256) return false;
                temp.push_back((byte_t)value);
                return true;
            };
            auto test = split_foreach(handle, lambda);
            split_end(handle);

            // encode
            if (errorcode_t::success == test) outpart = std::move(base16_encode(temp));
        }
        // pattern 2 hex:hex:...:hex
        else if (std::string::npos != source.find(":")) {
            // refine
            split_context_t* handle = nullptr;
            std::string temp;
            std::string refined;
            for (const auto& e : inpart) {
                if (('9' >= e && e >= '0') || ('f' >= e && e >= 'a') || ('F' >= e && e >= 'A') || (':' == e)) {
                    refined.push_back(e);
                }
            }
            split_begin(&handle, refined.c_str(), ":");
            auto lambda = [&temp](const std::string& item) -> bool {
                std::string hex = item;
                // bad case [...:0001f:11b:f::...]
                // case "0001f"
                while (hex.size() > 2 && '0' == hex.front()) hex.erase(0, 1);  // pop_front();
                // case "11b"
                if (hex.size() > 2) return false;
                // case "f" or empty
                while (hex.size() < 2) hex.insert(0, 1, '0');  // push_front('0');
                // current item size is 2bytes
                for (const auto& e : hex) {
                    temp.push_back((byte_t)e);
                }
                return true;
            };
            auto test = split_chained_foreach(handle, lambda);
            split_end(handle);

            // encode
            if (errorcode_t::success == test) outpart = std::move(temp);
        }
        // pattern 3 00 01 02 03 ...
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
            std::string temp;
            split_begin(&handle, inpart.c_str(), ",");
            auto lambda = [&temp](const std::string& item) -> bool {
                int value = atoi(item.c_str());
                if (value >= 256) return false;
                temp.push_back((byte_t)value);
                return true;
            };
            auto test = split_chained_foreach(handle, lambda);
            split_end(handle);

            if (errorcode_t::success != test) {
                temp.clear();
            }
        } else {
            // pattern 2 hex:hex:...:hex
            if (std::string::npos != source.find(":")) {
                split_context_t* handle = nullptr;
                std::string temp;
                std::string refined;
                for (const auto& e : inpart) {
                    if (('9' >= e && e >= '0') || ('f' >= e && e >= 'a') || ('F' >= e && e >= 'A') || (':' == e)) refined.push_back(e);
                }
                split_begin(&handle, refined.c_str(), ":");
                auto lambda = [&temp](const std::string& item) -> bool {
                    std::string hex = item;
                    // bad case [...:0001f:11b:f::...]
                    // case "0001f"
                    while (hex.size() > 2 && '0' == hex.front()) hex.erase(0, 1);  // pop_front();
                    // case "11b"
                    if (hex.size() > 2) return false;
                    // case "f" or empty
                    while (hex.size() < 2) hex.insert(0, 1, '0');  // push_front('0');
                    // current item size is 2bytes
                    for (const auto& e : hex) {
                        temp.push_back((byte_t)e);
                    }
                    return true;
                };
                auto test = split_chained_foreach(handle, lambda);
                split_end(handle);

                // decode
                if (errorcode_t::success == test) outpart = std::move(base16_decode(temp));
            }
            // pattern 3 00 01 02 03 ...
            else {
                if (std::string::npos != inpart.find("0x", 0)) inpart.erase(0, 2);
                // single phase
                std::string temp;
                for (auto e : inpart) {
                    if (('9' >= e && e >= '0') || ('F' >= e && e >= 'A') || ('f' >= e && e >= 'a')) {
                        temp.push_back(e);
                    }
                }
                outpart = std::move(base16_decode(temp));
            }
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
