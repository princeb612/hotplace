/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   oid.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <cctype>
#include <hotplace/sdk/base/nostd/atoi.hpp>
#include <hotplace/sdk/base/pattern/regex.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/io/basic/oid.hpp>

namespace hotplace {
namespace io {

void str_to_oid(const std::string& value, oid_t& oid) { str_to_oid(value.c_str(), value.size(), oid); }

void str_to_oid(const char* value, size_t size, oid_t& oid) {
    if (nullptr == value) return;
    oid.clear();
    size_t pos = 0;
    size_t brk = 0;
    for (size_t i = 0; i < size; ++i) {
        auto c = (unsigned char)value[i];
        if (('.' == c) || std::isdigit(c)) {
            continue;
        } else {
            oid.clear();
            return;
        }
    }
    while (errorcode_t::success == scan(value, size, pos, &brk, ".")) {
        auto node = t_atoi_n<uint32>(value + pos, brk - pos);
        oid.insert(oid.end(), node);
        pos = brk + 1;
    }
}

void oid_to_str(const oid_t& value, basic_stream& oid) {
    oid.clear();
    for (auto iter = value.begin(); iter != value.end(); iter++) {
        if (value.begin() != iter) {
            oid << ".";
        }
        oid << *iter;
    }
}

void asn1text_to_oid(const char* value, size_t size, oid_t& oid) {
    oid.clear();
    if (nullptr == value) return;
    size_t pos = 0;
    std::list<range_t> tokens;
    regex_token(value, size, R"(\d+)", pos, tokens);
    for (const auto& token : tokens) {
        auto node = t_atoi_n<uint32>(value + token.begin, token.end - token.begin);
        oid.push_back(node);
    }
}

void asn1text_to_oid(const char* value, size_t size, asn1oid_t& nodes) {
    size_t pos = 0;
    std::list<std::map<size_t, range_t>> tokens;
    regex_tokens(value, size, R"(([a-zA-Z0-9_-]+)(?:\((\d+)\))?)", pos, tokens);
    for (const auto& match_map : tokens) {
        std::string token_str;
        std::string num_str;

        auto it1 = match_map.find(1);
        if (match_map.end() != it1) {
            token_str.assign(value + it1->second.begin, it1->second.end - it1->second.begin);
        }
        auto it2 = match_map.find(2);
        if (match_map.end() != it2) {
            num_str.assign(value + it2->second.begin, it2->second.end - it2->second.begin);
        }

        uint32 arc = 0;
        if (false == num_str.empty()) {
            arc = t_atoi<uint32>(num_str.c_str());
        } else if (false == token_str.empty() && std::all_of(token_str.begin(), token_str.end(), ::isdigit)) {
            arc = t_atoi<uint32>(token_str.c_str());
        }

        nodes.push_back({arc, num_str.empty() ? "" : token_str});
    }
}

}  // namespace io
}  // namespace hotplace
