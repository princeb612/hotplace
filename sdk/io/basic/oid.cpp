/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   oid.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

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

void asn1str_to_oid(const char* value, size_t size, oid_t& oid) {
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

}  // namespace io
}  // namespace hotplace
