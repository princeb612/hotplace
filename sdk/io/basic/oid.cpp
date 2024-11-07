/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/template.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/string/string.hpp>
#include <sdk/io/basic/oid.hpp>

namespace hotplace {
namespace io {

void str_to_oid(const std::string& value, oid_t& oid) { str_to_oid(value.c_str(), value.size(), oid); }

void str_to_oid(const char* value, size_t size, oid_t& oid) {
    return_t ret = errorcode_t::success;
    size_t pos = 0;
    size_t brk = 0;
    while (errorcode_t::success == ret) {
        ret = scan(value, size, pos, &brk, ".");

        unsigned node = t_atoi_n<unsigned>(value + pos, (errorcode_t::success == ret) ? brk - pos - 1 : brk - pos);
        oid.insert(oid.end(), node);
        pos = brk;
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

}  // namespace io
}  // namespace hotplace
