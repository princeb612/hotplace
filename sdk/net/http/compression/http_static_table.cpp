/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/compression/http_static_table.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http_static_table::http_static_table() {}

match_result_t http_static_table::match(uint32 flags, const std::string& name, const std::string& value, size_t& index) {
    match_result_t state = match_result_t::not_matched;
    index = 0;

    __try2 {
        auto liter = _static_table.lower_bound(name);
        auto uiter = _static_table.upper_bound(name);

        for (auto iter = liter; iter != uiter; iter++) {
            if (iter == liter) {
                index = iter->second.second;  // :path: /sample/path
                state = match_result_t::key_matched;
            }
            if (value == iter->second.first) {
                index = iter->second.second;
                state = match_result_t::all_matched;
                break;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return state;
}

return_t http_static_table::select(uint32 flags, size_t index, std::string& name, std::string& value) {
    return_t ret = errorcode_t::not_found;
    __try2 {
        static_table_index_t::iterator iter = _static_table_index.find(index);
        if (_static_table_index.end() == iter) {
            ret = errorcode_t::not_found;
            __leave2;
        } else {
            name = iter->second.first;
            if ((hpack_layout_index | hpack_layout_name_value) & flags) {
                value = iter->second.second;
                ret = errorcode_t::success;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

size_t http_static_table::size() { return _static_table.size(); }

void http_static_table::load() {}

}  // namespace net
}  // namespace hotplace
