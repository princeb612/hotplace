/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http2/http_header_compression.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http_header_compression_table_static::http_header_compression_table_static() {}

match_result_t http_header_compression_table_static::match(uint32 flags, const std::string& name, const std::string& value, size_t& index) {
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

return_t http_header_compression_table_static::select(uint32 flags, size_t index, std::string& name, std::string& value) {
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

size_t http_header_compression_table_static::size() { return _static_table.size(); }

void http_header_compression_table_static::load() {}

hpack_static_table hpack_static_table::_instance;

hpack_static_table* hpack_static_table::get_instance() {
    _instance.load();
    return &_instance;
}

hpack_static_table::hpack_static_table() : http_header_compression_table_static() {}

void hpack_static_table::load() {
    if (_static_table.empty()) {
        critical_section_guard guard(_lock);
        if (_static_table.empty()) {
            // RFC 7541 Appendix A.  Static Table Definition
            // if (_static_table.empty()) ...
            auto lambda = [&](uint32 index, const char* name, const char* value) -> void {
                _static_table.insert(std::make_pair(name, std::make_pair(value ? value : "", index)));
                _static_table_index.insert(std::make_pair(index, std::make_pair(name, value ? value : "")));
            };
            http_resource::get_instance()->for_each_hpack_static_table(lambda);
        }
    }
}

}  // namespace net
}  // namespace hotplace
