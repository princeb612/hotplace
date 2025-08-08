/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/hpack/hpack_static_table.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

hpack_static_table hpack_static_table::_instance;

hpack_static_table* hpack_static_table::get_instance() {
    _instance.load();
    return &_instance;
}

hpack_static_table::hpack_static_table() : http_static_table() {}

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
