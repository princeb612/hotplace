/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http2/hpack.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

hpack_session::hpack_session() : _capacity(0x10000) {}

hpack_session::hpack_session(const hpack_session& rhs) : _dynamic_table(rhs._dynamic_table) {}

hpack_session& hpack_session::set_capacity(uint32 capacity) {
    /**
     * RFC 9113 6.5.2.  Defined Settings
     *  SETTINGS_HEADER_TABLE_SIZE (0x01)
     *
     * chrome request
     *   - http/2 frame type 4 SETTINGS
     *    > length 0x18(24) type 4 flags 00 stream identifier 00000000
     *    > flags [ ]
     *    > identifier 1 value 65536 (0x00010000)
     *    > identifier 2 value 0 (0x00000000)
     *    > identifier 4 value 6291456 (0x00600000)
     */
    if (capacity) {
        _capacity = capacity;
    }
    return *this;
}

bool hpack_session::operator==(const hpack_session& rhs) { return _dynamic_table == rhs._dynamic_table; }

bool hpack_session::operator!=(const hpack_session& rhs) { return _dynamic_table != rhs._dynamic_table; }

void hpack_session::for_each(std::function<void(const std::string&, const std::string&)> v) {
    if (v) {
        for (auto item : _dynamic_table) {
            v(item.first, item.second.first);
        }
    }
}

match_result_t hpack_session::match(const std::string& name, const std::string& value, size_t& index) {
    match_result_t state = match_result_t::not_matched;
    size_t idx = 0;
    for (const auto& pair : _dynamic_table) {
        const auto& k = pair.first;
        const auto& v = pair.second;
        if ((name == k) && (value == v.first)) {
            state = match_result_t::all_matched;
            index = idx;
            break;
        }
        idx++;
    }
    return state;
}

return_t hpack_session::select(uint32 flags, size_t index, std::string& name, std::string& value) {
    return_t ret = errorcode_t::not_found;
    size_t idx = 0;
    for (const auto& pair : _dynamic_table) {
        const auto& k = pair.first;
        const auto& v = pair.second;
        if (index == idx) {
            name = k;
            value = v.first;
            ret = errorcode_t::success;
            break;
        }
        idx++;
    }
    return ret;
}

return_t hpack_session::insert(const std::string& name, const std::string& value) {
    return_t ret = errorcode_t::success;
    /**
     * RFC 7541 2.3.3.  Index Address Space
     *
     *  <----------  Index Address Space ---------->
     *  <-- Static  Table -->  <-- Dynamic Table -->
     *  +---+-----------+---+  +---+-----------+---+
     *  | 1 |    ...    | s |  |s+1|    ...    |s+k|
     *  +---+-----------+---+  +---+-----------+---+
     *                         ^                   |
     *                         |                   V
     *                  Insertion Point      Dropping Point
     *
     *              Figure 1: Index Address Space
     */
    if (_capacity - 1 == _dynamic_table.size()) {
        _dynamic_table.pop_back();  // drop
    }
    _dynamic_table.push_front(std::make_pair(name, std::make_pair(value, 0)));  // insert
    return ret;
}

}  // namespace net
}  // namespace hotplace
