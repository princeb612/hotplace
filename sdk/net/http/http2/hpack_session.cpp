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

hpack_session::hpack_session() : _capacity(0x10000) {
#if PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP
    _inserted = 0;
    _dropped = 0;
#endif
}

hpack_session::hpack_session(const hpack_session& rhs) {
#if PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP
    _dynamic_map = rhs._dynamic_map;
    _dynamic_reversemap = rhs._dynamic_reversemap;
#else
    _dynamic_table = rhs._dynamic_table;
#endif
}

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

bool hpack_session::operator==(const hpack_session& rhs) {
#if PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP
    return _dynamic_map == rhs._dynamic_map;
#else
    return _dynamic_table == rhs._dynamic_table;
#endif
}

bool hpack_session::operator!=(const hpack_session& rhs) {
#if PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP
    return _dynamic_map != rhs._dynamic_map;
#else
    return _dynamic_table != rhs._dynamic_table;
#endif
}

void hpack_session::for_each(std::function<void(const std::string&, const std::string&)> v) {
    if (v) {
#if PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP
        for (auto item : _dynamic_map) {
            v(item.first, item.second.first);
        }
#else
        for (auto item : _dynamic_table) {
            v(item.first, item.second.first);
        }
#endif
    }
}

match_result_t hpack_session::match(const std::string& name, const std::string& value, size_t& index) {
    match_result_t state = match_result_t::not_matched;

#if PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP
    // using std::multimap
    auto lbound = _dynamic_map.lower_bound(name);
    auto ubound = _dynamic_map.upper_bound(name);
    for (auto iter = lbound; iter != ubound; iter++) {
        const auto& k = iter->first;
        const auto& v = iter->second;
        if ((name == k) && (value == v.first)) {
            state = match_result_t::all_matched;
            /**
             * get index from v.second
             *
             * consider following cases
             *  capacity = 3, _inserted = 2, _dropped = 0, table {1 0}, table.size = 2
             *  capacity = 3, _inserted = 3, _dropped = 0, table {2 1 0}, table.size = 3
             *  capacity = 3, _inserted = 4, _dropped = 1, table {3 2 1}, table.size = 3
             *  capacity = 3, _inserted = 5, _dropped = 2, table {4 3 2}, table.size = 3
             *
             * conclusion
             *  index = _inserted - _dropped - v.second + _dropped - 1 = _inserted - v.second - 1
             */
            auto idx = _inserted - v.second - 1;
            index = idx;
            auto static_entries = http_resource::get_instance()->sizeof_hpack_static_table_entries();
            index += (static_entries + 1);
            break;
        }
    }
#else
    // using std::list
    size_t idx = 0;
    for (const auto& pair : _dynamic_table) {
        const auto& k = pair.first;
        const auto& v = pair.second;
        if ((name == k) && (value == v.first)) {
            state = match_result_t::all_matched;
            index = idx;
            auto static_entries = http_resource::get_instance()->sizeof_hpack_static_table_entries();
            index += (static_entries + 1);
            break;
        }
        idx++;
    }
#endif
    return state;
}

return_t hpack_session::select(uint32 flags, size_t index, std::string& name, std::string& value) {
    return_t ret = errorcode_t::not_found;

    __try2 {
        auto static_entries = http_resource::get_instance()->sizeof_hpack_static_table_entries();
        if (index <= static_entries) {
            __leave2;
        }

        index -= (static_entries + 1);

#if PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP
        if (_dynamic_reversemap.size()) {
            /**
             * refer hpack_session::match
             * index = _inserted - v.second - 1
             * v.second = _inserted - index - 1
             */
            const auto& t = _inserted - index - 1;
            auto riter = _dynamic_reversemap.find(t);
            // never happen (_dynamic_reversemap.end() == riter)
            const auto& k = riter->second;
            auto lbound = _dynamic_map.lower_bound(k);
            auto ubound = _dynamic_map.upper_bound(k);

            for (auto iter = lbound; iter != ubound; iter++) {
                const auto& v = iter->second;
                if (t == v.second) {
                    name = k;
                    value = v.first;
                    break;
                }
            }
        }
#else
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
#endif
    }
    __finally2 {
        // do nothing
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

#if PERFORMANCE_HPACK_DYNAMIC_TABLE_USING_MAP
    if (_capacity - 1 == _dynamic_map.size()) {
        auto back = _dynamic_reversemap.find(_dropped);

        auto const& t = back->first;
        auto const& k = back->second;

        auto lbound = _dynamic_map.lower_bound(name);
        auto ubound = _dynamic_map.upper_bound(name);

        for (auto iter = lbound; iter != ubound; iter++) {
            auto const& v = iter->second;
            if (v.second == t) {
                _dynamic_map.erase(iter);
                break;
            }
        }
        _dynamic_reversemap.erase(back);
        _dropped++;
    }

    _dynamic_map.insert({name, {value, _inserted}});
    _dynamic_reversemap.insert({_inserted, name});
    _inserted++;
#else
    if (_capacity - 1 == _dynamic_table.size()) {
        _dynamic_table.pop_back();  // drop
    }

    _dynamic_table.push_front(std::make_pair(name, std::make_pair(value, 0)));  // insert
#endif

    return ret;
}

}  // namespace net
}  // namespace hotplace
