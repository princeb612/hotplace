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

http_header_compression_session::http_header_compression_session() : _separate(false), _inserted(0), _dropped(0), _capacity(0x10000), _tablesize(0) {}

void http_header_compression_session::for_each(std::function<void(const std::string&, const std::string&)> v) {
    if (v) {
        for (auto item : _dynamic_map) {
            v(item.first, item.second.first);
        }
    }
}

bool http_header_compression_session::operator==(const http_header_compression_session& rhs) {
    return (_separate == rhs._separate) && (_dynamic_map == rhs._dynamic_map);
}

bool http_header_compression_session::operator!=(const http_header_compression_session& rhs) {
    return (_separate != rhs._separate) || (_dynamic_map != rhs._dynamic_map);
}

match_result_t http_header_compression_session::match(const std::string& name, const std::string& value, size_t& index) {
    match_result_t state = match_result_t::not_matched;

    auto lbound = _dynamic_map.lower_bound(name);
    auto ubound = _dynamic_map.upper_bound(name);
    for (auto iter = lbound; iter != ubound; iter++) {
        const auto& k = iter->first;
        const auto& v = iter->second;
        if ((name == k) && (value == v.first)) {
            state = match_result_t::all_matched_dynamic;
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
            index = _inserted - v.second - 1;
            if (false == _separate) {
                // HPACK
                auto static_entries = http_resource::get_instance()->sizeof_hpack_static_table_entries();
                index += (static_entries + 1);
            }
            break;
        }
    }

    return state;
}

return_t http_header_compression_session::select(size_t index, std::string& name, std::string& value) {
    return_t ret = errorcode_t::not_found;

    __try2 {
        auto static_entries = http_resource::get_instance()->sizeof_hpack_static_table_entries();
        if (index <= static_entries) {
            __leave2;
        }

        if (false == _separate) {
            // HPACK
            index -= (static_entries + 1);
        }

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
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http_header_compression_session::insert(const std::string& name, const std::string& value) {
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

    // RFC 7541 4.1.  Calculating Table Size
    // RFC 9204 3.2.1.  Dynamic Table Size
    size_t entrysize = 0;
    http_header_compression::sizeof_entry(name, value, entrysize);
    _tablesize += entrysize;

    evict();

    _dynamic_map.insert({name, {value, _inserted}});
    _dynamic_reversemap.insert({_inserted, name});
    _entry_size.insert({_inserted, entrysize});

    _inserted++;

    return ret;
}

return_t http_header_compression_session::evict() {
    return_t ret = errorcode_t::success;

    while (_tablesize > _capacity) {
        // RFC 7541 4.2.  Maximum Table Size
        // RFC 7541 4.4.  Entry Eviction When Adding New Entries
        // RFC 9204 3.2.2.  Dynamic Table Capacity and Eviction
        auto back = _dynamic_reversemap.find(_dropped);

        auto const& t = back->first;
        auto const& k = back->second;

        auto dpiter = _entry_size.find(t);
        _tablesize -= dpiter->second;
        _entry_size.erase(dpiter);

        auto lbound = _dynamic_map.lower_bound(k);
        auto ubound = _dynamic_map.upper_bound(k);

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

    return ret;
}

void http_header_compression_session::set_capacity(uint32 capacity) {
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

        // RFC 7541 4.3.  Entry Eviction When Dynamic Table Size Changes
        evict();
    }
}

size_t http_header_compression_session::get_capacity() { return _capacity; }

size_t http_header_compression_session::get_tablesize() { return _tablesize; }

return_t http_header_compression_session::query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize) { return errorcode_t::success; }

}  // namespace net
}  // namespace hotplace
