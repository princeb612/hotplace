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

http_header_compression_session::http_header_compression_session() : _type(header_compression_hpack), _inserted(0), _dropped(0), _capacity(0), _tablesize(0) {}

void http_header_compression_session::for_each(std::function<void(const std::string&, const std::string&)> v) {
    if (v) {
        for (auto item : _dynamic_map) {
            v(item.first, item.second.first);
        }
    }
}

bool http_header_compression_session::operator==(const http_header_compression_session& rhs) {
    return (_type == rhs._type) && (_dynamic_map == rhs._dynamic_map);
}

bool http_header_compression_session::operator!=(const http_header_compression_session& rhs) {
    return (_type != rhs._type) || (_dynamic_map != rhs._dynamic_map);
}

void http_header_compression_session::trace(std::function<void(uint32, stream_t*)> f) { _df = f; }

match_result_t http_header_compression_session::match(const std::string& name, const std::string& value, size_t& index, uint32 flags) {
    match_result_t state = match_result_t::not_matched;

    auto lbound = _dynamic_map.lower_bound(name);
    auto ubound = _dynamic_map.upper_bound(name);
    std::priority_queue<size_t> pq;
    std::priority_queue<size_t> nr;

    for (auto iter = lbound; iter != ubound; iter++) {
        const auto& k = iter->first;
        const auto& v = iter->second;  // pair(value, entry)
        const auto& val = v.first;
        const auto& ent = v.second;
        if ((name == k) && (value == val)) {
            pq.push(ent);  // using greater
        }
        if (qpack_name_reference & flags) {
            if (name == k) {
                nr.push(ent);
            }
        }
    }

    auto get_entry = [&](size_t ent, size_t& idx) -> void {
        /**
         * get index from ent
         *
         * consider following cases
         *  capacity = 3, _inserted = 2, _dropped = 0, table {1 0}, entries = 2
         *  capacity = 3, _inserted = 3, _dropped = 0, table {2 1 0}, entries = 3
         *  capacity = 3, _inserted = 4, _dropped = 1, table {3 2 1}, entries = 3
         *  capacity = 3, _inserted = 5, _dropped = 2, table {4 3 2}, entries = 3
         *
         * conclusion
         *  index = entries - ent + _dropped - 1 = _inserted - _dropped - ent + _dropped - 1 = _inserted - ent - 1
         */
        idx = _inserted - ent - 1;
        if (header_compression_hpack == _type) {
            /**
             * HPACK
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
            auto static_entries = http_resource::get_instance()->sizeof_hpack_static_table_entries();
            idx += (static_entries + 1);
        }
    };

    if (pq.size()) {
        state = match_result_t::all_matched_dynamic;
        auto const& ent = pq.top();  // biggest = latest
        get_entry(ent, index);
    } else if (nr.size()) {
        state = match_result_t::key_matched_dynamic;
        auto const& ent = nr.top();
        get_entry(ent, index);
    }

    return state;
}

return_t http_header_compression_session::select(size_t index, uint32 flags, std::string& name, std::string& value) {
    return_t ret = errorcode_t::not_found;

    __try2 {
        if (header_compression_hpack == type()) {
            // HPACK
            auto static_entries = http_resource::get_instance()->sizeof_hpack_static_table_entries();
            if (index <= static_entries) {
                __leave2;
            }
            index -= (static_entries + 1);
        } else if (header_compression_qpack == type()) {
            if (qpack_postbase_index & flags) {
                index = _inserted - _dropped - index - 1;
            }
        }

        if (_dynamic_reversemap.size()) {
            /**
             * refer hpack_session::match
             * index = _inserted - v.second - 1
             * v.second = _inserted - index - 1
             */
            const auto& t = _inserted - index - 1;
            auto riter = _dynamic_reversemap.find(t);
            if (_dynamic_reversemap.end() != riter) {
                const auto& pne = riter->second;  // pair(name, entry size)
                const auto& nam = pne.first;
                auto lbound = _dynamic_map.lower_bound(nam);
                auto ubound = _dynamic_map.upper_bound(nam);

                for (auto iter = lbound; iter != ubound; iter++) {
                    const auto& pve = iter->second;  // pair(value, entry)
                    const auto& val = pve.first;
                    const auto& ent = pve.second;
                    if (t == ent) {
                        name = nam;
                        value = val;
                        ret = errorcode_t::success;
                        break;
                    }
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

    // RFC 7541 4.1.  Calculating Table Size
    // RFC 9204 3.2.1.  Dynamic Table Size
    size_t entrysize = 0;
    http_header_compression::sizeof_entry(name, value, entrysize);

    if (entrysize < _capacity) {
        _tablesize += entrysize;

        evict();

        _dynamic_map.insert({name, {value, _inserted}});
        _dynamic_reversemap.insert({_inserted, {name, entrysize}});

        if (_df) {
            basic_stream bs;
            bs.printf("insert entry[%zi] %s=%s", _inserted, name.c_str(), value.c_str());
            _df(header_compression_event_insert, &bs);
        }

        _inserted++;
    } else {
        ret = errorcode_t::insufficient;
    }

    return ret;
}

return_t http_header_compression_session::evict() {
    return_t ret = errorcode_t::success;

    while (_dynamic_reversemap.size() && (_tablesize > _capacity)) {
        // RFC 7541 4.2.  Maximum Table Size
        // RFC 7541 4.4.  Entry Eviction When Adding New Entries
        // RFC 9204 3.2.2.  Dynamic Table Capacity and Eviction
        auto entry = _dropped;
        auto back = _dynamic_reversemap.find(entry);

        if (_dynamic_reversemap.end() != back) {
            auto const& t = back->first;   // entry
            auto const& k = back->second;  // (name, entry size)

            auto const& name = k.first;
            auto const& entrysize = k.second;

            _tablesize -= entrysize;

            auto lbound = _dynamic_map.lower_bound(name);
            auto ubound = _dynamic_map.upper_bound(name);

            for (auto iter = lbound; iter != ubound; iter++) {
                auto const& v = iter->second;  // pair(value, entry)
                auto const& val = v.first;
                auto const& ent = v.second;
                if (ent == t) {
                    if (_df) {
                        basic_stream bs;
                        bs.printf("evict entry[%zi] %s=%s", entry, name.c_str(), val.c_str());
                        _df(header_compression_event_evict, &bs);
                    }
                    _dynamic_map.erase(iter);
                    break;
                }
            }

            _dynamic_reversemap.erase(back);
            _dropped++;
        }
    }

    return ret;
}

void http_header_compression_session::set_capacity(uint32 capacity) {
    /**
     * RFC 9113 6.5.2.  Defined Settings
     *  SETTINGS_HEADER_TABLE_SIZE (0x01)
     * RFC 9204 5.  Configuration
     *  SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01)
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

size_t http_header_compression_session::get_entries() { return _inserted - _dropped; }

return_t http_header_compression_session::query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize) { return errorcode_t::success; }

uint8 http_header_compression_session::type() { return _type; }

}  // namespace net
}  // namespace hotplace