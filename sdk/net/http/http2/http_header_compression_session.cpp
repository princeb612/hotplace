/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <math.h>

#include <sdk/net/http/http2/http_header_compression.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

return_t qpack_ric2eic(size_t capacity, size_t ric, size_t base, size_t& eic, bool& sign, size_t& deltabase) {
    return_t ret = errorcode_t::success;
    if (capacity) {
        /* RFC 9204 4.5.1.1.  Required Insert Count
         *  if (ReqInsertCount) EncInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1
         *  else EncInsertCount = 0;
         */
        if (0 == ric) {
            eic = ric;
        } else {
            size_t maxentries = ::floor(capacity / 32);
            eic = (ric % (2 * maxentries)) + 1;
        }

        /* RFC 9204 4.5.1.2.  Base
         *  A Sign bit of 1 indicates that the Base is less than the Required Insert Count
         *
         *  if (0 == Sign) DeltaBase = Base - ReqInsertCount
         *  else DeltaBase = ReqInsertCount - Base - 1
         */
        sign = (ric > base);
        if (ric > base) {
            deltabase = ric - base - 1;
        } else {
            deltabase = ric - base;
        }
    } else {
        eic = 0;
        sign = false;
        deltabase = 0;
    }

    return ret;
}

return_t qpack_eic2ric(size_t capacity, size_t tni, size_t eic, bool sign, size_t deltabase, size_t& ric, size_t& base) {
    return_t ret = errorcode_t::success;
    __try2 {
        /**
         * RFC 9204 4.5.1.1.  Required Insert Count
         *
         * FullRange = 2 * MaxEntries
         * if EncodedInsertCount == 0:
         *    ReqInsertCount = 0
         * else:
         *    if EncodedInsertCount > FullRange:
         *       Error
         *    MaxValue = TotalNumberOfInserts + MaxEntries
         *
         *    # MaxWrapped is the largest possible value of
         *    # ReqInsertCount that is 0 mod 2 * MaxEntries
         *    MaxWrapped = floor(MaxValue / FullRange) * FullRange
         *    ReqInsertCount = MaxWrapped + EncodedInsertCount - 1
         *
         *    # If ReqInsertCount exceeds MaxValue, the Encoder's value
         *    # must have wrapped one fewer time
         *    if ReqInsertCount > MaxValue:
         *       if ReqInsertCount <= FullRange:
         *          Error
         *       ReqInsertCount -= FullRange
         *
         *    # Value of 0 must be encoded as 0.
         *    if ReqInsertCount == 0:
         *       Error
         */
        size_t maxentries = ::floor(capacity / 32);
        eic = (ric % (2 * maxentries)) + 1;
        size_t fullrange = 2 * maxentries;
        if (0 == eic) {
            ric = 0;
        } else {
            if (eic > fullrange) {
                ret = errorcode_t::invalid_request;
                __leave2;
            }

            size_t maxvalue = tni + maxentries;
            size_t maxwrapped = ::floor(maxvalue / fullrange) * fullrange;
            ric = maxwrapped + eic - 1;

            if (ric > maxvalue) {
                if (ric <= fullrange) {
                    ret = errorcode_t::invalid_request;
                    __leave2;
                } else {
                    ric -= fullrange;
                }
            }

            if (0 == ric) {
                ret = errorcode_t::invalid_request;
                __leave2;
            }

            /* RFC 9204 4.5.1.2.  Base
             *  A Sign bit of 1 indicates that the Base is less than the Required Insert Count
             *
             *  if (0 == Sign) Base = DeltaBase + ReqInsertCount
             *  else Base = ReqInsertCount - DeltaBase - 1
             */
            if (0 == sign) {
                base = deltabase + ric;
            } else {
                base = ric - deltabase - 1;
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

http_header_compression_session::http_header_compression_session() : _separate(false), _inserted(0), _dropped(0), _capacity(0), _tablesize(0) {}

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
        idx = _inserted - ent - 1;
        if (false == _separate) {
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

    // RFC 7541 4.1.  Calculating Table Size
    // RFC 9204 3.2.1.  Dynamic Table Size
    size_t entrysize = 0;
    http_header_compression::sizeof_entry(name, value, entrysize);
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
