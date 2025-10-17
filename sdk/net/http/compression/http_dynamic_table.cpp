/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/net/http/compression/http_dynamic_table.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http_dynamic_table::http_dynamic_table() : _type(header_compression_hpack), _tablesize(0), _capacity(0), _inserted(0), _dropped(0), _ack(0) {}

http_dynamic_table::~http_dynamic_table() {}

void http_dynamic_table::pick(size_t entry, const std::string& name, std::string& value) {
    critical_section_guard guard(_lock);
    auto iter = _dynamic_reversemap.find(entry);
    if (_dynamic_reversemap.end() != iter) {
        const std::string& key = iter->second.first;
        auto lbound = _dynamic_map.lower_bound(key);
        auto ubound = _dynamic_map.upper_bound(key);
        for (auto bound = lbound; bound != ubound; bound++) {
            const auto& ent = bound->second;
            if (entry == ent.second) {
                value = ent.first;
            }
        }
    }
}

void http_dynamic_table::for_each(std::function<void(size_t, size_t, const std::string&, const std::string&)> f) {}

void http_dynamic_table::dump(const std::string& desc, std::function<void(const char*, size_t)> f) {}

bool http_dynamic_table::operator==(const http_dynamic_table& rhs) { return (_type == rhs._type) && (_dynamic_map == rhs._dynamic_map); }

bool http_dynamic_table::operator!=(const http_dynamic_table& rhs) { return (_type != rhs._type) || (_dynamic_map != rhs._dynamic_map); }

match_result_t http_dynamic_table::match(uint32 flags, const std::string& name, const std::string& value, size_t& index) {
    match_result_t state = match_result_t::not_matched;

    critical_section_guard guard(_lock);

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
        const auto& ent = pq.top();  // biggest = latest
        get_entry(ent, index);
    } else if (nr.size()) {
        state = match_result_t::key_matched_dynamic;
        const auto& ent = nr.top();
        get_entry(ent, index);
    }

    return state;
}

return_t http_dynamic_table::select(uint32 flags, size_t index, std::string& name, std::string& value) {
    return_t ret = errorcode_t::not_found;

    __try2 {
        critical_section_guard guard(_lock);

        if (header_compression_hpack == get_type()) {
            // HPACK
            auto static_entries = http_resource::get_instance()->sizeof_hpack_static_table_entries();
            if (index <= static_entries) {
                __leave2;
            }
            index -= (static_entries + 1);
        } else if (header_compression_qpack == get_type()) {
            if (qpack_postbase_index & flags) {
                index = _inserted - _dropped - index - 1;
            }
        }

        if (_dynamic_reversemap.size()) {
            /**
             * refer hpack_dynamic_table::match
             * index = _inserted - v.second - 1
             * v.second = _inserted - index - 1
             */
            size_t t = _inserted - index - 1;
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

        if (errorcode_t::success == ret) {
            trace_debug_event(trace_category_net, trace_event_header_compression_select,
                              [&](basic_stream& dbs) -> void { dbs << "index [" << index << "] " << name << "=" << value << "\n"; });
        }
    }
    __finally2 {}
    return ret;
}

return_t http_dynamic_table::insert(const std::string& name, const std::string& value) {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);

    commit_pair item;
    item.name = name;
    item.value = value;
    _commit_queue.push(item);

    return ret;
}

return_t http_dynamic_table::commit() {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);
    while (false == _commit_queue.empty()) {
        commit_pair item = _commit_queue.front();
        _commit_queue.pop();

        const auto& name = item.name;
        const auto& value = item.value;

        // RFC 7541 4.1.  Calculating Table Size
        // RFC 9204 3.2.1.  Dynamic Table Size
        size_t entrysize = 0;
        http_header_compression::sizeof_entry(name, value, entrysize);

        if (entrysize < _capacity) {
            _tablesize += entrysize;

            evict();

            _dynamic_map.insert({name, {value, _inserted}});
            _dynamic_reversemap.insert({_inserted, {name, entrysize}});

            if (_hook) {
                _hook(trace_category_net, trace_event_header_compression_insert);
            }

#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_header_compression_insert,
                                  [&](basic_stream& dbs) -> void { dbs.println("+ insert entry[%zi] %s=%s", _inserted, name.c_str(), value.c_str()); });
            }
#endif

            _inserted++;
        } else {
            ret = errorcode_t::insufficient;
        }
    }

    return ret;
}

return_t http_dynamic_table::evict() {
    return_t ret = errorcode_t::success;

    critical_section_guard guard(_lock);
    while (_dynamic_reversemap.size() && (_tablesize > _capacity)) {
        // RFC 7541 4.2.  Maximum Table Size
        // RFC 7541 4.4.  Entry Eviction When Adding New Entries
        // RFC 9204 3.2.2.  Dynamic Table Capacity and Eviction
        auto entry = _dropped;
        auto back = _dynamic_reversemap.find(entry);

        if (_dynamic_reversemap.end() != back) {
            const auto& t = back->first;   // entry
            const auto& k = back->second;  // (name, entry size)

            const auto& name = k.first;
            const auto& entrysize = k.second;

            _tablesize -= entrysize;

            auto lbound = _dynamic_map.lower_bound(name);
            auto ubound = _dynamic_map.upper_bound(name);

            for (auto iter = lbound; iter != ubound; iter++) {
                const auto& v = iter->second;  // pair(value, entry)
                const auto& val = v.first;
                const auto& ent = v.second;
                if (ent == t) {
                    if (_hook) {
                        _hook(trace_category_net, trace_event_header_compression_evict);
                    }

#if defined DEBUG
                    if (istraceable(trace_category_net)) {
                        trace_debug_event(trace_category_net, trace_event_header_compression_evict,
                                          [&](basic_stream& dbs) -> void { dbs.println("- evict  entry[%zi] %s=%s", entry, name.c_str(), val.c_str()); });
                    }
#endif
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

void http_dynamic_table::set_capacity(uint32 capacity) {
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
    _capacity = capacity;

#if defined DEBUG
    if (istraceable(trace_category_net)) {
        trace_debug_event(trace_category_net, trace_event_header_compression_evict,
                          [&](basic_stream& dbs) -> void { dbs.println("> set capacity %zi", capacity); });
    }
#endif

    // RFC 7541 4.3.  Entry Eviction When Dynamic Table Size Changes
    evict();
}

void http_dynamic_table::ack() { _ack = _inserted; }

void http_dynamic_table::cancel() {}

void http_dynamic_table::increment(size_t inc) { _ack += inc; }

size_t http_dynamic_table::get_capacity() { return _capacity; }

size_t http_dynamic_table::get_tablesize() { return _tablesize; }

size_t http_dynamic_table::get_entries() { return _inserted - _dropped; }

return_t http_dynamic_table::query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize) { return errorcode_t::success; }

uint8 http_dynamic_table::get_type() { return _type; }

void http_dynamic_table::set_type(uint8 type) { _type = type; }

size_t http_dynamic_table::dynamic_map_size() { return _dynamic_map.size(); }

void http_dynamic_table::set_debug_hook(std::function<void(trace_category_t, uint32 event)> fn) { _hook = fn; }

}  // namespace net
}  // namespace hotplace
