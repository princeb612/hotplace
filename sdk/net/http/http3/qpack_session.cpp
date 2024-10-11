/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/http/http3/qpack.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

// studying

qpack_session::qpack_session() : http_header_compression_session(), _capacity(0x10000), _inserted(0), _dropped(0) {}

match_result_t qpack_session::match(const std::string& name, const std::string& value, size_t& index) {
    match_result_t state = match_result_t::not_matched;
    // using std::multimap
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
            break;
        }
    }
    return state;
}

return_t qpack_session::select(size_t index, std::string& name, std::string& value) {
    return_t ret = errorcode_t::not_found;

    __try2 {
        auto static_entries = http_resource::get_instance()->sizeof_hpack_static_table_entries();
        if (index <= static_entries) {
            __leave2;
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

return_t qpack_session::insert(const std::string& name, const std::string& value) {
    return_t ret = errorcode_t::success;

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

    return ret;
}

return_t qpack_session::ctrl(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == resp) || (respsize < sizeof(size_t))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (cmd) {
            case qpack_cmd_size: {
                respsize = sizeof(size_t);
                auto tablesize = _dynamic_map.size();
                memcpy(resp, &tablesize, respsize);
            } break;
            case qpack_cmd_inserted:
                respsize = sizeof(size_t);
                memcpy(resp, &_inserted, respsize);
                break;
            case qpack_cmd_dropped:
                respsize = sizeof(size_t);
                memcpy(resp, &_dropped, respsize);
                break;
            case qpack_cmd_postbase_index:
                if (req && (sizeof(size_t) == reqsize)) {
                    respsize = sizeof(size_t);
                    size_t data = *(size_t*)req;
                    size_t tablesize = _dynamic_map.size();
                    if (data > tablesize) {
                        ret = errorcode_t::out_of_range;
                    } else {
                        auto postbase = tablesize - data - 1;
                        memcpy(resp, &postbase, respsize);
                    }
                } else {
                    ret = errorcode_t::bad_request;
                }
                break;
            case qpack_cmd_section_prefix:
                if (req && (sizeof(qpack_section_prefix_t) == reqsize)) {
                    qpack_section_prefix_t* req_section_prefix = (qpack_section_prefix_t*)req;
                    qpack_section_prefix_t* resp_section_prefix = (qpack_section_prefix_t*)resp;
                    const auto& ric = req_section_prefix->ric;
                    const auto& reqbase = req_section_prefix->base;
                    auto& respinscnt = resp_section_prefix->ric;
                    auto& respbase = resp_section_prefix->base;

                    respsize = sizeof(qpack_section_prefix_t);
                    /* RFC 9204 4.5.1.1.  Required Insert Count
                     *  if (ReqInsertCount) EncInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1
                     *  else EncInsertCount = 0;
                     */
                    if (0 == ric) {
                        respinscnt = ric;
                    } else {
                        respinscnt = (ric % (2 * _capacity)) + 1;
                    }
                    /* RFC 9204 4.5.1.2.  Base
                     *  A Sign bit of 1 indicates that the Base is less than the Required Insert Count
                     *  if (0 == Sign) Base = DeltaBase + ReqInsertCount
                     *  else Base = ReqInsertCount - DeltaBase - 1
                     */
                    if (req_section_prefix->sign()) {
                        respbase = ric - reqbase - 1;
                    } else {
                        respbase = ric + reqbase;
                    }
                } else {
                    ret = errorcode_t::bad_request;
                }
                break;
            default:
                ret = errorcode_t::not_supported;
                break;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
