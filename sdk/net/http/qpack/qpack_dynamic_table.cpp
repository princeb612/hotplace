/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/http/qpack/qpack_dynamic_table.hpp>

namespace hotplace {
namespace net {

qpack_dynamic_table::qpack_dynamic_table() : http_dynamic_table() {
    set_type(header_compression_qpack);

    // RFC 9204 5.  Configuration
    // SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01):  The default value is zero.
    _capacity = 0;
}

qpack_dynamic_table::~qpack_dynamic_table() {}

void qpack_dynamic_table::for_each(std::function<void(size_t, size_t, const std::string&, const std::string&)> f) {
    if (f) {
        critical_section_guard guard(_lock);
        auto entries = _dynamic_reversemap.size();
        for (auto iter = _dynamic_reversemap.begin(); iter != _dynamic_reversemap.end(); iter++) {
            size_t entry = iter->first;
            size_t entno = (entry - _dropped);
            size_t entsize = iter->second.second;
            const std::string& key = iter->second.first;
            std::string value;
            pick(entry, key, value);
            f(entno, entsize, key, value);
        }
    }
}

void qpack_dynamic_table::dump(const std::string& desc, std::function<void(const char*, size_t)> f) {
    if (f) {
        critical_section_guard guard(_lock);
        basic_stream bs;

        bs << "> " << desc;
        f(bs.c_str(), bs.size());

        auto lambda = [&]() -> void {
            bs.clear();
            bs << "  ^-- acknowledged --^";
            f(bs.c_str(), bs.size());
        };

        auto entries = _dynamic_reversemap.size();
        if (0 == entries) {
            lambda();
        }
        size_t entry = 0;
        for (auto iter = _dynamic_reversemap.begin(); iter != _dynamic_reversemap.end(); iter++) {
            entry = iter->first;
            if (entry == _ack) {
                lambda();
            }

            size_t entno = (entry - _dropped);
            size_t entsize = iter->second.second;
            const std::string& key = iter->second.first;
            std::string value;
            pick(entry, key, value);
            bs.clear();
            bs.printf(" %3zi (s = %zi) %s: %s", entno, entsize, key.c_str(), value.c_str());
            f(bs.c_str(), bs.size());
        }
        if ((entry + 1) == _ack) {
            lambda();
        }

        bs.clear();
        bs.printf("  table size %zi", get_tablesize());
        f(bs.c_str(), bs.size());
    }
}

return_t qpack_dynamic_table::query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == resp) || (respsize < sizeof(size_t))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (cmd) {
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
                    size_t entries = dynamic_map_size();
                    if (data > entries) {
                        ret = errorcode_t::out_of_range;
                    } else {
                        auto postbase = entries - data - 1;
                        memcpy(resp, &postbase, respsize);
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
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
