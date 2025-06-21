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

hpack_dynamic_table::hpack_dynamic_table() : http_dynamic_table() {
    // _type = header_compression_hpack;

    // RFC 7540 6.5.2.  Defined SETTINGS Parameters
    // SETTINGS_HEADER_TABLE_SIZE (0x1):
    // ... The initial value is 4,096 octets.
    _capacity = 4096;
}

void hpack_dynamic_table::for_each(std::function<void(size_t, size_t, const std::string&, const std::string&)> f) {
    if (f) {
        critical_section_guard guard(_lock);
        auto entries = _dynamic_reversemap.size();
        for (auto iter = _dynamic_reversemap.rbegin(); iter != _dynamic_reversemap.rend(); iter++) {
            size_t entry = iter->first;
            size_t entno = entries - (entry - _dropped);
            size_t entsize = iter->second.second;
            const std::string& key = iter->second.first;
            std::string value;
            pick(entry, key, value);
            f(entno, entsize, key, value);
        }
    }
}

void hpack_dynamic_table::dump(const std::string& desc, std::function<void(const char*, size_t)> f) {
    if (f) {
        critical_section_guard guard(_lock);
        basic_stream bs;

        bs << "> " << desc;
        f(bs.c_str(), bs.size());
        auto lambda = [&](size_t entno, size_t entsize, const std::string& name, const std::string& value) -> void {
            bs.clear();
            bs.printf(" [%3zi](s = %zi) %s: %s", entno, entsize, name.c_str(), value.c_str());
            f(bs.c_str(), bs.size());
        };
        for_each(lambda);
        bs.clear();
        bs.printf("      table size %zi", get_tablesize());
        f(bs.c_str(), bs.size());
    }
}

return_t hpack_dynamic_table::query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == resp) || (respsize < sizeof(size_t))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (cmd) {
            case hpack_cmd_inserted:
                respsize = sizeof(size_t);
                memcpy(resp, &_inserted, respsize);
                break;
            case hpack_cmd_dropped:
                respsize = sizeof(size_t);
                memcpy(resp, &_dropped, respsize);
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
