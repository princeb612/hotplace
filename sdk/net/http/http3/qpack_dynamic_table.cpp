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

qpack_dynamic_table::qpack_dynamic_table() : http_dynamic_table() {
    _type = header_compression_qpack;

    // RFC 9204 5.  Configuration
    // SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01):  The default value is zero.
    _capacity = 0;
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
                    size_t entries = _dynamic_map.size();
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
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
