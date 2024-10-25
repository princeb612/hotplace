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
