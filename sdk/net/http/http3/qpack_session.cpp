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

qpack_session::qpack_session() : http_header_compression_session() { _separate = true; }

return_t qpack_session::query(int cmd, void* req, size_t reqsize, void* resp, size_t& respsize) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == resp) || (respsize < sizeof(size_t))) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        switch (cmd) {
            case qpack_cmd_tablesize: {
                respsize = sizeof(size_t);
                memcpy(resp, &_tablesize, respsize);
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
