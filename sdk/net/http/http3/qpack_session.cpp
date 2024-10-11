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
