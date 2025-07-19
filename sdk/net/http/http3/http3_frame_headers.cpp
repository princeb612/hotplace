/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/dump_memory.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http3/http3_frame.hpp>
#include <sdk/net/http/http3/qpack.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>

namespace hotplace {
namespace net {

http3_frame_headers::http3_frame_headers(qpack_dynamic_table* dyntable) : http3_frame(h3_frame_headers), _dyntable(dyntable) {
    if (nullptr == dyntable) {
        throw exception(not_specified);
    }
}

return_t http3_frame_headers::do_read_payload(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        // CHECK HERE
        qpack_encoder encoder;
        std::list<qpack_decode_t> kv;
        ret = encoder.decode(_dyntable, stream, size, pos, kv, qpack_quic_stream_header);
#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            for (auto entry : kv) {
                dbs.println("%s: %s", entry.name.c_str(), entry.value.c_str());
            }
            trace_debug_event(trace_category_net, trace_event_http3, &dbs);
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t http3_frame_headers::do_write(binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        //
    }
    __finally2 {}
    return ret;
}

}  // namespace net
}  // namespace hotplace
