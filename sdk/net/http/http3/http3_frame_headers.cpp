/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/http/compression/http_header_compression_stream.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame_headers.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>
#include <hotplace/sdk/net/tls/quic_session.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

http3_frame_headers::http3_frame_headers(tls_session* session) : http3_frame(h3_frame_headers), _session(session) {
    if (nullptr == session) {
        throw exception(no_session);
    }
}

return_t http3_frame_headers::do_read_payload(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        auto& dyntable = _session->get_quic_session().get_dynamic_table();

        /**
         *  RFC 9114 7.2.2.  HEADERS
         *  HEADERS Frame {
         *    Type (i) = 0x01,
         *    Length (i),
         *    Encoded Field Section (..),
         *  }
         */
        qpack_encoder encoder;
        std::list<http_compression_decode_t> kv;
        ret = encoder.decode(&dyntable, stream, size, pos, kv, qpack_quic_stream_header);
#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_http3, [&](basic_stream& dbs) -> void {
                uint32 mask = qpack_decode_index | qpack_decode_nameref | qpack_decode_namevalue;
                for (auto entry : kv) {
                    if (mask & entry.flags) {
                        dbs.println("> %s: %s", entry.name.c_str(), entry.value.c_str());
                    }
                }
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t http3_frame_headers::do_write(binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        qpack_stream stream;
        uint32 flags = qpack_quic_stream_header;
        auto& dyntable = _session->get_quic_session().get_dynamic_table();
        stream.set_dyntable(&dyntable);
        for (const auto& item : _kv) {
            stream.encode_header(item.first, item.second, flags);
        }
        stream.pack(flags);
        _payload = std::move(stream.get_binary());

        payload pl;
        pl << new payload_member(new quic_encoded(uint64(h3_frame_headers)))  //
           << new payload_member(new quic_encoded(uint64(_payload.size())))   //
           << new payload_member(_payload);
        pl.write(bin);
    }
    __finally2 {}
    return ret;
}

http3_frame_headers& http3_frame_headers::add(const std::string& name, const std::string& value) {
    _kv.push_back({name, value});
    return *this;
}

}  // namespace net
}  // namespace hotplace
