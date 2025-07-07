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
#include <sdk/net/http/http3/http3_stream.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>

namespace hotplace {
namespace net {

http3_stream::http3_stream() { _shared.make_share(this); }

return_t http3_stream::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;

    constexpr char constexpr_type[] = "HTTP/3 stream type";
    constexpr char constexpr_push_id[] = "push_id";
    uint64 type = 0;
    {
        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_type)  //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_push_id, constexpr_push_id);
        pl.set_condition(constexpr_type, [&](payload* pl, payload_member* item) -> void {
            auto type = pl->t_value_of<uint64>(constexpr_type);
            pl->set_group(constexpr_push_id, (h3_push_stream == type));
        });
        pl.read(stream, size, pos);

        type = pl.t_value_of<uint64>(constexpr_type);
    }

#if defined DEBUG
    auto resource = http_resource::get_instance();
    auto nameof_stream = resource->get_h3_stream_name(type);
    if (false == nameof_stream.empty()) {
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("# %s %I64i (%s)", constexpr_type, type, resource->get_h3_stream_name(type).c_str());
            trace_debug_event(trace_category_net, trace_event_http3, &dbs);
        }
    }
#endif

    switch (type) {
        case h3_qpack_decoder_stream: {
        } break;
        case h3_qpack_encoder_stream: {
        } break;
        case h3_push_stream: {
        } break;
        case h3_control_stream: {
            http3_frames frames;
            ret = frames.read(stream, size, pos);
        } break;
    }
    return ret;
}

return_t http3_stream::write(binary_t& bin) {
    return_t ret = errorcode_t::success;
    return ret;
}

void http3_stream::addref() { _shared.addref(); }

void http3_stream::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
