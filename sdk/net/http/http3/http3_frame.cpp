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
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/quic/quic.hpp>
#include <sdk/net/tls/quic/quic_encoded.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_type[] = "HTTP/3 frame type";
constexpr char constexpr_length[] = "length";
constexpr char constexpr_payload[] = "payload";

http3_frame::http3_frame(h3_frame_t type) : _type(type) { _shared.make_share(this); }

return_t http3_frame::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        ret = do_read_frame(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        size_t ppos = 0;
        ret = do_read_payload(_payload.empty() ? nullptr : &_payload[0], _payload.size(), ppos);
    }
    __finally2 {}
    return ret;
}

return_t http3_frame::write(binary_t& bin) {
    return_t ret = errorcode_t::success;
    ret = do_write(bin);
    return ret;
}

return_t http3_frame::do_read_frame(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;

    size_t fpos = pos;
    __try2 {
        uint64 type = 0;
        uint64 length = 0;
        binary_t frame_payload;

        {
            // RFC 9114 7.1.  Frame Layout
            payload pl;
            pl << new payload_member(new quic_encoded(uint64(0)), constexpr_type)    //
               << new payload_member(new quic_encoded(uint64(0)), constexpr_length)  //
               << new payload_member(binary_t(), constexpr_payload);
            pl.set_reference_value(constexpr_payload, constexpr_length);
            ret = pl.read(stream, size, pos);

            type = pl.t_value_of<uint64>(constexpr_type);
            length = pl.t_value_of<uint64>(constexpr_length);
            pl.get_binary(constexpr_payload, frame_payload);
        }

#if defined DEBUG
        {
            http_resource* resource = http_resource::get_instance();
            basic_stream dbs;
            dbs.println("# %s %I64i (%s) %s", constexpr_type, type, resource->get_h3_frame_name(type).c_str(), (fragmented == ret) ? "fragmented" : "");
            dbs.println(" > %s 0x%I64x (%I64i)", constexpr_length, length, length);
            dump_memory(frame_payload, &dbs, 16, 3, 0, dump_notrunc);
            trace_debug_event(trace_category_net, trace_event_http3, &dbs);
        }
#endif

        _payload = std::move(frame_payload);
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            pos = fpos;
        }
    }

    return ret;
}

return_t http3_frame::do_read_payload(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t http3_frame::do_write(binary_t& bin) {
    return_t ret = errorcode_t::success;
    return ret;
}

h3_frame_t http3_frame::get_type() { return _type; }

void http3_frame::addref() { _shared.addref(); }

void http3_frame::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
