/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   http3_frame.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/dump_memory.hpp>
#include <hotplace/sdk/base/basic/function_pipeline.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/http/http3/http3_frame.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_type[] = "HTTP/3 frame type";
constexpr char constexpr_length[] = "length";
constexpr char constexpr_payload[] = "payload";

http3_frame::http3_frame(h3_frame_t type) : _type(type) { _shared.make_share(this); }

http3_frame::~http3_frame() {}

return_t http3_frame::read(const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .run([&]() -> return_t { return do_read_frame(stream, size, pos); });
    return pipeline.result();
}

return_t http3_frame::write(binary_t& bin) {
    function_pipeline<return_t> pipeline;

    pipeline  //
        .run([&]() -> return_t {
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_http3, [&](basic_stream& dbs) -> void {
                    auto resource = http_resource::get_instance();
                    dbs.println("+ %s %I64i (%s)", constexpr_type, get_type(), resource->get_h3_frame_name(get_type()).c_str());
                });
            }
#endif

            return do_write(bin);
        });
    return pipeline.result();
}

return_t http3_frame::do_read_frame(const byte_t* stream, size_t size, size_t& pos) {
    function_pipeline<return_t> pipeline;
    size_t fpos = pos;
    binary_t frame_payload;
#if defined DEBUG
    uint64 type = 0;
    uint64 length = 0;
#endif

    pipeline  //
        .test_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream); })
        .run_trycatch([&]() -> return_t {
            payload pl;

            // RFC 9114 7.1.  Frame Layout
            pl << new payload_member(new quic_encoded(uint64(0)), constexpr_type)    //
               << new payload_member(new quic_encoded(uint64(0)), constexpr_length)  //
               << new payload_member(binary_t(), constexpr_payload);
            pl.set_reference_value(constexpr_payload, constexpr_length);
            auto rc = pl.read(stream, size, pos);
            if (false == error_traits<return_t>::is_not_fail(rc)) {
                return rc;
            }

#if defined DEBUG
            type = pl.t_value_of<uint64>(constexpr_type);
            length = pl.t_value_of<uint64>(constexpr_length);
#endif
            pl.get_binary(constexpr_payload, frame_payload);

            return success;
        })
        .walk_always([&](return_t lasterror) -> void {
#if defined DEBUG
            if (istraceable(trace_category_net)) {
                trace_debug_event(trace_category_net, trace_event_http3, [&](basic_stream& dbs) -> void {
                    http_resource* resource = http_resource::get_instance();
                    dbs.println("# %s %I64i (%s) %s", constexpr_type, type, resource->get_h3_frame_name(type).c_str(), (fragmented == lasterror) ? "fragmented" : "");
                    dbs.println(" > %s 0x%I64x (%I64i)", constexpr_length, length, length);
                    if (check_trace_level(loglevel_debug)) {
                        dump_memory(frame_payload, &dbs, 16, 3, 0, dump_notrunc);
                    }
                });
            }
#endif
        })
        .run([&]() -> return_t {
            size_t ppos = 0;
            return do_read_payload(frame_payload.data(), frame_payload.size(), ppos);
        })
        .walk_failed([&]() -> void { pos = fpos; });
    return pipeline.result();
}

return_t http3_frame::do_read_payload(const byte_t* stream, size_t size, size_t& pos) { return errorcode_t::success; }

return_t http3_frame::do_write(binary_t& bin) { return errorcode_t::success; }

h3_frame_t http3_frame::get_type() { return _type; }

void http3_frame::addref() { _shared.addref(); }

void http3_frame::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
