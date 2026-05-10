/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   http3_frame_settings.cpp
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
#include <hotplace/sdk/net/http/http3/http3_frame_settings.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_identifier[] = "identifier";
constexpr char constexpr_value[] = "value";

http3_frame_settings::http3_frame_settings() : http3_frame(h3_frame_settings) {}

return_t http3_frame_settings::do_read_payload(const byte_t* stream, size_t size, size_t& pos) {
    // RFC 9114 Figure 7: SETTINGS Frame

    function_pipeline<return_t> pipeline;
    pipeline  //
        .goahead_if_not_fail()
        .test_parameter([&]() -> bool { return (nullptr != stream); })
        .walk([&]() -> void {
            while (pos < size) {
                pipeline  //
                    .run_trycatch([&]() -> return_t {
                        payload pl;
                        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_identifier)  //
                           << new payload_member(new quic_encoded(uint64(0)), constexpr_value);

                        auto rc = pl.read(stream, size, pos);
                        if (false == error_traits<return_t>::is_not_fail(rc)) {
                            __trace_return(rc);
                        }

#if defined DEBUG
                        uint64 id = 0;
                        uint64 value = 0;
                        id = pl.t_value_of<uint64>(constexpr_identifier);
                        value = pl.t_value_of<uint64>(constexpr_value);

                        if (istraceable(trace_category_net)) {
                            auto resource = http_resource::get_instance();
                            trace_debug_event(trace_category_net, trace_event_http3, [&](basic_stream& dbs) -> void {
                                dbs.println("  > %I64i (%s) 0x%0I64x (%I64i)", id, resource->get_h3_settings_name(id).c_str(), value, value);
                            });
                        }
#endif
                        return success;
                    });
            }
        });
    return pipeline.result();
}

return_t http3_frame_settings::do_write(binary_t& bin) {
    function_pipeline<return_t> pipeline;

    for (auto& item : _params) {
        auto id = item.first;
        auto& value = item.second;

        pipeline  //
            .run_trycatch([&]() -> return_t {
#if defined DEBUG
                if (istraceable(trace_category_net)) {
                    auto resource = http_resource::get_instance();
                    trace_debug_event(trace_category_net, trace_event_http3,
                                      [&](basic_stream& dbs) -> void { dbs << "  > " << id << " (" << resource->get_h3_settings_name(id) << ") " << value << "\n"; });
                }
#endif

                payload pl;
                switch (value.content().type) {
                    case TYPE_NULL: {
                        pl << new payload_member(new quic_encoded(uint64(id)), constexpr_identifier)  //
                           << new payload_member(new quic_encoded(uint64(0)), constexpr_value);
                    } break;
                    case TYPE_UINT64: {
                        auto v = value.content().data.ui64;

                        pl << new payload_member(new quic_encoded(uint64(id)), constexpr_identifier)  //
                           << new payload_member(new quic_encoded(v), constexpr_value);
                    } break;
                    case TYPE_BINARY: {
                        pl << new payload_member(new quic_encoded(uint64(id)), constexpr_identifier)  //
                           << new payload_member(new quic_encoded(value.to_bin()), constexpr_value);
                    } break;
                    default:
                        break;
                }

                return pl.write(_payload);
            });
    }

    pipeline  //
        .run_trycatch([&]() -> return_t {
            payload pl;
            pl << new payload_member(new quic_encoded(uint64(h3_frame_settings)))  //
               << new payload_member(new quic_encoded(uint64(_payload.size())))    //
               << new payload_member(_payload);

            return pl.write(bin);
        });
    return pipeline.result();
}

http3_frame_settings& http3_frame_settings::set(uint16 id, uint64 value) {
    critical_section_guard guard(_lock);
    _params.push_back({id, variant(value)});
    return *this;
}

http3_frame_settings& http3_frame_settings::set(uint16 id, const binary_t& value) {
    critical_section_guard guard(_lock);
    _params.push_back({id, variant(value)});
    return *this;
}

}  // namespace net
}  // namespace hotplace
