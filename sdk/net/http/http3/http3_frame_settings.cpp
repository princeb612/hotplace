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
    return_t ret = errorcode_t::success;
    // RFC 9114 Figure 7: SETTINGS Frame
    auto resource = http_resource::get_instance();
    uint64 id = 0;
    uint64 value = 0;
    while (pos < size) {
        payload pl;
        pl << new payload_member(new quic_encoded(uint64(0)), constexpr_identifier)  //
           << new payload_member(new quic_encoded(uint64(0)), constexpr_value);
        pl.read(stream, size, pos);

        id = pl.t_value_of<uint64>(constexpr_identifier);
        value = pl.t_value_of<uint64>(constexpr_value);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs.println("  > %I64i (%s) 0x%0I64x (%I64i)", id, resource->get_h3_settings_name(id).c_str(), value, value);
            trace_debug_event(trace_category_net, trace_event_http3, &dbs);
        }
#endif
    }
    return ret;
}

return_t http3_frame_settings::do_write(binary_t& bin) {
    return_t ret = errorcode_t::success;
    auto resource = http_resource::get_instance();
    binary_t temp;

    for (auto& item : _params) {
        auto id = item.first;
        auto& value = item.second;

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            basic_stream dbs;
            dbs << "  > " << id << " (" << resource->get_h3_settings_name(id) << ") " << value << "\n";
            trace_debug_event(trace_category_net, trace_event_http3, &dbs);
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
        }
        pl.write(_payload);
    }

    payload pl;
    pl << new payload_member(new quic_encoded(uint64(h3_frame_settings)))  //
       << new payload_member(new quic_encoded(uint64(_payload.size())))    //
       << new payload_member(_payload);
    pl.write(bin);

    return ret;
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
