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

http3_frame_settings::http3_frame_settings() : http3_frame(h3_frame_settings) {}

return_t http3_frame_settings::do_read_payload(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    // RFC 9114 Figure 7: SETTINGS Frame
    constexpr char constexpr_identifier[] = "identifier";
    constexpr char constexpr_value[] = "value";
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
            dbs.println("  > %I64i (%s) %I64i", id, resource->get_h3_settings_name(id).c_str(), value);
            trace_debug_event(trace_category_net, trace_event_http3, &dbs);
        }
#endif
    }
    return ret;
}

return_t http3_frame_settings::do_write(binary_t& bin) {
    return_t ret = errorcode_t::success;
    return ret;
}

}  // namespace net
}  // namespace hotplace
