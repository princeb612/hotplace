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
#include <hotplace/sdk/net/http/http3/http3_frame_data.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>
#include <hotplace/sdk/net/http/qpack/qpack_encoder.hpp>
#include <hotplace/sdk/net/tls/quic/quic.hpp>
#include <hotplace/sdk/net/tls/quic/quic_encoded.hpp>

namespace hotplace {
namespace net {

/**
 *  RFC 9114 7.2.1.  DATA
 *  DATA Frame {
 *    Type (i) = 0x00,
 *    Length (i),
 *    Data (..),
 *  }
 */

http3_frame_data::http3_frame_data() : http3_frame(h3_frame_data) {}

return_t http3_frame_data::do_read_payload(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_http3, [&](basic_stream& dbs) -> void { dbs.println("%.*s", (unsigned)size, (char*)stream); });
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t http3_frame_data::do_write(binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        payload pl;
        pl << new payload_member(new quic_encoded(uint64(get_type())))       //
           << new payload_member(new quic_encoded(uint64(_payload.size())))  //
           << new payload_member(_payload);
        pl.write(bin);
    }
    __finally2 {}
    return ret;
}

return_t http3_frame_data::set_contents(const std::string& contents) {
    return_t ret = errorcode_t::success;
    _payload = str2bin(contents);
    return ret;
}

std::string http3_frame_data::get_contents() {
    std::string value;
    value = bin2str(_payload);
    return value;
}

}  // namespace net
}  // namespace hotplace
