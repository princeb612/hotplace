/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_ping::http2_frame_ping() : http2_frame(h2_frame_t::h2_frame_ping), _opaque(0) {}

http2_frame_ping::http2_frame_ping(const http2_frame_ping& rhs) : http2_frame(rhs), _opaque(rhs._opaque) {}

return_t http2_frame_ping::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame::read(header, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // PING frames MUST contain 8 octets of opaque data in the payload.
        byte_t* ptr_payload = nullptr;
        ret = get_payload(header, size, &ptr_payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_opaque);

        pl.read(ptr_payload, get_payload_size());

        _opaque = pl.t_value_of<uint32>(constexpr_frame_opaque);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_ping::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_opaque, true, constexpr_frame_opaque);

    binary_t bin_payload;
    pl.write(bin_payload);

    set_payload_size(bin_payload.size());

    http2_frame::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_frame_ping::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);

        s->printf(" > %s %I64u\n", constexpr_frame_opaque, _opaque);
    }
}

}  // namespace net
}  // namespace hotplace
