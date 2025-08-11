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
#include <sdk/net/http/http2/http2_frame_ping.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_ping::http2_frame_ping() : http2_frame(h2_frame_t::h2_frame_ping), _opaque(0) {}

http2_frame_ping::http2_frame_ping(const http2_frame_ping& rhs) : http2_frame(rhs), _opaque(rhs._opaque) {}

http2_frame_ping::~http2_frame_ping() {}

return_t http2_frame_ping::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_opaque);

        pl.read(stream, size, pos);

        _opaque = pl.t_value_of<uint32>(constexpr_frame_opaque);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_ping::do_write_body(binary_t& body) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_opaque, true, constexpr_frame_opaque);
    pl.write(body);

    ret = set_payload_size(body.size());

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
