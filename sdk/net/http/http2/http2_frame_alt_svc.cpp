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
#include <sdk/io/basic/payload.hpp>
#include <sdk/net/http/http2/http2_frame_alt_svc.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_alt_svc::http2_frame_alt_svc() : http2_frame(h2_frame_t::h2_frame_altsvc) {}

http2_frame_alt_svc::http2_frame_alt_svc(const http2_frame_alt_svc& rhs) : http2_frame(rhs) {
    _origin = rhs._origin;
    _altsvc = rhs._altsvc;
}

http2_frame_alt_svc::~http2_frame_alt_svc() {}

return_t http2_frame_alt_svc::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint16)0, true, constexpr_frame_origin_len)  //
           << new payload_member(binary_t(), constexpr_frame_origin)           //
           << new payload_member(binary_t(), constexpr_frame_alt_svc_field_value);

        // size(origin) = value(origin len)
        // size(altsvc) = _payload_size - sizeof(uint16) - value(origin len)
        pl.set_reference_value(constexpr_frame_origin, constexpr_frame_origin_len);

        pl.read(stream, size, pos);

        pl.get_binary(constexpr_frame_origin, _origin);
        pl.get_binary(constexpr_frame_alt_svc_field_value, _altsvc);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_alt_svc::do_write_body(binary_t& body) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member((uint16)_origin.size(), true, constexpr_frame_origin_len)  //
       << new payload_member(_origin, constexpr_frame_origin)                           //
       << new payload_member(_altsvc, constexpr_frame_alt_svc_field_value);
    pl.write(body);

    ret = set_payload_size(body.size());

    return ret;
}

void http2_frame_alt_svc::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);
        s->printf(" > %s %u\n", constexpr_frame_origin_len, _origin.size());
        s->printf(" > %s\n", constexpr_frame_origin);
        dump_memory(_origin, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf(" > %s\n", constexpr_frame_alt_svc_field_value);
        dump_memory(_altsvc, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
    }
}

void http2_frame_alt_svc::set_origin(const binary_t& origin) { _origin = origin; }

void http2_frame_alt_svc::set_altsvc(const binary_t& altsvc) { _altsvc = altsvc; }

const binary_t& http2_frame_alt_svc::get_origin() { return _origin; }

const binary_t& http2_frame_alt_svc::get_altsvc() { return _altsvc; }

}  // namespace net
}  // namespace hotplace
