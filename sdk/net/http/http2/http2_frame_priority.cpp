/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/basic/payload.hpp>
#include <hotplace/sdk/net/http/http2/http2_frame_priority.hpp>
#include <hotplace/sdk/net/http/http2/http2_protocol.hpp>
#include <hotplace/sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_priority::http2_frame_priority() : http2_frame(h2_frame_t::h2_frame_priority), _exclusive(false), _dependency(0), _weight(0) {}

http2_frame_priority::http2_frame_priority(const http2_frame_priority& rhs)
    : http2_frame(rhs), _exclusive(rhs._exclusive), _dependency(rhs._dependency), _weight(rhs._weight) {}

http2_frame_priority::~http2_frame_priority() {}

return_t http2_frame_priority::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_stream_dependency)  //
           << new payload_member((uint8)0, constexpr_frame_weight);

        pl.set_reference_value(constexpr_frame_padding, constexpr_frame_pad_length);
        pl.read(stream, size, pos);

        uint32 temp = pl.t_value_of<uint32>(constexpr_frame_stream_dependency);
        _exclusive = (temp & 0x80000000) ? true : false;
        _dependency = (temp & 0x7fffffff);
        _weight = pl.t_value_of<uint8>(constexpr_frame_weight);
    }
    __finally2 {}
    return ret;
}

return_t http2_frame_priority::do_write_body(binary_t& body) {
    return_t ret = errorcode_t::success;

    uint32 dependency = _dependency;
    if (_exclusive) {
        dependency |= 0x80000000;
    }

    payload pl;
    pl << new payload_member(dependency, true, constexpr_frame_stream_dependency)  //
       << new payload_member(_weight, constexpr_frame_weight);
    pl.write(body);

    ret = set_payload_size(body.size());

    return ret;
}

void http2_frame_priority::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);

        s->printf(" > %s %u\n", constexpr_frame_exclusive, _exclusive ? 1 : 0);
        s->printf(" > %s %u\n", constexpr_frame_stream_dependency, _dependency);
        s->printf(" > %s %u\n", constexpr_frame_weight, _weight);
    }
}

}  // namespace net
}  // namespace hotplace
