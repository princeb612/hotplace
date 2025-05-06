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

http2_frame_priority::http2_frame_priority() : http2_frame(h2_frame_t::h2_frame_priority), _exclusive(false), _dependency(0), _weight(0) {}

http2_frame_priority::http2_frame_priority(const http2_frame_priority& rhs)
    : http2_frame(rhs), _exclusive(rhs._exclusive), _dependency(rhs._dependency), _weight(rhs._weight) {}

return_t http2_frame_priority::read(http2_frame_header_t const* header, size_t size) {
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

        byte_t* ptr_payload = nullptr;
        ret = get_payload(header, size, &ptr_payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_stream_dependency) << new payload_member((uint8)0, constexpr_frame_weight);

        pl.set_reference_value(constexpr_frame_padding, constexpr_frame_pad_length);

        pl.read(ptr_payload, get_payload_size());

        uint32 temp = pl.t_value_of<uint32>(constexpr_frame_stream_dependency);
        _exclusive = (temp & 0x80000000) ? true : false;
        _dependency = (temp & 0x7fffffff);
        _weight = pl.t_value_of<uint8>(constexpr_frame_weight);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_priority::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    uint32 dependency = _dependency;
    if (_exclusive) {
        dependency |= 0x80000000;
    }

    payload pl;
    pl << new payload_member(dependency, true, constexpr_frame_stream_dependency) << new payload_member(_weight, constexpr_frame_weight);

    binary_t bin_payload;
    pl.write(bin_payload);

    set_payload_size(bin_payload.size());

    http2_frame::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

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
