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
#include <sdk/net/http/http2/http2_frame_headers.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_headers::http2_frame_headers() : http2_frame(h2_frame_t::h2_frame_headers), _padlen(0), _exclusive(false), _dependency(0), _weight(0) {}

http2_frame_headers::http2_frame_headers(const http2_frame_headers& rhs)
    : http2_frame(rhs), _padlen(rhs._padlen), _exclusive(rhs._exclusive), _dependency(rhs._dependency), _weight(rhs._weight) {
    _fragment = rhs._fragment;
}

http2_frame_headers::~http2_frame_headers() {}

return_t http2_frame_headers::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint8)0, constexpr_frame_pad_length, constexpr_frame_padding)                 //
           << new payload_member((uint32)0, true, constexpr_frame_stream_dependency, constexpr_frame_priority)  //
           << new payload_member((uint8)0, constexpr_frame_weight, constexpr_frame_priority)                    //
           << new payload_member(binary_t(), constexpr_frame_fragment)                                          //
           << new payload_member(binary_t(), constexpr_frame_padding, constexpr_frame_padding);

        auto dopad = (get_flags() & h2_flag_t::h2_flag_padded) ? true : false;
        auto dopriority = (get_flags() & h2_flag_t::h2_flag_priority) ? true : false;
        pl.set_group(constexpr_frame_padding, dopad)
            .set_group(constexpr_frame_priority, dopriority)
            .set_reference_value(constexpr_frame_padding, constexpr_frame_pad_length);

        pl.read(stream, size, pos);

        if (get_flags() & h2_flag_t::h2_flag_padded) {
            _padlen = pl.t_value_of<uint8>(constexpr_frame_pad_length);
        }
        if (get_flags() & h2_flag_t::h2_flag_priority) {
            uint32 temp = pl.t_value_of<uint32>(constexpr_frame_stream_dependency);
            _exclusive = (temp & 0x80000000) ? true : false;
            _dependency = (temp & 0x7fffffff);
            _weight = pl.t_value_of<uint8>(constexpr_frame_weight);
        }
        pl.get_binary(constexpr_frame_fragment, _fragment);
    }
    __finally2 {}
    return ret;
}

return_t http2_frame_headers::do_write_body(binary_t& body) {
    return_t ret = errorcode_t::success;

    uint32 dependency = _dependency;
    if (_exclusive) {
        dependency |= 0x80000000;
    }

    payload pl;
    pl << new payload_member(_padlen, constexpr_frame_pad_length, constexpr_frame_padding)
       << new payload_member(dependency, true, constexpr_frame_stream_dependency, constexpr_frame_priority)
       << new payload_member(_weight, constexpr_frame_weight, constexpr_frame_priority)  //
       << new payload_member(_fragment, constexpr_frame_fragment)                        //
       << new payload_member(uint8(0), _padlen, constexpr_frame_padding, constexpr_frame_padding);

    auto dopad = (get_flags() & h2_flag_t::h2_flag_padded) ? true : false;
    auto dopriority = (get_flags() & h2_flag_t::h2_flag_priority) ? true : false;
    pl.set_group(constexpr_frame_padding, dopad).set_group(constexpr_frame_priority, dopriority);
    pl.write(body);

    uint8 flags = get_flags();
    if (_padlen) {
        flags |= h2_flag_t::h2_flag_padded;
    } else {
        flags &= ~h2_flag_t::h2_flag_padded;
    }
    if (dependency) {
        flags |= h2_flag_t::h2_flag_priority;
    } else {
        flags &= ~h2_flag_t::h2_flag_priority;
    }
    set_flags(flags);

    ret = set_payload_size(body.size());

    return ret;
}

void http2_frame_headers::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);
        if (get_flags() & h2_flag_t::h2_flag_priority) {
            s->printf(" > %s E:%u %08x\n", constexpr_frame_stream_dependency, _exclusive ? 1 : 0, _dependency);
            s->printf(" > %s %02x\n", constexpr_frame_weight, _weight);
        }
        s->printf(" > %s\n", constexpr_frame_fragment);
        dump_memory(_fragment, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);

        auto lambda = [&](const std::string& name, const std::string& value) -> void { s->printf(" > %s: %s\n", name.c_str(), value.c_str()); };
        http2_frame::read_compressed_header(_fragment, lambda);
    }
}

void http2_frame_headers::set_fragment(const binary_t& fragment) { _fragment = fragment; }

const binary_t& http2_frame_headers::get_fragment() { return _fragment; }

}  // namespace net
}  // namespace hotplace
