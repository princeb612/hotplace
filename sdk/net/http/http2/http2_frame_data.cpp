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
#include <sdk/net/http/http2/http2_frame_data.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_data::http2_frame_data() : http2_frame(h2_frame_t::h2_frame_data), _padlen(0) {}

http2_frame_data::http2_frame_data(const http2_frame_data& rhs) : http2_frame(rhs), _padlen(rhs._padlen) { _data = rhs._data; }

http2_frame_data::~http2_frame_data() {}

return_t http2_frame_data::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // Pad Length?
        // conditional (as signified by a "?" in the diagram) and is only present if the PADDED flag is set
        payload pl;
        pl << new payload_member((uint8)0, constexpr_frame_pad_length, constexpr_frame_padding)  //
           << new payload_member(binary_t(), constexpr_frame_data)                               //
           << new payload_member(binary_t(), constexpr_frame_padding, constexpr_frame_padding);

        auto dopad = (get_flags() & h2_flag_t::h2_flag_padded) ? true : false;
        pl.set_group(constexpr_frame_padding, dopad).set_reference_value(constexpr_frame_padding, constexpr_frame_pad_length);

        pl.read(stream, size, pos);

        _padlen = pl.t_value_of<uint8>(constexpr_frame_pad_length);
        pl.get_binary(constexpr_frame_data, _data);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_data::do_write_body(binary_t& body) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_padlen, constexpr_frame_pad_length, constexpr_frame_padding)  //
       << new payload_member(_data, constexpr_frame_data)                                   //
       << new payload_member((uint8)0, _padlen, constexpr_frame_padding, constexpr_frame_padding);
    pl.set_group(constexpr_frame_padding, _padlen ? true : false);
    pl.write(body);

    uint8 flags = get_flags();
    if (_padlen) {
        flags |= h2_flag_t::h2_flag_padded;
    } else {
        flags &= ~h2_flag_t::h2_flag_padded;
    }
    set_flags(flags);

    ret = set_payload_size(body.size());

    return ret;
}

void http2_frame_data::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);
        s->printf(" > %s\n", constexpr_frame_data);
        dump_memory(_data, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);
    }
}

void http2_frame_data::set_data(const binary_t& data) { _data = data; }

void http2_frame_data::set_data(const char* data, size_t size) {
    if (data) {
        _data.clear();
        _data.insert(_data.end(), data, data + size);
    }
}

const binary_t& http2_frame_data::get_data() { return _data; }

}  // namespace net
}  // namespace hotplace
