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
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_data::http2_frame_data() : http2_frame(h2_frame_t::h2_frame_data), _padlen(0) {}

http2_frame_data::http2_frame_data(const http2_frame_data& rhs) : http2_frame(rhs), _padlen(rhs._padlen) { _data = rhs._data; }

return_t http2_frame_data::read(http2_frame_header_t const* header, size_t size) {
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

        // Pad Length?
        // conditional (as signified by a "?" in the diagram) and is only present if the PADDED flag is set
        payload pl;
        pl << new payload_member((uint8)0, constexpr_frame_pad_length, constexpr_frame_padding)  //
           << new payload_member(binary_t(), constexpr_frame_data)                               //
           << new payload_member(binary_t(), constexpr_frame_padding, constexpr_frame_padding);

        pl.set_group(constexpr_frame_padding, (get_flags() & h2_flag_t::h2_flag_padded) ? true : false)
            .set_reference_value(constexpr_frame_padding, constexpr_frame_pad_length);

        pl.read(ptr_payload, get_payload_size());

        _padlen = pl.t_value_of<uint8>(constexpr_frame_pad_length);
        pl.get_binary(constexpr_frame_data, _data);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_data::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_padlen, constexpr_frame_pad_length, constexpr_frame_padding)  //
       << new payload_member(_data, constexpr_frame_data)                                   //
       << new payload_member((uint8)0, _padlen, constexpr_frame_padding, constexpr_frame_padding);

    pl.set_group(constexpr_frame_padding, _padlen ? true : false);

    binary_t bin_payload;
    pl.write(bin_payload);

    uint8 flags = get_flags();
    if (_padlen) {
        flags |= h2_flag_t::h2_flag_padded;
    } else {
        flags &= ~h2_flag_t::h2_flag_padded;
    }
    set_flags(flags);
    set_payload_size(bin_payload.size());

    http2_frame::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

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
