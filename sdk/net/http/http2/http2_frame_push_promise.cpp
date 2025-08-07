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
#include <sdk/net/http/http2/http2_frame_push_promise.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_push_promise::http2_frame_push_promise() : http2_frame(h2_frame_t::h2_frame_push_promise), _padlen(0), _promised_id(0) {}

http2_frame_push_promise::http2_frame_push_promise(const http2_frame_push_promise& rhs)
    : http2_frame(rhs), _padlen(rhs._padlen), _promised_id(rhs._promised_id) {
    _fragment = rhs._fragment;
}

http2_frame_push_promise::~http2_frame_push_promise() {}

return_t http2_frame_push_promise::read(http2_frame_header_t const* header, size_t size) {
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
        pl << new payload_member((uint8)0, constexpr_frame_pad_length, constexpr_frame_padding)
           << new payload_member((uint32)0, true, constexpr_frame_promised_stream_id) << new payload_member(binary_t(), constexpr_frame_fragment)
           << new payload_member(binary_t(), constexpr_frame_padding, constexpr_frame_padding);

        pl.set_group(constexpr_frame_padding, (get_flags() & h2_flag_t::h2_flag_padded) ? true : false)
            .set_reference_value(constexpr_frame_padding, constexpr_frame_pad_length);

        pl.read(ptr_payload, get_payload_size());

        if (get_flags() & h2_flag_t::h2_flag_padded) {
            _padlen = pl.t_value_of<uint8>(constexpr_frame_pad_length);
        }

        _promised_id = pl.t_value_of<uint32>(constexpr_frame_promised_stream_id);
        pl.get_binary(constexpr_frame_fragment, _fragment);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_push_promise::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_padlen, constexpr_frame_pad_length, constexpr_frame_padding)
       << new payload_member(_promised_id, true, constexpr_frame_promised_stream_id) << new payload_member(_fragment, constexpr_frame_fragment)
       << new payload_member(uint8(0), _padlen, constexpr_frame_padding, constexpr_frame_padding);

    pl.set_group(constexpr_frame_padding, (get_flags() & h2_flag_t::h2_flag_padded) ? true : false);

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

void http2_frame_push_promise::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);
        s->printf(" > %s %u\n", constexpr_frame_promised_stream_id, _promised_id);
        s->printf(" > %s\n", constexpr_frame_fragment);
        dump_memory(_fragment, s, 16, 3, 0x0, dump_memory_flag_t::dump_notrunc);

        auto reader = [&](const std::string& name, const std::string& value) -> void { s->printf(" > %s: %s\n", name.c_str(), value.c_str()); };
        http2_frame::read_compressed_header(_fragment, reader);
    }
}

void http2_frame_push_promise::set_fragment(const binary_t& fragment) { _fragment = fragment; }

const binary_t& http2_frame_push_promise::get_fragment() { return _fragment; }

}  // namespace net
}  // namespace hotplace
