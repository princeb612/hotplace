/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/system/critical_section.hpp>
#include <sdk/io/basic/zlib.hpp>
#include <sdk/io/string/string.hpp>
#include <sdk/io/system/types.hpp>
#include <sdk/net/basic/sdk.hpp>
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

constexpr char constexpr_frame_length[] = "length";
constexpr char constexpr_frame_type[] = "type";
constexpr char constexpr_frame_flags[] = "flags";
constexpr char constexpr_frame_stream_identifier[] = "stream identifier";
constexpr char constexpr_frame_pad_length[] = "pad length";
constexpr char constexpr_frame_data[] = "data";
constexpr char constexpr_frame_padding[] = "padding";
constexpr char constexpr_frame_stream_dependency[] = "stream dependency";
constexpr char constexpr_frame_weight[] = "weight";
constexpr char constexpr_frame_fragment[] = "fragment";
constexpr char constexpr_frame_priority[] = "priority";
constexpr char constexpr_frame_error_code[] = "error code";
constexpr char constexpr_frame_promised_stream_id[] = "promised stream id";
constexpr char constexpr_frame_opaque[] = "opaque";
constexpr char constexpr_frame_last_stream_id[] = "last stream id";
constexpr char constexpr_frame_debug_data[] = "debug data";
constexpr char constexpr_frame_window_size_increment[] = "window size increment";

constexpr char constexpr_frame_exclusive[] = "exclusive";
constexpr char constexpr_frame_identifier[] = "identifier";
constexpr char constexpr_frame_value[] = "value";

http2_frame_header::http2_frame_header() : _payload_size(0), _type(0), _flags(0), _stream_id(0), _hpack_encoder(nullptr), _hpack_session(nullptr) {}

http2_frame_header::http2_frame_header(h2_frame_t type)
    : _payload_size(0), _type(type), _flags(0), _stream_id(0), _hpack_encoder(nullptr), _hpack_session(nullptr) {}

http2_frame_header::http2_frame_header(const http2_frame_header_t& header) { read(&header, sizeof(http2_frame_header_t)); }

http2_frame_header::http2_frame_header(const http2_frame_header& rhs) {
    _payload_size = rhs._payload_size;
    _type = rhs._type;
    _flags = rhs._flags;
    _stream_id = rhs._stream_id;
    _hpack_encoder = rhs._hpack_encoder;
    _hpack_session = rhs._hpack_session;
}

uint32 http2_frame_header::get_frame_size() { return sizeof(http2_frame_header_t) + get_payload_size(); }

uint32 http2_frame_header::get_payload_size() { return _payload_size; }

uint8 http2_frame_header::get_type() { return _type; }

uint8 http2_frame_header::get_flags() { return _flags; }

uint32 http2_frame_header::get_stream_id() { return _stream_id; }

return_t http2_frame_header::get_payload(http2_frame_header_t const* header, size_t size, byte_t** payload) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header || nullptr == payload) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *payload = (byte_t*)header + sizeof(http2_frame_header_t);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_header::set_payload_size(uint32 size) {
    return_t ret = errorcode_t::success;
    if (size > 0x00ffffff) {
        ret = errorcode_t::bad_data;
    } else {
        _payload_size = size;
    }
    return ret;
}

http2_frame_header& http2_frame_header::set_type(h2_frame_t type) {
    _type = type;
    return *this;
}

http2_frame_header& http2_frame_header::set_flags(uint8 flags) {
    _flags = flags;
    return *this;
}

http2_frame_header& http2_frame_header::set_stream_id(uint32 id) {
    _stream_id = id;
    return *this;
}

http2_frame_header& http2_frame_header::set_hpack_encoder(hpack_encoder* encoder) {
    _hpack_encoder = encoder;
    return *this;
}

http2_frame_header& http2_frame_header::set_hpack_session(hpack_session* session) {
    _hpack_session = session;
    return *this;
}

hpack_encoder* http2_frame_header::get_hpack_encoder() { return _hpack_encoder; }

hpack_session* http2_frame_header::get_hpack_session() { return _hpack_session; }

return_t http2_frame_header::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (size < sizeof(http2_frame_header_t)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        payload pl;
        pl << new payload_member(uint32_24_t(0), constexpr_frame_length) << new payload_member((uint8)0, constexpr_frame_type)
           << new payload_member((uint8)0, constexpr_frame_flags) << new payload_member((uint32)0, true, constexpr_frame_stream_identifier);

        pl.read((byte_t*)header, size);

        _payload_size = t_variant_to_int<uint32>(pl.select(constexpr_frame_length)->get_variant().content());
        _type = t_variant_to_int<uint8>(pl.select(constexpr_frame_type)->get_variant().content());
        _flags = t_variant_to_int<uint8>(pl.select(constexpr_frame_flags)->get_variant().content());
        _stream_id = t_variant_to_int<uint32>(pl.select(constexpr_frame_stream_identifier)->get_variant().content());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_header::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(uint32_24_t(_payload_size), constexpr_frame_length) << new payload_member((uint8)_type, constexpr_frame_type)
       << new payload_member((uint8)_flags, constexpr_frame_flags) << new payload_member((uint32)_stream_id, true, constexpr_frame_stream_identifier);

    pl.dump(frame);

    return ret;
}

void http2_frame_header::dump(stream_t* s) {
    if (s) {
        http_resource* resource = http_resource::get_instance();
        std::string frame_name = resource->get_frame_name(get_type());

        s->printf("- http/2 frame type %d %s\n", get_type(), frame_name.c_str());
        s->printf("> ");
        s->printf("%s %u ", constexpr_frame_length, get_payload_size());
        s->printf("%s %u ", constexpr_frame_type, get_type());
        s->printf("%s %02x ", constexpr_frame_flags, get_flags());
        s->printf("%s %08x ", constexpr_frame_stream_identifier, get_stream_id());
        s->printf("\n");
        s->printf("> %s [ ", constexpr_frame_flags);

        resource->for_each_frame_flag_names(get_type(), get_flags(), [&](uint8 flag, const std::string& name) -> void { s->printf("%s ", name.c_str()); });

        s->printf("]\n");
    }
}

void http2_frame_header::dump_hpack(stream_t* s, const binary_t& b) {
    if (s && get_hpack_encoder() && get_hpack_session()) {
        size_t pos = 0;
        std::string name;
        std::string value;

        while (pos < b.size()) {
            get_hpack_encoder()->decode_header(get_hpack_session(), &b[0], b.size(), pos, name, value);
            s->printf("> %s: %s\n", name.c_str(), value.c_str());
        }
    }
}

}  // namespace net
}  // namespace hotplace
