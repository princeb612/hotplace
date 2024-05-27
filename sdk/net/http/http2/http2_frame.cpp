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
#include <sdk/net/http/http2/http2_frame.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

// error: redeclaration in gcc [4.8.5, ? ]
// extern const char var[]
// constexpr char var[]

#if __GNUC__ >= 5
#define CONSTEXPR constexpr
#else
#define CONSTEXPR const
#endif

CONSTEXPR char constexpr_frame_length[] = "length";
CONSTEXPR char constexpr_frame_type[] = "type";
CONSTEXPR char constexpr_frame_flags[] = "flags";
CONSTEXPR char constexpr_frame_stream_identifier[] = "stream identifier";
CONSTEXPR char constexpr_frame_pad_length[] = "pad length";
CONSTEXPR char constexpr_frame_data[] = "data";
CONSTEXPR char constexpr_frame_padding[] = "padding";
CONSTEXPR char constexpr_frame_stream_dependency[] = "stream dependency";
CONSTEXPR char constexpr_frame_weight[] = "weight";
CONSTEXPR char constexpr_frame_fragment[] = "fragment";
CONSTEXPR char constexpr_frame_priority[] = "priority";
CONSTEXPR char constexpr_frame_error_code[] = "error code";
CONSTEXPR char constexpr_frame_promised_stream_id[] = "promised stream id";
CONSTEXPR char constexpr_frame_opaque[] = "opaque";
CONSTEXPR char constexpr_frame_last_stream_id[] = "last stream id";
CONSTEXPR char constexpr_frame_debug_data[] = "debug data";
CONSTEXPR char constexpr_frame_window_size_increment[] = "window size increment";

CONSTEXPR char constexpr_frame_exclusive[] = "exclusive";
CONSTEXPR char constexpr_frame_identifier[] = "identifier";
CONSTEXPR char constexpr_frame_value[] = "value";

http2_frame::http2_frame() : _payload_size(0), _type(0), _flags(0), _stream_id(0), _hpack_encoder(nullptr), _hpack_session(nullptr) {}

http2_frame::http2_frame(h2_frame_t type) : _payload_size(0), _type(type), _flags(0), _stream_id(0), _hpack_encoder(nullptr), _hpack_session(nullptr) {}

http2_frame::http2_frame(const http2_frame_header_t& header) { read(&header, sizeof(http2_frame_header_t)); }

http2_frame::http2_frame(const http2_frame& rhs) {
    _payload_size = rhs._payload_size;
    _type = rhs._type;
    _flags = rhs._flags;
    _stream_id = rhs._stream_id;
    _hpack_encoder = rhs._hpack_encoder;
    _hpack_session = rhs._hpack_session;
}

uint32 http2_frame::get_frame_size() { return sizeof(http2_frame_header_t) + get_payload_size(); }

uint32 http2_frame::get_payload_size() { return _payload_size; }

uint8 http2_frame::get_type() { return _type; }

uint8 http2_frame::get_flags() { return _flags; }

uint32 http2_frame::get_stream_id() { return _stream_id; }

return_t http2_frame::get_payload(http2_frame_header_t const* header, size_t size, byte_t** payload) {
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

return_t http2_frame::set_payload_size(uint32 size) {
    return_t ret = errorcode_t::success;
    if (size > 0x00ffffff) {
        ret = errorcode_t::bad_data;
    } else {
        _payload_size = size;
    }
    return ret;
}

http2_frame& http2_frame::set_type(h2_frame_t type) {
    _type = type;
    return *this;
}

http2_frame& http2_frame::set_flags(uint8 flags) {
    _flags = flags;
    return *this;
}

http2_frame& http2_frame::set_stream_id(uint32 id) {
    switch (_type) {
        case h2_frame_data:           // 6.1 DATA
        case h2_frame_headers:        // 6.2 HEADERS
        case h2_frame_priority:       // 6.3 PRIORITY
        case h2_frame_rst_stream:     // 6.4 RST_STREAM
        case h2_frame_push_promise:   // 6.6 PUSH_PROMISE
        case h2_frame_goaway:         // 6.8 GOAWAY
        case h2_frame_window_update:  // 6.9 WINDOW_UPDATE affected stream, entire connection (0)
        case h2_frame_continuation:   // 6.10 CONTINUATION
            _stream_id = id;
            break;
        case h2_frame_settings:  // 6.5 SETTINGS
        case h2_frame_ping:      // 6.7 PING
        default:
            break;
    }
    return *this;
}

http2_frame& http2_frame::load_hpack(hpack& hp) {
    _hpack_encoder = hp.get_encoder();
    _hpack_session = hp.get_session();
    return *this;
}

http2_frame& http2_frame::set_hpack_encoder(hpack_encoder* encoder) {
    _hpack_encoder = encoder;
    return *this;
}

http2_frame& http2_frame::set_hpack_session(hpack_session* session) {
    _hpack_session = session;
    return *this;
}

hpack_encoder* http2_frame::get_hpack_encoder() { return _hpack_encoder; }

hpack_session* http2_frame::get_hpack_session() { return _hpack_session; }

return_t http2_frame::read(http2_frame_header_t const* header, size_t size) {
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

        _payload_size = t_to_int<uint32>(pl.select(constexpr_frame_length));
        _type = t_to_int<uint8>(pl.select(constexpr_frame_type));
        _flags = t_to_int<uint8>(pl.select(constexpr_frame_flags));
        _stream_id = t_to_int<uint32>(pl.select(constexpr_frame_stream_identifier));
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(uint32_24_t(_payload_size), constexpr_frame_length) << new payload_member((uint8)_type, constexpr_frame_type)
       << new payload_member((uint8)_flags, constexpr_frame_flags) << new payload_member((uint32)_stream_id, true, constexpr_frame_stream_identifier);

    pl.dump(frame);

    return ret;
}

void http2_frame::dump(stream_t* s) {
    if (s) {
        http_resource* resource = http_resource::get_instance();
        std::string frame_name = resource->get_frame_name(get_type());

        s->printf("- http/2 frame type %d %s\n", get_type(), frame_name.c_str());
        s->printf(" > ");
        s->printf("%s 0x%02x(%u) ", constexpr_frame_length, get_payload_size(), get_payload_size());
        s->printf("%s %u ", constexpr_frame_type, get_type());
        s->printf("%s %02x ", constexpr_frame_flags, get_flags());
        s->printf("%s %08x ", constexpr_frame_stream_identifier, get_stream_id());
        s->printf("\n");
        s->printf(" > %s [ ", constexpr_frame_flags);

        resource->for_each_frame_flag_names(get_type(), get_flags(), [&](uint8 flag, const std::string& name) -> void { s->printf("%s ", name.c_str()); });

        s->printf("]\n");
    }
}

void http2_frame::read_compressed_header(const byte_t* buf, size_t size, std::function<void(const std::string&, const std::string&)> v) {
    if (buf && v && get_hpack_encoder() && get_hpack_session()) {
        size_t pos = 0;
        std::string name;
        std::string value;

        while (pos < size) {
            get_hpack_encoder()->decode_header(get_hpack_session(), buf, size, pos, name, value);
            v(name, value);
        }
    }
}

void http2_frame::read_compressed_header(const binary_t& b, std::function<void(const std::string&, const std::string&)> v) {
    read_compressed_header(&b[0], b.size(), v);
}

}  // namespace net
}  // namespace hotplace
