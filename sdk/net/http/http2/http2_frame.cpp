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
#include <sdk/net/http/http_header.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

// RFC 7540 4.  HTTP Frames
CONSTEXPR char constexpr_frame_length[] = "length";
CONSTEXPR char constexpr_frame_type[] = "type";
CONSTEXPR char constexpr_frame_flags[] = "flags";
CONSTEXPR char constexpr_frame_stream_identifier[] = "stream identifier";
// RFC 7540 6.  Frame Definitions
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
// RFC 7838 4.  The ALTSVC HTTP/2 Frame
CONSTEXPR char constexpr_frame_origin_len[] = "origin-len";
CONSTEXPR char constexpr_frame_origin[] = "origin";
CONSTEXPR char constexpr_frame_alt_svc_field_value[] = "alt-svc-field-value";

http2_frame::http2_frame() : _payload_size(0), _type(0), _flags(0), _stream_id(0), _hpack_dyntable(nullptr) { _shared.make_share(this); }

http2_frame::http2_frame(h2_frame_t type) : _payload_size(0), _type(type), _flags(0), _stream_id(0), _hpack_dyntable(nullptr) { _shared.make_share(this); }

http2_frame::http2_frame(const http2_frame& rhs) {
    _payload_size = rhs._payload_size;
    _type = rhs._type;
    _flags = rhs._flags;
    _stream_id = rhs._stream_id;
    _hpack_dyntable = rhs._hpack_dyntable;
    _shared.make_share(this);
}

http2_frame::~http2_frame() {}

uint32 http2_frame::get_frame_size() { return sizeof(http2_frame_header_t) + get_payload_size(); }

uint32 http2_frame::get_payload_size() { return _payload_size; }

uint8 http2_frame::get_type() { return _type; }

uint8 http2_frame::get_flags() { return _flags; }

uint32 http2_frame::get_stream_id() { return _stream_id; }

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
        case h2_frame_data:           // RFC 7540 6.1 DATA
        case h2_frame_headers:        // RFC 7540 6.2 HEADERS
        case h2_frame_priority:       // RFC 7540 6.3 PRIORITY
        case h2_frame_rst_stream:     // RFC 7540 6.4 RST_STREAM
        case h2_frame_push_promise:   // RFC 7540 6.6 PUSH_PROMISE
        case h2_frame_goaway:         // RFC 7540 6.8 GOAWAY
        case h2_frame_window_update:  // RFC 7540 6.9 WINDOW_UPDATE affected stream, entire connection (0)
        case h2_frame_continuation:   // RFC 7540 6.10 CONTINUATION
            _stream_id = id;
            break;
        case h2_frame_settings:  // RFC 7540 6.5 SETTINGS
        case h2_frame_ping:      // RFC 7540 6.7 PING
        case h2_frame_altsvc:    // RFC 7838 4.  The ALTSVC HTTP/2 Frame
        default:
            break;
    }
    return *this;
}

http2_frame& http2_frame::load_hpack(hpack_stream& hp) {
    _hpack_dyntable = hp.get_session();
    return *this;
}

http2_frame& http2_frame::set_hpack_session(hpack_dynamic_table* session) {
    _hpack_dyntable = session;
    return *this;
}

hpack_dynamic_table* http2_frame::get_hpack_session() { return _hpack_dyntable; }

return_t http2_frame::read(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    auto frpos = pos;
    __try2 {
        ret = do_read_header(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = do_read_body(stream, size, pos);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            pos = frpos;
        }
    }
    return ret;
}

return_t http2_frame::do_read_header(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (size < pos + sizeof(http2_frame_header_t)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        payload pl;
        pl << new payload_member(uint24_t(0), constexpr_frame_length)  //
           << new payload_member((uint8)0, constexpr_frame_type)       //
           << new payload_member((uint8)0, constexpr_frame_flags)      //
           << new payload_member((uint32)0, true, constexpr_frame_stream_identifier);

        pl.read(stream, size, pos);

        _payload_size = pl.t_value_of<uint32>(constexpr_frame_length);
        _type = pl.t_value_of<uint8>(constexpr_frame_type);
        _flags = pl.t_value_of<uint8>(constexpr_frame_flags);
        _stream_id = pl.t_value_of<uint32>(constexpr_frame_stream_identifier);

        if (_payload_size + pos < size) {
            ret = errorcode_t::bad_data;
            __leave2;
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame::do_read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    // override
    return ret;
}

return_t http2_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    auto snapshot = frame.size();
    __try2 {
        binary_t body;
        ret = do_write_body(body);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        ret = do_write_header(frame, body);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {
        if (errorcode_t::success != ret) {
            frame.resize(snapshot);  // rollback
        }
    }
    return ret;
}

return_t http2_frame::do_write_header(binary_t& frame, const binary_t& body) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(uint24_t(body.size()), constexpr_frame_length)  //
       << new payload_member((uint8)_type, constexpr_frame_type)             //
       << new payload_member((uint8)_flags, constexpr_frame_flags)           //
       << new payload_member((uint32)_stream_id, true, constexpr_frame_stream_identifier);
    pl.write(frame);

    binary_append(frame, body);

    return ret;
}

return_t http2_frame::do_write_body(binary_t& frame) {
    return_t ret = errorcode_t::success;
    // override
    return ret;
}

void http2_frame::dump(stream_t* s) {
    if (s) {
        http_resource* resource = http_resource::get_instance();
        std::string frame_name = resource->get_h2_frame_name(get_type());

        s->printf("- http/2 frame type %d %s\n", get_type(), frame_name.c_str());
        s->printf(" > ");
        s->printf("%s 0x%02x(%u) ", constexpr_frame_length, get_payload_size(), get_payload_size());
        s->printf("%s %u ", constexpr_frame_type, get_type());
        s->printf("%s %02x ", constexpr_frame_flags, get_flags());
        s->printf("%s %08x ", constexpr_frame_stream_identifier, get_stream_id());
        s->printf("\n");
        s->printf(" > %s [ ", constexpr_frame_flags);

        auto lambda = [&](uint8 flag, const std::string& name) -> void { s->printf("%s ", name.c_str()); };
        resource->for_each_h2_frame_flag_names(get_type(), get_flags(), lambda);

        s->printf("]\n");
    }
}

void http2_frame::read_compressed_header(const byte_t* buf, size_t size, std::function<void(const std::string&, const std::string&)> v) {
    if (buf && v && get_hpack_session()) {
        size_t pos = 0;
        std::string name;
        std::string value;

        hpack_encoder encoder;
        while (pos < size) {
            encoder.decode_header(get_hpack_session(), buf, size, pos, name, value);
            v(name, value);
        }
        get_hpack_session()->commit();
    }
}

void http2_frame::read_compressed_header(const binary_t& b, std::function<void(const std::string&, const std::string&)> v) {
    read_compressed_header(&b[0], b.size(), v);
}

return_t http2_frame::write_compressed_header(binary_t& frag, const std::string& name, const std::string& value, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == get_hpack_session()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }
        hpack_encoder encoder;
        encoder.encode_header(get_hpack_session(), frag, name, value, flags);
        get_hpack_session()->commit();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame::write_compressed_header(http_header* header, binary_t& frag, uint32 flags) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (nullptr == get_hpack_session()) {
            ret = errorcode_t::not_ready;
            __leave2;
        }

        hpack_encoder encoder;
        auto lambda = [&](const std::string& name, const std::string& value) -> void { encoder.encode_header(get_hpack_session(), frag, name, value, flags); };
        header->get_headers(lambda);
        get_hpack_session()->commit();
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

void http2_frame::addref() { _shared.addref(); }

void http2_frame::release() { _shared.delref(); }

}  // namespace net
}  // namespace hotplace
