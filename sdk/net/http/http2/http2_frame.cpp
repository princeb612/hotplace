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

http2_frame_header::http2_frame_header() : _payload_size(0), _type(0), _flags(0), _stream_id(0) {}

http2_frame_header::http2_frame_header(h2_frame_t type) : _payload_size(0), _type(type), _flags(0), _stream_id(0) {}

http2_frame_header::http2_frame_header(const http2_frame_header& o) {
    _payload_size = o._payload_size;
    _type = o._type;
    _flags = o._flags;
    _stream_id = o._stream_id;
}

http2_frame_header::http2_frame_header(http2_frame_header_t const& header) { read(&header, sizeof(http2_frame_header_t)); }

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
        s->printf("%s %u ", constexpr_frame_stream_identifier, get_stream_id());
        s->printf("\n");
        s->printf("> %s [ ", constexpr_frame_flags);

        resource->for_each_frame_flag_names(get_flags(), [&](uint8 flag, std::string const& name) -> void { s->printf("%s ", name.c_str()); });

        s->printf("]\n");
    }
}

http2_data_frame::http2_data_frame() : http2_frame_header(h2_frame_t::h2_frame_data), _padlen(0) {}

return_t http2_data_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame_header::read(header, size);
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
        pl << new payload_member((uint8)0, constexpr_frame_pad_length, constexpr_frame_padding) << new payload_member(binary_t(), constexpr_frame_data)
           << new payload_member(binary_t(), constexpr_frame_padding, constexpr_frame_padding);

        pl.set_group(constexpr_frame_padding, (get_flags() & h2_flag_t::h2_flag_padded) ? true : false)
            .set_reference_value(constexpr_frame_padding, constexpr_frame_pad_length);

        pl.read(ptr_payload, get_payload_size());

        _padlen = t_variant_to_int<uint8>(pl.select(constexpr_frame_pad_length)->get_variant().content());
        pl.select(constexpr_frame_length)->get_variant().dump(_data, true);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_data_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_padlen, constexpr_frame_pad_length, constexpr_frame_padding) << new payload_member(_data, constexpr_frame_data)
       << new payload_member((uint8)0, _padlen, constexpr_frame_padding, constexpr_frame_padding);

    pl.set_group(constexpr_frame_padding, _padlen ? true : false);

    binary_t bin_payload;
    pl.dump(bin_payload);

    uint8 flags = 0;
    if (_padlen) {
        flags |= h2_flag_t::h2_flag_padded;
    }
    set_payload_size(bin_payload.size());
    set_flags(flags);

    http2_frame_header::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_data_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);
        s->printf("> %s\n", constexpr_frame_data);
        dump_memory(_data, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
    }
}

http2_headers_frame::http2_headers_frame() : http2_frame_header(h2_frame_t::h2_frame_headers), _padlen(0), _exclusive(false), _dependency(0), _weight(0) {}

return_t http2_headers_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame_header::read(header, size);
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
           << new payload_member((uint32)0, true, constexpr_frame_stream_dependency, constexpr_frame_priority)
           << new payload_member((uint8)0, constexpr_frame_weight, constexpr_frame_priority) << new payload_member(binary_t(), constexpr_frame_fragment)
           << new payload_member(binary_t(), constexpr_frame_padding, constexpr_frame_padding);

        pl.set_group(constexpr_frame_padding, (get_flags() & h2_flag_t::h2_flag_padded) ? true : false)
            .set_group(constexpr_frame_priority, (get_flags() & h2_flag_t::h2_flag_priority) ? true : false)
            .set_reference_value(constexpr_frame_padding, constexpr_frame_pad_length);

        pl.read(ptr_payload, get_payload_size());

        if (get_flags() & h2_flag_t::h2_flag_padded) {
            _padlen = t_variant_to_int<uint8>(pl.select(constexpr_frame_pad_length)->get_variant().content());
        }
        if (get_flags() & h2_flag_t::h2_flag_priority) {
            uint32 temp = t_variant_to_int<uint32>(pl.select(constexpr_frame_stream_dependency)->get_variant().content());
            _exclusive = (temp & 0x80000000) ? true : false;
            _dependency = (temp & 0x7fffffff);
            _weight = t_variant_to_int<uint8>(pl.select(constexpr_frame_weight)->get_variant().content());
        }
        pl.select(constexpr_frame_fragment)->get_variant().dump(_fragment, true);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_headers_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    uint32 dependency = _dependency;
    if (_exclusive) {
        dependency |= 0x80000000;
    }

    payload pl;
    pl << new payload_member(_padlen, constexpr_frame_pad_length, constexpr_frame_padding)
       << new payload_member(dependency, true, constexpr_frame_stream_dependency, constexpr_frame_priority)
       << new payload_member(_weight, constexpr_frame_weight, constexpr_frame_priority) << new payload_member(_fragment, constexpr_frame_fragment)
       << new payload_member(uint8(0), _padlen, constexpr_frame_padding, constexpr_frame_padding);

    pl.set_group(constexpr_frame_padding, (get_flags() & h2_flag_t::h2_flag_padded) ? true : false)
        .set_group(constexpr_frame_priority, (get_flags() & h2_flag_t::h2_flag_priority) ? true : false);

    binary_t bin_payload;
    pl.dump(bin_payload);

    uint8 flags = 0;
    if (_padlen) {
        flags |= h2_flag_t::h2_flag_padded;
    }
    if (dependency) {
        flags |= h2_flag_t::h2_flag_priority;
    }
    set_payload_size(bin_payload.size());
    set_flags(flags);

    http2_frame_header::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_headers_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);
        s->printf("> %s\n", constexpr_frame_fragment);
        dump_memory(_fragment, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
    }
}

http2_priority_frame::http2_priority_frame() : http2_frame_header(h2_frame_t::h2_frame_priority), _exclusive(false), _dependency(0), _weight(0) {}

return_t http2_priority_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame_header::read(header, size);
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

        uint32 temp = t_variant_to_int<uint32>(pl.select(constexpr_frame_stream_dependency)->get_variant().content());
        _exclusive = (temp & 0x80000000) ? true : false;
        _dependency = (temp & 0x7fffffff);
        _weight = t_variant_to_int<uint8>(pl.select(constexpr_frame_weight)->get_variant().content());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_priority_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    uint32 dependency = _dependency;
    if (_exclusive) {
        dependency |= 0x80000000;
    }

    payload pl;
    pl << new payload_member(dependency, true, constexpr_frame_stream_dependency) << new payload_member(_weight, constexpr_frame_weight);

    binary_t bin_payload;
    pl.dump(bin_payload);

    uint8 flags = 0;
    set_payload_size(bin_payload.size());
    set_flags(flags);

    http2_frame_header::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_priority_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> %s %u\n", constexpr_frame_exclusive, _exclusive ? 1 : 0);
        s->printf("> %s %u\n", constexpr_frame_stream_dependency, _dependency);
        s->printf("> %s %u\n", constexpr_frame_weight, _weight);
    }
}

http2_rst_stream_frame::http2_rst_stream_frame() : http2_frame_header(h2_frame_t::h2_frame_rst_stream), _errorcode(0) {}

return_t http2_rst_stream_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame_header::read(header, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        byte_t* ptr_payload = nullptr;
        ret = get_payload(header, size, &ptr_payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_error_code);

        pl.read(ptr_payload, get_payload_size());

        _errorcode = t_variant_to_int<uint32>(pl.select(constexpr_frame_error_code)->get_variant().content());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_rst_stream_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_errorcode, true, constexpr_frame_error_code);

    binary_t bin_payload;
    pl.dump(bin_payload);

    uint8 flags = 0;
    set_payload_size(bin_payload.size());
    set_flags(flags);

    http2_frame_header::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_rst_stream_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> %s %u\n", constexpr_frame_error_code, _errorcode);
    }
}

http2_settings_frame::http2_settings_frame() : http2_frame_header(h2_frame_t::h2_frame_settings) {}

http2_settings_frame& http2_settings_frame::add(uint16 id, uint32 value) {
    h2_setting_map_pib_t pib = _settings.insert(std::make_pair(id, value));
    if (false == pib.second) {
        pib.first->second = value;
    }
    return *this;
}

return_t http2_settings_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = http2_frame_header::read(header, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        uint32 len = get_payload_size();
        if ((size < get_frame_size()) || (len % sizeof(http2_setting_t))) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        byte_t* payload = nullptr;
        ret = get_payload(header, size, &payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        uint32 pos = 0;
        while (pos < len) {
            http2_setting_t* setting = (http2_setting_t*)(payload + pos);

            uint16 id = ntoh16(setting->id);
            uint32 value = ntoh32(setting->value);
            add(id, value);

            pos += sizeof(http2_setting_t);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_settings_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    uint32 len = _settings.size() * sizeof(http2_setting_t);
    ret = set_payload_size(len);

    if (errorcode_t::success == ret) {
        http2_frame_header::write(frame);

        // RFC 7540 Figure 10: Setting Format
        h2_setting_map_t::iterator iter;
        for (iter = _settings.begin(); iter != _settings.end(); iter++) {
            binsert<uint16>(frame, iter->first, hton16);
            binsert<uint32>(frame, iter->second, hton32);
        }
    }

    return ret;
}

void http2_settings_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        h2_setting_map_t::iterator iter;
        for (iter = _settings.begin(); iter != _settings.end(); iter++) {
            s->printf("> ");
            s->printf("%s %u ", constexpr_frame_identifier, iter->first);
            s->printf("%s %u (0x%08x) ", constexpr_frame_value, iter->second, iter->second);
            s->printf("\n");
        }
    }
}

http2_push_promise_frame::http2_push_promise_frame() : http2_frame_header(h2_frame_t::h2_frame_push_promise), _padlen(0), _promised_id(0) {}

return_t http2_push_promise_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame_header::read(header, size);
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
            _padlen = t_variant_to_int<uint8>(pl.select(constexpr_frame_pad_length)->get_variant().content());
        }

        _promised_id = t_variant_to_int<uint32>(pl.select(constexpr_frame_promised_stream_id)->get_variant().content());
        pl.select(constexpr_frame_fragment)->get_variant().dump(_fragment, true);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_push_promise_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_padlen, constexpr_frame_pad_length, constexpr_frame_padding)
       << new payload_member(_promised_id, true, constexpr_frame_promised_stream_id) << new payload_member(_fragment, constexpr_frame_fragment)
       << new payload_member(uint8(0), _padlen, constexpr_frame_padding, constexpr_frame_padding);

    pl.set_group(constexpr_frame_padding, (get_flags() & h2_flag_t::h2_flag_padded) ? true : false);

    binary_t bin_payload;
    pl.dump(bin_payload);

    uint8 flags = 0;
    if (_padlen) {
        flags |= h2_flag_t::h2_flag_padded;
    }
    set_payload_size(bin_payload.size());
    set_flags(flags);

    http2_frame_header::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_push_promise_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);
        s->printf("> %s %u\n", constexpr_frame_promised_stream_id, _promised_id);
        s->printf("> %s\n", constexpr_frame_fragment);
        dump_memory(_fragment, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
    }
}

http2_ping_frame::http2_ping_frame() : http2_frame_header(h2_frame_t::h2_frame_ping), _opaque(0) {}

return_t http2_ping_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame_header::read(header, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // PING frames MUST contain 8 octets of opaque data in the payload.
        byte_t* ptr_payload = nullptr;
        ret = get_payload(header, size, &ptr_payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_opaque);

        pl.read(ptr_payload, get_payload_size());

        _opaque = t_variant_to_int<uint32>(pl.select(constexpr_frame_opaque)->get_variant().content());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_ping_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_opaque, true, constexpr_frame_opaque);

    binary_t bin_payload;
    pl.dump(bin_payload);

    uint8 flags = 0;
    set_payload_size(bin_payload.size());
    set_flags(flags);

    http2_frame_header::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_ping_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> %s %I64u\n", constexpr_frame_opaque, _opaque);
    }
}

http2_goaway_frame::http2_goaway_frame() : http2_frame_header(h2_frame_t::h2_frame_goaway), _last_id(0), _errorcode(0) {}

return_t http2_goaway_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame_header::read(header, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        byte_t* ptr_payload = nullptr;
        ret = get_payload(header, size, &ptr_payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_last_stream_id) << new payload_member((uint32)0, true, constexpr_frame_error_code)
           << new payload_member(binary_t(), constexpr_frame_debug_data);

        pl.read(ptr_payload, get_payload_size());

        _last_id = t_variant_to_int<uint32>(pl.select(constexpr_frame_last_stream_id)->get_variant().content());
        _errorcode = t_variant_to_int<uint32>(pl.select(constexpr_frame_error_code)->get_variant().content());
        pl.select(constexpr_frame_fragment)->get_variant().dump(_debug, true);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_goaway_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_last_id, true, constexpr_frame_last_stream_id) << new payload_member(_errorcode, true, constexpr_frame_error_code)
       << new payload_member(_debug, constexpr_frame_debug_data);

    binary_t bin_payload;
    pl.dump(bin_payload);

    uint8 flags = 0;
    set_payload_size(bin_payload.size());
    set_flags(flags);

    http2_frame_header::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_goaway_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> %s %u\n", constexpr_frame_last_stream_id, _last_id);
        s->printf("> %s %u\n", constexpr_frame_error_code, _errorcode);
        s->printf("> %s\n", constexpr_frame_debug_data);
        dump_memory(_debug, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
    }
}

http2_window_update_frame::http2_window_update_frame() : http2_frame_header(h2_frame_t::h2_frame_window_update), _increment(0) {}

return_t http2_window_update_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame_header::read(header, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        byte_t* ptr_payload = nullptr;
        ret = get_payload(header, size, &ptr_payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        payload pl;
        pl << new payload_member((uint32)0, true, constexpr_frame_window_size_increment);

        pl.read(ptr_payload, get_payload_size());

        _increment = t_variant_to_int<uint32>(pl.select(constexpr_frame_window_size_increment)->get_variant().content());
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_window_update_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_increment, true, constexpr_frame_window_size_increment);

    binary_t bin_payload;
    pl.dump(bin_payload);

    uint8 flags = 0;
    set_payload_size(bin_payload.size());
    set_flags(flags);

    http2_frame_header::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_window_update_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> %s %u\n", constexpr_frame_window_size_increment, _increment);
    }
}

http2_continuation_frame::http2_continuation_frame() : http2_frame_header(h2_frame_t::h2_frame_continuation) {}

return_t http2_continuation_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        // check size and then read header
        ret = http2_frame_header::read(header, size);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        byte_t* ptr_payload = nullptr;
        ret = get_payload(header, size, &ptr_payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        payload pl;
        pl << new payload_member(binary_t(), constexpr_frame_fragment);

        pl.read(ptr_payload, get_payload_size());

        pl.select(constexpr_frame_fragment)->get_variant().dump(_fragment, true);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_continuation_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    payload pl;
    pl << new payload_member(_fragment, constexpr_frame_fragment);

    binary_t bin_payload;
    pl.dump(bin_payload);

    uint8 flags = 0;
    set_payload_size(bin_payload.size());
    set_flags(flags);

    http2_frame_header::write(frame);
    frame.insert(frame.end(), bin_payload.begin(), bin_payload.end());

    return ret;
}

void http2_continuation_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> %s\n", constexpr_frame_fragment);
        dump_memory(_fragment, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
    }
}

}  // namespace net
}  // namespace hotplace
