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
#include <sdk/net/http/http2_frame.hpp>
#include <sdk/net/tls/tls.hpp>

namespace hotplace {
using namespace io;
namespace net {

uint32 h2_get_payload_size(http2_frame_header_t const* header) {
    uint32 ret_value = 0;

    if (header) {
        uint32 uint32_len = 0;
        byte_t* byte_ptr = (byte_t*)&uint32_len;
        memcpy(byte_ptr + 1, header->len, 3);

        ret_value = ntohl(uint32_len);
    }

    return ret_value;
}

return_t h2_set_payload_size(http2_frame_header_t* header, uint32 size) {
    return_t ret = errorcode_t::success;
    __try2 {
        const uint32 max_size = (1 << 24) - 1;
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (size > max_size) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }

        uint32 uint32_len = htonl(size);
        byte_t* byte_ptr = (byte_t*)&uint32_len;
        memcpy(header->len, byte_ptr + 1, 3);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

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

        uint32 len = h2_get_payload_size(header);

        // check payload
        if (size < sizeof(http2_frame_header_t) + len) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        byte_t* payload = (byte_t*)header + sizeof(http2_frame_header_t);
        uint8 padlen = 0;
        uint32 pos = 0;

        typedef std::set<uint8> h2_frame_set_t;

        // check pad - DATA, HEADERS, PUSH_PROMISE (only present if the PADDED flag is set)
        if (h2_flag_t::h2_flag_padded & header->flags) {
            h2_frame_set_t conditional_pad;
            conditional_pad.insert(h2_frame_data);
            conditional_pad.insert(h2_frame_headers);
            conditional_pad.insert(h2_frame_push_promise);
            h2_frame_set_t::iterator iter = conditional_pad.find(header->type);
            if (conditional_pad.end() != iter) {
                if (len < 1) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }

                padlen = payload[0];
                pos++;
                if (padlen + 1 < len) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            } else {
                ret = errorcode_t::bad_data;
                __leave2;
            }
        }
        // check priority - HEADERS (only present if the PRIORITY flag is set)
        if (h2_frame_t::h2_frame_headers == header->type) {
            if (h2_flag_t::h2_flag_priority & header->flags) {
                if (len < pos + sizeof(http2_priority_t) + padlen) {
                    ret = errorcode_t::bad_data;
                    __leave2;
                }
            }
        }

        _payload_size = len;
        _type = header->type;
        _flags = header->flags;
        _stream_id = ntohl(header->stream_id);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_frame_header::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    http2_frame_header_t temp;

    h2_set_payload_size(&temp, _payload_size);
    temp.type = _type;
    temp.flags = _flags;
    temp.stream_id = htonl(_stream_id);

    byte_t* p = (byte_t*)&temp;
    frame.insert(frame.end(), p, p + sizeof(http2_frame_header_t));

    return ret;
}

void http2_frame_header::dump(stream_t* s) {
    if (s) {
        typedef struct _http_frame_typename_t {
            uint8 type;
            const char* name;
        } http_frame_typename_t;
        typedef struct _http_frame_flags_t {
            uint8 flag;
            const char* name;
        } http_frame_flags_t;

        http_frame_typename_t frame_names[] = {
            {
                h2_frame_t::h2_frame_data,
                "DATA",
            },
            {
                h2_frame_t::h2_frame_headers,
                "HEADERS",
            },
            {
                h2_frame_t::h2_frame_priority,
                "PRIORITY",
            },
            {
                h2_frame_t::h2_frame_rst_stream,
                "RST_STREAM",
            },
            {
                h2_frame_t::h2_frame_settings,
                "SETTINGS",
            },
            {
                h2_frame_t::h2_frame_push_promise,
                "PUSH_PROMISE",
            },
            {
                h2_frame_t::h2_frame_ping,
                "PING",
            },
            {
                h2_frame_t::h2_frame_goaway,
                "GOAWAY",
            },
            {
                h2_frame_t::h2_frame_window_update,
                "WINDOW_UPDATE",
            },
            {
                h2_frame_t::h2_frame_continuation,
                "CONTINUATION",
            },
        };
        http_frame_flags_t frame_flags[] = {
            {
                h2_flag_t::h2_flag_end_stream,
                "END_STREAM",
            },
            {
                h2_flag_t::h2_flag_end_headers,
                "END_HEADERS",
            },
            {
                h2_flag_t::h2_flag_padded,
                "PADDED",
            },
            {
                h2_flag_t::h2_flag_priority,
                "PRIORITY",
            },
        };

        s->printf("- http/2 frame type %d %s\n", get_type(), frame_names[get_type()].name);
        s->printf("> len %u type %u flags 0x%02x stream identifier %u\n", get_payload_size(), get_type(), get_flags(), get_stream_id());
        s->printf("> flags [ ");
        for (uint32 i = 0; i < RTL_NUMBER_OF(frame_flags); i++) {
            http_frame_flags_t* item = frame_flags + i;
            if (item->flag & get_flags()) {
                s->printf("%s ", item->name);
            }
        }
        s->printf("]\n");
        // dump_memory(bin, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
        // s->printf("\n");
    }
}

return_t http2_frame_header::set_uint8(uint8& target, uint8 source) {
    return_t ret = errorcode_t::success;
    target = source;
    return ret;
}

return_t http2_frame_header::set_uint16(uint16& target, uint16 source) {
    return_t ret = errorcode_t::success;
    target = source;
    return ret;
}

return_t http2_frame_header::set_uint32(uint32& target, uint32 source) {
    return_t ret = errorcode_t::success;
    target = source;
    return ret;
}

return_t http2_frame_header::set_uint64(uint64& target, uint64 source) {
    return_t ret = errorcode_t::success;
    target = source;
    return ret;
}

return_t http2_frame_header::set_uint128(uint128& target, uint128 source) {
    return_t ret = errorcode_t::success;
    target = source;
    return ret;
}

return_t http2_frame_header::set_binary(binary_t& target, byte_t* source, size_t size, size_t limit) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        if (limit && (size > limit)) {
            ret = errorcode_t::out_of_range;
            __leave2;
        }

        target.clear();
        target.insert(target.end(), source, source + size);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

http2_data_frame::http2_data_frame() : http2_frame_header(h2_frame_t::h2_frame_data) {}

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

        byte_t* payload = nullptr;
        ret = get_payload(header, size, &payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // Pad Length?
        // conditional (as signified by a "?" in the diagram) and is only present if the PADDED flag is set
        if (get_flags() & h2_flag_t::h2_flag_padded) {
            // padlen(1) + data(len-1-padlen) + pad(padlen)
            uint8 padlen = payload[0];
            uint32 datalen = get_payload_size() - (1 + padlen);
            byte_t* data = payload + 1;
            byte_t* pad = payload + (1 + datalen);

            set_binary(_data, data, datalen);
            set_binary(_pad, pad, padlen);
        } else {
            set_binary(_data, payload, get_payload_size());
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_data_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    uint8 flags = 0;
    uint8 padsize = 0;
    if (_pad.size()) {
        flags |= h2_flag_t::h2_flag_padded;
        padsize = 1;
    }

    set_flags(flags);
    ret = set_payload_size(padsize + _data.size() + _pad.size());

    if (errorcode_t::success == ret) {
        http2_frame_header::write(frame);

        if (flags & h2_flag_t::h2_flag_padded) {
            frame.insert(frame.end(), (uint8)_pad.size());
        }
        frame.insert(frame.end(), _data.begin(), _data.end());
        if (flags & h2_flag_t::h2_flag_padded) {
            frame.insert(frame.end(), _pad.begin(), _pad.end());
        }
    }
    return ret;
}

void http2_data_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);
        s->printf("> data\n");
        dump_memory(_data, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
        if (_pad.size()) {
            s->printf("> pad\n");
            dump_memory(_pad, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
            s->printf("\n");
        }
    }
}

http2_headers_frame::http2_headers_frame() : http2_frame_header(h2_frame_t::h2_frame_headers), _use_priority(false), _dependency(0), _weight(0) {}

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

        byte_t* payload = nullptr;
        ret = get_payload(header, size, &payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        uint32 pos = 0;
        uint8 padlen = 0;
        http2_priority_t* priority = nullptr;
        if (get_flags() & h2_flag_t::h2_flag_padded) {
            pos++;
            padlen = payload[0];
        }
        uint32 prilen = 0;
        if (get_flags() & h2_flag_t::h2_flag_priority) {
            priority = (http2_priority_t*)(payload + pos);
            prilen = sizeof(http2_priority_t);

            _use_priority = true;
            _dependency = ntohl(priority->dependency);
            _weight = priority->weight;
        } else {
            _use_priority = false;
        }

        byte_t* fragment = payload + pos + prilen;
        uint32 fraglen = get_payload_size() - (pos + prilen + padlen);

        byte_t* pad = payload + pos + prilen + fraglen;

        set_binary(_fragment, fragment, fraglen);
        set_binary(_pad, pad, padlen);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}
return_t http2_headers_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    uint8 flags = 0;
    uint32 padsize = 0;
    uint32 depsize = 0;
    if (_pad.size()) {
        flags |= h2_flag_t::h2_flag_padded;
        padsize = 1;
    }
    if (_use_priority) {
        flags |= h2_flag_t::h2_flag_priority;
        depsize = sizeof(http2_priority_t);
    }

    set_flags(flags);
    ret = set_payload_size(padsize + depsize + _fragment.size() + _pad.size());

    if (errorcode_t::success == ret) {
        http2_frame_header::write(frame);

        if (flags & h2_flag_t::h2_flag_padded) {
            frame.insert(frame.end(), (uint8)_pad.size());  // Pad Length?
        }
        if (flags & h2_flag_t::h2_flag_priority) {
            binsert<uint32>(frame, _dependency, htonl);  // Stream Dependency?
            frame.insert(frame.end(), _weight);          // Weight?
        }
        frame.insert(frame.end(), _fragment.begin(), _fragment.end());
        if (flags & h2_flag_t::h2_flag_padded) {
            frame.insert(frame.end(), _pad.begin(), _pad.end());
        }
    }
    return ret;
}

void http2_headers_frame::dump(stream_t* s) {
    if (s) {
        basic_stream bs;
        uint8 flags = 0;
        uint32 padsize = 0;
        uint32 depsize = 0;
        if (_pad.size()) {
            flags |= h2_flag_t::h2_flag_padded;
            padsize = 1;
        }
        if (_use_priority) {
            flags |= h2_flag_t::h2_flag_priority;
            depsize = sizeof(http2_priority_t);
        }

        http2_frame_header::dump(s);
        s->printf("> fragment\n");
        dump_memory(_fragment, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
        s->printf("\n");
        if (_pad.size()) {
            s->printf("> pad\n");
            dump_memory(_pad, s, 16, 2, 0x0, dump_memory_flag_t::dump_notrunc);
            s->printf("\n");
        }
    }
}

http2_priority_frame::http2_priority_frame() : http2_frame_header(h2_frame_t::h2_frame_priority), _exclusive(false), _dependency(0), _weight(0) {}

uint8 http2_priority_frame::get_exclusive() { return _exclusive ? 1 : 0; }

uint32 http2_priority_frame::get_dependency() { return _dependency; }

uint8 http2_priority_frame::get_weight() { return _weight; }

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

        byte_t* payload = nullptr;
        ret = get_payload(header, size, &payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // A PRIORITY frame with a length other than 5 octets MUST be treated as a stream error (Section 5.4.2) of type FRAME_SIZE_ERROR.
        if (get_payload_size() != sizeof(http2_priority_t)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        http2_priority_t priority;
        http2_priority_t* temp = (http2_priority_t*)payload;
        priority.dependency = ntohl(temp->dependency);
        priority.weight = temp->weight;

        _exclusive = (priority.dependency & 0x80000000) ? true : false;
        _dependency = (priority.dependency & 0x7fffffff);
        _weight = priority.weight;
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_priority_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    ret = set_payload_size(sizeof(http2_priority_t));

    if (errorcode_t::success == ret) {
        http2_frame_header::write(frame);

        http2_priority_t priority;
        priority.dependency = _dependency;
        if (_exclusive) {
            priority.dependency |= 0x80000000;
        }
        priority.weight = _weight;

        binsert<uint32>(frame, priority.dependency, htonl);
        frame.insert(frame.end(), priority.weight);
    }

    return ret;
}

void http2_priority_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> exclusive %u dependency %u weight %u\n", get_exclusive(), get_dependency(), get_weight());
    }
}

http2_rst_stream_frame::http2_rst_stream_frame() : http2_frame_header(h2_frame_t::h2_frame_rst_stream), _errorcode(0) {}

uint32 http2_rst_stream_frame::get_errorcode() { return _errorcode; }

http2_rst_stream_frame& http2_rst_stream_frame::set_errorcode(uint32 errorcode) {
    _errorcode = errorcode;
    return *this;
}

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

        byte_t* payload = nullptr;
        ret = get_payload(header, size, &payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // The RST_STREAM frame contains a single unsigned, 32-bit integer identifying the error code
        if (get_payload_size() != sizeof(uint32)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        uint32 temp = *(uint32*)payload;
        _errorcode = ntohl(temp);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_rst_stream_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    ret = set_payload_size(sizeof(uint32));
    if (errorcode_t::success == ret) {
        http2_frame_header::write(frame);

        binsert<uint32>(frame, _errorcode, htonl);
    }

    return ret;
}

void http2_rst_stream_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> errorcode %u\n", get_errorcode());
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

            uint16 id = ntohs(setting->id);
            uint32 value = ntohl(setting->value);
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
            binsert<uint16>(frame, iter->first, htons);
            binsert<uint32>(frame, iter->second, htonl);
        }
    }

    return ret;
}

void http2_settings_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        h2_setting_map_t::iterator iter;
        for (iter = _settings.begin(); iter != _settings.end(); iter++) {
            s->printf("> id %u value %u (0x%08x)\n", iter->first, iter->second, iter->second);
        }
    }
}

http2_push_promise_frame::http2_push_promise_frame() : http2_frame_header(h2_frame_t::h2_frame_push_promise), _promised_id(0) {}

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

        byte_t* payload = nullptr;
        ret = get_payload(header, size, &payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        uint32 pos = 0;
        uint8 padlen = 0;
        http2_priority_t* priority = nullptr;
        if (get_flags() & h2_flag_t::h2_flag_padded) {
            pos++;
            padlen = payload[0];
        }
        uint32 temp = *(uint32*)(payload + pos);
        byte_t* frag = payload + pos + sizeof(uint32);
        uint32 fraglen = get_payload_size() - (pos + sizeof(uint32) + padlen);
        byte_t* pad = payload + pos + sizeof(uint32) + fraglen;

        _promised_id = ntohl(temp);
        set_binary(_fragment, frag, fraglen);
        set_binary(_pad, pad, padlen);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_push_promise_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    // TODO
    return ret;
}

void http2_push_promise_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        // TODO
    }
}

http2_ping_frame::http2_ping_frame() : http2_frame_header(h2_frame_t::h2_frame_ping), _opaque(0) {}

uint64 http2_ping_frame::get_opaque() { return _opaque; }

http2_ping_frame& http2_ping_frame::set_opaque(uint64 opaque) {
    _opaque = opaque;
    return *this;
}

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

        byte_t* payload = nullptr;
        ret = get_payload(header, size, &payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // PING frames MUST contain 8 octets of opaque data in the payload.
        if (get_payload_size() != sizeof(uint64)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        uint64 temp = *(uint64*)payload;
        _opaque = ntoh64(temp);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_ping_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    ret = set_payload_size(sizeof(uint64));

    if (errorcode_t::success == ret) {
        http2_frame_header::write(frame);

        binsert<uint64>(frame, _opaque, hton64);
    }

    return ret;
}

void http2_ping_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> opaque %I64u\n", get_opaque());
    }
}

http2_goaway_frame::http2_goaway_frame() : http2_frame_header(h2_frame_t::h2_frame_goaway), _last_id(0), _errorcode(0) {}

uint32 http2_goaway_frame::get_last_id() { return _last_id; }

uint32 http2_goaway_frame::get_errorcode() { return _errorcode; }

http2_goaway_frame& http2_goaway_frame::set_last_id(uint32 last_id) {
    _last_id = last_id;
    return *this;
}

http2_goaway_frame& http2_goaway_frame::set_errorcode(uint32 errorcode) {
    _errorcode = errorcode;
    return *this;
}

http2_goaway_frame& http2_goaway_frame::set_debug(byte_t* debug, size_t size) {
    if (debug) {
        _debug.clear();
        _debug.insert(_debug.end(), debug, debug + size);
    }
    return *this;
}

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

        byte_t* payload = nullptr;
        ret = get_payload(header, size, &payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (get_payload_size() < sizeof(uint64)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        http2_goaway_t* goaway = (http2_goaway_t*)payload;
        _last_id = ntohl(goaway->last_id);
        _errorcode = ntohl(goaway->errorcode);
        uint32 debuglen = get_payload_size() - (sizeof(uint32) + sizeof(uint32));
        set_debug(goaway->debug, debuglen);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_goaway_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    set_payload_size(sizeof(uint32) + sizeof(uint32) + _debug.size());

    if (errorcode_t::success == ret) {
        http2_frame_header::write(frame);

        binsert<uint64>(frame, _last_id, htonl);
        binsert<uint64>(frame, _errorcode, htonl);
        frame.insert(frame.end(), _debug.begin(), _debug.end());
    }

    return ret;
}

void http2_goaway_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> last_id %u errorcode %u\n", get_last_id(), get_errorcode());
        basic_stream bs;
        dump_memory(_debug, &bs, 16, 2);
        s->printf("> debug\n%s\n", bs.c_str());
    }
}

http2_window_update_frame::http2_window_update_frame() : http2_frame_header(h2_frame_t::h2_frame_window_update), _increment(0) {}

uint32 http2_window_update_frame::get_increment() { return _increment; }

http2_window_update_frame& http2_window_update_frame::set_increment(uint32 increment) {
    _increment;
    return *this;
}

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

        byte_t* payload = nullptr;
        ret = get_payload(header, size, &payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        if (get_payload_size() != sizeof(uint32)) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        uint32 temp = *(uint32*)payload;
        _increment = ntohl(temp);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_window_update_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    set_payload_size(sizeof(uint32));

    http2_frame_header::write(frame);

    binsert<uint32>(frame, _increment, htonl);

    return ret;
}

void http2_window_update_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        s->printf("> increment %u\n", get_increment());
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

        byte_t* payload = nullptr;
        ret = get_payload(header, size, &payload);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // TODO
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_continuation_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    // TODO
    return ret;
}

void http2_continuation_frame::dump(stream_t* s) {
    if (s) {
        http2_frame_header::dump(s);

        // TODO
    }
}

}  // namespace net
}  // namespace hotplace
