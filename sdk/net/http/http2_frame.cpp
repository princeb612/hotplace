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

template <typename TYPE>
void binsert(binary_t& bin, TYPE value, std::function<TYPE(TYPE)> func) {
    TYPE t = func(value);
    byte_t* b = (byte_t*)&t;
    bin.insert(bin.end(), b, b + sizeof(TYPE));
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

http2_frame_header& http2_frame_header::set_payload_size(uint32 size) {
    _payload_size = size;
    return *this;
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

        _payload_size = h2_get_payload_size(header);
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

    // RFC 7540 Figure 1: Frame Layout
    byte_t* p = (byte_t*)&temp;
    frame.insert(frame.end(), p, p + sizeof(http2_frame_header_t));

    return ret;
}

http2_data_frame::http2_data_frame() : http2_frame_header(h2_frame_t::h2_frame_data) {}

http2_data_frame& http2_data_frame::set_data(byte_t* data, size_t size) {
    if (data) {
        _data.clear();
        _data.insert(_data.end(), data, data + size);
    }
    return *this;
}

http2_data_frame& http2_data_frame::set_pad(byte_t* pad, size_t size) {
    if (pad && (size <= 0xff)) {
        _pad.clear();
        _pad.insert(_pad.end(), pad, pad + size);
    }
    return *this;
}

return_t http2_data_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == header) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = http2_frame_header::read(header, size);
        // TODO - studying
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t http2_data_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;

    // RFC 7540 Figure 1: Frame Layout
    http2_frame_header::write(frame);

    // RFC 7540 Figure 6: DATA Frame Payload
    uint8 padlen = (uint8)_pad.size();
    frame.insert(frame.end(), padlen);
    frame.insert(frame.end(), _data.begin(), _data.end());
    frame.insert(frame.end(), _pad.begin(), _pad.end());

    return ret;
}

http2_headers_frame::http2_headers_frame() : http2_frame_header(h2_frame_t::h2_frame_headers) {}

return_t http2_headers_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    //
    return ret;
}
return_t http2_headers_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    //
    return ret;
}

http2_priority_frame::http2_priority_frame() : http2_frame_header(h2_frame_t::h2_frame_priority) {}

return_t http2_priority_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    return ret;
}
return_t http2_priority_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    return ret;
}

http2_rst_stream_frame::http2_rst_stream_frame() : http2_frame_header(h2_frame_t::h2_frame_rst_stream) {}

return_t http2_rst_stream_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t http2_rst_stream_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    return ret;
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

        byte_t* p = (byte_t*)header;
        uint32 pos = 0;
        while (pos < len) {
            http2_setting_t* setting = (http2_setting_t*)(p + pos);

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
    set_payload_size(len);
    http2_frame_header::write(frame);

    // RFC 7540 Figure 10: Setting Format
    h2_setting_map_t::iterator iter;
    for (iter = _settings.begin(); iter != _settings.end(); iter++) {
        binsert<uint16>(frame, iter->first, htons);
        binsert<uint32>(frame, iter->second, htonl);
    }
    return ret;
}

http2_push_promise_frame::http2_push_promise_frame() : http2_frame_header(h2_frame_t::h2_frame_push_promise) {}

return_t http2_push_promise_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t http2_push_promise_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    return ret;
}

http2_ping_frame::http2_ping_frame() : http2_frame_header(h2_frame_t::h2_frame_ping) {}

return_t http2_ping_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t http2_ping_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    return ret;
}

http2_goaway_frame::http2_goaway_frame() : http2_frame_header(h2_frame_t::h2_frame_goaway) {}

return_t http2_goaway_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t http2_goaway_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    return ret;
}

http2_window_update_frame::http2_window_update_frame() : http2_frame_header(h2_frame_t::h2_frame_window_update) {}

return_t http2_window_update_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t http2_window_update_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    return ret;
}

http2_continuation_frame::http2_continuation_frame() : http2_frame_header(h2_frame_t::h2_frame_continuation) {}

return_t http2_continuation_frame::read(http2_frame_header_t const* header, size_t size) {
    return_t ret = errorcode_t::success;
    return ret;
}

return_t http2_continuation_frame::write(binary_t& frame) {
    return_t ret = errorcode_t::success;
    return ret;
}

}  // namespace net
}  // namespace hotplace
