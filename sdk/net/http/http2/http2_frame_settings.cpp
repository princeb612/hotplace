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

http2_frame_settings::http2_frame_settings() : http2_frame_header(h2_frame_t::h2_frame_settings) {}

http2_frame_settings::http2_frame_settings(const http2_frame_settings& rhs) : http2_frame_header(rhs) { _settings = rhs._settings; }

http2_frame_settings& http2_frame_settings::add(uint16 id, uint32 value) {
    h2_setting_map_pib_t pib = _settings.insert(std::make_pair(id, value));
    if (false == pib.second) {
        pib.first->second = value;
    }
    return *this;
}

return_t http2_frame_settings::read(http2_frame_header_t const* header, size_t size) {
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

return_t http2_frame_settings::write(binary_t& frame) {
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

void http2_frame_settings::dump(stream_t* s) {
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

}  // namespace net
}  // namespace hotplace
