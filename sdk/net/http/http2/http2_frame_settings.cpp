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
#include <sdk/net/http/http2/http2_frame_settings.hpp>
#include <sdk/net/http/http2/http2_protocol.hpp>
#include <sdk/net/http/http_resource.hpp>

namespace hotplace {
namespace net {

http2_frame_settings::http2_frame_settings() : http2_frame(h2_frame_t::h2_frame_settings) {}

http2_frame_settings::http2_frame_settings(const http2_frame_settings& rhs) : http2_frame(rhs) { _settings = rhs._settings; }

http2_frame_settings::~http2_frame_settings() {}

http2_frame_settings& http2_frame_settings::add(uint16 id, uint32 value) {
    h2_setting_map_pib_t pib = _settings.insert(std::make_pair(id, value));
    if (false == pib.second) {
        pib.first->second = value;
    }
    return *this;
}

return_t http2_frame_settings::find(uint16 id, uint32& value) {
    return_t ret = errorcode_t::success;
    auto iter = _settings.find(id);
    if (_settings.end() == iter) {
        ret = errorcode_t::not_found;
        value = 0;
    } else {
        value = iter->second;
    }
    return ret;
}

return_t http2_frame_settings::read_body(const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        while (pos < size) {
            http2_setting_t* setting = (http2_setting_t*)(stream + pos);

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

return_t http2_frame_settings::write_body(binary_t& body) {
    return_t ret = errorcode_t::success;

    uint32 len = _settings.size() * sizeof(http2_setting_t);
    ret = set_payload_size(len);

    if (errorcode_t::success == ret) {
        // RFC 7540 Figure 10: Setting Format
        for (const auto& pair : _settings) {
            const auto& k = pair.first;
            const auto& v = pair.second;
            binary_append(body, k, hton16);
            binary_append(body, v, hton32);
        }
    }

    return ret;
}

void http2_frame_settings::dump(stream_t* s) {
    if (s) {
        http2_frame::dump(s);

        auto resource = http_resource::get_instance();
        h2_setting_map_t::iterator iter;
        for (const auto& pair : _settings) {
            const auto& k = pair.first;
            const auto& v = pair.second;
            std::string setting(resource->get_h2_settings_name(k));
            s->printf(" > ");
            s->printf("%s %u ", constexpr_frame_identifier, k);
            s->printf("%s %u (%s 0x%08x) ", constexpr_frame_value, v, setting.c_str(), v);
            s->printf("\n");
        }
    }
}

}  // namespace net
}  // namespace hotplace
