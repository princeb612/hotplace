/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *          RFC 8446 The Transport Layer Security (TLS) Protocol Version 1.3
 *          RFC 6066 Transport Layer Security (TLS) Extensions: Extension Definitions
 *          RFC 5246 The Transport Layer Security (TLS) Protocol Version 1.2
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tlsspec/tls.hpp>
#include <sdk/net/tlsspec/tls_advisor.hpp>

namespace hotplace {
namespace net {

return_t tls_dump_alert(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == s || nullptr == session || nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (pos + 2 > size) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        tls_advisor* advisor = tls_advisor::get_instance();
        uint8 level = stream[pos++];
        uint8 desc = stream[pos++];

        constexpr char constexpr_level[] = "alert level";
        constexpr char constexpr_desc[] = "alert desc ";

        s->autoindent(1);
        s->printf(" > %s %i %s\n", constexpr_level, level, advisor->alert_level_string(level).c_str());
        s->printf(" > %s %i %s\n", constexpr_desc, desc, advisor->alert_desc_string(desc).c_str());
        s->autoindent(0);
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

}  // namespace net
}  // namespace hotplace
