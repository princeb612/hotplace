/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>
#include <sdk/net/tls1/tls_record.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_level[] = "alert level";
constexpr char constexpr_desc[] = "alert desc ";

tls_alert::tls_alert(tls_session* session) : tls_record(tls_content_type_alert, session), _level(0), _desc(0) {}

return_t tls_alert::read_data(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 len = get_length();

        {
            auto session = get_session();
            size_t tpos = 0;
            size_t recpos = get_header_range().begin;

            // RFC 8446 6.  Alert Protocol
            // RFC 5246 7.2.  Alert Protocol
            auto session_info = session->get_session_info(dir);
            if (session_info.doprotect()) {
                tls_protection& protection = session->get_tls_protection();
                binary_t plaintext;
                binary_t tag;
                auto tlsversion = protection.get_tls_version();
                if (is_basedon_tls13(tlsversion)) {
                    ret = protection.decrypt_tls13(session, dir, stream, len, recpos, plaintext, tag, debugstream);
                } else {
                    ret = protection.decrypt_tls1(session, dir, stream, size, recpos, plaintext, debugstream);
                }
                if (errorcode_t::success == ret) {
                    tpos = 0;
                    ret = read_plaintext(dir, &plaintext[0], plaintext.size(), tpos);
                }
            } else {
                tpos = pos;
                ret = read_plaintext(dir, stream, size, tpos);
            }
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_alert::read_plaintext(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos, stream_t* debugstream) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == stream) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (pos + 2 > size) {
            ret = errorcode_t::bad_data;
            __leave2;
        }

        uint8 level = 0;
        uint8 desc = 0;
        {
            level = stream[pos++];
            desc = stream[pos++];
        }
        {
            _level = level;
            _desc = desc;
        }

        if (debugstream) {
            tls_advisor* advisor = tls_advisor::get_instance();

            debugstream->printf(" > %s %i %s\n", constexpr_level, level, advisor->alert_level_string(level).c_str());
            debugstream->printf(" > %s %i %s\n", constexpr_desc, desc, advisor->alert_desc_string(desc).c_str());
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_alert::write(tls_direction_t dir, binary_t& bin, stream_t* debugstream) { return errorcode_t::not_supported; }

}  // namespace net
}  // namespace hotplace
