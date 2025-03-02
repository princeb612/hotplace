/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/binary.hpp>
#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/base/unittest/trace.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls_advisor.hpp>
#include <sdk/net/tls/tls_protection.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_level[] = "alert level";
constexpr char constexpr_desc[] = "alert desc ";

tls_record_alert::tls_record_alert(tls_session* session) : tls_record(tls_content_type_alert, session), _level(0), _desc(0) {}

tls_record_alert::tls_record_alert(tls_session* session, uint8 level, uint8 desc) : tls_record(tls_content_type_alert, session), _level(level), _desc(desc) {}

return_t tls_record_alert::do_read_body(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
    return_t ret = errorcode_t::success;
    __try2 {
        uint16 len = get_body_size();

        {
            auto session = get_session();
            size_t tpos = 0;
            size_t recpos = offsetof_header();

            // RFC 8446 6.  Alert Protocol
            // RFC 5246 7.2.  Alert Protocol
            auto session_info = session->get_session_info(dir);
            if (session_info.apply_protection()) {
                tls_protection& protection = session->get_tls_protection();
                auto tlsversion = protection.get_tls_version();
                auto cs = protection.get_cipher_suite();
                binary_t plaintext;

                tls_advisor* tlsadvisor = tls_advisor::get_instance();
                const tls_cipher_suite_t* hint = tlsadvisor->hintof_cipher_suite(cs);
                auto declen = (cbc == hint->mode) ? size : len;
                ret = protection.decrypt(session, dir, stream, declen, recpos, plaintext);
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

return_t tls_record_alert::read_plaintext(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos) {
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

        if (istraceable()) {
            basic_stream dbs;
            tls_advisor* advisor = tls_advisor::get_instance();

            dbs.printf(" > %s %i %s\n", constexpr_level, level, advisor->alert_level_string(level).c_str());
            dbs.printf(" > %s %i %s\n", constexpr_desc, desc, advisor->alert_desc_string(desc).c_str());

            trace_debug_event(category_net, net_event_tls_read, &dbs);
        }
    }
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t tls_record_alert::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    binary_append(bin, _level);
    binary_append(bin, _desc);
    return ret;
}

}  // namespace net
}  // namespace hotplace
