/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/binary.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/unittest/trace.hpp>
#include <hotplace/sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>
#include <hotplace/sdk/net/tls/tls_protection.hpp>
#include <hotplace/sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

constexpr char constexpr_alert[] = "alert";
constexpr char constexpr_level[] = "alert level";
constexpr char constexpr_desc[] = "alert desc ";

tls_record_alert::tls_record_alert(tls_session* session) : tls_record(tls_content_type_alert, session), _level(0), _desc(0) {}

tls_record_alert::tls_record_alert(tls_session* session, uint8 level, uint8 desc) : tls_record(tls_content_type_alert, session), _level(level), _desc(desc) {}

tls_record_alert::~tls_record_alert() {}

return_t tls_record_alert::do_postprocess(tls_direction_t dir) {
    return_t ret = errorcode_t::success;
    return ret;
}

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
            auto& session_info = session->get_session_info(dir);
            if (session_info.apply_protection()) {
                tls_protection& protection = session->get_tls_protection();
                auto tlsversion = protection.get_tls_version();
                auto cs = protection.get_cipher_suite();
                binary_t plaintext;

                tls_advisor* tlsadvisor = tls_advisor::get_instance();
                auto limit = recpos + get_record_size();
                ret = protection.decrypt(session, dir, stream, limit, recpos, plaintext);
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
    __finally2 {}
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

        check_status(dir);

#if defined DEBUG
        if (istraceable(trace_category_net)) {
            trace_debug_event(trace_category_net, trace_event_tls_record, [&](basic_stream& dbs) -> void {
                tls_advisor* advisor = tls_advisor::get_instance();

                dbs.println("\e[1;35m > %s\e[0m", constexpr_alert);
                dbs.println(" > %s %i %s", constexpr_level, level, advisor->nameof_tls_alert_level(level).c_str());
                dbs.println(" > %s %i %s", constexpr_desc, desc, advisor->nameof_tls_alert_desc(desc).c_str());
            });
        }
#endif
    }
    __finally2 {}
    return ret;
}

return_t tls_record_alert::do_write_body(tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;
    binary_append(bin, get_level());
    binary_append(bin, get_desc());
    return ret;
}

bool tls_record_alert::apply_protection() { return true; }

tls_record_alert& tls_record_alert::set(uint8 level, uint8 desc) {
    _level = level;
    _desc = desc;
    return *this;
}

void tls_record_alert::operator<<(tls_record* record) {
    if (record) {
        if (tls_content_type_alert == record->get_type()) {
            tls_record_alert* alert = (tls_record_alert*)record;
            set(alert->get_level(), alert->get_desc());
        }
        record->release();
    }
}

uint8 tls_record_alert::get_level() const { return _level; }

uint8 tls_record_alert::get_desc() const { return _desc; }

void tls_record_alert::check_status(tls_direction_t dir) {
    if ((tls_alertlevel_warning == get_level()) && (tls_alertdesc_close_notify == get_desc())) {
        auto session = get_session();
        if (from_client == dir) {
            session->update_session_status(session_status_client_close_notified);
        } else if (from_server == dir) {
            session->update_session_status(session_status_server_close_notified);
        }
    }
}

}  // namespace net
}  // namespace hotplace
