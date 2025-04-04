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

#include <sdk/net/tls/tls/record/dtls13_ciphertext.hpp>
#include <sdk/net/tls/tls/record/tls_record.hpp>
#include <sdk/net/tls/tls/record/tls_record_ack.hpp>
#include <sdk/net/tls/tls/record/tls_record_alert.hpp>
#include <sdk/net/tls/tls/record/tls_record_application_data.hpp>
#include <sdk/net/tls/tls/record/tls_record_builder.hpp>
#include <sdk/net/tls/tls/record/tls_record_change_cipher_spec.hpp>
#include <sdk/net/tls/tls/record/tls_record_handshake.hpp>
#include <sdk/net/tls/tls/record/tls_record_unknown.hpp>
#include <sdk/net/tls/tls_session.hpp>

namespace hotplace {
namespace net {

tls_record_builder::tls_record_builder() : _session(nullptr), _type(0), _dir(from_any), _construct(false) {}

tls_record_builder& tls_record_builder::set(tls_session* session) {
    _session = session;
    return *this;
}

tls_record_builder& tls_record_builder::set(uint8 type) {
    _type = type;
    return *this;
}

tls_record_builder& tls_record_builder::set(tls_direction_t dir) {
    _dir = dir;
    return *this;
}

tls_record_builder& tls_record_builder::construct() {
    _construct = true;
    return *this;
}

tls_record* tls_record_builder::build() {
    tls_record* record = nullptr;
    auto session = get_session();
    if (session) {
        switch (get_type()) {
            case tls_content_type_change_cipher_spec: {
                __try_new_catch_only(record, new tls_record_change_cipher_spec(session));
            } break;
            case tls_content_type_alert: {
                if (is_construct()) {
                    bool is_kind_of_tls = session->get_tls_protection().is_kindof_tls();
                    bool is_kind_of_tls13 = session->get_tls_protection().is_kindof_tls13();
                    bool apply_protection = session->get_session_info(get_direction()).apply_protection();
                    if (is_kind_of_tls13 && apply_protection) {
                        __try_new_catch_only(record, new tls_record_application_data(session));  // encapsulation
                    } else {
                        __try_new_catch_only(record, new tls_record_alert(session));
                    }
                } else {
                    __try_new_catch_only(record, new tls_record_alert(session));
                }
            } break;
            case tls_content_type_handshake: {
                if (is_construct()) {
                    bool is_kind_of_tls = session->get_tls_protection().is_kindof_tls();
                    bool is_kind_of_tls13 = session->get_tls_protection().is_kindof_tls13();
                    bool apply_protection = session->get_session_info(get_direction()).apply_protection();
                    if (is_kind_of_tls13 && apply_protection) {
                        __try_new_catch_only(record, new tls_record_application_data(session));  // encapsulation
                    } else {
                        __try_new_catch_only(record, new tls_record_handshake(session));
                    }
                } else {
                    __try_new_catch_only(record, new tls_record_handshake(session));
                }
            } break;
            case tls_content_type_application_data: {
                __try_new_catch_only(record, new tls_record_application_data(session));
            } break;
            case tls_content_type_ack: {
                __try_new_catch_only(record, new tls_record_ack(session));
            } break;
            case tls_content_type_heartbeat:
            case tls_content_type_tls12_cid:
            default: {
                if (TLS_CONTENT_TYPE_MASK_CIPHERTEXT & get_type()) {
                    // DTLS 1.3 Ciphertext
                    __try_new_catch_only(record, new dtls13_ciphertext(get_type(), session));
                } else {
                    // TLS 1.2~, DTLS 1.3 Plaintext
                    __try_new_catch_only(record, new tls_record_unknown(get_type(), session));
                }
            } break;
        }
    }
    return record;
}

tls_session* tls_record_builder::get_session() { return _session; }

uint8 tls_record_builder::get_type() { return _type; }

tls_direction_t tls_record_builder::get_direction() { return _dir; }

bool tls_record_builder::is_construct() { return _construct; }

}  // namespace net
}  // namespace hotplace
