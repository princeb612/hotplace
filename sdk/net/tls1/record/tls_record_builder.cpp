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

#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_record.hpp>

namespace hotplace {
namespace net {

tls_record_builder::tls_record_builder() : _session(nullptr), _type(0) {}

tls_record_builder& tls_record_builder::set(tls_session* session) {
    _session = session;
    return *this;
}

tls_record_builder& tls_record_builder::set(uint8 type) {
    _type = type;
    return *this;
}

tls_record* tls_record_builder::build() {
    tls_record* record = nullptr;
    switch (get_type()) {
        case tls_content_type_change_cipher_spec: {
            __try_new_catch_only(record, new tls_record_change_cipher_spec(get_session()));
        } break;
        case tls_content_type_alert: {
            __try_new_catch_only(record, new tls_record_alert(get_session()));
        } break;
        case tls_content_type_handshake: {
            __try_new_catch_only(record, new tls_record_handshake(get_session()));
        } break;
        case tls_content_type_application_data: {
            __try_new_catch_only(record, new tls_application_data(get_session()));
        } break;
        case tls_content_type_ack: {
            __try_new_catch_only(record, new tls_record_ack(get_session()));
        } break;
        case tls_content_type_heartbeat:
        case tls_content_type_tls12_cid:
        default: {
            if (TLS_CONTENT_TYPE_MASK_CIPHERTEXT & get_type()) {
                // DTLS 1.3 Ciphertext
                __try_new_catch_only(record, new dtls13_ciphertext(get_type(), get_session()));
            } else {
                // TLS 1.2~, DTLS 1.3 Plaintext
                __try_new_catch_only(record, new tls_record_unknown(get_type(), get_session()));
            }
        } break;
    }
    return record;
}

tls_session* tls_record_builder::get_session() { return _session; }

uint8 tls_record_builder::get_type() { return _type; }

}  // namespace net
}  // namespace hotplace
