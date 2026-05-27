/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   resource_tls_parameters.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

#define ENDOF_DATA

define_tls_variable(alert_level_code) = {
    {tls_alertlevel_t::warning, "warning"},
    {tls_alertlevel_t::fatal, "fatal"},
};
define_tls_sizeof_variable(alert_level_code);

define_tls_variable(alert_code) = {
    {tls_alertdesc_t::close_notify, "close_notify"},                                        // 0
    {tls_alertdesc_t::unexpected_message, "unexpected_message"},                            // 10
    {tls_alertdesc_t::bad_record_mac, "bad_record_mac"},                                    // 20
    {tls_alertdesc_t::decryption_failed, "decryption_failed"},                              // 21
    {tls_alertdesc_t::record_overflow, "record_overflow"},                                  // 22
    {tls_alertdesc_t::decompression_failure, "decompression_failure"},                      // 30
    {tls_alertdesc_t::handshake_failure, "handshake_failure"},                              // 40
    {tls_alertdesc_t::no_certificate, "no_certificate"},                                    // 41
    {tls_alertdesc_t::bad_certificate, "bad_certificate"},                                  // 42
    {tls_alertdesc_t::unsupported_certificate, "unsupported_certificate"},                  // 43
    {tls_alertdesc_t::certificate_revoked, "certificate_revoked"},                          // 44
    {tls_alertdesc_t::certificate_expired, "certificate_expired"},                          // 45
    {tls_alertdesc_t::certificate_unknown, "certificate_unknown"},                          // 46
    {tls_alertdesc_t::illegal_parameter, "illegal_parameter"},                              // 47
    {tls_alertdesc_t::unknown_ca, "unknown_ca"},                                            // 48
    {tls_alertdesc_t::access_denied, "access_denied"},                                      // 49
    {tls_alertdesc_t::decode_error, "decode_error"},                                        // 50
    {tls_alertdesc_t::decrypt_error, "decrypt_error"},                                      // 51
    {tls_alertdesc_t::too_many_cids_requested, "too_many_cids_requested"},                  // 52
    {tls_alertdesc_t::export_restriction, "export_restriction"},                            // 60
    {tls_alertdesc_t::protocol_version, "protocol_version"},                                // 70
    {tls_alertdesc_t::insufficient_security, "insufficient_security"},                      // 71
    {tls_alertdesc_t::internal_error, "internal_error"},                                    // 80
    {tls_alertdesc_t::inappropriate_fallback, "inappropriate_fallback"},                    // 86
    {tls_alertdesc_t::user_canceled, "user_canceled"},                                      // 90
    {tls_alertdesc_t::no_renegotiation, "no_renegotiation"},                                // 100
    {tls_alertdesc_t::missing_extension, "missing_extension"},                              // 109
    {tls_alertdesc_t::unsupported_extension, "unsupported_extension"},                      // 110
    {tls_alertdesc_t::certificate_unobtainable, "certificate_unobtainable"},                // 111
    {tls_alertdesc_t::unrecognized_name, "unrecognized_name"},                              // 112
    {tls_alertdesc_t::bad_certificate_status_response, "bad_certificate_status_response"},  // 113
    {tls_alertdesc_t::bad_certificate_hash_value, "bad_certificate_hash_value"},            // 114
    {tls_alertdesc_t::unknown_psk_identity, "unknown_psk_identity"},                        // 115
    {tls_alertdesc_t::certificate_required, "certificate_required"},                        // 116
    {tls_alertdesc_t::no_application_protocol, "no_application_protocol"},                  // 120
    {tls_alertdesc_t::ech_required, "ech_required"},                                        // 121
};
define_tls_sizeof_variable(alert_code);

define_tls_variable(client_cert_type_code) = {
    {1, "rsa_sign"},
    {2, "dss_sign"},
    {3, "rsa_fixed_dh"},
    {4, "dss_fixed_dh"},
    {5, "rsa_ephemeral_dh_RESERVED"},
    {6, "dss_ephemeral_dh_RESERVED"},
    {20, "fortezza_dms_RESERVED"},
    {64, "ecdsa_sign"},
    {65, "rsa_fixed_ecdh"},
    {66, "ecdsa_fixed_ecdh"},
    {67, "gost_sign256"},
    {68, "gost_sign512"},
};
define_tls_sizeof_variable(client_cert_type_code);

define_tls_variable(content_type_code) = {
    {tls_content_type_t::change_cipher_spec, "change_cipher_spec"},              // RFC 8446 0x14
    {tls_content_type_t::alert, "alert"},                                        // RFC 8446 0x15
    {tls_content_type_t::handshake, "handshake"},                                // RFC 8446 0x16
    {tls_content_type_t::application_data, "application_data"},                  // RFC 8446 0x17
    {tls_content_type_t::heartbeat, "heartbeat"},                                // RFC 6520 0x18
    {tls_content_type_t::tls12_cid, "tls12_cid"},                                // RFC 9146 0x19
    {tls_content_type_t::ack, "ack"},                                            // RFC 9147 0x1a
    {tls_content_type_t::return_routability_check, "return_routability_check"},  // draft-ietf-tls-dtls-rrc-10
};
define_tls_sizeof_variable(content_type_code);

define_tls_variable(ec_curve_type_code) = {
    {1, "explicit_prime"},  // RFC 8422
    {2, "explicit_char2"},  // RFC 8422
    {3, "named_curve"},     // RFC 8422
};
define_tls_sizeof_variable(ec_curve_type_code);

define_tls_variable(ec_point_format_code) = {
    {0, "uncompressed"},
    {1, "ansiX962_compressed_prime"},
    {2, "ansiX962_compressed_char2"},
};
define_tls_sizeof_variable(ec_point_format_code);

define_tls_variable(kdf_id_code) = {
    // RFC 9258 Table 1: TLS KDF Identifiers Registry
    {0x0001, "HKDF_SHA256"},
    {0x0002, "HKDF_SHA384"},
};
define_tls_sizeof_variable(kdf_id_code);

define_tls_variable(handshake_type_code) = {
    {tls_handshake_type_t::hello_request, "hello_request"},                            // 0
    {tls_handshake_type_t::client_hello, "client_hello"},                              // 1
    {tls_handshake_type_t::server_hello, "server_hello"},                              // 2
    {tls_handshake_type_t::hello_verify_request, "hello_verify_request"},              // 3
    {tls_handshake_type_t::new_session_ticket, "new_session_ticket"},                  // 4
    {tls_handshake_type_t::end_of_early_data, "end_of_early_data"},                    // 5
    {tls_handshake_type_t::hello_retry_request, "hello_retry_request_RESERVED"},       // 6
    {tls_handshake_type_t::encrypted_extensions, "encrypted_extensions"},              // 8
    {tls_handshake_type_t::request_connection_id, "request_connection_id"},            // 9
    {tls_handshake_type_t::new_connection_id, "new_connection_id"},                    // 10
    {tls_handshake_type_t::certificate, "certificate"},                                // 11
    {tls_handshake_type_t::server_key_exchange, "server_key_exchange"},                // 12
    {tls_handshake_type_t::certificate_request, "certificate_request"},                // 13
    {tls_handshake_type_t::server_hello_done, "server_hello_done"},                    // 14
    {tls_handshake_type_t::certificate_verify, "certificate_verify"},                  // 15
    {tls_handshake_type_t::client_key_exchange, "client_key_exchange"},                // 16
    {tls_handshake_type_t::client_certificate_request, "client_certificate_request"},  // 17
    {tls_handshake_type_t::finished, "finished"},                                      // 20
    {tls_handshake_type_t::certificate_url, "certificate_url_RESERVED"},               // 21
    {tls_handshake_type_t::certificate_status, "certificate_status_RESERVED"},         // 22
    {tls_handshake_type_t::supplemental_data, "supplemental_data_RESERVED"},           // 23
    {tls_handshake_type_t::key_update, "key_update"},                                  // 24
    {tls_handshake_type_t::compressed_certificate, "compressed_certificate"},          // 25
    {tls_handshake_type_t::ekt_key, "ekt_key"},                                        // 26
    {tls_handshake_type_t::message_hash, "message_hash"},                              // 254
};
define_tls_sizeof_variable(handshake_type_code);

define_tls_variable(hash_alg_code) = {
    {1, "md5"}, {2, "sha1"}, {3, "sha224"}, {4, "sha256"}, {5, "sha384"}, {6, "sha512"}, {8, "intrinsic"},
};
define_tls_sizeof_variable(hash_alg_code);

define_tls_variable(psk_keyexchange_code) = {
    {0, "psk_ke"},      // PSK-only key establishment
    {1, "psk_dhe_ke"},  // PSK with (EC)DHE key establishment
};
define_tls_sizeof_variable(psk_keyexchange_code);

define_tls_variable(sig_alg_code) = {
    {1, "rsa"}, {2, "dsa"}, {3, "ecdsa"}, {7, "ed25519"}, {8, "ed448"}, {64, "gostr34102012_256"}, {65, "gostr34102012_512"},
};
define_tls_sizeof_variable(sig_alg_code);

}  // namespace net
}  // namespace hotplace
