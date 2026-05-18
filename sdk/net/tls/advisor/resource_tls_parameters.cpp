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
    {1, "warning"},
    {2, "fatal"},
};
define_tls_sizeof_variable(alert_level_code);

define_tls_variable(alert_code) = {
    {0, "close_notify"},
    {10, "unexpected_message"},
    {20, "bad_record_mac"},
    {21, "decryption_failed"},  // _RESERVED
    {22, "record_overflow"},
    {30, "decompression_failure"},  // _RESERVED
    {40, "handshake_failure"},
    {41, "no_certificate"},  // _RESERVED
    {42, "bad_certificate"},
    {43, "unsupported_certificate"},
    {44, "certificate_revoked"},
    {45, "certificate_expired"},
    {46, "certificate_unknown"},
    {47, "illegal_parameter"},
    {48, "unknown_ca"},
    {49, "access_denied"},
    {50, "decode_error"},
    {51, "decrypt_error"},
    {52, "too_many_cids_requested"},
    {60, "export_restriction"},  // _RESERVED
    {70, "protocol_version"},
    {71, "insufficient_security"},
    {80, "internal_error"},
    {86, "inappropriate_fallback"},
    {90, "user_canceled"},
    {100, "no_renegotiation"},  // _RESERVED
    {109, "missing_extension"},
    {110, "unsupported_extension"},
    {111, "certificate_unobtainable"},  // _RESERVED
    {112, "unrecognized_name"},
    {113, "bad_certificate_status_response"},
    {114, "bad_certificate_hash_value"},  // _RESERVED
    {115, "unknown_psk_identity"},
    {116, "certificate_required"},
    {120, "no_application_protocol"},
    {121, "ech_required"},
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
    {20, "change_cipher_spec"},        // RFC 8446
    {21, "alert"},                     // RFC 8446
    {22, "handshake"},                 // RFC 8446
    {23, "application_data"},          // RFC 8446
    {24, "heartbeat"},                 // RFC 6520
    {25, "tls12_cid"},                 // RFC 9146
    {26, "ack"},                       // RFC 9147
    {27, "return_routability_check"},  // draft-ietf-tls-dtls-rrc-10
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
    {1, "client_hello"},
    {2, "server_hello"},
    {3, "hello_verify_request"},
    {4, "new_session_ticket"},
    {5, "end_of_early_data"},
    {6, "hello_retry_request_RESERVED"},
    {8, "encrypted_extensions"},
    {9, "request_connection_id"},
    {10, "new_connection_id"},
    {11, "certificate"},
    {12, "server_key_exchange"},
    {13, "certificate_request"},
    {14, "server_hello_done"},
    {15, "certificate_verify"},
    {16, "client_key_exchange"},
    {17, "client_certificate_request"},
    {20, "finished"},
    {21, "certificate_url_RESERVED"},
    {22, "certificate_status_RESERVED"},
    {23, "supplemental_data_RESERVED"},
    {24, "key_update"},
    {25, "compressed_certificate"},
    {26, "ekt_key"},
    {254, "message_hash"},
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
