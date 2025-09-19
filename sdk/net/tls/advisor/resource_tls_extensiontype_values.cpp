/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

#define ENDOF_DATA

define_tls_variable(compression_alg_code) = {
    {1, "zlib"},
    {2, "brotli"},
    {3, "zstd"},
};
define_tls_sizeof_variable(compression_alg_code);

define_tls_variable(cert_status_type_code) = {
    {1, "ocsp"},
    {2, "ocsp_multi_RESERVED"},
};
define_tls_sizeof_variable(cert_status_type_code);

define_tls_variable(cert_type_code) = {
    {0, "X509"},
    {1, "OpenPGP_RESERVED"},
    {2, "Raw Public Key"},
    {3, "1609Dot2"},
};
define_tls_sizeof_variable(cert_type_code);

define_tls_variable(extension_type_code) = {
    {0x0000, "server_name"},  // RFC 8446 9.2, RFC 6066
    {0x0001, "max_fragment_length"},
    {0x0002, "client_certificate_url"},
    {0x0003, "trusted_ca_keys"},
    {0x0004, "truncated_hmac"},
    {0x0005, "status_request"},
    {0x0006, "user_mapping"},
    {0x0007, "client_authz"},
    {0x0008, "server_authz"},
    {0x0009, "cert_type"},
    {0x000a, "supported_groups"},  // RFC 8446 4.2.7, 9.2 (renamed from "elliptic_curves")
    {0x000b, "ec_point_formats"},
    {0x000c, "srp"},
    {0x000d, "signature_algorithms"},  // RFC 8446 4.2.3, 9.2
    {0x000e, "use_srtp"},
    {0x000f, "heartbeat"},
    {0x0010, "application_layer_protocol_negotiation"},
    {0x0011, "status_request_v2"},
    {0x0012, "signed_certificate_timestamp"},
    {0x0013, "client_certificate_type"},
    {0x0014, "server_certificate_type"},
    {0x0015, "padding"},
    {0x0016, "encrypt_then_mac"},
    {0x0017, "extended_master_secret"},
    {0x0018, "token_binding"},
    {0x0019, "cached_info"},
    {0x001a, "tls_lts"},
    {0x001b, "compress_certificate"},
    {0x001c, "record_size_limit"},
    {0x001d, "pwd_protect"},
    {0x001e, "pwd_clear"},
    {0x001f, "password_salt"},
    {0x0020, "ticket_pinning"},
    {0x0021, "tls_cert_with_extern_psk"},
    {0x0022, "delegated_credential"},
    {0x0023, "session_ticket"},  // (renamed from "SessionTicket TLS")
    {0x0024, "TLMSP"},
    {0x0025, "TLMSP_proxying"},
    {0x0026, "TLMSP_delegate"},
    {0x0027, "supported_ekt_ciphers"},
    {0x0029, "pre_shared_key"},
    {0x002a, "early_data"},
    {0x002b, "supported_versions"},  // RFC 8446 4.2.1, 9.2
    {0x002c, "cookie"},              // RFC 8446 4.2.2, 9.2
    {0x002d, "psk_key_exchange_modes"},
    {0x002f, "certificate_authorities"},
    {0x0030, "oid_filters"},
    {0x0031, "post_handshake_auth"},
    {0x0032, "signature_algorithms_cert"},  // RFC 8446 4.2.3, 9.2
    {0x0033, "key_share"},                  // RFC 8446 4.2.8, 9.2
    {0x0034, "transparency_info"},
    {0x0035, "connection_id (deprecated)"},
    {0x0036, "connection_id"},
    {0x0037, "external_id_hash"},
    {0x0038, "external_session_id"},
    {0x0039, "quic_transport_parameters"},
    {0x003a, "ticket_request"},
    {0x003b, "dnssec_chain"},
    {0x003c, "sequence_number_encryption_algorithms"},
    {0x003d, "rrc"},
    {0x003e, "tls_flags"},
    {0x3374, "next_protocol_negotiation"},
    {0x4469, "application settings"},
    {0xfd00, "ech_outer_extensions"},
    {0xfe0d, "encrypted_client_hello"},
    {0xff01, "renegotiation_info"},
};
define_tls_sizeof_variable(extension_type_code);

}  // namespace net
}  // namespace hotplace
