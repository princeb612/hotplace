/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

// keep single line
#define ENTRY(x, y) \
    { x, y }

define_tls_variable(cert_compression_algid_code) = {
    ENTRY(1, "zlib"),
    ENTRY(2, "brotli"),
    ENTRY(3, "zstd"),
};
define_tls_sizeof_variable(cert_compression_algid_code);

define_tls_variable(cert_status_type_code) = {
    ENTRY(1, "ocsp"),
    ENTRY(2, "ocsp_multi_RESERVED"),
};
define_tls_sizeof_variable(cert_status_type_code);

define_tls_variable(cert_type_code) = {
    ENTRY(0, "X509"),
    ENTRY(1, "OpenPGP_RESERVED"),
    ENTRY(2, "Raw Public Key"),
    ENTRY(3, "1609Dot2"),
};
define_tls_sizeof_variable(cert_type_code);

define_tls_variable(extension_type_code) = {
    ENTRY(0x0000, "server_name"),  // RFC 8446 9.2, RFC 6066
    ENTRY(0x0001, "max_fragment_length"),
    ENTRY(0x0002, "client_certificate_url"),
    ENTRY(0x0003, "trusted_ca_keys"),
    ENTRY(0x0004, "truncated_hmac"),
    ENTRY(0x0005, "status_request"),
    ENTRY(0x0006, "user_mapping"),
    ENTRY(0x0007, "client_authz"),
    ENTRY(0x0008, "server_authz"),
    ENTRY(0x0009, "cert_type"),
    ENTRY(0x000a, "supported_groups"),  // RFC 8446 4.2.7, 9.2 (renamed from "elliptic_curves")
    ENTRY(0x000b, "ec_point_formats"),
    ENTRY(0x000c, "srp"),
    ENTRY(0x000d, "signature_algorithms"),  // RFC 8446 4.2.3, 9.2
    ENTRY(0x000e, "use_srtp"),
    ENTRY(0x000f, "heartbeat"),
    ENTRY(0x0010, "application_layer_protocol_negotiation"),
    ENTRY(0x0011, "status_request_v2"),
    ENTRY(0x0012, "signed_certificate_timestamp"),
    ENTRY(0x0013, "client_certificate_type"),
    ENTRY(0x0014, "server_certificate_type"),
    ENTRY(0x0015, "padding"),
    ENTRY(0x0016, "encrypt_then_mac"),
    ENTRY(0x0017, "extended_master_secret"),
    ENTRY(0x0018, "token_binding"),
    ENTRY(0x0019, "cached_info"),
    ENTRY(0x001a, "tls_lts"),
    ENTRY(0x001b, "compress_certificate"),
    ENTRY(0x001c, "record_size_limit"),
    ENTRY(0x001d, "pwd_protect"),
    ENTRY(0x001e, "pwd_clear"),
    ENTRY(0x001f, "password_salt"),
    ENTRY(0x0020, "ticket_pinning"),
    ENTRY(0x0021, "tls_cert_with_extern_psk"),
    ENTRY(0x0022, "delegated_credential"),
    ENTRY(0x0023, "session_ticket"),  // (renamed from "SessionTicket TLS")
    ENTRY(0x0024, "TLMSP"),
    ENTRY(0x0025, "TLMSP_proxying"),
    ENTRY(0x0026, "TLMSP_delegate"),
    ENTRY(0x0027, "supported_ekt_ciphers"),
    ENTRY(0x0029, "pre_shared_key"),
    ENTRY(0x002a, "early_data"),
    ENTRY(0x002b, "supported_versions"),  // RFC 8446 4.2.1, 9.2
    ENTRY(0x002c, "cookie"),              // RFC 8446 4.2.2, 9.2
    ENTRY(0x002d, "psk_key_exchange_modes"),
    ENTRY(0x002f, "certificate_authorities"),
    ENTRY(0x0030, "oid_filters"),
    ENTRY(0x0031, "post_handshake_auth"),
    ENTRY(0x0032, "signature_algorithms_cert"),  // RFC 8446 4.2.3, 9.2
    ENTRY(0x0033, "key_share"),                  // RFC 8446 4.2.8, 9.2
    ENTRY(0x0034, "transparency_info"),
    ENTRY(0x0035, "connection_id (deprecated)"),
    ENTRY(0x0036, "connection_id"),
    ENTRY(0x0037, "external_id_hash"),
    ENTRY(0x0038, "external_session_id"),
    ENTRY(0x0039, "quic_transport_parameters"),
    ENTRY(0x003a, "ticket_request"),
    ENTRY(0x003b, "dnssec_chain"),
    ENTRY(0x003c, "sequence_number_encryption_algorithms"),
    ENTRY(0x003d, "rrc"),
    ENTRY(0x003e, "tls_flags"),
    ENTRY(0x4469, "application settings"),
    ENTRY(0xfd00, "ech_outer_extensions"),
    ENTRY(0xfe0d, "encrypted_client_hello"),
    ENTRY(0xff01, "renegotiation_info"),
};
define_tls_sizeof_variable(extension_type_code);

}  // namespace net
}  // namespace hotplace
