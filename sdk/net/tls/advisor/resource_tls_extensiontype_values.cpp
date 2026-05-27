/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   resource_tls_extensiontype_values.cpp
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
    {tls_extension_type_t::server_name, "server_name"},  // RFC 8446 9.2, RFC 6066
    {tls_extension_type_t::max_fragment_length, "max_fragment_length"},
    {tls_extension_type_t::client_certificate_url, "client_certificate_url"},
    {tls_extension_type_t::trusted_ca_keys, "trusted_ca_keys"},
    {tls_extension_type_t::truncated_hmac, "truncated_hmac"},
    {tls_extension_type_t::status_request, "status_request"},
    {tls_extension_type_t::user_mapping, "user_mapping"},
    {tls_extension_type_t::client_authz, "client_authz"},
    {tls_extension_type_t::server_authz, "server_authz"},
    {tls_extension_type_t::cert_type, "cert_type"},
    {tls_extension_type_t::supported_groups, "supported_groups"},  // RFC 8446 4.2.7, 9.2 (renamed from "elliptic_curves")
    {tls_extension_type_t::ec_point_formats, "ec_point_formats"},
    {tls_extension_type_t::srp, "srp"},
    {tls_extension_type_t::signature_algorithms, "signature_algorithms"},  // RFC 8446 4.2.3, 9.2
    {tls_extension_type_t::use_srtp, "use_srtp"},
    {tls_extension_type_t::heartbeat, "heartbeat"},
    {tls_extension_type_t::alpn, "application_layer_protocol_negotiation"},
    {tls_extension_type_t::status_request_v2, "status_request_v2"},
    {tls_extension_type_t::signed_certificate_timestamp, "signed_certificate_timestamp"},
    {tls_extension_type_t::client_certificate_type, "client_certificate_type"},
    {tls_extension_type_t::server_certificate_type, "server_certificate_type"},
    {tls_extension_type_t::padding, "padding"},
    {tls_extension_type_t::encrypt_then_mac, "encrypt_then_mac"},
    {tls_extension_type_t::extended_master_secret, "extended_master_secret"},
    {tls_extension_type_t::token_binding, "token_binding"},
    {tls_extension_type_t::cached_info, "cached_info"},
    {tls_extension_type_t::tls_lts, "tls_lts"},
    {tls_extension_type_t::compress_certificate, "compress_certificate"},
    {tls_extension_type_t::record_size_limit, "record_size_limit"},
    {tls_extension_type_t::pwd_protect, "pwd_protect"},
    {tls_extension_type_t::pwd_clear, "pwd_clear"},
    {tls_extension_type_t::password_salt, "password_salt"},
    {tls_extension_type_t::ticket_pinning, "ticket_pinning"},
    {tls_extension_type_t::cert_with_extern_psk, "cert_with_extern_psk"},
    {tls_extension_type_t::delegated_credential, "delegated_credential"},
    {tls_extension_type_t::session_ticket, "session_ticket"},  // (renamed from "SessionTicket TLS")
    {tls_extension_type_t::tlmsp, "TLMSP"},
    {tls_extension_type_t::tlmsp_proxying, "TLMSP_proxying"},
    {tls_extension_type_t::tlmsp_delegate, "TLMSP_delegate"},
    {tls_extension_type_t::supported_ekt_ciphers, "supported_ekt_ciphers"},
    {tls_extension_type_t::pre_shared_key, "pre_shared_key"},
    {tls_extension_type_t::early_data, "early_data"},
    {tls_extension_type_t::supported_versions, "supported_versions"},  // RFC 8446 4.2.1, 9.2
    {tls_extension_type_t::cookie, "cookie"},                          // RFC 8446 4.2.2, 9.2
    {tls_extension_type_t::psk_key_exchange_modes, "psk_key_exchange_modes"},
    {tls_extension_type_t::certificate_authorities, "certificate_authorities"},
    {tls_extension_type_t::oid_filters, "oid_filters"},
    {tls_extension_type_t::post_handshake_auth, "post_handshake_auth"},
    {tls_extension_type_t::signature_algorithms_cert, "signature_algorithms_cert"},  // RFC 8446 4.2.3, 9.2
    {tls_extension_type_t::key_share, "key_share"},                                  // RFC 8446 4.2.8, 9.2
    {tls_extension_type_t::transparency_info, "transparency_info"},
    {tls_extension_type_t::connection_id_deprecated, "connection_id (deprecated)"},
    {tls_extension_type_t::connection_id, "connection_id"},
    {tls_extension_type_t::external_id_hash, "external_id_hash"},
    {tls_extension_type_t::external_session_id, "external_session_id"},
    {tls_extension_type_t::quic_transport_parameters, "quic_transport_parameters"},
    {tls_extension_type_t::ticket_request, "ticket_request"},
    {tls_extension_type_t::dnssec_chain, "dnssec_chain"},
    {tls_extension_type_t::sequence_number_encryption_algorithms, "sequence_number_encryption_algorithms"},
    {tls_extension_type_t::rrc, "rrc"},
    {tls_extension_type_t::tls_flags, "tls_flags"},
    {tls_extension_type_t::next_protocol_negotiation, "next_protocol_negotiation"},
    {tls_extension_type_t::alps, "application settings"},
    {tls_extension_type_t::ech_outer_extensions, "ech_outer_extensions"},
    {tls_extension_type_t::encrypted_client_hello, "encrypted_client_hello"},
    {tls_extension_type_t::renegotiation_info, "renegotiation_info"},
};
define_tls_sizeof_variable(extension_type_code);

}  // namespace net
}  // namespace hotplace
