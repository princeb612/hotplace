/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/net/tls/quic/types.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

const tls_version_hint_t tls_version_hint[] = {
    {tls_13, tls_13, 1, flag_kindof_tls, "TLS v1.3"},  //
    {tls_12, tls_12, 1, flag_kindof_tls, "TLS v1.2"},  // RFC 5246 A.1.  Record Layer
    {tls_11, tls_11, 0, flag_kindof_tls, "TLS v1.1"},  // RFC 4346 A.1. Record Layer
    {tls_10, tls_10, 0, flag_kindof_tls, "TLS v1.0"},  // RFC 2246 A.1. Record layer
    {dtls_13, tls_13, 1, 0, "DTLS 1.3"},               //
    {dtls_12, tls_12, 1, 0, "DTLS 1.2"},               //
    {dtls_11, tls_11, 0, 0, "DTLS 1.1"},               //
    {dtls_10, tls_10, 0, 0, "DTLS 1.0"},               //
};
const size_t sizeof_tls_version_hint = RTL_NUMBER_OF(tls_version_hint);

define_tls_variable(session_status_code) = {
    {session_status_client_hello, "client_hello"},
    {session_status_server_hello, "server_hello"},
    {session_status_hello_verify_request, "hello_verify_request"},
    {session_status_server_cert, "server_certificate"},
    {session_status_server_key_exchange, "server_key_exchange"},
    {session_status_server_hello_done, "server_hello_done"},
    {session_status_server_cert_verified, "server_certificate_verified"},
    {session_status_client_key_exchange, "client_key_exchange"},
    {session_status_server_finished, "server_finished"},
    {session_status_client_finished, "client_finished"},
    {session_status_client_close_notified, "client_close_notify"},
    {session_status_server_close_notified, "server_close_notify"},
};
define_tls_sizeof_variable(session_status_code);

define_tls_variable(secret_code) = {
    {tls_secret_early_secret, "secret_early_secret"},
    {tls_secret_master, "secret_master"},
    {tls_secret_client_mac_key, "secret_client_mac_key"},
    {tls_secret_server_mac_key, "secret_server_mac_key"},
    {tls_secret_client_key, "secret_client_key"},
    {tls_secret_client_iv, "secret_client_iv"},
    {tls_secret_server_key, "secret_server_key"},
    {tls_secret_server_iv, "secret_server_iv"},
    {tls_secret_initial_quic, "secret_initial_quic"},
    {tls_secret_initial_quic_client, "secret_initial_quic_client"},
    {tls_secret_initial_quic_server, "secret_initial_quic_server"},
    {tls_secret_initial_quic_client_key, "secret_initial_quic_client_key"},
    {tls_secret_initial_quic_server_key, "secret_initial_quic_server_key"},
    {tls_secret_initial_quic_client_iv, "secret_initial_quic_client_iv"},
    {tls_secret_initial_quic_server_iv, "secret_initial_quic_server_iv"},
    {tls_secret_initial_quic_client_hp, "secret_initial_quic_client_hp"},
    {tls_secret_initial_quic_server_hp, "secret_initial_quic_server_hp"},
    {tls_secret_handshake_derived, "secret_handshake_derived"},
    {tls_secret_handshake, "secret_handshake"},
    {tls_secret_c_hs_traffic, "secret_c_hs_traffic"},
    {tls_secret_s_hs_traffic, "secret_s_hs_traffic"},
    {tls_secret_handshake_client_key, "secret_handshake_client_key"},
    {tls_secret_handshake_server_key, "secret_handshake_server_key"},
    {tls_secret_handshake_client_iv, "secret_handshake_client_iv"},
    {tls_secret_handshake_server_iv, "secret_handshake_server_iv"},
    {tls_secret_handshake_client_sn_key, "secret_handshake_client_sn_key"},
    {tls_secret_handshake_server_sn_key, "secret_handshake_server_sn_key"},
    {tls_secret_handshake_quic_client_key, "secret_handshake_quic_client_key"},
    {tls_secret_handshake_quic_server_key, "secret_handshake_quic_server_key"},
    {tls_secret_handshake_quic_client_iv, "secret_handshake_quic_client_iv"},
    {tls_secret_handshake_quic_server_iv, "secret_handshake_quic_server_iv"},
    {tls_secret_handshake_quic_client_hp, "secret_handshake_quic_client_hp"},
    {tls_secret_handshake_quic_server_hp, "secret_handshake_quic_server_hp"},
    {tls_secret_c_e_traffic, "secret_c_e_traffic"},
    {tls_secret_c_e_traffic_key, "secret_c_e_traffic_key"},
    {tls_secret_c_e_traffic_iv, "secret_c_e_traffic_iv"},
    {tls_secret_application_derived, "secret_application_derived"},
    {tls_secret_application, "secret_application"},
    {tls_secret_c_ap_traffic, "secret_c_ap_traffic"},
    {tls_secret_s_ap_traffic, "secret_s_ap_traffic"},
    {tls_secret_application_client_key, "secret_application_client_key"},
    {tls_secret_application_server_key, "secret_application_server_key"},
    {tls_secret_application_client_iv, "secret_application_client_iv"},
    {tls_secret_application_server_iv, "secret_application_server_iv"},
    {tls_secret_application_client_sn_key, "secret_application_client_sn_key"},
    {tls_secret_application_server_sn_key, "secret_application_server_sn_key"},
    {tls_secret_application_quic_client_key, "secret_application_quic_client_key"},
    {tls_secret_application_quic_server_key, "secret_application_quic_server_key"},
    {tls_secret_application_quic_client_iv, "secret_application_quic_client_iv"},
    {tls_secret_application_quic_server_iv, "secret_application_quic_server_iv"},
    {tls_secret_application_quic_client_hp, "secret_application_quic_client_hp"},
    {tls_secret_application_quic_server_hp, "secret_application_quic_server_hp"},
    {tls_secret_exp_master, "secret_exp_master"},
    {tls_secret_e_exp_master, "secret_e_exp_master"},
    {tls_secret_res_master, "secret_res_master"},
    {tls_secret_resumption_master, "secret_resumption_master"},
    {tls_secret_resumption, "secret_resumption"},
    {tls_secret_resumption_early, "secret_resumption_early"},
    {tls_context_shared_secret, "context_shared_secret"},
    {tls_context_transcript_hash, "context_transcript_hash"},
    {tls_context_empty_hash, "context_empty_hash"},
    {tls_context_client_hello, "context_client_hello"},
    {tls_context_server_hello, "context_server_hello"},
    {tls_context_server_finished, "context_server_finished"},
    {tls_context_client_finished, "context_client_finished"},
    {tls_context_client_hello_random, "context_client_hello_random"},
    {tls_context_server_hello_random, "context_server_hello_random"},
    {tls_context_server_key_exchange, "context_server_key_exchange"},
    {tls_context_client_key_exchange, "context_client_key_exchange"},
    {tls_context_session_id, "context_session_id"},
    {tls_context_cookie, "context_cookie"},
    {tls_context_nonce_explicit, "context_nonce_explicit"},
    {tls_context_alpn, "context_alpn"},
    {tls_context_client_verifydata, "context_client_verifydata"},
    {tls_context_server_verifydata, "context_server_verifydata"},
    {tls_context_segment, "context_segment"},
    {tls_context_fragment, "context_fragment"},
    {tls_context_new_session_ticket, "context_new_session_ticket"},
    {tls_context_resumption_binder_key, "context_resumption_binder_key"},
    {tls_context_resumption_finished_key, "context_resumption_finished_key"},
    {tls_context_resumption_finished, "context_resumption_finished"},
    {tls_context_resumption_binder_hash, "context_resumption_binder_hash"},
    {tls_context_quic_dcid, "context_quic_dcid"},
    {tls_context_client_cid, "context_client_cid"},
    {tls_context_server_cid, "context_server_cid"},
    {tls_context_dtls_cookie, "context_dtls_cookie"},
};
define_tls_sizeof_variable(secret_code);

define_tls_variable(quic_stream_id_code) = {
    {quic_stream_client_bidi, "Client-Initiated, Bidirectional"},
    {quic_stream_server_bidi, "Server-Initiated, Bidirectional"},
    {quic_stream_client_uni, "Client-Initiated, Unidirectional"},
    {quic_stream_server_uni, "Server-Initiated, Unidirectional"},
};
define_tls_sizeof_variable(quic_stream_id_code);

define_tls_variable(protection_space_code) = {
    {protection_default, "default"},
    {protection_initial, "initial"},
    {protection_handshake, "handshake"},
    {protection_application, "application"},
};
define_tls_sizeof_variable(protection_space_code);

#if 0

enum tls_layer_t : uint8 {
    tls_layer_record = 1,
    tls_layer_handshake = 2,
    tls_layer_extension = 3,
    tls_layer_packet = 4,
    tls_layer_frame = 5,
};

struct tls_layer_hint_t {
    tls_layer_t layer;
    uint16 code;
    tls_version_t minver;
    tls_version_t maxver;
    uint32 flags;
};

/*
 * minver or maxver
 *   if new feature fill minver
 *   if deprecated feature fill maxver
 */
const tls_layer_hint_t tls_layer_hint[] = {
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    // TLS HandshakeType

    {tls_layer_handshake, tls_hs_hello_request, tls_10, tls_12},           // RFC 2246, 5246
    {tls_layer_handshake, tls_hs_client_hello},                            // RFC 2246, 5246, 8446
    {tls_layer_handshake, tls_hs_server_hello},                            // RFC 2246, 5246, 8446
    {tls_layer_handshake, tls_hs_hello_verify_request, dtls_12, dtls_13},  // RFC 6347, 9147
    {tls_layer_handshake, tls_hs_new_session_ticket, tls_13, tls_13},      // RFC 8446
    {tls_layer_handshake, tls_hs_end_of_early_data},                       // RFC 8446
    {tls_layer_handshake, tls_hs_hello_retry_request},                     // RFC 9147 reserved
    {tls_layer_handshake, tls_hs_encrypted_extensions, tls_13, tls_13},    // RFC 8446
    {tls_layer_handshake, tls_hs_request_connection_id},                   // RFC 9147
    {tls_layer_handshake, tls_hs_new_connection_id},                       // RFC 9147
    {tls_layer_handshake, tls_hs_certificate, tls_10, tls_13},             // RFC 2246
    {tls_layer_handshake, tls_hs_server_key_exchange, tls_10, tls_12},     // RFC 2246, 5246
    {tls_layer_handshake, tls_hs_certificate_request, tls_10, tls_13},     // RFC 2246, 5246, 8446
    {tls_layer_handshake, tls_hs_server_hello_done, tls_10, tls_12},       // RFC 2246, 5246
    {tls_layer_handshake, tls_hs_certificate_verify, tls_10, tls_13},      // RFC 2246, 5246, 8446
    {tls_layer_handshake, tls_hs_client_key_exchange, tls_10, tls_12},     // RFC 2246, 5246
    {tls_layer_handshake, tls_hs_certificate_request, tls_10, tls_13},     // RFC 2246, 5246, 8446
    {tls_layer_handshake, tls_hs_finished, tls_10, tls_13},                // RFC 2246, 5246, 8446
    {tls_layer_handshake, tls_hs_certificate_url},                         // RFC 8446 reserved
    {tls_layer_handshake, tls_hs_certificate_status},                      // RFC 8446 reserved
    {tls_layer_handshake, tls_hs_supplemental_data},                       // RFC 8446 reserved
    {tls_layer_handshake, tls_hs_key_update, tls_13, tls_13},              // RFC 8446
    {tls_layer_handshake, tls_hs_compressed_certificate},                  //
    {tls_layer_handshake, tls_hs_ekt_key},                                 //

    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    // TLS ExtensionType Values

    {tls_layer_extension, tls1_ext_server_name},                            // RFC 6066, 8446, 9261
    {tls_layer_extension, tls1_ext_max_fragment_length},                    // RFC 6066, 8446, 8449
    {tls_layer_extension, tls1_ext_client_certificate_url},                 // RFC 6066
    {tls_layer_extension, tls1_ext_trusted_ca_keys},                        // RFC 6066
    {tls_layer_extension, tls1_ext_truncated_hmac},                         // RFC 6066
    {tls_layer_extension, tls1_ext_status_request},                         // RFC 8446
    {tls_layer_extension, tls1_ext_user_mapping},                           // RFC 4681
    {tls_layer_extension, tls1_ext_client_authz},                           // RFC 5878
    {tls_layer_extension, tls1_ext_server_authz},                           // RFC 5878
    {tls_layer_extension, tls1_ext_cert_type},                              // RFC 6091
    {tls_layer_extension, tls1_ext_supported_groups},                       // RFC 7919, 8422, 8446
    {tls_layer_extension, tls1_ext_ec_point_formats},                       // RFC 8422
    {tls_layer_extension, tls1_ext_srp},                                    // RFC 5054
    {tls_layer_extension, tls1_ext_signature_algorithms},                   // RFC 5246, 8446
    {tls_layer_extension, tls1_ext_use_srtp},                               // RFC 5764, 8446
    {tls_layer_extension, tls1_ext_heartbeat},                              // RFC 6520, 8446
    {tls_layer_extension, tls1_ext_alpn},                                   // RFC 7301, 8446
    {tls_layer_extension, tls1_ext_status_request_v2},                      // RFC 6961
    {tls_layer_extension, tls1_ext_signed_certificate_timestamp},           // RFC 6962, 8446
    {tls_layer_extension, tls1_ext_client_certificate_type},                // RFC 7250, 8446
    {tls_layer_extension, tls1_ext_server_certificate_type},                // RFC 7250, 8446
    {tls_layer_extension, tls1_ext_padding},                                // RFC 7685, 8446
    {tls_layer_extension, tls1_ext_encrypt_then_mac},                       // RFC 7366
    {tls_layer_extension, tls1_ext_extended_master_secret},                 // RFC 7627
    {tls_layer_extension, tls1_ext_token_binding},                          // RFC 8472
    {tls_layer_extension, tls1_ext_cached_info},                            // RFC 7924
    {tls_layer_extension, tls1_ext_compress_certificate},                   // RFC 8879
    {tls_layer_extension, tls1_ext_record_size_limit},                      // RFC 8449
    {tls_layer_extension, tls1_ext_pwd_protect},                            // RFC 8492
    {tls_layer_extension, tls1_ext_pwd_clear},                              // RFC 8492
    {tls_layer_extension, tls1_ext_password_salt},                          // RFC 8492
    {tls_layer_extension, tls1_ext_ticket_pinning},                         // RFC 8672
    {tls_layer_extension, tls1_ext_cert_with_extern_psk},                   // RFC 8773
    {tls_layer_extension, tls1_ext_delegated_credential},                   // RFC 9345
    {tls_layer_extension, tls1_ext_session_ticket},                         // RFC 5077, 8447
    {tls_layer_extension, tls1_ext_tlmsp},                                  //
    {tls_layer_extension, tls1_ext_tlmsp_proxying},                         //
    {tls_layer_extension, tls1_ext_tlmsp_delegate},                         //
    {tls_layer_extension, tls1_ext_supported_ekt_ciphers},                  // RFC 8870
    {tls_layer_extension, tls1_ext_pre_shared_key},                         // RFC 8446
    {tls_layer_extension, tls1_ext_early_data},                             // RFC 8446
    {tls_layer_extension, tls1_ext_supported_versions, tls_13, tls_13, 0},  // RFC 8446
    {tls_layer_extension, tls1_ext_cookie},                                 // RFC 8446
    {tls_layer_extension, tls1_ext_psk_key_exchange_modes},                 // RFC 8446
    {tls_layer_extension, tls1_ext_certificate_authorities},                // RFC 8446
    {tls_layer_extension, tls1_ext_oid_filters},                            // RFC 8446
    {tls_layer_extension, tls1_ext_post_handshake_auth},                    // RFC 8446
    {tls_layer_extension, tls1_ext_signature_algorithms_cert},              // RFC 8446
    {tls_layer_extension, tls1_ext_key_share, tls_13, tls_13},              // RFC 8446
    {tls_layer_extension, tls1_ext_transparency_info},                      // RFC 9162
    {tls_layer_extension, tls1_ext_connection_id},                          // RFC 9146
    {tls_layer_extension, tls1_ext_external_id_hash},                       // RFC 8844
    {tls_layer_extension, tls1_ext_external_session_id},                    // RFC 8844
    {tls_layer_extension, tls1_ext_quic_transport_parameters},              // RFC 9001
    {tls_layer_extension, tls1_ext_ticket_request},                         // RFC 9149
    {tls_layer_extension, tls1_ext_dnssec_chain},                           //
    {tls_layer_extension, tls1_ext_sequence_number_encryption_algorithms},  //
    {tls_layer_extension, tls1_ext_rrc},                                    //
    {tls_layer_extension, tls1_ext_tls_flags},                              //
    {tls_layer_extension, tls1_ext_next_protocol_negotiation},              //
    {tls_layer_extension, tls1_ext_alps},                                   //
    {tls_layer_extension, tls1_ext_encrypted_client_hello},                 //
    {tls_layer_extension, tls1_ext_renegotiation_info},                     //
};

#endif

}  // namespace net
}  // namespace hotplace
