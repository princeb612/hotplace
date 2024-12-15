/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLSSPEC_TYPES__
#define __HOTPLACE_SDK_NET_TLSSPEC_TYPES__

#include <sdk/base/system/types.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

/* RFC 8446 5.  Record Protocol */
enum tls_content_type_t : uint8 {
    tls_content_type_invalid = 0,
    tls_content_type_change_cipher_spec = 20,  // 0x14
    tls_content_type_alert = 21,               // 0x15
    tls_content_type_handshake = 22,           // 0x16
    tls_content_type_application_data = 23,    // 0x17
    tls_content_type_heartbeat = 24,           // 0x18
    tls_content_type_tls12_cid = 25,           // 0x19
    tls_content_type_ack = 26,                 // 0x20
};

#pragma pack(push, 1)
struct tls_content_t {
    tls_content_type_t type;
    uint16 version;
    uint16 length;  // 2^14
};
#pragma pack(pop)

enum tls_version_t {
    tls_13 = 0x0304,
    tls_12 = 0x0303,
    tls_11 = 0x0302,
    tls_10 = 0x0301,
    dtls_12 = 0xfefd,
};

/*
 * RFC 8446 4.  Handshake Protocol
 * RFC 5246 7.4.  Handshake Protocol
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */
enum tls_handshake_type_t : uint8 {
    tls_handshake_hello_request = 0,                // 0x00
    tls_handshake_client_hello = 1,                 // 0x01 CH
    tls_handshake_server_hello = 2,                 // 0x02 SH
    tls_handshake_new_session_ticket = 4,           // 0x04 NST
    tls_handshake_end_of_early_data = 5,            // 0x05
    tls_handshake_encrypted_extensions = 8,         // 0x08 EE
    tls_handshake_request_connection_id = 9,        //
    tls_handshake_new_connection_id = 10,           //
    tls_handshake_certificate = 11,                 // 0x0b CT
    tls_handshake_server_key_exchange = 12,         // 0x0c
    tls_handshake_certificate_request = 13,         // 0x0d CR
    tls_handshake_server_hello_done = 14,           // 0x0e
    tls_handshake_certificate_verify = 15,          // 0x0f
    tls_handshake_client_key_exchange = 16,         // 0x10
    tls_handshake_client_certificate_request = 17,  //
    tls_handshake_finished = 20,                    // 0x14
    tls_handshake_certificate_url = 21,             // 0x15
    tls_handshake_certificate_status = 22,          // 0x16
    tls_handshake_key_update = 24,                  // 0x18
    tls_handshake_compressed_certificate = 25,      //
    tls_handshake_message_hash = 254,               // 0xfe
};

/* RFC 8446 4.  Handshake Protocol */
#pragma pack(push, 1)
struct tls_handshake_t {
    tls_handshake_type_t msg_type;
    uint24_t length;
};
#pragma pack(pop)

/**
 * RFC 5246 7.2.  Alert Protocol
 * RFC 8446 6.  Alert Protocol
 */
enum tls_alertlevel_t : uint8 {
    tls_alertlevel_warning = 1,
    tls_alertlevel_fatal = 2,
};
enum tls_alertdesc_t : uint8 {
    tls_alertdesc_close_notify = 0,
    tls_alertdesc_unexpected_message = 10,
    tls_alertdesc_bad_record_mac = 20,
    tls_alertdesc_decryption_failed_RESERVED = 21,  // TLS 1.2
    tls_alertdesc_record_overflow = 22,
    tls_alertdesc_decompression_failure = 30,  // TLS 1.2
    tls_alertdesc_handshake_failure = 40,
    tls_alertdesc_no_certificate_RESERVED = 41,  // TLS 1.2
    tls_alertdesc_bad_certificate = 42,
    tls_alertdesc_unsupported_certificate = 43,
    tls_alertdesc_certificate_revoked = 44,
    tls_alertdesc_certificate_expired = 45,
    tls_alertdesc_certificate_unknown = 46,
    tls_alertdesc_illegal_parameter = 47,
    tls_alertdesc_unknown_ca = 48,
    tls_alertdesc_access_denied = 49,
    tls_alertdesc_decode_error = 50,
    tls_alertdesc_decrypt_error = 51,
    tls_alertdesc_export_restriction_RESERVED = 60,  // TLS 1.2
    tls_alertdesc_protocol_version = 70,
    tls_alertdesc_insufficient_security = 71,
    tls_alertdesc_internal_error = 80,
    tls_alertdesc_inappropriate_fallback = 86,
    tls_alertdesc_user_canceled = 90,
    tls_alertdesc_no_renegotiation = 100,  // TLS 1.2
    tls_alertdesc_missing_extension = 109,
    tls_alertdesc_unsupported_extension = 110,
    tls_alertdesc_unrecognized_name = 112,
    tls_alertdesc_bad_certificate_status_response = 113,
    tls_alertdesc_unknown_psk_identity = 115,
    tls_alertdesc_certificate_required = 116,
    tls_alertdesc_no_application_protocol = 120,
};

enum tls_extensions_t : uint16 {
    /* RFC 8446 4.2.  Extensions */
    tls_extension_server_name = 0,                             /* RFC 6066 */
    tls_extension_max_fragment_length = 1,                     /* RFC 6066 */
    tls_extension_status_request = 5,                          /* RFC 6066 */
    tls_extension_supported_groups = 10,                       /* RFC 8422, 7919 */
    tls_extension_signature_algorithms = 13,                   /* RFC 8446 */
    tls_extension_use_srtp = 14,                               /* RFC 5764 */
    tls_extension_heartbeat = 15,                              /* RFC 6520 */
    tls_extension_application_layer_protocol_negotiation = 16, /* RFC 7301 */
    tls_extension_alpn = 16,                                   // abbr.
    tls_extension_signed_certificate_timestamp = 18,           /* RFC 6962 */
    tls_extension_client_certificate_type = 19,                /* RFC 7250 */
    tls_extension_server_certificate_type = 20,                /* RFC 7250 */
    tls_extension_padding = 21,                                /* RFC 7685 */
    tls_extension_pre_shared_key = 41,                         /* RFC 8446 */
    tls_extension_early_data = 42,                             /* RFC 8446 */
    tls_extension_supported_versions = 43,                     /* RFC 8446 */
    tls_extension_cookie = 44,                                 /* RFC 8446 */
    tls_extension_psk_key_exchange_modes = 45,                 /* RFC 8446 */
    tls_extension_certificate_authorities = 47,                /* RFC 8446 */
    tls_extension_oid_filters = 48,                            /* RFC 8446 */
    tls_extension_post_handshake_auth = 49,                    /* RFC 8446 */
    tls_extension_signature_algorithms_cert = 50,              /* RFC 8446 */
    tls_extension_key_share = 51,                              /* RFC 8446 */
    /* RFC 9001 8.2.  QUIC Transport Parameters Extension */
    tls_extension_quic_transport_parameters = 57,  // RFC 9001, see quic_param_t
    // RFC 4366, 6066
    tls_extension_client_certificate_url = 2,  // RFC 4366
    tls_extension_trusted_ca_keys = 3,         // RFC 4366
    tls_extension_truncated_hmac = 4,          // RFC 4366
    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
    tls_extension_user_mapping = 6,             // RFC 4681
    tls_extension_ec_point_formats = 11,        // RFC 8422
    tls_extension_srp = 12,                     // RFC 5054
    tls_extension_status_request_v2 = 17,       // RFC 6961
    tls_extension_encrypt_then_mac = 22,        // RFC 7366
    tls_extension_extended_master_secret = 23,  // RFC 7627
    tls_extension_token_binding = 24,           // RFC 8472
    tls_extension_cached_info = 25,             // RFC 7924
    tls_extension_compress_certificate = 27,    // RFC 8879
    tls_extension_record_size_limit = 28,       // RFC 8449
    tls_extension_delegated_credential = 34,    // RFC 9345
    tls_extension_session_ticket = 35,          // RFC 5077, 8447
    tls_extension_TLMSP = 36,                   // extended master secret
    tls_extension_supported_ekt_ciphers = 39,   // RFC 8870
    tls_extension_transparency_info = 52,       // RFC 9162 Certificate Transparency Version 2.0
    tls_extension_external_id_hash = 55,        // RFC 8844
    tls_extension_external_session_id = 56,     // RFC 8844
    tls_extension_ticket_request = 58,          // RFC 9149 TLS Ticket Requests
    tls_extension_application_layer_protocol_settings = 17513,
    tls_extension_alps = 17513,
    tls_extension_encrypted_client_hello = 65037,
    tls_extension_renegotiation_info = 65281,  // RFC 5746 Transport Layer Security (TLS) Renegotiation Indication Extension
};

/**
 * tls_extension_supported_groups
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */
enum tls_named_curve_t : uint16 {
    // RFC 8446 4.2.7.  Supported Groups
    // RFC 8422 5.1.1.  Supported Elliptic Curves Extension
    // deprecated (1..22), reserved (0xFE00..0xFEFF), deprecated(0xFF01..0xFF02)

    /* Elliptic Curve Groups (ECDHE) */
    tls_named_curve_secp256r1 = 0x0017,
    tls_named_curve_secp384r1 = 0x0018,
    tls_named_curve_secp521r1 = 0x0019,
    tls_named_curve_x25519 = 0x001d,
    tls_named_curve_x448 = 0x001e,

    /* Finite Field Groups (DHE) */
    tls_named_curve_ffdhe2048 = 0x0100,
    tls_named_curve_ffdhe3072 = 0x0101,
    tls_named_curve_ffdhe4096 = 0x0102,
    tls_named_curve_ffdhe6144 = 0x0103,
    tls_named_curve_ffdhe8192 = 0x0104,

    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
};

/**
 * RFC 8446 4.2.3.  Signature Algorithms
 * tls_extension_signature_algorithms
 */
enum tls_signature_scheme_t : uint16 {
    /* RSASSA-PKCS1-v1_5 algorithms */
    tls_signature_scheme_rsa_pkcs1_sha256 = 0x0401,
    tls_signature_scheme_rsa_pkcs1_sha384 = 0x0501,
    tls_signature_scheme_rsa_pkcs1_sha512 = 0x0601,

    /* ECDSA algorithms */
    tls_signature_scheme_ecdsa_secp256r1_sha256 = 0x0403,
    tls_signature_scheme_ecdsa_secp384r1_sha384 = 0x0503,
    tls_signature_scheme_ecdsa_secp521r1_sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    tls_signature_scheme_rsa_pss_rsae_sha256 = 0x0804,
    tls_signature_scheme_rsa_pss_rsae_sha384 = 0x0805,
    tls_signature_scheme_rsa_pss_rsae_sha512 = 0x0806,

    /* EdDSA algorithms */
    tls_signature_scheme_ed25519 = 0x0807,
    tls_signature_scheme_ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    tls_signature_scheme_rsa_pss_pss_sha256 = 0x0809,
    tls_signature_scheme_rsa_pss_pss_sha384 = 0x080a,
    tls_signature_scheme_rsa_pss_pss_sha512 = 0x080b,

    /* Legacy algorithms */
    tls_signature_scheme_rsa_pkcs1_sha1 = 0x0201,
    tls_signature_scheme_ecdsa_sha1 = 0x0203,
};

struct tls_alert_t {
    tls_alertlevel_t level;
    tls_alertdesc_t desc;
};

/**
 * 15..8
 *    00 pre
 *    01 handshake
 *    02 application
 *    03 exporter
 *    04 resumption
 *    f0 userspace/usercontext
 * 7..6
 *    80 reserved
 *    40 reserved
 * 5..0
 */
#define TLS_SECRET 0x0000
#define TLS_SECRET_HANDSHAKE 0x0100
#define TLS_SECRET_APPLICATION 0x0200
#define TLS_SECRET_EXPORTER 0x0300
#define TLS_SECRET_RESUMPTION 0x0400
#define TLS_SECRET_USERCONTEXT 0xf000

#define TLS_SECRET_EARLY 0x0001
#define TLS_SECRET_CLIENT_MAC_KEY 0x0002
#define TLS_SECRET_SERVER_MAC_KEY 0x0003
#define TLS_SECRET_BINDER 0x0004
#define TLS_SECRET_DERIVED 0x0005
#define TLS_SECRET_MASTER 0x0006
#define TLS_SECRET_CLIENT 0x0007
#define TLS_SECRET_CLIENT_KEY 0x0008
#define TLS_SECRET_CLIENT_IV 0x0009
#define TLS_SECRET_SERVER 0x000a
#define TLS_SECRET_SERVER_KEY 0x000b
#define TLS_SECRET_SERVER_IV 0x000c
#define TLS_SECRET_CLIENT_QUIC_KEY 0x0011
#define TLS_SECRET_CLIENT_QUIC_IV 0x0012
#define TLS_SECRET_CLIENT_QUIC_HP 0x0013
#define TLS_SECRET_SERVER_QUIC_KEY 0x0014
#define TLS_SECRET_SERVER_QUIC_IV 0x0015
#define TLS_SECRET_SERVER_QUIC_HP 0x0016

enum tls_secret_t : uint16 {
    tls_secret_early_secret = (TLS_SECRET | TLS_SECRET_EARLY),
    tls_secret_master = (TLS_SECRET | TLS_SECRET_MASTER),
    tls_secret_client_mac_key = (TLS_SECRET | TLS_SECRET_CLIENT_MAC_KEY),
    tls_secret_server_mac_key = (TLS_SECRET | TLS_SECRET_SERVER_MAC_KEY),
    tls_secret_client_key = (TLS_SECRET | TLS_SECRET_CLIENT_KEY),
    tls_secret_client_iv = (TLS_SECRET | TLS_SECRET_CLIENT_IV),
    tls_secret_server_key = (TLS_SECRET | TLS_SECRET_SERVER_KEY),
    tls_secret_server_iv = (TLS_SECRET | TLS_SECRET_SERVER_IV),

    tls_secret_handshake_derived = (TLS_SECRET_HANDSHAKE | TLS_SECRET_DERIVED),
    tls_secret_handshake = (TLS_SECRET_HANDSHAKE | TLS_SECRET_MASTER),
    tls_secret_handshake_client = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT),
    tls_secret_handshake_server = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER),
    tls_secret_handshake_client_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_KEY),
    tls_secret_handshake_client_iv = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_IV),
    tls_secret_handshake_quic_client_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_QUIC_KEY),
    tls_secret_handshake_quic_client_iv = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_QUIC_IV),
    tls_secret_handshake_quic_client_hp = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_QUIC_HP),
    tls_secret_handshake_server_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_KEY),
    tls_secret_handshake_server_iv = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_IV),
    tls_secret_handshake_quic_server_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_QUIC_KEY),
    tls_secret_handshake_quic_server_iv = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_QUIC_IV),
    tls_secret_handshake_quic_server_hp = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_QUIC_HP),

    tls_secret_application_derived = (TLS_SECRET_APPLICATION | TLS_SECRET_DERIVED),
    tls_secret_application = (TLS_SECRET_APPLICATION | TLS_SECRET_MASTER),
    tls_secret_application_client = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT),
    tls_secret_application_server = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER),
    tls_secret_application_client_key = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_KEY),
    tls_secret_application_client_iv = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_IV),
    tls_secret_application_server_key = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_KEY),
    tls_secret_application_server_iv = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_IV),

    tls_secret_application_quic_client_key = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_QUIC_KEY),
    tls_secret_application_quic_client_iv = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_QUIC_IV),
    tls_secret_application_quic_client_hp = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_QUIC_HP),
    tls_secret_application_quic_server_key = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_QUIC_KEY),
    tls_secret_application_quic_server_iv = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_QUIC_IV),
    tls_secret_application_quic_server_hp = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_QUIC_HP),

    tls_secret_exporter_master = (TLS_SECRET_EXPORTER | TLS_SECRET_MASTER),

    tls_secret_resumption_binder = (TLS_SECRET_RESUMPTION | TLS_SECRET_BINDER),
    tls_secret_resumption_master = (TLS_SECRET_RESUMPTION | TLS_SECRET_MASTER),
    tls_secret_resumption = (TLS_SECRET_RESUMPTION),
    tls_secret_resumption_early = (TLS_SECRET_RESUMPTION | TLS_SECRET_EARLY),

    tls_context_shared_secret = (TLS_SECRET_USERCONTEXT | 0x01),
    tls_context_transcript_hash = (TLS_SECRET_USERCONTEXT | 0x02),
    tls_context_empty_hash = (TLS_SECRET_USERCONTEXT | 0x04),
    tls_context_client_hello = (TLS_SECRET_USERCONTEXT | 0x05),         // CH client_hello
    tls_context_server_hello = (TLS_SECRET_USERCONTEXT | 0x06),         // SH server_hello (handshake)
    tls_context_server_finished = (TLS_SECRET_USERCONTEXT | 0x07),      // F server finished (application, exporter)
    tls_context_client_finished = (TLS_SECRET_USERCONTEXT | 0x08),      // F client finished (resumption)
    tls_context_client_hello_random = (TLS_SECRET_USERCONTEXT | 0x09),  // CH client_hello (server_key_update)
    tls_context_server_hello_random = (TLS_SECRET_USERCONTEXT | 0x0a),  // SH server_hello (server_key_update)
    tls_context_server_key_exchange = (TLS_SECRET_USERCONTEXT | 0x0b),  // SKE server_key_exchange (pre_master_secret)
    tls_context_client_key_exchange = (TLS_SECRET_USERCONTEXT | 0x0c),  // CKE client_key_exchange (pre_master_secret)
};

enum tls_mode_t : uint8 {
    tls_mode_client = (1 << 0),
    tls_mode_server = (1 << 1),
    tls_mode_tls = (1 << 2),
    tls_mode_quic = (1 << 3),
};

// TODO
enum tls_role_t {
    role_server = 0,
    role_client = 1,
};

class tls_protection;
class tls_session;
class tls_advisor;

}  // namespace net
}  // namespace hotplace

#endif
