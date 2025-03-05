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

#ifndef __HOTPLACE_SDK_NET_TLS_TYPES__
#define __HOTPLACE_SDK_NET_TLS_TYPES__

#include <sdk/base/system/types.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

/*
 * RFC 8446 5.  Record Protocol
 * RFC 9147 4.  The DTLS Record Layer
 *          0 1 2 3 4 5 6 7
 *          +-+-+-+-+-+-+-+-+
 *          |0|0|1|C|S|L|E E|
 *          DTLS 0x20..0x3F
 */
enum tls_content_type_t : uint8 {
    tls_content_type_invalid = 0,
    tls_content_type_change_cipher_spec = 0x14,  // 20, RFC 2246
    tls_content_type_alert = 0x15,               // 21, RFC 2246
    tls_content_type_handshake = 0x16,           // 22, RFC 2246
    tls_content_type_application_data = 0x17,    // 23, RFC 2246
    tls_content_type_heartbeat = 0x18,           // 24, RFC 6520, RFC 8446
    tls_content_type_tls12_cid = 0x19,           // 25
    tls_content_type_ack = 0x1a,                 // 26
};
#define TLS_CONTENT_TYPE_MASK_CIPHERTEXT 0x20

#pragma pack(push, 1)
union tls_content_t {
    struct {
        tls_content_type_t type;
        uint16 version;
        uint16 length;
    } tls;
    struct {
        tls_content_type_t type;
        uint16 version;
        uint16 keyepoch;
        byte_t recordseq[6];
        uint16 length;
    } dtls;
};
#pragma pack(pop)

enum tls_version_t : uint16 {
    tls_unknown = 0,   // internal
    tls_draft = 1,     // internal
    tls_13 = 0x0304,   // RFC 8446
    tls_12 = 0x0303,   // RFC 5246
    tls_11 = 0x0302,   // RFC 4346
    tls_10 = 0x0301,   // RFC 2246
    dtls_13 = 0xfefc,  // RFC 6347
    dtls_12 = 0xfefd,  // RFC 9147
};

/*
 * RFC 8446 4.  Handshake Protocol
 * RFC 5246 7.4.  Handshake Protocol
 * RFC 2246 7.4. Handshake protocol
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */
enum tls_hs_type_t : uint8 {
    tls_hs_hello_request = 0,                // 0x00     RFC 2246
    tls_hs_client_hello = 1,                 // 0x01 CH  RFC 2246
    tls_hs_server_hello = 2,                 // 0x02 SH  RFC 2246
    tls_hs_hello_verify_request = 3,         // 0x03     RFC 8446
    tls_hs_new_session_ticket = 4,           // 0x04 NST RFC 8446
    tls_hs_end_of_early_data = 5,            // 0x05     RFC 8446
    tls_hs_hello_retry_request = 6,          // 0x06     RFC 8446
    tls_hs_encrypted_extensions = 8,         // 0x08 EE  RFC 8446
    tls_hs_request_connection_id = 9,        // 0x09     RFC 9147
    tls_hs_new_connection_id = 10,           // 0x0a     RFC 9147
    tls_hs_certificate = 11,                 // 0x0b CT  RFC 2246
    tls_hs_server_key_exchange = 12,         // 0x0c     RFC 2246
    tls_hs_certificate_request = 13,         // 0x0d CR  RFC 2246
    tls_hs_server_hello_done = 14,           // 0x0e     RFC 2246
    tls_hs_certificate_verify = 15,          // 0x0f     RFC 2246
    tls_hs_client_key_exchange = 16,         // 0x10     RFC 2246
    tls_hs_client_certificate_request = 17,  //
    tls_hs_finished = 20,                    // 0x14     RFC 2246
    tls_hs_certificate_url = 21,             // 0x15     RFC 8446
    tls_hs_certificate_status = 22,          // 0x16     RFC 8446
    tls_hs_supplemental_data = 23,           // 0x17     RFC 8446
    tls_hs_key_update = 24,                  // 0x18     RFC 8446
    tls_hs_compressed_certificate = 25,      //
    tls_hs_message_hash = 254,               // 0xfe, server hello, RFC 8446 4.4.1.  The Transcript Hash
};

/* RFC 8446 4.  Handshake Protocol */
#pragma pack(push, 1)
struct tls_handshake_t {
    tls_hs_type_t msg_type;
    uint24_t length;
};
#pragma pack(pop)

/**
 * RFC 2246 7.2. Alert protocol
 * RFC 5246 7.2.  Alert Protocol
 * RFC 8446 6.  Alert Protocol
 */
enum tls_alertlevel_t : uint8 {
    tls_alertlevel_warning = 1,
    tls_alertlevel_fatal = 2,
};
enum tls_alertdesc_t : uint8 {
    tls_alertdesc_close_notify = 0,                       // RFC 2246, RFC 5246 7.2.1. Closure alerts
    tls_alertdesc_unexpected_message = 10,                // RFC 2246
    tls_alertdesc_bad_record_mac = 20,                    // RFC 2246
    tls_alertdesc_decryption_failed = 21,                 // RFC 2246
    tls_alertdesc_record_overflow = 22,                   // RFC 2246
    tls_alertdesc_decompression_failure = 30,             // RFC 2246
    tls_alertdesc_handshake_failure = 40,                 // RFC 2246
    tls_alertdesc_no_certificate = 41,                    // RFC 5246
    tls_alertdesc_bad_certificate = 42,                   // RFC 2246
    tls_alertdesc_unsupported_certificate = 43,           // RFC 2246
    tls_alertdesc_certificate_revoked = 44,               // RFC 2246
    tls_alertdesc_certificate_expired = 45,               // RFC 2246
    tls_alertdesc_certificate_unknown = 46,               // RFC 2246
    tls_alertdesc_illegal_parameter = 47,                 // RFC 2246
    tls_alertdesc_unknown_ca = 48,                        // RFC 2246
    tls_alertdesc_access_denied = 49,                     // RFC 2246
    tls_alertdesc_decode_error = 50,                      // RFC 2246
    tls_alertdesc_decrypt_error = 51,                     // RFC 2246
    tls_alertdesc_export_restriction = 60,                // RFC 2246
    tls_alertdesc_protocol_version = 70,                  // RFC 2246
    tls_alertdesc_insufficient_security = 71,             // RFC 2246
    tls_alertdesc_internal_error = 80,                    // RFC 2246
    tls_alertdesc_inappropriate_fallback = 86,            // RFC 8446
    tls_alertdesc_user_canceled = 90,                     // RFC 2246
    tls_alertdesc_no_renegotiation = 100,                 // RFC 2246
    tls_alertdesc_missing_extension = 109,                // RFC 8446
    tls_alertdesc_unsupported_extension = 110,            // RFC 5246
    tls_alertdesc_unrecognized_name = 112,                // RFC 8446
    tls_alertdesc_bad_certificate_status_response = 113,  // RFC 8446
    tls_alertdesc_unknown_psk_identity = 115,             // RFC 8446
    tls_alertdesc_certificate_required = 116,             // RFC 8446
    tls_alertdesc_no_application_protocol = 120,          // RFC 8446
};

enum tls1_ext_type_t : uint16 {
    tls1_ext_server_name = 0x0000,                             // RFC 6066
    tls1_ext_max_fragment_length = 0x0001,                     // RFC 6066
    tls1_ext_client_certificate_url = 0x0002,                  // RFC 4366
    tls1_ext_trusted_ca_keys = 0x0003,                         // RFC 4366
    tls1_ext_truncated_hmac = 0x0004,                          // RFC 4366
    tls1_ext_status_request = 0x0005,                          // RFC 6066
    tls1_ext_user_mapping = 0x0006,                            // RFC 4681
    tls1_ext_supported_groups = 0x000a,                        // RFC 8422, 7919
    tls1_ext_ec_point_formats = 0x000b,                        // RFC 8422
    tls1_ext_srp = 0x000c,                                     // RFC 5054
    tls1_ext_signature_algorithms = 0x000d,                    // RFC 8446
    tls1_ext_use_srtp = 0x000e,                                // RFC 5764
    tls1_ext_heartbeat = 0x000f,                               // RFC 6520
    tls1_ext_application_layer_protocol_negotiation = 0x0010,  // RFC 7301
    tls1_ext_alpn = 0x0010,                                    // abbr.
    tls1_ext_status_request_v2 = 0x0011,                       // RFC 6961
    tls1_ext_signed_certificate_timestamp = 0x0012,            // RFC 6962
    tls1_ext_client_certificate_type = 0x0013,                 // RFC 7250
    tls1_ext_server_certificate_type = 0x0014,                 // RFC 7250
    tls1_ext_padding = 0x0015,                                 // RFC 7685
    tls1_ext_encrypt_then_mac = 0x0016,                        // RFC 7366
    tls1_ext_extended_master_secret = 0x0017,                  // RFC 7627
    tls1_ext_token_binding = 0x0018,                           // RFC 8472
    tls1_ext_cached_info = 0x0019,                             // RFC 7924
    tls1_ext_compress_certificate = 0x001b,                    // RFC 8879
    tls1_ext_record_size_limit = 0x001c,                       // RFC 8449
    tls1_ext_delegated_credential = 0x0022,                    // RFC 9345
    tls1_ext_session_ticket = 0x0023,                          // RFC 5077, 8447
    tls1_ext_tlmsp = 0x0024,                                   // extended master secret
    tls1_ext_supported_ekt_ciphers = 0x0027,                   // RFC 8870
    tls1_ext_pre_shared_key = 0x0029,                          // RFC 8446
    tls1_ext_early_data = 0x002a,                              // RFC 8446
    tls1_ext_supported_versions = 0x002b,                      // RFC 8446
    tls1_ext_cookie = 0x002c,                                  // RFC 8446
    tls1_ext_psk_key_exchange_modes = 0x002d,                  // RFC 8446
    tls1_ext_certificate_authorities = 0x002f,                 // RFC 8446
    tls1_ext_oid_filters = 0x0030,                             // RFC 8446
    tls1_ext_post_handshake_auth = 0x0031,                     // RFC 8446
    tls1_ext_signature_algorithms_cert = 0x0032,               // RFC 8446
    tls1_ext_key_share = 0x0033,                               // RFC 8446
    tls1_ext_transparency_info = 0x0034,                       // RFC 9162 Certificate Transparency Version 2.0
    tls1_ext_external_id_hash = 0x0037,                        // RFC 8844
    tls1_ext_external_session_id = 0x0038,                     // RFC 8844
    tls1_ext_quic_transport_parameters = 0x0039,               // RFC 9001, see quic_param_t
    tls1_ext_ticket_request = 0x003a,                          // RFC 9149 TLS Ticket Requests
    tls1_ext_next_protocol_negotiation = 0x3374,
    tls1_ext_application_layer_protocol_settings = 0x4469,
    tls1_ext_alps = 0x4469,
    tls1_ext_encrypted_client_hello = 0xfe0d,
    tls1_ext_renegotiation_info = 0xff01,  // RFC 5746 Transport Layer Security (TLS) Renegotiation Indication Extension
};

/**
 * tls1_ext_supported_groups
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
 * tls1_ext_signature_algorithms
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
 *    00
 *    01 handshake
 *    02 application
 *    03 exporter
 *    04 resumption
 *    f0 userspace/usercontext
 * 7..6
 *    80 early
 *    40 reserved
 * 5..0
 *    assign
 */
#define TLS_SECRET 0x0000
#define TLS_SECRET_INITIAL 0x0100
#define TLS_SECRET_HANDSHAKE 0x0200
#define TLS_SECRET_APPLICATION 0x0300
#define TLS_SECRET_EXPORTER 0x0400
#define TLS_SECRET_RESUMPTION 0x0500
#define TLS_SECRET_USERCONTEXT 0xf000
#define TLS_SECRET_EARLY 0x0080

#define TLS_SECRET_CLIENT_MAC_KEY 0x0002
#define TLS_SECRET_SERVER_MAC_KEY 0x0003
#define TLS_SECRET_BINDER 0x0004
/**
 * derived, master, client, server
 */
#define TLS_SECRET_DERIVED 0x0005
#define TLS_SECRET_MASTER 0x0006
#define TLS_SECRET_CLIENT 0x0007
#define TLS_SECRET_SERVER 0x000a
/**
 * calcurate master (various)
 * secret_client_key = HKDF_Expand(hashalg, keysize, secret_client, "key", empty)
 * secret_client_iv  = HKDF_Expand(hashalg, ivsize,  secret_client, "iv",  empty)
 * secret_server_key = HKDF_Expand(hashalg, keysize, secret_server, "key", empty)
 * secret_server_iv  = HKDF_Expand(hashalg, ivsize,  secret_server, "iv",  empty)
 */
#define TLS_SECRET_CLIENT_KEY 0x0008
#define TLS_SECRET_CLIENT_IV 0x0009
#define TLS_SECRET_SERVER_KEY 0x000b
#define TLS_SECRET_SERVER_IV 0x000c
/**
 * DTLS "sn"
 * secret_client_sn = HKDF_Expand(hashalg, keysize, secret_client, "sn", empty)
 * secret_server_sn = HKDF_Expand(hashalg, keysize, secret_server, "sn", empty)
 */
#define TLS_SECRET_CLIENT_SN_KEY 0x000e
#define TLS_SECRET_SERVER_SN_KEY 0x000f
/**
 * QUIC "key", "iv", "hp" (headr protection)
 * secret_client_quic_key = HKDF_Expand(hashalg, keysize, secret_client, "quic key", empty)
 * secret_client_quic_iv  = HKDF_Expand(hashalg, ivsize,  secret_client, "quic iv",  empty)
 * secret_client_quic_hp  = HKDF_Expand(hashalg, keysize, secret_client, "quic hp",  empty)
 * secret_server_quic_key = HKDF_Expand(hashalg, keysize, secret_server, "quic key", empty)
 * secret_server_quic_iv  = HKDF_Expand(hashalg, ivsize,  secret_server, "quic iv",  empty)
 * secret_server_quic_hp  = HKDF_Expand(hashalg, keysize, secret_server, "quic hp",  empty)
 */
#define TLS_SECRET_CLIENT_QUIC_KEY 0x0011
#define TLS_SECRET_CLIENT_QUIC_IV 0x0012
#define TLS_SECRET_CLIENT_QUIC_HP 0x0013
#define TLS_SECRET_SERVER_QUIC_KEY 0x0014
#define TLS_SECRET_SERVER_QUIC_IV 0x0015
#define TLS_SECRET_SERVER_QUIC_HP 0x0016
#define TLS_SECRET_SERVER_QUIC_KU 0x0017

/**
 * @brief   secret
 * @see     openssl_kdf
 * @remarks
 *          ||                  concatenate
 *          empty               ""
 *          salt                00 (1)
 *          empty_hash          hash(hashalg, empty) = transcript_hash(hashalg, "")
 *          empty_ikm           00..00 (dlen)
 *          reshash             0000 (2)
 *          tls_label("label")  "tls13 " || label
 *                              "dtls13" || label
 *          shared_secret       DH, ECDH calculation
 *          context_hash        transcript_hash(handshake message)
 *          value(secret)       literally
 *          keysize             cipher key size
 *          ivsize              12
 */
enum tls_secret_t : uint16 {
    tls_secret_unknown = 0,

    // HKDF_Extract(hashalg, salt, empty_ikm)
    tls_secret_early_secret = (TLS_SECRET | TLS_SECRET_EARLY),
    // RFC 2246 6.3. Key calculation
    // RFC 5246 5.  HMAC and the Pseudorandom Function
    // key_block = PRF(SecurityParameters.master_secret,
    //                    "key expansion",
    //                    SecurityParameters.server_random +
    //                    SecurityParameters.client_random);
    //
    // client_write_MAC_secret[SecurityParameters.hash_size]
    // server_write_MAC_secret[SecurityParameters.hash_size]
    // client_write_key[SecurityParameters.key_material_length]
    // server_write_key[SecurityParameters.key_material_length]
    // client_write_IV[SecurityParameters.IV_size]
    // server_write_IV[SecurityParameters.IV_size]
    tls_secret_master = (TLS_SECRET_INITIAL | TLS_SECRET_MASTER),
    tls_secret_client_mac_key = (TLS_SECRET_INITIAL | TLS_SECRET_CLIENT_MAC_KEY),
    tls_secret_server_mac_key = (TLS_SECRET_INITIAL | TLS_SECRET_SERVER_MAC_KEY),
    tls_secret_client_key = (TLS_SECRET_INITIAL | TLS_SECRET_CLIENT_KEY),
    tls_secret_client_iv = (TLS_SECRET_INITIAL | TLS_SECRET_CLIENT_IV),
    tls_secret_server_key = (TLS_SECRET_INITIAL | TLS_SECRET_SERVER_KEY),
    tls_secret_server_iv = (TLS_SECRET_INITIAL | TLS_SECRET_SERVER_IV),

    tls_secret_initial_quic = (TLS_SECRET_INITIAL | TLS_SECRET_MASTER),
    tls_secret_initial_quic_client = (TLS_SECRET_INITIAL | TLS_SECRET_CLIENT),
    tls_secret_initial_quic_server = (TLS_SECRET_INITIAL | TLS_SECRET_SERVER),
    tls_secret_initial_quic_client_key = (TLS_SECRET_INITIAL | TLS_SECRET_CLIENT_QUIC_KEY),
    tls_secret_initial_quic_server_key = (TLS_SECRET_INITIAL | TLS_SECRET_SERVER_QUIC_KEY),
    tls_secret_initial_quic_client_iv = (TLS_SECRET_INITIAL | TLS_SECRET_CLIENT_QUIC_IV),
    tls_secret_initial_quic_server_iv = (TLS_SECRET_INITIAL | TLS_SECRET_SERVER_QUIC_IV),
    tls_secret_initial_quic_client_hp = (TLS_SECRET_INITIAL | TLS_SECRET_CLIENT_QUIC_HP),
    tls_secret_initial_quic_server_hp = (TLS_SECRET_INITIAL | TLS_SECRET_SERVER_QUIC_HP),

    // HKDF_Expand(hashalg, dlen, value(tls_secret_early_secret), tls_label("derived"), empty_hash)
    tls_secret_handshake_derived = (TLS_SECRET_HANDSHAKE | TLS_SECRET_DERIVED),
    // CLIENT_HANDSHAKE_TRAFFIC_SECRET, client_handshake_traffic_secret
    // HKDF_Extract(hashalg, value(tls_secret_handshake_derived), shared_secret)
    tls_secret_handshake = (TLS_SECRET_HANDSHAKE | TLS_SECRET_MASTER),
    tls_secret_c_hs_traffic = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT),
    tls_client_handshake_server = tls_secret_c_hs_traffic,
    client_handshake_traffic_secret = tls_secret_c_hs_traffic,
    // SERVER_HANDSHAKE_TRAFFIC_SECRET, server_handshake_traffic_secret
    // HKDF_Expand(hashalg, dlen, value(tls_secret_handshake), tls_label("c hs traffic"), context_hash)
    tls_secret_s_hs_traffic = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER),
    // HKDF_Expand(hashalg, dlen, value(tls_secret_handshake), tls_label("s hs traffic"), context_hash)
    tls_secret_handshake_server = tls_secret_s_hs_traffic,
    server_handshake_traffic_secret = tls_secret_s_hs_traffic,
    // HKDF_Expand(hashalg, keysize, value(tls_secret_c_hs_traffic), tls_label("key"), empty)
    tls_secret_handshake_client_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_KEY),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_s_hs_traffic), tls_label("key"), empty)
    tls_secret_handshake_server_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_KEY),
    // HKDF_Expand(hashalg, ivsize, value(tls_secret_c_hs_traffic), tls_label("iv"), empty)
    tls_secret_handshake_client_iv = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_IV),
    // HKDF_Expand(hashalg, ivsize, value(tls_secret_s_hs_traffic), tls_label("iv"), empty)
    tls_secret_handshake_server_iv = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_IV),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_c_hs_traffic), tls_label("sn"), empty)
    tls_secret_handshake_client_sn_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_SN_KEY),  // DTLS
    // HKDF_Expand(hashalg, keysize, value(tls_secret_s_hs_traffic), tls_label("sn"), empty)
    tls_secret_handshake_server_sn_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_SN_KEY),  // DTLS
    // HKDF_Expand(hashalg, keysize, value(tls_secret_c_hs_traffic), tls_label("quic key"), empty)
    tls_secret_handshake_quic_client_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_QUIC_KEY),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_s_hs_traffic), tls_label("quic key"), empty)
    tls_secret_handshake_quic_server_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_QUIC_KEY),
    // HKDF_Expand(hashalg, ivsize, value(tls_secret_c_hs_traffic), tls_label("quic iv"), empty)
    tls_secret_handshake_quic_client_iv = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_QUIC_IV),
    // HKDF_Expand(hashalg, ivsize, value(tls_secret_s_hs_traffic), tls_label("quic iv"), empty)
    tls_secret_handshake_quic_server_iv = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_QUIC_IV),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_c_hs_traffic), tls_label("quic hp"), empty)
    tls_secret_handshake_quic_client_hp = (TLS_SECRET_HANDSHAKE | TLS_SECRET_CLIENT_QUIC_HP),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_s_hs_traffic), tls_label("quic hp"), empty)
    tls_secret_handshake_quic_server_hp = (TLS_SECRET_HANDSHAKE | TLS_SECRET_SERVER_QUIC_HP),

    // HKDF_Expand(hashalg, dlen, value(tls_secret_resumption_early), tls_label("c e traffic"), context_hash)
    tls_secret_c_e_traffic = (TLS_SECRET_HANDSHAKE | TLS_SECRET_EARLY | TLS_SECRET_CLIENT),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_c_e_traffic), tls_label("key"), empty)
    tls_secret_c_e_traffic_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_EARLY | TLS_SECRET_CLIENT_KEY),
    // HKDF_Expand(hashalg, ivsize, value(tls_secret_c_e_traffic), tls_label("iv"), empty)
    tls_secret_c_e_traffic_iv = (TLS_SECRET_HANDSHAKE | TLS_SECRET_EARLY | TLS_SECRET_CLIENT_IV),

    // tls_secret_s_e_traffic = (TLS_SECRET_HANDSHAKE | TLS_SECRET_EARLY | TLS_SECRET_SERVER),
    // tls_secret_s_e_traffic_key = (TLS_SECRET_HANDSHAKE | TLS_SECRET_EARLY | TLS_SECRET_SERVER_KEY),
    // tls_secret_s_e_traffic_iv = (TLS_SECRET_HANDSHAKE | TLS_SECRET_EARLY | TLS_SECRET_SERVER_IV),

    // HKDF_Expand(hashalg, dlen, value(tls_secret_handshake), tls_label("derived"), empty_hash)
    tls_secret_application_derived = (TLS_SECRET_APPLICATION | TLS_SECRET_DERIVED),
    // HKDF_Extract(hashalg, value(tls_secret_application_derived), empty_ikm)
    tls_secret_application = (TLS_SECRET_APPLICATION | TLS_SECRET_MASTER),
    // CLIENT_TRAFFIC_SECRET_0, client_application_traffic_secret_0
    // HKDF_Expand(hashalg, dlen, value(tls_secret_application), "c ap traffic", context_hash)
    tls_secret_c_ap_traffic = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT),
    tls_secret_application_client = tls_secret_c_ap_traffic,
    client_application_traffic_secret_0 = tls_secret_c_ap_traffic,
    // SERVER_TRAFFIC_SECRET_0, server_application_traffic_secret_0
    // HKDF_Expand(hashalg, dlen, value(tls_secret_application), "s ap traffic", context_hash)
    tls_secret_s_ap_traffic = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER),
    tls_secret_application_server = tls_secret_s_ap_traffic,
    server_application_traffic_secret_0 = tls_secret_s_ap_traffic,
    // HKDF_Expand(hashalg, keysize, value(tls_secret_application_client), tls_label("key"), empty)
    tls_secret_application_client_key = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_KEY),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_application_server), tls_label("key"), empty)
    tls_secret_application_server_key = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_KEY),
    // HKDF_Expand(hashalg, ivsize, value(tls_secret_application_client), tls_label("iv"), empty)
    tls_secret_application_client_iv = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_IV),
    // HKDF_Expand(hashalg, ivsize, value(tls_secret_application_server), tls_label("iv"), empty)
    tls_secret_application_server_iv = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_IV),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_application_client), tls_label("sn"), empty)
    tls_secret_application_client_sn_key = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_SN_KEY),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_application_server), tls_label("sn"), empty)
    tls_secret_application_server_sn_key = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_SN_KEY),

    // HKDF_Expand(hashalg, keysize, value(tls_secret_application_client), tls_label("quic key"), empty)
    tls_secret_application_quic_client_key = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_QUIC_KEY),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_application_server), tls_label("quic key"), empty)
    tls_secret_application_quic_server_key = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_QUIC_KEY),
    // HKDF_Expand(hashalg, ivsize, value(tls_secret_application_client), tls_label("quic iv"), empty)
    tls_secret_application_quic_client_iv = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_QUIC_IV),
    // HKDF_Expand(hashalg, ivsize, value(tls_secret_application_server), tls_label("quic iv"), empty)
    tls_secret_application_quic_server_iv = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_QUIC_IV),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_application_client), tls_label("quic hp"), empty)
    tls_secret_application_quic_client_hp = (TLS_SECRET_APPLICATION | TLS_SECRET_CLIENT_QUIC_HP),
    // HKDF_Expand(hashalg, keysize, value(tls_secret_application_server), tls_label("quic hp"), empty)
    tls_secret_application_quic_server_hp = (TLS_SECRET_APPLICATION | TLS_SECRET_SERVER_QUIC_HP),

    // EXPORTER_SECRET, exporter_master_secret, secret_exporter_master
    // HKDF_Expand(hashalg, dlen, vale(tls_secret_application), tls_label("exp master", context_hash)
    tls_secret_exp_master = (TLS_SECRET_EXPORTER | TLS_SECRET_MASTER),
    tls_secret_exporter_master = tls_secret_exp_master,

    // HKDF_Expand(hashalg, dlen, value(tls_secret_resumption_early), "e exp master", context_hash)
    tls_secret_e_exp_master = (TLS_SECRET_EXPORTER | TLS_SECRET_EARLY | TLS_SECRET_MASTER),

    // tls_secret_resumption_binder = (TLS_SECRET_RESUMPTION | TLS_SECRET_BINDER),

    // HKDF_Expand(hashalg, dlen, value(tls_secret_application), tls_label("res master"), context_hash)
    tls_secret_res_master = (TLS_SECRET_RESUMPTION | TLS_SECRET_MASTER),  // secret_resumption_master
    tls_secret_resumption_master = tls_secret_res_master,
    // HKDF_Expand(hashalg, dlen, value(tls_secret_res_master), tls_label(resumption), reshash)
    tls_secret_resumption = (TLS_SECRET_RESUMPTION),
    // HKDF_Extract(hashalg, empty_ikm, value(tls_secret_resumption))
    tls_secret_resumption_early = (TLS_SECRET_RESUMPTION | TLS_SECRET_EARLY),

    tls_context_shared_secret = (TLS_SECRET_USERCONTEXT | 0x01),
    tls_context_transcript_hash = (TLS_SECRET_USERCONTEXT | 0x02),
    tls_context_empty_hash = (TLS_SECRET_USERCONTEXT | 0x04),
    tls_context_client_hello = (TLS_SECRET_USERCONTEXT | 0x05),             // CH client_hello
    tls_context_server_hello = (TLS_SECRET_USERCONTEXT | 0x06),             // SH server_hello (handshake)
    tls_context_server_finished = (TLS_SECRET_USERCONTEXT | 0x07),          // F server finished (application, exporter)
    tls_context_client_finished = (TLS_SECRET_USERCONTEXT | 0x08),          // F client finished (resumption)
    tls_context_client_hello_random = (TLS_SECRET_USERCONTEXT | 0x09),      // CH client_hello (server_key_update)
    tls_context_server_hello_random = (TLS_SECRET_USERCONTEXT | 0x0a),      // SH server_hello (server_key_update)
    tls_context_server_key_exchange = (TLS_SECRET_USERCONTEXT | 0x0b),      // SKE server_key_exchange (pre_master_secret)
    tls_context_client_key_exchange = (TLS_SECRET_USERCONTEXT | 0x0c),      // CKE client_key_exchange (pre_master_secret)
    tls_context_resumption_binder_key = (TLS_SECRET_USERCONTEXT | 0x0d),    // CH 0-RTT
    tls_context_resumption_finished_key = (TLS_SECRET_USERCONTEXT | 0x0e),  // CH 0-RTT
    tls_context_resumption_finished = (TLS_SECRET_USERCONTEXT | 0x0f),      // CH 0-RTT
    tls_context_resumption_binder_hash = (TLS_SECRET_USERCONTEXT | 0x10),   // CH 0-RTT

    tls_context_quic_dcid = (TLS_SECRET_USERCONTEXT | 0x11),
    tls_context_fragment = (TLS_SECRET_USERCONTEXT | 0x1b),  // DTLS, QUIC
};

enum tls_direction_t {
    from_any = 0,
    from_client = 1,  // client -> server
    from_server = 2,  // server -> client
};

enum tls_message_flow_t {
    tls_1_rtt = 0,
    tls_0_rtt = 1,
    tls_hello_retry_request = 2,
};

/**
 * @brief record number (TLS, DTLS), packet number (QUIC)
 * @remarks
 *          TLS, DTLS
 *          RFC 9000 12.3.  Packet Numbers
 *          | space                  |                         | level                  |
 *          | N/A                    | TLS, DTLS               | protection_default     |
 *          | initial space          | initial packets         | protection_initial     |
 *          | handshake space        | handshake packets       | protection_handshake   |
 *          | application data space | 0-RTT and 1-RTT packets | protection_application |
 */
enum protection_level_t : uint8 {
    protection_default = 0,
    protection_initial = 1,
    protection_handshake = 2,
    protection_application = 3,
};

class tls_protection;
class tls_session;
class tls_advisor;

}  // namespace net
}  // namespace hotplace

#endif
