/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   types.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_NET_TLS_TYPES__
#define __HOTPLACE_SDK_NET_TLS_TYPES__

#include <hotplace/sdk/base/system/types.hpp>
#include <hotplace/sdk/net/types.hpp>

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
enum class tls_content_type_t : uint8 {
    unknown = 0,
    change_cipher_spec = 0x14,        // 20, RFC 2246
    alert = 0x15,                     // 21, RFC 2246
    handshake = 0x16,                 // 22, RFC 2246
    application_data = 0x17,          // 23, RFC 2246
    heartbeat = 0x18,                 // 24, RFC 6520, RFC 8446
    tls12_cid = 0x19,                 // 25, RFC 9146 0x19
    ack = 0x1a,                       // 26, RFC 9147 0x1a
    return_routability_check = 0x1b,  // draft-ietf-tls-dtls-rrc-10
};

/*
 * RFC 8446 4.  Handshake Protocol
 * RFC 5246 7.4.  Handshake Protocol
 * RFC 2246 7.4. Handshake protocol
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */
enum class tls_handshake_type_t : uint8 {
    certificate = 11,                 // 0x0b CT  RFC 2246
    certificate_request = 13,         // 0x0d CR  RFC 2246
    certificate_status = 22,          // 0x16     RFC 8446
    certificate_url = 21,             // 0x15     RFC 8446
    certificate_verify = 15,          // 0x0f     RFC 2246
    client_certificate_request = 17,  //
    client_hello = 1,                 // 0x01 CH  RFC 2246
    client_key_exchange = 16,         // 0x10     RFC 2246
    compressed_certificate = 25,      //
    ekt_key = 26,                     //
    encrypted_extensions = 8,         // 0x08 EE  RFC 8446
    end_of_early_data = 5,            // 0x05     RFC 8446
    finished = 20,                    // 0x14     RFC 2246
    hello_request = 0,                // 0x00     RFC 2246
    hello_retry_request = 6,          // 0x06     RFC 8446
    hello_verify_request = 3,         // 0x03     RFC 8446
    key_update = 24,                  // 0x18     RFC 8446
    message_hash = 254,               // 0xfe, server hello, RFC 8446 4.4.1.  The Transcript Hash
    new_connection_id = 10,           // 0x0a     RFC 9147
    new_session_ticket = 4,           // 0x04 NST RFC 8446
    request_connection_id = 9,        // 0x09     RFC 9147
    server_hello = 2,                 // 0x02 SH  RFC 2246
    server_hello_done = 14,           // 0x0e     RFC 2246
    server_key_exchange = 12,         // 0x0c     RFC 2246
    supplemental_data = 23,           // 0x17     RFC 8446
};

enum class tls_extension_type_t : uint16 {
    unknown = (uint16)-1,
    alpn = 0x0010,                                   // abbr.
    alps = 0x4469,                                   //
    application_layer_protocol_negotiation = alpn,   // RFC 7301
    application_layer_protocol_settings = alps,      //
    cached_info = 0x0019,                            // RFC 7924
    cert_type = 0x0009,                              //
    cert_with_extern_psk = 0x0021,                   //
    certificate_authorities = 0x002f,                // RFC 8446
    client_authz = 0x0007,                           //
    client_certificate_type = 0x0013,                // RFC 7250
    client_certificate_url = 0x0002,                 // RFC 4366
    compress_certificate = 0x001b,                   // RFC 8879
    connection_id = 0x0036,                          //
    cookie = 0x002c,                                 // RFC 8446
    delegated_credential = 0x0022,                   // RFC 9345
    dnssec_chain = 0x003b,                           //
    early_data = 0x002a,                             // RFC 8446
    ec_point_formats = 0x000b,                       // RFC 8422
    encrypt_then_mac = 0x0016,                       // RFC 7366
    encrypted_client_hello = 0xfe0d,                 //
    extended_master_secret = 0x0017,                 // RFC 7627
    external_id_hash = 0x0037,                       // RFC 8844
    external_session_id = 0x0038,                    // RFC 8844
    heartbeat = 0x000f,                              // RFC 6520
    key_share = 0x0033,                              // RFC 8446
    max_fragment_length = 0x0001,                    // RFC 6066
    next_protocol_negotiation = 0x3374,              //
    oid_filters = 0x0030,                            // RFC 8446
    padding = 0x0015,                                // RFC 7685
    password_salt = 0x001f,                          //
    post_handshake_auth = 0x0031,                    // RFC 8446
    pre_shared_key = 0x0029,                         // RFC 8446
    psk_key_exchange_modes = 0x002d,                 // RFC 8446
    pwd_clear = 0x001e,                              //
    pwd_protect = 0x001d,                            //
    quic_transport_parameters = 0x0039,              // RFC 9001, see quic_param_t
    record_size_limit = 0x001c,                      // RFC 8449
    renegotiation_info = 0xff01,                     // RFC 5746 Transport Layer Security (TLS) Renegotiation Indication Extension
    rrc = 0x003d,                                    //
    sequence_number_encryption_algorithms = 0x003c,  //
    server_authz = 0x0008,                           //
    server_certificate_type = 0x0014,                // RFC 7250
    server_name = 0x0000,                            // RFC 6066
    session_ticket = 0x0023,                         // RFC 5077, 8447
    signature_algorithms = 0x000d,                   // RFC 8446
    signature_algorithms_cert = 0x0032,              // RFC 8446
    signed_certificate_timestamp = 0x0012,           // RFC 6962
    sni = server_name,                               //
    srp = 0x000c,                                    // RFC 5054
    status_request = 0x0005,                         // RFC 6066
    status_request_v2 = 0x0011,                      // RFC 6961
    supported_ekt_ciphers = 0x0027,                  // RFC 8870
    supported_groups = 0x000a,                       // RFC 8422, 7919
    supported_versions = 0x002b,                     // RFC 8446
    ticket_pinning = 0x0020,                         //
    ticket_request = 0x003a,                         // RFC 9149 TLS Ticket Requests
    tlmsp = 0x0024,                                  // extended master secret
    tlmsp_delegate = 0x0026,                         //
    tlmsp_proxying = 0x0025,                         //
    tls_flags = 0x003e,                              //
    token_binding = 0x0018,                          // RFC 8472
    transparency_info = 0x0034,                      // RFC 9162 Certificate Transparency Version 2.0
    truncated_hmac = 0x0004,                         // RFC 4366
    trusted_ca_keys = 0x0003,                        // RFC 4366
    use_srtp = 0x000e,                               // RFC 5764
    user_mapping = 0x0006,                           // RFC 4681
    tls_lts = 0x001a,                                //
    connection_id_deprecated = 0x0035,               //
    ech_outer_extensions = 0xfd00,                   //
};

#define TLS_CONTENT_TYPE_MASK_CIPHERTEXT 0x20

#pragma pack(push, 1)
struct tls_header {
    tls_content_type_t type;
    uint16 version;
    uint16 length;
};
struct dtls_header {
    tls_content_type_t type;
    uint16 version;
    uint16 keyepoch;
    byte_t recordseq[6];
    uint16 length;
};
union tls_content_t {
    tls_header tls;
    dtls_header dtls;
};
#pragma pack(pop)

enum tls_version_t : uint16 {
    unknown = 0,       // internal
    draft = 1,         // internal
    tls_13 = 0x0304,   // RFC 8446
    tls_12 = 0x0303,   // RFC 5246
    tls_11 = 0x0302,   // RFC 4346
    tls_10 = 0x0301,   // RFC 2246
    dtls_13 = 0xfefc,  // RFC 6347
    dtls_12 = 0xfefd,  // RFC 9147
    dtls_11 = 0xfefe,
    dtls_10 = 0xfeff,
};

/* RFC 8446 4.  Handshake Protocol */
#pragma pack(push, 1)
struct tls_handshake_t {
    tls_handshake_type_t msg_type;
    byte_t length[3];
};
struct dtls_handshake_t {
    tls_handshake_type_t msg_type;
    byte_t length[3];
    uint16 seq;
    byte_t fragment_offset[3];
    byte_t fragment_len[3];
};
#pragma pack(pop)

/**
 * RFC 2246 7.2. Alert protocol
 * RFC 5246 7.2.  Alert Protocol
 * RFC 8446 6.  Alert Protocol
 */
enum class tls_alertlevel_t : uint8 {
    unknown = 0,
    warning = 1,
    fatal = 2,
};
enum class tls_alertdesc_t : uint8 {
    unknown = (uint8)-1,
    close_notify = 0,                       // RFC 2246, RFC 5246 7.2.1. Closure alerts
    unexpected_message = 10,                // RFC 2246
    bad_record_mac = 20,                    // RFC 2246
    decryption_failed = 21,                 // RFC 2246
    record_overflow = 22,                   // RFC 2246
    decompression_failure = 30,             // RFC 2246
    handshake_failure = 40,                 // RFC 2246
    no_certificate = 41,                    // RFC 5246
    bad_certificate = 42,                   // RFC 2246
    unsupported_certificate = 43,           // RFC 2246
    certificate_revoked = 44,               // RFC 2246
    certificate_expired = 45,               // RFC 2246
    certificate_unknown = 46,               // RFC 2246
    illegal_parameter = 47,                 // RFC 2246
    unknown_ca = 48,                        // RFC 2246
    access_denied = 49,                     // RFC 2246
    decode_error = 50,                      // RFC 2246
    decrypt_error = 51,                     // RFC 2246
    too_many_cids_requested = 52,           //
    export_restriction = 60,                // RFC 2246
    protocol_version = 70,                  // RFC 2246
    insufficient_security = 71,             // RFC 2246
    internal_error = 80,                    // RFC 2246
    inappropriate_fallback = 86,            // RFC 8446
    user_canceled = 90,                     // RFC 2246
    no_renegotiation = 100,                 // RFC 2246
    missing_extension = 109,                // RFC 8446
    unsupported_extension = 110,            // RFC 5246
    certificate_unobtainable = 111,         //
    unrecognized_name = 112,                // RFC 8446
    bad_certificate_status_response = 113,  // RFC 8446
    bad_certificate_hash_value = 114,       //
    unknown_psk_identity = 115,             // RFC 8446
    certificate_required = 116,             // RFC 8446
    no_application_protocol = 120,          // RFC 8446
    ech_required = 121,                     //
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

    /* TLS_SECRET_USERCONTEXT+0 ~ TLS_SECRET_USERCONTEXT+0xff */
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
    tls_context_session_id = (TLS_SECRET_USERCONTEXT | 0x0d),               //
    tls_context_cookie = (TLS_SECRET_USERCONTEXT | 0x0e),                   //
    tls_context_nonce_explicit = (TLS_SECRET_USERCONTEXT | 0x0f),           //
    tls_context_alpn = (TLS_SECRET_USERCONTEXT | 0x11),                     //
    tls_context_client_verifydata = (TLS_SECRET_USERCONTEXT | 0x12),        //
    tls_context_server_verifydata = (TLS_SECRET_USERCONTEXT | 0x13),        //
    tls_context_segment = (TLS_SECRET_USERCONTEXT | 0x1a),                  //
    tls_context_fragment = (TLS_SECRET_USERCONTEXT | 0x1b),                 // DTLS Handshake, QUIC FRAME CRYPTO
    tls_context_new_session_ticket = (TLS_SECRET_USERCONTEXT | 0x1d),       // RFC 8446 4.6.1. ticket
    tls_context_resumption_binder_key = (TLS_SECRET_USERCONTEXT | 0x21),    // CH 0-RTT
    tls_context_resumption_finished_key = (TLS_SECRET_USERCONTEXT | 0x22),  // CH 0-RTT
    tls_context_resumption_finished = (TLS_SECRET_USERCONTEXT | 0x23),      // CH 0-RTT
    tls_context_resumption_binder_hash = (TLS_SECRET_USERCONTEXT | 0x24),   // CH 0-RTT
    tls_context_quic_dcid = (TLS_SECRET_USERCONTEXT | 0x31),                //
    tls_context_client_cid = (TLS_SECRET_USERCONTEXT | 0x32),               //
    tls_context_server_cid = (TLS_SECRET_USERCONTEXT | 0x33),               //
    tls_context_dtls_cookie = (TLS_SECRET_USERCONTEXT | 0x34),              // network_session level
    tls_context_stateless_reset_token = (TLS_SECRET_USERCONTEXT | 0x35),    //
};

/**
 * @brief direction
 * @remarks
 *          | tls_direction_t       | quic_stream_id_t        |
 *          | client_initiated_bidi | quic_stream_client_bidi |
 *          | server_initiated_bidi | quic_stream_server_bidi |
 *          | client_initiated_uni  | quic_stream_client_uni  |
 *          | server_initiated_uni  | quic_stream_server_uni  |
 */
enum tls_direction_t {
    from_any = 0,
    from_client = 1,                     // client-initiated, uni-directional (client -> server)
    from_server = 2,                     // server-initiated, uni-directional (server -> client)
    client_initiated_uni = from_client,  // RFC 9000 2.1. 0x00
    server_initiated_uni = from_server,  // RFC 9000 2.1. 0x01
    client_initiated_bidi = 3,           // RFC 9000 2.1. client-initiated, bi-directional 0x02
    server_initiated_bidi = 4,           // RFC 9000 2.1. server-initiated, bi-directional 0x03
};

bool is_anydirection(tls_direction_t dir);
bool is_unidirection(tls_direction_t dir);
bool is_bidirection(tls_direction_t dir);
bool is_clientinitiated(tls_direction_t dir);
bool is_serverinitiated(tls_direction_t dir);

enum tls_flow_t {
    tls_flow_1rtt = 0,
    tls_flow_0rtt = 1,                 // TLS 1.3
    tls_flow_hello_retry_request = 2,  // TLS 1.3
    tls_flow_renegotiation = 3,        // TLS 1.2
};

/**
 * @brief record number (TLS, DTLS), packet number (QUIC)
 * @remarks
 *          TLS, DTLS
 *          RFC 9000 12.3.  Packet Numbers
 *          |           | space                  | cryptographic separation | protection space       |
 *          | TLS, DTLS | N/A                    | N/A                      | protection_default     |
 *          | QUIC      | initial space          | initial packets          | protection_initial     |
 *          | QUIC      | handshake space        | handshake packets        | protection_handshake   |
 *          | QUIC      | application data space | 0-RTT and 1-RTT packets  | protection_application |
 */
enum protection_space_t : uint8 {
    protection_default = 0,
    protection_initial = 1,
    protection_handshake = 2,
    protection_application = 3,
};

enum session_status_t : uint32 {
    session_status_client_hello = (1 << 0),           // 00000001
    session_status_server_hello = (1 << 1),           // 00000002
    session_status_hello_verify_request = (1 << 2),   // 00000004
    session_status_encrypted_extensions = (1 << 3),   // 00000008
    session_status_server_cert = (1 << 4),            // 00000010
    session_status_server_key_exchange = (1 << 5),    // 00000020
    session_status_server_hello_done = (1 << 6),      // 00000040 tls_handshake_type_t::server_hello_done
    session_status_server_cert_verified = (1 << 7),   // 00000080 tls_handshake_certificate_verify
    session_status_client_key_exchange = (1 << 8),    // 00000100
    session_status_client_cert = (1 << 9),            // 00000200
    session_status_client_cert_verified = (1 << 10),  // 00000400
    session_status_server_finished = (1 << 11),       // 00000800 tls_handshake_finished
    session_status_client_finished = (1 << 12),       // 00001000 tls_handshake_finished
    session_status_client_close_notified = 0x40000000,
    session_status_server_close_notified = 0x80000000,
};

enum tls_internal_flag_t : uint32 {
    dont_control_dtls_sequence = (1 << 0),
    dont_control_dtls_handshake_sequence = (1 << 1),
};

class dtls_record_arrange;
class dtls_record_publisher;
class quic_packet_publisher;
class quic_session;
class sslkeylog_exporter;
class sslkeylog_importer;
class tls_advisor;
class tls_protection;
class tls_session;

}  // namespace net
}  // namespace hotplace

#endif
