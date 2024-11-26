/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * studying
 *  RFC 8446
 *  RFC 5246
 *  -- RFC 8996 --
 *  RFC 4346
 *  RFC 2246
 *
 * RFC 8446 2.  Protocol Overview
 *
 *        Client                                           Server
 *
 * Key  ^ ClientHello
 * Exch | + key_share*
 *      | + signature_algorithms*
 *      | + psk_key_exchange_modes*
 *      v + pre_shared_key*       -------->
 *                                                   ServerHello  ^ Key
 *                                                  + key_share*  | Exch
 *                                             + pre_shared_key*  v
 *                                         {EncryptedExtensions}  ^  Server
 *                                         {CertificateRequest*}  v  Params
 *                                                {Certificate*}  ^
 *                                          {CertificateVerify*}  | Auth
 *                                                    {Finished}  v
 *                                <--------  [Application Data*]
 *      ^ {Certificate*}
 * Auth | {CertificateVerify*}
 *      v {Finished}              -------->
 *        [Application Data]      <------->  [Application Data]
 *
 *               +  Indicates noteworthy extensions sent in the
 *                  previously noted message.
 *
 *               *  Indicates optional or situation-dependent
 *                  messages/extensions that are not always sent.
 *
 *               {} Indicates messages protected using keys
 *                  derived from a [sender]_handshake_traffic_secret.
 *
 *               [] Indicates messages protected using keys
 *                  derived from [sender]_application_traffic_secret_N.
 *
 *                Figure 1: Message Flow for Full TLS Handshake
 */

#ifndef __HOTPLACE_SDK_NET_TLS_SPEC__
#define __HOTPLACE_SDK_NET_TLS_SPEC__

#include <sdk/base/system/critical_section.hpp>
#include <sdk/base/system/types.hpp>
#include <sdk/crypto/basic/crypto_key.hpp>
#include <sdk/crypto/crypto/crypto_hash.hpp>
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
};

struct tls_content_t {
    tls_content_type_t type;
    uint16 version;
    uint16 length;  // 2^14
};

/*
 * RFC 8446 4.  Handshake Protocol
 * RFC 5246 7.4.  Handshake Protocol
 */
enum tls_handshake_type_t : uint8 {
    // TLS 1.3
    tls_handshake_client_hello = 1,          // CH
    tls_handshake_server_hello = 2,          // SH
    tls_handshake_new_session_ticket = 4,    // NST
    tls_handshake_end_of_early_data = 5,     //
    tls_handshake_encrypted_extensions = 8,  // EE
    tls_handshake_certificate = 11,          // CT
    tls_handshake_certificate_request = 13,  // CR
    tls_handshake_certificate_verify = 15,   //
    tls_handshake_finished = 20,             //
    tls_handshake_key_update = 24,           //
    tls_handshake_message_hash = 254,        //
    // TLS 1.2
    tls_handshake_server_key_exchange = 12,
    tls_handshake_server_hello_done = 14,
    tls_handshake_client_key_exchange = 16,
    //
    tls_handshake_hello_request = 0,
    tls_handshake_certificate_url = 21,
    tls_handshake_certificate_status = 22,
};

/* RFC 8446 4.  Handshake Protocol */
#pragma pack(push, 1)
struct tls_handshake_t {
    tls_handshake_type_t msg_type;
    uint24_t length;
};
#pragma pack(pop)

enum tls_alertlevel_t : uint8 {
    tls_alertlevel_warning = 1,
    tls_alertlevel_fatal = 2,
};

enum tls_alertdesc_t : uint8 {
    tls_alertdesc_close_notify = 0,
    tls_alertdesc_unexpected_message = 10,
    tls_alertdesc_bad_record_mac = 20,
    tls_alertdesc_record_overflow = 22,
    tls_alertdesc_handshake_failure = 40,
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
    tls_alertdesc_protocol_version = 70,
    tls_alertdesc_insufficient_security = 71,
    tls_alertdesc_internal_error = 80,
    tls_alertdesc_inappropriate_fallback = 86,
    tls_alertdesc_user_canceled = 90,
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
    tls_extension_renegotiation_info = 65281,   // RFC 5746 Transport Layer Security (TLS) Renegotiation Indication Extension
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

enum tls_secret_t : uint16 {
    tls_secret_shared_secret = 1,
    tls_secret_hello_hash = 2,
    tls_secret_early_secret = 3,
    tls_secret_empty_hash = 4,
    tls_secret_handshake_derived = 0x20,
    tls_secret_handshake = 0x21,
    tls_secret_handshake_client = 0x22,
    tls_secret_handshake_server = 0x23,
    tls_secret_handshake_client_key = 0x24,
    tls_secret_handshake_client_iv = 0x25,
    tls_secret_handshake_quic_client_key = 0x26,
    tls_secret_handshake_quic_client_iv = 0x27,
    tls_secret_handshake_quic_client_hp = 0x28,
    tls_secret_handshake_client_finished = 0x29,
    tls_secret_handshake_server_key = 0x2a,
    tls_secret_handshake_server_iv = 0x2b,
    tls_secret_handshake_quic_server_key = 0x2c,
    tls_secret_handshake_quic_server_iv = 0x2d,
    tls_secret_handshake_quic_server_hp = 0x2e,
    tls_secret_handshake_server_finished = 0x2f,

    tls_secret_master_derived = 0x40,
    tls_secret_master = 0x41,
};

enum tls_mode_t : uint8 {
    tls_mode_tls = (1 << 0),
    tls_mode_quic = (1 << 1),
    tls_mode_client = (1 << 2),
    tls_mode_server = (1 << 3),
};

// studying ...
class tls_protection;
class tls_session;

class tls_protection {
   public:
    tls_protection(uint8 mode = -1);
    ~tls_protection();

    uint8 get_mode();

    // server_hello cipher_suite
    uint16 get_cipher_suite();
    void set_cipher_suite(uint16 alg);
    transcript_hash* begin_transcript_hash();
    transcript_hash* get_transcript_hash();

    crypto_key& get_cert();
    crypto_key& get_key();
    crypto_key& get_keyexchange();
    /**
     * @brief   calc
     * @remarks generate secrets related to tls_mode_t
     */
    return_t calc(tls_session* session);

    void get_item(tls_secret_t type, binary_t& item);
    const binary_t& get_item(tls_secret_t type);
    void set_item(tls_secret_t type, const binary_t& item);

    return_t build_iv(tls_session* session, tls_secret_t type, binary_t& iv);

    /**
     * @brief   AEAD
     */
    return_t decrypt(tls_session* session, const byte_t* stream, size_t size, binary_t& decrypted, size_t aadlen, binary_t& tag,
                     stream_t* debugstream = nullptr);
    /**
     * @brief   verify
     */
    return_t certificate_verify(tls_session* session, uint16 scheme, const binary_t& signature);

   private:
    uint8 _mode;  // see tls_mode_t
    uint16 _alg;
    transcript_hash* _transcript_hash;
    crypto_key _cert;
    crypto_key _key;
    crypto_key _keyexchange;  // psk_ke, psk_dhe_ke
    std::map<tls_secret_t, binary_t> _kv;
};

enum session_item_t {
    item_client_hello = 0,
    item_client_hello_keyshare = 1,
    item_server_hello = 2,
    item_server_certificate = 3,
};

class tls_session {
   public:
    tls_session();

    tls_protection& get_tls_protection();

    // IV
    uint64 get_sequence(bool inc = false);
    void inc_sequence();

    // hello_hash, certificate_verify
    void set(session_item_t type, const byte_t* begin, size_t size);
    void set(session_item_t type, const binary_t& item);
    const binary_t& get(session_item_t type);
    void erase(session_item_t type);

   protected:
    uint64 _seq;
    tls_protection _tls_protection;
    std::map<session_item_t, binary_t> _kv;
};

struct tls_alg_info_t {
    uint16 alg;
    crypt_algorithm_t cipher;
    crypt_mode_t mode;
    uint8 tagsize;
    hash_algorithm_t mac;
};

class tls_advisor {
   public:
    static tls_advisor* get_instance();
    ~tls_advisor();

    std::string content_type_string(uint8 type);
    std::string handshake_type_string(uint8 type);
    std::string tls_version_string(uint16 code);
    std::string tls_extension_string(uint16 code);
    std::string cipher_suite_string(uint16 code);
    const tls_alg_info_t* hintof_tls_algorithm(uint16 code);
    hash_algorithm_t hash_alg_of(uint16 code);
    std::string compression_method_string(uint8 code);

    // tls_extension_server_name 0x0000
    std::string sni_nametype_string(uint16 code);
    // tls_extension_supported_groups 0x000a
    std::string named_curve_string(uint16 code);
    // tls_extension_ec_point_formats 0x000b
    std::string ec_point_format_string(uint8 code);
    // tls_extension_signature_algorithms 0x000d
    std::string signature_scheme_string(uint16 code);
    // tls_extension_psk_key_exchange_modes 0x002d
    std::string psk_key_exchange_mode_string(uint8 mode);
    // tls_extension_quic_transport_parameters 0x0039
    std::string quic_param_string(uint16 code);

   protected:
    tls_advisor();
    void load_resource();
    void load_content_types();
    void load_handshake_types();
    void load_tls_version();
    void load_tls_extensions();
    void load_cipher_suites();
    void load_named_curves();
    void load_ec_point_formats();
    void load_signature_schemes();
    void load_psk_kems();
    void load_quic_param();

    static tls_advisor _instance;
    critical_section _lock;
    std::map<uint8, std::string> _content_types;
    std::map<uint8, std::string> _handshake_types;
    std::map<uint16, std::string> _tls_version;
    std::map<uint16, std::string> _tls_extensions;
    std::map<uint16, std::string> _cipher_suites;
    std::map<uint16, tls_alg_info_t*> _tls_alg_info;

    // tls_extension_supported_groups 0x000a
    std::map<uint16, std::string> _named_curves;
    // tls_extension_ec_point_formats 0x000b
    std::map<uint8, std::string> _ec_point_formats;
    // tls_extension_signature_algorithms 0x000d
    std::map<uint16, std::string> _signature_schemes;
    // tls_extension_psk_key_exchange_modes 0x0002d
    std::map<uint8, std::string> _psk_kem;
    // tls_extension_quic_transport_parameters 0x0039
    std::map<uint16, std::string> _quic_params;

    bool _load;
};

/**
 * @brief   dump
 * @param   stream_t* s [out]
 * @param   const byte_t* stream [in]
 * @param   size_t size [in]
 * @param   size_t& pos [inout]
 */
return_t tls_dump_record(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
return_t tls_dump_change_cipher_spec(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
return_t tls_dump_alert(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
return_t tls_dump_handshake(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
return_t tls_dump_application_data(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);
return_t tls_dump_extension(stream_t* s, tls_session* session, const byte_t* stream, size_t size, size_t& pos);

}  // namespace net
}  // namespace hotplace

#endif
