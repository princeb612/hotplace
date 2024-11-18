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
#include <sdk/net/types.hpp>

namespace hotplace {
namespace net {

/* RFC 8446 5.  Record Protocol */
enum tls_content_type_t : uint8 {
    tls_content_type_invalid = 0,
    tls_content_type_change_cipher_spec = 20,
    tls_content_type_alert = 21,
    tls_content_type_handshake = 22,
    tls_content_type_application_data = 23,
};

struct tls_plaintext_t {
    tls_content_type_t type;
    uint16 version;
    uint16 length;  // 2^14
    const byte_t* fragment;
};

/*
 * RFC 8446 4.  Handshake Protocol
 * RFC 5246 7.4.  Handshake Protocol
 */
enum tls_handshaketype_t : uint8 {
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
struct tls_handshake_t {
    tls_handshaketype_t msg_type;
    uint24_t length;
};

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
    ls_extension_quic_transport_parameters = 57,
    // RFC 4366, 6066
    tls_extension_client_certificate_url = 2,  // RFC 4366
    tls_extension_trusted_ca_keys = 3,         // RFC 4366
    tls_extension_truncated_hmac = 4,          // RFC 4366
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

class tls_resource {
   public:
    static tls_resource* get_instance();
    ~tls_resource();

    std::string tls_version_string(uint16 code);
    std::string cipher_suite_string(uint16 code);
    std::string compression_method_string(uint8 code);
    std::string sni_nametype_string(uint16 code);
    std::string named_curve_string(uint16 code);
    std::string signature_scheme_string(uint16 code);

   protected:
    tls_resource();
    void load_resource();
    void load_tls_version();
    void load_cipher_suites();
    void load_named_curves();
    void load_signature_schemes();

    static tls_resource _instance;
    critical_section _lock;
    std::map<uint16, std::string> _tls_version;
    std::map<uint16, std::string> _cipher_suites;
    std::map<uint16, std::string> _named_curves;
    std::map<uint16, std::string> _signature_schemes;
    bool _load;
};

/**
 * @brief   dump
 * @param   stream_t* s [out]
 * @param   const byte_t* stream [in]
 * @param   size_t size [in]
 * @param   size_t& pos [inout]
 */
return_t tls_dump_record(stream_t* s, const byte_t* stream, size_t size, size_t& pos);
return_t tls_dump_handshake(stream_t* s, const byte_t* stream, size_t size, size_t& pos);

}  // namespace net
}  // namespace hotplace

#endif
