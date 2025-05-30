/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

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

/**
 * DO NOT USE if pri 0
 */
const tls_sig_scheme_t tls_sig_schemes[] = {
    {0x0201, 0, kty_rsa, crypt_sig_rsassa_pkcs15, NID_rsa, sig_sha1, "rsa_pkcs1_sha1"},                     // RFC 9155
    {0x0202, 0, kty_dh, crypt_sig_dsa, NID_dhKeyAgreement, sig_sha1, "dsa_sha1_RESERVED"},                  //
    {0x0203, 0, kty_ec, crypt_sig_ecdsa, 0, sig_sha1, "ecdsa_sha1"},                                        // RFC 9155
    {0x0301, 0, kty_rsa, crypt_sig_rsassa_pkcs15, NID_rsa, sig_sha224, "SHA224 RSA"},                       // bakward compatibility, wireshark
    {0x0302, 0, kty_dsa, crypt_sig_dsa, NID_dsa, sig_sha224, "SHA224 DSA"},                                 // bakward compatibility, wireshark
    {0x0303, 0, kty_ec, crypt_sig_ecdsa, 0, sig_sha224, "SHA224 ECDSA"},                                    // bakward compatibility, wireshark
    {0x0401, tls_flag_support, kty_rsa, crypt_sig_rsassa_pkcs15, NID_rsa, sig_sha256, "rsa_pkcs1_sha256"},  // RFC 8446 9.1 MUST
    {0x0402, 0, kty_dh, crypt_sig_dsa, NID_dhKeyAgreement, sig_sha256, "dsa_sha256_RESERVED"},              //
    {0x0403, tls_flag_support, kty_ec, crypt_sig_ecdsa, NID_X9_62_prime256v1, sig_sha256,
     "ecdsa_secp256r1_sha256"},  // RFC 8446 9.1 MUST, RFC 8446 11 Recommended
    {0x0420, 0, kty_rsa, crypt_sig_rsassa_pkcs15, NID_rsa, sig_sha256, "rsa_pkcs1_sha256_legacy"},
    {0x0501, 0, kty_rsa, crypt_sig_rsassa_pkcs15, NID_rsa, sig_sha384, "rsa_pkcs1_sha384"},
    {0x0502, 0, kty_dh, crypt_sig_dsa, NID_dhKeyAgreement, sig_sha384, "dsa_sha384_RESERVED"},
    {0x0503, tls_flag_support, kty_ec, crypt_sig_ecdsa, NID_secp384r1, sig_sha384, "ecdsa_secp384r1_sha384"},  // RFC 8446 11 Recommended
    {0x0520, 0, kty_rsa, crypt_sig_rsassa_pkcs15, NID_rsa, sig_sha384, "rsa_pkcs1_sha384_legacy"},
    {0x0601, 0, kty_rsa, crypt_sig_rsassa_pkcs15, NID_rsa, sig_sha512, "rsa_pkcs1_sha512"},
    {0x0602, 0, kty_dh, crypt_sig_dsa, NID_dhKeyAgreement, sig_sha512, "dsa_sha512_RESERVED"},
    {0x0603, 0, kty_ec, crypt_sig_ecdsa, NID_secp521r1, sig_sha512, "ecdsa_secp521r1_sha512"},
    {0x0620, 0, kty_rsa, crypt_sig_rsassa_pkcs15, NID_rsa, sig_sha512, "rsa_pkcs1_sha512_legacy"},
    {0x0704, 0, kty_unknown, crypt_sig_unknown, 0, sig_sha256, "eccsi_sha256"},
    {0x0705, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "iso_ibs1"},
    {0x0706, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "iso_ibs2"},
    {0x0707, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "iso_chinese_ibs"},
    {0x0708, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "sm2sig_sm3"},
    {0x0709, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_256a"},
    {0x070a, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_256b"},
    {0x070b, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_256c"},
    {0x070c, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_256d"},
    {0x070d, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_512a"},
    {0x070e, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_512b"},
    {0x070f, 0, kty_unknown, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_512c"},
    {0x0804, tls_flag_support, kty_rsa, crypt_sig_rsassa_pss, NID_rsa, sig_sha256, "rsa_pss_rsae_sha256"},  // RFC 8446 9.1 MUST, RFC 8446 11 Recommended
    {0x0805, tls_flag_support, kty_rsa, crypt_sig_rsassa_pss, NID_rsa, sig_sha384, "rsa_pss_rsae_sha384"},  // RFC 8446 9.1 MUST, RFC 8446 11 Recommended
    {0x0806, tls_flag_support, kty_rsa, crypt_sig_rsassa_pss, NID_rsa, sig_sha512, "rsa_pss_rsae_sha512"},  // RFC 8446 9.1 MUST, RFC 8446 11 Recommended
    {0x0807, tls_flag_support, kty_okp, crypt_sig_eddsa, NID_ED25519, sig_unknown, "ed25519"},              // RFC 8446 11 Recommended
    {0x0808, 0, kty_okp, crypt_sig_eddsa, NID_ED448, sig_unknown, "ed448"},                                 //
    {0x0809, tls_flag_support, kty_rsapss, crypt_sig_rsassa_pss, NID_rsassaPss, sig_sha256, "rsa_pss_pss_sha256"},  // RFC 8446 11 Recommended
    {0x080a, tls_flag_support, kty_rsapss, crypt_sig_rsassa_pss, NID_rsassaPss, sig_sha384, "rsa_pss_pss_sha384"},  // RFC 8446 11 Recommended
    {0x080b, tls_flag_support, kty_rsapss, crypt_sig_rsassa_pss, NID_rsassaPss, sig_sha512, "rsa_pss_pss_sha512"},  // RFC 8446 11 Recommended
    {0x081a, 0, kty_ec, crypt_sig_ecdsa, NID_brainpoolP256r1, sig_sha256, "ecdsa_brainpoolP256r1tls13_sha256"},
    {0x081b, 0, kty_ec, crypt_sig_ecdsa, NID_brainpoolP384r1, sig_sha384, "ecdsa_brainpoolP384r1tls13_sha384"},
    {0x081c, 0, kty_ec, crypt_sig_ecdsa, NID_brainpoolP512r1, sig_sha512, "ecdsa_brainpoolP512r1tls13_sha512"},
};
define_tls_sizeof_variable(sig_scheme);

const tls_group_t tls_groups[] = {
    // RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
    // ffdhe2048~ffdhe8192

    // sa. const hint_curve_t hint_curves[]

    {0x0001, tls_flag_support, kty_ec, NID_sect163k1, "sect163k1"},         // K-163, ansit163k1
    {0x0002, tls_flag_support, kty_ec, NID_sect163r1, "sect163r1"},         // ansit163r1
    {0x0003, tls_flag_support, kty_ec, NID_sect163r2, "sect163r2"},         // B-163, ansit163r2
    {0x0004, tls_flag_support, kty_ec, NID_sect193r1, "sect193r1"},         // ansit193r1
    {0x0005, tls_flag_support, kty_ec, NID_sect193r2, "sect193r2"},         // sect193r2
    {0x0006, tls_flag_support, kty_ec, NID_sect233k1, "sect233k1"},         // K-233, ansit233k1
    {0x0007, tls_flag_support, kty_ec, NID_sect233r1, "sect233r1"},         // B-233, ansit233r1
    {0x0008, tls_flag_support, kty_ec, NID_sect239k1, "sect239k1"},         // ansit239k1
    {0x0009, tls_flag_support, kty_ec, NID_sect283k1, "sect283k1"},         // K-283, ansit283k1
    {0x000a, tls_flag_support, kty_ec, NID_sect283r1, "sect283r1"},         // B-283, ansit283r1
    {0x000b, tls_flag_support, kty_ec, NID_sect409k1, "sect409k1"},         // K-409, ansit409k1
    {0x000c, tls_flag_support, kty_ec, NID_sect409r1, "sect409r1"},         // B-409, ansit409r1
    {0x000d, tls_flag_support, kty_ec, NID_sect571k1, "sect571k1"},         // K-571, ansit571k1
    {0x000e, tls_flag_support, kty_ec, NID_sect571r1, "sect571r1"},         // B-571, ansit571r1
    {0x000f, tls_flag_support, kty_ec, NID_secp160k1, "secp160k1"},         // ansip160k1
    {0x0010, tls_flag_support, kty_ec, NID_secp160r1, "secp160r1"},         // ansip160r1
    {0x0011, tls_flag_support, kty_ec, NID_secp160r2, "secp160r2"},         // ansip160r2
    {0x0012, tls_flag_support, kty_ec, NID_secp192k1, "secp192k1"},         // ansip192k1
    {0x0013, tls_flag_support, kty_ec, NID_X9_62_prime192v1, "secp192r1"},  // P-192, prime192v1
    {0x0014, tls_flag_support, kty_ec, NID_secp224k1, "secp224k1"},         // ansip224k1
    {0x0015, tls_flag_support, kty_ec, NID_secp224r1, "secp224r1"},         // ansip224r1
    {0x0016, tls_flag_support, kty_ec, NID_secp256k1, "secp256k1"},         // ansip256k1
    {0x0017, tls_flag_support, kty_ec, NID_X9_62_prime256v1, "secp256r1"},  // P-256, prime256v1, RFC 8446 9.1 MUST
    {0x0018, tls_flag_support, kty_ec, NID_secp384r1, "secp384r1"},         // P-384, ansip384r1
    {0x0019, tls_flag_support, kty_ec, NID_secp521r1, "secp521r1"},         // P-521, ansip521r1
    {0x001a, tls_flag_support, kty_ec, NID_brainpoolP256r1, "brainpoolP256r1"},
    {0x001b, tls_flag_support, kty_ec, NID_brainpoolP384r1, "brainpoolP384r1"},
    {0x001c, tls_flag_support, kty_ec, NID_brainpoolP512r1, "brainpoolP512r1"},
    {0x001d, tls_flag_support, kty_okp, NID_X25519, "x25519"},  // RFC 8446 8446 9.1 MUST
    {0x001e, tls_flag_support, kty_okp, NID_X448, "x448"},
    {0x001f, 0, kty_unknown, 0, "brainpoolP256r1tls13"},
    {0x0020, 0, kty_unknown, 0, "brainpoolP384r1tls13"},
    {0x0021, 0, kty_unknown, 0, "brainpoolP512r1tls13"},
    {0x0022, 0, kty_unknown, 0, "GC256A"},
    {0x0023, 0, kty_unknown, 0, "GC256B"},
    {0x0024, 0, kty_unknown, 0, "GC256C"},
    {0x0025, 0, kty_unknown, 0, "GC256D"},
    {0x0026, 0, kty_unknown, 0, "GC512A"},
    {0x0027, 0, kty_unknown, 0, "GC512B"},
    {0x0028, 0, kty_unknown, 0, "GC512C"},
    {0x0029, 0, kty_unknown, 0, "curveSM2"},
    {0x0100, tls_flag_support, kty_dh, NID_ffdhe2048, "ffdhe2048"},
    {0x0101, tls_flag_support, kty_dh, NID_ffdhe3072, "ffdhe3072"},
    {0x0102, tls_flag_support, kty_dh, NID_ffdhe4096, "ffdhe4096"},
    {0x0103, tls_flag_support, kty_dh, NID_ffdhe6144, "ffdhe6144"},
    {0x0104, tls_flag_support, kty_dh, NID_ffdhe8192, "ffdhe8192"},
    {0x0200, 0, kty_unknown, 0, "MLKEM512"},
    {0x0201, 0, kty_unknown, 0, "MLKEM768"},
    {0x0202, 0, kty_unknown, 0, "MLKEM1024"},
    {0x11eb, 0, kty_unknown, 0, "SecP256r1MLKEM768"},
    {0x11ec, 0, kty_unknown, 0, "X25519MLKEM768"},
    {0x6399, 0, kty_unknown, 0, "X25519Kyber768Draft00 (OBSOLETE)"},
    {0x639a, 0, kty_unknown, 0, "SecP256r1Kyber768Draft00 (OBSOLETE)"},
    {0xff01, 0, kty_unknown, 0, "arbitrary_explicit_prime_curves"},
    {0xff02, 0, kty_unknown, 0, "arbitrary_explicit_char2_curves"},
};
const size_t sizeof_tls_groups = RTL_NUMBER_OF(tls_groups);

}  // namespace net
}  // namespace hotplace
