/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
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
#define ENTRY5(e1, e2, e3, e4, e5) \
    { e1, e2, e3, e4, e5 }

define_tls_variable(alert_level_code) = {
    ENTRY(1, "warning"),
    ENTRY(2, "fatal"),
};
define_tls_sizeof_variable(alert_level_code);

define_tls_variable(alert_code) = {
    ENTRY(0, "close_notify"),
    ENTRY(10, "unexpected_message"),
    ENTRY(20, "bad_record_mac"),
    ENTRY(21, "decryption_failed_RESERVED"),
    ENTRY(22, "record_overflow"),
    ENTRY(30, "decompression_failure_RESERVED"),
    ENTRY(40, "handshake_failure"),
    ENTRY(41, "no_certificate_RESERVED"),
    ENTRY(42, "bad_certificate"),
    ENTRY(43, "unsupported_certificate"),
    ENTRY(44, "certificate_revoked"),
    ENTRY(45, "certificate_expired"),
    ENTRY(46, "certificate_unknown"),
    ENTRY(47, "illegal_parameter"),
    ENTRY(48, "unknown_ca"),
    ENTRY(49, "access_denied"),
    ENTRY(50, "decode_error"),
    ENTRY(51, "decrypt_error"),
    ENTRY(52, "too_many_cids_requested"),
    ENTRY(60, "export_restriction_RESERVED"),
    ENTRY(70, "protocol_version"),
    ENTRY(71, "insufficient_security"),
    ENTRY(80, "internal_error"),
    ENTRY(86, "inappropriate_fallback"),
    ENTRY(90, "user_canceled"),
    ENTRY(100, "no_renegotiation_RESERVED"),
    ENTRY(109, "missing_extension"),
    ENTRY(110, "unsupported_extension"),
    ENTRY(111, "certificate_unobtainable_RESERVED"),
    ENTRY(112, "unrecognized_name"),
    ENTRY(113, "bad_certificate_status_response"),
    ENTRY(114, "bad_certificate_hash_value_RESERVED"),
    ENTRY(115, "unknown_psk_identity"),
    ENTRY(116, "certificate_required"),
    ENTRY(120, "no_application_protocol"),
    ENTRY(121, "ech_required"),
};
define_tls_sizeof_variable(alert_code);

define_tls_variable(cipher_suite_code) = {
    ENTRY(0x0000, "TLS_NULL_WITH_NULL_NULL"),  // MUST NOT be negotiated
    ENTRY(0x0001, "TLS_RSA_WITH_NULL_MD5"),
    ENTRY(0x0002, "TLS_RSA_WITH_NULL_SHA"),
    ENTRY(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
    ENTRY(0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
    ENTRY(0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
    ENTRY(0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
    ENTRY(0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA"),
    ENTRY(0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    ENTRY(0x0009, "TLS_RSA_WITH_DES_CBC_SHA"),
    ENTRY(0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"),
    ENTRY(0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA"),
    ENTRY(0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    ENTRY(0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA"),
    ENTRY(0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
    ENTRY(0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA"),
    ENTRY(0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    ENTRY(0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"),
    ENTRY(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"),
    ENTRY(0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"),
    ENTRY(0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"),
    ENTRY(0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA"),
    ENTRY(0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0x001e, "TLS_KRB5_WITH_DES_CBC_SHA"),
    ENTRY(0x001f, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0x0020, "TLS_KRB5_WITH_RC4_128_SHA"),
    ENTRY(0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA"),
    ENTRY(0x0022, "TLS_KRB5_WITH_DES_CBC_MD5"),
    ENTRY(0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"),
    ENTRY(0x0024, "TLS_KRB5_WITH_RC4_128_MD5"),
    ENTRY(0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5"),
    ENTRY(0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"),
    ENTRY(0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"),
    ENTRY(0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"),
    ENTRY(0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"),
    ENTRY(0x002a, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"),
    ENTRY(0x002b, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"),
    ENTRY(0x002c, "TLS_PSK_WITH_NULL_SHA"),      // RFC 4785
    ENTRY(0x002d, "TLS_DHE_PSK_WITH_NULL_SHA"),  // RFC 4785
    ENTRY(0x002e, "TLS_RSA_PSK_WITH_NULL_SHA"),  // RFC 4785
    ENTRY(0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"),
    ENTRY(0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"),
    ENTRY(0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"),
    ENTRY(0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"),
    ENTRY(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    ENTRY(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"),
    ENTRY(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
    ENTRY(0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"),
    ENTRY(0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"),
    ENTRY(0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
    ENTRY(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
    ENTRY(0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA"),
    ENTRY(0x003b, "TLS_RSA_WITH_NULL_SHA256"),
    ENTRY(0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
    ENTRY(0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
    ENTRY(0x003e, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"),
    ENTRY(0x003f, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"),
    ENTRY(0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"),
    ENTRY(0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"),
    ENTRY(0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"),
    ENTRY(0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"),
    ENTRY(0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"),
    ENTRY(0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"),
    ENTRY(0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"),
    ENTRY(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
    ENTRY(0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"),
    ENTRY(0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"),
    ENTRY(0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"),
    ENTRY(0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
    ENTRY(0x006c, "TLS_DH_anon_WITH_AES_128_CBC_SHA256"),
    ENTRY(0x006d, "TLS_DH_anon_WITH_AES_256_CBC_SHA256"),
    ENTRY(0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"),
    ENTRY(0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"),
    ENTRY(0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"),
    ENTRY(0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"),
    ENTRY(0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"),
    ENTRY(0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"),
    ENTRY(0x008a, "TLS_PSK_WITH_RC4_128_SHA"),
    ENTRY(0x008b, "TLS_PSK_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0x008c, "TLS_PSK_WITH_AES_128_CBC_SHA"),
    ENTRY(0x008d, "TLS_PSK_WITH_AES_256_CBC_SHA"),
    ENTRY(0x008e, "TLS_DHE_PSK_WITH_RC4_128_SHA"),
    ENTRY(0x008f, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"),
    ENTRY(0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"),
    ENTRY(0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA"),
    ENTRY(0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"),
    ENTRY(0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"),
    ENTRY(0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"),
    ENTRY(0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA"),
    ENTRY(0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA"),
    ENTRY(0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA"),
    ENTRY(0x009a, "TLS_DHE_RSA_WITH_SEED_CBC_SHA"),
    ENTRY(0x009b, "TLS_DH_anon_WITH_SEED_CBC_SHA"),
    ENTRY(0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
    ENTRY(0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    ENTRY(0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
    ENTRY(0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
    ENTRY(0x00a0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"),
    ENTRY(0x00a1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"),
    ENTRY(0x00a2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"),
    ENTRY(0x00a3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"),
    ENTRY(0x00a4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"),
    ENTRY(0x00a5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"),
    ENTRY(0x00a6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256"),
    ENTRY(0x00a7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384"),
    ENTRY(0x00a8, "TLS_PSK_WITH_AES_128_GCM_SHA256"),      // RFC 5487 2
    ENTRY(0x00a9, "TLS_PSK_WITH_AES_256_GCM_SHA384"),      // RFC 5487 2
    ENTRY(0x00aa, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"),  // RFC 5487 2
    ENTRY(0x00ab, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"),  // RFC 5487 2
    ENTRY(0x00ac, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"),  // RFC 5487 2
    ENTRY(0x00ad, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"),  // RFC 5487 2
    ENTRY(0x00ae, "TLS_PSK_WITH_AES_128_CBC_SHA256"),      // RFC 5487 3.1
    ENTRY(0x00af, "TLS_PSK_WITH_AES_256_CBC_SHA384"),      // RFC 5487 3.1
    ENTRY(0x00b0, "TLS_PSK_WITH_NULL_SHA256"),             // RFC 5487 3.1
    ENTRY(0x00b1, "TLS_PSK_WITH_NULL_SHA384"),             // RFC 5487 3.1
    ENTRY(0x00b2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"),  // RFC 5487 3.2
    ENTRY(0x00b3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"),  // RFC 5487 3.2
    ENTRY(0x00b4, "TLS_DHE_PSK_WITH_NULL_SHA256"),         // RFC 5487 3.2
    ENTRY(0x00b5, "TLS_DHE_PSK_WITH_NULL_SHA384"),         // RFC 5487 3.2
    ENTRY(0x00b6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"),  // RFC 5487 3.3
    ENTRY(0x00b7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"),  // RFC 5487 3.3
    ENTRY(0x00b8, "TLS_RSA_PSK_WITH_NULL_SHA256"),         // RFC 5487 3.3
    ENTRY(0x00b9, "TLS_RSA_PSK_WITH_NULL_SHA384"),         // RFC 5487 3.3
    ENTRY(0x00ba, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0x00bb, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0x00bc, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0x00bd, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0x00be, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0x00bf, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0x00c0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"),
    ENTRY(0x00c1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"),
    ENTRY(0x00c2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"),
    ENTRY(0x00c3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"),
    ENTRY(0x00c4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"),
    ENTRY(0x00c5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"),
    ENTRY(0x00c6, "TLS_SM4_GCM_SM3"),
    ENTRY(0x00c7, "TLS_SM4_CCM_SM3"),
    ENTRY(0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"),
    ENTRY(0x1301, "TLS_AES_128_GCM_SHA256"),        // RFC 8446 B.4 TLS 1.3, 9.1 mandatory-to-implement, MUST
    ENTRY(0x1302, "TLS_AES_256_GCM_SHA384"),        // RFC 8446 B.4 TLS 1.3, 9.1 mandatory-to-implement, SHOULD
    ENTRY(0x1303, "TLS_CHACHA20_POLY1305_SHA256"),  // RFC 8446 B.4 TLS 1.3, 9.1 mandatory-to-implement, SHOULD
    ENTRY(0x1304, "TLS_AES_128_CCM_SHA256"),        // RFC 8446 B.4 TLS 1.3
    ENTRY(0x1305, "TLS_AES_128_CCM_8_SHA256"),      // RFC 8446 B.4 TLS 1.3
    ENTRY(0x1306, "TLS_AEGIS_256_SHA512"),
    ENTRY(0x1307, "TLS_AEGIS_128L_SHA256"),
    ENTRY(0x5600, "TLS_FALLBACK_SCSV"),
    ENTRY(0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"),
    ENTRY(0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"),
    ENTRY(0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"),
    ENTRY(0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"),
    ENTRY(0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"),
    ENTRY(0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
    ENTRY(0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    ENTRY(0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
    ENTRY(0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA"),
    ENTRY(0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA"),
    ENTRY(0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"),
    ENTRY(0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"),
    ENTRY(0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA"),
    ENTRY(0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
    ENTRY(0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    ENTRY(0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    ENTRY(0xc015, "TLS_ECDH_anon_WITH_NULL_SHA"),
    ENTRY(0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA"),
    ENTRY(0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"),
    ENTRY(0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"),
    ENTRY(0xc01a, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0xc01b, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0xc01c, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0xc01d, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"),
    ENTRY(0xc01e, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"),
    ENTRY(0xc01f, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"),
    ENTRY(0xc020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"),
    ENTRY(0xc021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"),
    ENTRY(0xc022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"),
    ENTRY(0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
    ENTRY(0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
    ENTRY(0xc025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"),
    ENTRY(0xc026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"),
    ENTRY(0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
    ENTRY(0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
    ENTRY(0xc029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"),
    ENTRY(0xc02a, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"),
    ENTRY(0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
    ENTRY(0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    ENTRY(0xc02d, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"),
    ENTRY(0xc02e, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"),
    ENTRY(0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    ENTRY(0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    ENTRY(0xc031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"),
    ENTRY(0xc032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"),
    ENTRY(0xc033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA"),
    ENTRY(0xc034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"),
    ENTRY(0xc035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"),
    ENTRY(0xc036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"),
    ENTRY(0xc037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"),
    ENTRY(0xc038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"),
    ENTRY(0xc039, "TLS_ECDHE_PSK_WITH_NULL_SHA"),
    ENTRY(0xc03a, "TLS_ECDHE_PSK_WITH_NULL_SHA256"),
    ENTRY(0xc03b, "TLS_ECDHE_PSK_WITH_NULL_SHA384"),
    ENTRY(0xc03c, "TLS_RSA_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc03d, "TLS_RSA_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc03e, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc03f, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc04a, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc04b, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc04c, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc04d, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc04e, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc04f, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc05a, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc05b, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc05c, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc05d, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc05e, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc05f, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc06a, "TLS_PSK_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc06b, "TLS_PSK_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc06c, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc06d, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc06e, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"),
    ENTRY(0xc06f, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"),
    ENTRY(0xc070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"),
    ENTRY(0xc071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"),
    ENTRY(0xc072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0xc073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"),
    ENTRY(0xc074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0xc075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"),
    ENTRY(0xc076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0xc077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"),
    ENTRY(0xc078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0xc079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"),
    ENTRY(0xc07a, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc07b, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc07c, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc07d, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc07e, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc07f, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc08a, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc08b, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc08c, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc08d, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc08e, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc08f, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"),
    ENTRY(0xc093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"),
    ENTRY(0xc094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0xc095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
    ENTRY(0xc096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0xc097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
    ENTRY(0xc098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0xc099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
    ENTRY(0xc09a, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"),
    ENTRY(0xc09b, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"),
    ENTRY(0xc09c, "TLS_RSA_WITH_AES_128_CCM"),
    ENTRY(0xc09d, "TLS_RSA_WITH_AES_256_CCM"),
    ENTRY(0xc09e, "TLS_DHE_RSA_WITH_AES_128_CCM"),
    ENTRY(0xc09f, "TLS_DHE_RSA_WITH_AES_256_CCM"),
    ENTRY(0xc0a0, "TLS_RSA_WITH_AES_128_CCM_8"),
    ENTRY(0xc0a1, "TLS_RSA_WITH_AES_256_CCM_8"),
    ENTRY(0xc0a2, "TLS_DHE_RSA_WITH_AES_128_CCM_8"),
    ENTRY(0xc0a3, "TLS_DHE_RSA_WITH_AES_256_CCM_8"),
    ENTRY(0xc0a4, "TLS_PSK_WITH_AES_128_CCM"),
    ENTRY(0xc0a5, "TLS_PSK_WITH_AES_256_CCM"),
    ENTRY(0xc0a6, "TLS_DHE_PSK_WITH_AES_128_CCM"),
    ENTRY(0xc0a7, "TLS_DHE_PSK_WITH_AES_256_CCM"),
    ENTRY(0xc0a8, "TLS_PSK_WITH_AES_128_CCM_8"),
    ENTRY(0xc0a9, "TLS_PSK_WITH_AES_256_CCM_8"),
    ENTRY(0xc0aa, "TLS_PSK_DHE_WITH_AES_128_CCM_8"),
    ENTRY(0xc0ab, "TLS_PSK_DHE_WITH_AES_256_CCM_8"),
    ENTRY(0xc0ac, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"),
    ENTRY(0xc0ad, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"),
    ENTRY(0xc0ae, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"),
    ENTRY(0xc0af, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"),
    ENTRY(0xc0b0, "TLS_ECCPWD_WITH_AES_128_GCM_SHA256"),
    ENTRY(0xc0b1, "TLS_ECCPWD_WITH_AES_256_GCM_SHA384"),
    ENTRY(0xc0b2, "TLS_ECCPWD_WITH_AES_128_CCM_SHA256"),
    ENTRY(0xc0b3, "TLS_ECCPWD_WITH_AES_256_CCM_SHA384"),
    ENTRY(0xc0b4, "TLS_SHA256_SHA256"),
    ENTRY(0xc0b5, "TLS_SHA384_SHA384"),
    ENTRY(0xc100, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"),
    ENTRY(0xc101, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"),
    ENTRY(0xc102, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"),
    ENTRY(0xc103, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"),
    ENTRY(0xc104, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"),
    ENTRY(0xc105, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"),
    ENTRY(0xc106, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"),
    ENTRY(0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    ENTRY(0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
    ENTRY(0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    ENTRY(0xccab, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"),
    ENTRY(0xccac, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
    ENTRY(0xccad, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
    ENTRY(0xccae, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"),
    ENTRY(0xd001, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"),
    ENTRY(0xd002, "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"),
    ENTRY(0xd003, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"),
    ENTRY(0xd005, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"),
};
define_tls_sizeof_variable(cipher_suite_code);

define_tls_variable(client_cert_type_code) = {
    ENTRY(1, "rsa_sign"),
    ENTRY(2, "dss_sign"),
    ENTRY(3, "rsa_fixed_dh"),
    ENTRY(4, "dss_fixed_dh"),
    ENTRY(5, "rsa_ephemeral_dh_RESERVED"),
    ENTRY(6, "dss_ephemeral_dh_RESERVED"),
    ENTRY(20, "fortezza_dms_RESERVED"),
    ENTRY(64, "ecdsa_sign"),
    ENTRY(65, "rsa_fixed_ecdh"),
    ENTRY(66, "ecdsa_fixed_ecdh"),
    ENTRY(67, "gost_sign256"),
    ENTRY(68, "gost_sign512"),
};
define_tls_sizeof_variable(client_cert_type_code);

define_tls_variable(content_type_code) = {
    ENTRY(20, "change_cipher_spec"),        // RFC 8446
    ENTRY(21, "alert"),                     // RFC 8446
    ENTRY(22, "handshake"),                 // RFC 8446
    ENTRY(23, "application_data"),          // RFC 8446
    ENTRY(24, "heartbeat"),                 // RFC 6520
    ENTRY(25, "tls12_cid"),                 // RFC 9146
    ENTRY(26, "ack"),                       // RFC 9147
    ENTRY(27, "return_routability_check"),  // draft-ietf-tls-dtls-rrc-10
};
define_tls_sizeof_variable(content_type_code);

define_tls_variable(ec_curve_type_code) = {
    ENTRY(1, "explicit_prime"),  // RFC 8422
    ENTRY(2, "explicit_char2"),  // RFC 8422
    ENTRY(3, "named_curve"),     // RFC 8422
};
define_tls_sizeof_variable(ec_curve_type_code);

define_tls_variable(ec_point_format_code) = {
    ENTRY(0, "uncompressed"),
    ENTRY(1, "ansiX962_compressed_prime"),
    ENTRY(2, "ansiX962_compressed_char2"),
};
define_tls_sizeof_variable(ec_point_format_code);

define_tls_variable(kdf_id_code) = {
    // RFC 9258 Table 1: TLS KDF Identifiers Registry
    ENTRY(0x0001, "HKDF_SHA256"),
    ENTRY(0x0002, "HKDF_SHA384"),
};
define_tls_sizeof_variable(kdf_id_code);

define_tls_variable(handshake_type_code) = {
    ENTRY(1, "client_hello"),
    ENTRY(2, "server_hello"),
    ENTRY(3, "hello_verify_request_RESERVED"),
    ENTRY(4, "new_session_ticket"),
    ENTRY(5, "end_of_early_data"),
    ENTRY(6, "hello_retry_request_RESERVED"),
    ENTRY(8, "encrypted_extensions"),
    ENTRY(9, "request_connection_id"),
    ENTRY(10, "new_connection_id"),
    ENTRY(11, "certificate"),
    ENTRY(12, "server_key_exchange"),
    ENTRY(13, "certificate_request"),
    ENTRY(14, "server_hello_done"),
    ENTRY(15, "certificate_verify"),
    ENTRY(16, "client_key_exchange"),
    ENTRY(17, "client_certificate_request"),
    ENTRY(20, "finished"),
    ENTRY(21, "certificate_url_RESERVED"),
    ENTRY(22, "certificate_status_RESERVED"),
    ENTRY(23, "supplemental_data_RESERVED"),
    ENTRY(24, "key_update"),
    ENTRY(25, "compressed_certificate"),
    ENTRY(26, "ekt_key"),
    ENTRY(254, "message_hash"),
};
define_tls_sizeof_variable(handshake_type_code);

define_tls_variable(hash_alg_code) = {
    ENTRY(1, "md5"), ENTRY(2, "sha1"), ENTRY(3, "sha224"), ENTRY(4, "sha256"), ENTRY(5, "sha384"), ENTRY(6, "sha512"), ENTRY(8, "intrinsic"),
};
define_tls_sizeof_variable(hash_alg_code);

define_tls_variable(psk_keyexchange_code) = {
    ENTRY(0, "psk_ke"),      // PSK-only key establishment
    ENTRY(1, "psk_dhe_ke"),  // PSK with (EC)DHE key establishment
};
define_tls_sizeof_variable(psk_keyexchange_code);

define_tls_variable(sig_alg_code) = {
    ENTRY(1, "rsa"), ENTRY(2, "dsa"), ENTRY(3, "ecdsa"), ENTRY(7, "ed25519"), ENTRY(8, "ed448"), ENTRY(64, "gostr34102012_256"), ENTRY(65, "gostr34102012_512"),
};
define_tls_sizeof_variable(sig_alg_code);

const tls_sig_scheme_t tls_sig_schemes[] = {
    ENTRY5(0x0201, crypt_sig_rsassa_pkcs15, nid_rsa, sig_sha1, "rsa_pkcs1_sha1"),
    ENTRY5(0x0203, crypt_sig_ecdsa, 0, sig_sha1, "ecdsa_sha1"),
    ENTRY5(0x0401, crypt_sig_rsassa_pkcs15, nid_rsa, sig_sha256, "rsa_pkcs1_sha256"),             // RFC 8446 9.1 MUST
    ENTRY5(0x0403, crypt_sig_ecdsa, NID_X9_62_prime256v1, sig_sha256, "ecdsa_secp256r1_sha256"),  // RFC 8446 9.1 MUST
    ENTRY5(0x0420, crypt_sig_rsassa_pkcs15, nid_rsa, sig_sha256, "rsa_pkcs1_sha256_legacy"),
    ENTRY5(0x0501, crypt_sig_rsassa_pkcs15, nid_rsa, sig_sha384, "rsa_pkcs1_sha384"),
    ENTRY5(0x0503, crypt_sig_ecdsa, NID_secp384r1, sig_sha384, "ecdsa_secp384r1_sha384"),
    ENTRY5(0x0520, crypt_sig_rsassa_pkcs15, nid_rsa, sig_sha384, "rsa_pkcs1_sha384_legacy"),
    ENTRY5(0x0601, crypt_sig_rsassa_pkcs15, nid_rsa, sig_sha512, "rsa_pkcs1_sha512"),
    ENTRY5(0x0603, crypt_sig_ecdsa, NID_secp521r1, sig_sha512, "ecdsa_secp521r1_sha512"),
    ENTRY5(0x0620, crypt_sig_rsassa_pkcs15, nid_rsa, sig_sha512, "rsa_pkcs1_sha512_legacy"),
    ENTRY5(0x0704, crypt_sig_unknown, 0, sig_sha256, "eccsi_sha256"),                  // TODO
    ENTRY5(0x0705, crypt_sig_unknown, 0, sig_unknown, "iso_ibs1"),                     // TODO
    ENTRY5(0x0706, crypt_sig_unknown, 0, sig_unknown, "iso_ibs2"),                     // TODO
    ENTRY5(0x0707, crypt_sig_unknown, 0, sig_unknown, "iso_chinese_ibs"),              // TODO
    ENTRY5(0x0708, crypt_sig_unknown, 0, sig_unknown, "sm2sig_sm3"),                   // TODO
    ENTRY5(0x0709, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_256a"),           // TODO
    ENTRY5(0x070a, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_256b"),           // TODO
    ENTRY5(0x070b, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_256c"),           // TODO
    ENTRY5(0x070c, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_256d"),           // TODO
    ENTRY5(0x070d, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_512a"),           // TODO
    ENTRY5(0x070e, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_512b"),           // TODO
    ENTRY5(0x070f, crypt_sig_unknown, 0, sig_unknown, "gostr34102012_512c"),           // TODO
    ENTRY5(0x0804, crypt_sig_rsassa_pss, nid_rsa, sig_sha256, "rsa_pss_rsae_sha256"),  // RFC 8446 9.1 MUST
    ENTRY5(0x0805, crypt_sig_rsassa_pss, nid_rsa, sig_sha384, "rsa_pss_rsae_sha384"),
    ENTRY5(0x0806, crypt_sig_rsassa_pss, nid_rsa, sig_sha512, "rsa_pss_rsae_sha512"),
    ENTRY5(0x0807, crypt_sig_eddsa, NID_ED25519, sig_unknown, "ed25519"),
    ENTRY5(0x0808, crypt_sig_eddsa, NID_ED448, sig_unknown, "ed448"),
    ENTRY5(0x0809, crypt_sig_rsassa_pss, nid_rsapss, sig_sha256, "rsa_pss_pss_sha256"),
    ENTRY5(0x080a, crypt_sig_rsassa_pss, nid_rsapss, sig_sha384, "rsa_pss_pss_sha384"),
    ENTRY5(0x080b, crypt_sig_rsassa_pss, nid_rsapss, sig_sha512, "rsa_pss_pss_sha512"),
    ENTRY5(0x081a, crypt_sig_ecdsa, NID_brainpoolP256r1, sig_sha256, "ecdsa_brainpoolP256r1tls13_sha256"),
    ENTRY5(0x081b, crypt_sig_ecdsa, NID_brainpoolP384r1, sig_sha384, "ecdsa_brainpoolP384r1tls13_sha384"),
    ENTRY5(0x081c, crypt_sig_ecdsa, NID_brainpoolP512r1, sig_sha512, "ecdsa_brainpoolP512r1tls13_sha512"),
    ENTRY5(0x0202, crypt_sig_dsa, 0, sig_sha1, "dsa_sha1_RESERVED"),      // TODO
    ENTRY5(0x0402, crypt_sig_dsa, 0, sig_sha256, "dsa_sha256_RESERVED"),  // TODO
    ENTRY5(0x0502, crypt_sig_dsa, 0, sig_sha384, "dsa_sha384_RESERVED"),  // TODO
    ENTRY5(0x0602, crypt_sig_dsa, 0, sig_sha512, "dsa_sha512_RESERVED"),  // TODO
};
define_tls_sizeof_variable(sig_scheme);

define_tls_variable(supported_group_code) = {
    // RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
    // ffdhe2048~ffdhe8192

    // sa. const hint_curve_t hint_curves[]

    ENTRY(0x0001, "sect163k1"),  // K-163, ansit163k1
    ENTRY(0x0002, "sect163r1"),  // ansit163r1
    ENTRY(0x0003, "sect163r2"),  // B-163, ansit163r2
    ENTRY(0x0004, "sect193r1"),  // ansit193r1
    ENTRY(0x0005, "sect193r2"),  // sect193r2
    ENTRY(0x0006, "sect233k1"),  // K-233, ansit233k1
    ENTRY(0x0007, "sect233r1"),  // B-233, ansit233r1
    ENTRY(0x0008, "sect239k1"),  // ansit239k1
    ENTRY(0x0009, "sect283k1"),  // K-283, ansit283k1
    ENTRY(0x000a, "sect283r1"),  // B-283, ansit283r1
    ENTRY(0x000b, "sect409k1"),  // K-409, ansit409k1
    ENTRY(0x000c, "sect409r1"),  // B-409, ansit409r1
    ENTRY(0x000d, "sect571k1"),  // K-571, ansit571k1
    ENTRY(0x000e, "sect571r1"),  // B-571, ansit571r1
    ENTRY(0x000f, "secp160k1"),  // ansip160k1
    ENTRY(0x0010, "secp160r1"),  // ansip160r1
    ENTRY(0x0011, "secp160r2"),  // ansip160r2
    ENTRY(0x0012, "secp192k1"),  // ansip192k1
    ENTRY(0x0013, "secp192r1"),  // P-192, prime192v1
    ENTRY(0x0014, "secp224k1"),  // ansip224k1
    ENTRY(0x0015, "secp224r1"),  // ansip224r1
    ENTRY(0x0016, "secp256k1"),  // ansip256k1
    ENTRY(0x0017, "secp256r1"),  // P-256, prime256v1, RFC 8446 9.1 MUST
    ENTRY(0x0018, "secp384r1"),  // P-384, ansip384r1
    ENTRY(0x0019, "secp521r1"),  // P-521, ansip521r1
    ENTRY(0x001a, "brainpoolP256r1"),
    ENTRY(0x001b, "brainpoolP384r1"),
    ENTRY(0x001c, "brainpoolP512r1"),
    ENTRY(0x001d, "x25519"),  // RFC 8446 8446 9.1 MUST
    ENTRY(0x001e, "x448"),
    ENTRY(0x001f, "brainpoolP256r1tls13"),
    ENTRY(0x0020, "brainpoolP384r1tls13"),
    ENTRY(0x0021, "brainpoolP512r1tls13"),
    ENTRY(0x0022, "GC256A"),
    ENTRY(0x0023, "GC256B"),
    ENTRY(0x0024, "GC256C"),
    ENTRY(0x0025, "GC256D"),
    ENTRY(0x0026, "GC512A"),
    ENTRY(0x0027, "GC512B"),
    ENTRY(0x0028, "GC512C"),
    ENTRY(0x0029, "curveSM2"),
    ENTRY(0x0100, "ffdhe2048"),
    ENTRY(0x0101, "ffdhe3072"),
    ENTRY(0x0102, "ffdhe4096"),
    ENTRY(0x0103, "ffdhe6144"),
    ENTRY(0x0104, "ffdhe8192"),
    ENTRY(0x0200, "MLKEM512"),
    ENTRY(0x0201, "MLKEM768"),
    ENTRY(0x0202, "MLKEM1024"),
    ENTRY(0x11eb, "SecP256r1MLKEM768"),
    ENTRY(0x11ec, "X25519MLKEM768"),
    ENTRY(0x6399, "X25519Kyber768Draft00 (OBSOLETE)"),
    ENTRY(0x639a, "SecP256r1Kyber768Draft00 (OBSOLETE)"),
    ENTRY(0xff01, "arbitrary_explicit_prime_curves"),
    ENTRY(0xff02, "arbitrary_explicit_char2_curves"),
};
define_tls_sizeof_variable(supported_group_code);

}  // namespace net
}  // namespace hotplace
