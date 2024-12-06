/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tlsspec/tls.hpp>

namespace hotplace {
namespace net {

tls_advisor tls_advisor::_instance;

tls_advisor* tls_advisor::get_instance() {
    if (false == _instance._load) {
        critical_section_guard guard(_instance._lock);
        if (false == _instance._load) {
            _instance.load_resource();
            _instance._load = true;
        }
    }
    return &_instance;
}

tls_advisor::tls_advisor() : _load(false) {}

tls_advisor::~tls_advisor() {}

void tls_advisor::load_resource() {
    load_content_types();
    load_handshake_types();
    load_tls_version();
    load_tls_extensions();
    load_cipher_suites();
    load_tls_alerts();
    load_named_curves();
    load_ec_point_formats();
    load_signature_schemes();
    load_psk_kem();
    load_certificate_related();
    load_quic_param();
}

void tls_advisor::load_content_types() {
    _content_types.insert({20, "change_cipher_spec"});
    _content_types.insert({21, "alert"});
    _content_types.insert({22, "handshake"});
    _content_types.insert({23, "application_data"});
}

void tls_advisor::load_handshake_types() {
    _handshake_types.insert({1, "client_hello"});
    _handshake_types.insert({2, "server_hello"});
    _handshake_types.insert({4, "new_session_ticket"});
    _handshake_types.insert({5, "end_of_early_data"});
    _handshake_types.insert({8, "encrypted_extensions"});
    _handshake_types.insert({11, "certificate"});
    _handshake_types.insert({12, "server_key_exchange"});
    _handshake_types.insert({13, "certificate_request"});
    _handshake_types.insert({14, "server_hello_done"});
    _handshake_types.insert({15, "certificate_verify"});
    _handshake_types.insert({16, "client_key_exchange"});
    _handshake_types.insert({20, "finished"});
    _handshake_types.insert({24, "key_update"});
    _handshake_types.insert({254, "message_hash"});
}

void tls_advisor::load_tls_version() {
    // 0x0304
    //  RFC 8446
    //   4.1.2.  Client Hello - see legacy_version
    //   4.2.1.  Supported Versions
    //   5.1.  Record Layer
    //   9.2.  Mandatory-to-Implement Extensions
    _tls_version.insert({0x0304, "TLS v1.3"});

    _tls_version.insert({0x0303, "TLS v1.2"});  // RFC 5246 A.1.  Record Layer
    // deprecated
    _tls_version.insert({0x0302, "TLS v1.1"});  // RFC 4346 A.1. Record Layer
    _tls_version.insert({0x0301, "TLS v1.0"});  // RFC 2246 A.1. Record layer

    _tls_version.insert({0xfefd, "DTLS 1.2"});
}

void tls_advisor::load_tls_extensions() {
    /* https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml */
    _tls_extensions.insert({0x0000, "server_name"});
    _tls_extensions.insert({0x0001, "max_fragment_length"});
    _tls_extensions.insert({0x0005, "status_request"});
    _tls_extensions.insert({0x000a, "supported_groups"});
    _tls_extensions.insert({0x000b, "ec_point_formats"});
    _tls_extensions.insert({0x000d, "signature_algorithms"});
    _tls_extensions.insert({0x000e, "use_srtp"});
    _tls_extensions.insert({0x000f, "heartbeat"});
    _tls_extensions.insert({0x0010, "application_layer_protocol_negotiation"});
    _tls_extensions.insert({0x0012, "signed_certificate_timestamp"});
    _tls_extensions.insert({0x0013, "client_certificate_type"});
    _tls_extensions.insert({0x0014, "server_certificate_type"});
    _tls_extensions.insert({0x0015, "padding"});
    _tls_extensions.insert({0x001c, "record_size_limit"});
    _tls_extensions.insert({0x0016, "encrypt_then_mac"});
    _tls_extensions.insert({0x0017, "extended_master_secret"});
    _tls_extensions.insert({0x0023, "session_ticket"});
    _tls_extensions.insert({0x0024, "TLMSP"});
    _tls_extensions.insert({0x0029, "pre_shared_key"});
    _tls_extensions.insert({0x002a, "early_data"});
    _tls_extensions.insert({0x002b, "supported_versions"});
    _tls_extensions.insert({0x002c, "cookie"});
    _tls_extensions.insert({0x002d, "psk_key_exchange_modes"});
    _tls_extensions.insert({0x002f, "certificate_authorities"});
    _tls_extensions.insert({0x0030, "oid_filters"});
    _tls_extensions.insert({0x0031, "post_handshake_auth"});
    _tls_extensions.insert({0x0032, "signature_algorithms_cert"});
    _tls_extensions.insert({0x0033, "key_share"});
    _tls_extensions.insert({0x0039, "quic_transport_parameters"});
    _tls_extensions.insert({0xff01, "renegotiation_info"});
}

tls_alg_info_t tls_alg_info[] = {
    {
        0x1301,  // TLS_AES_128_GCM_SHA256
        aes128,
        gcm,
        16,
        sha2_256,
    },
    {
        0x1302,  // TLS_AES_256_GCM_SHA384
        aes256,
        gcm,
        16,
        sha2_384,
    },
    {
        0x1303,  // TLS_CHACHA20_POLY1305_SHA256
        chacha20,
        crypt_aead,
        16,
        sha2_256,
    },
    {
        0x1304,  // TLS_AES_128_CCM_SHA256, Tag 16
        aes128,
        ccm,
        16,
        sha2_256,
    },
    {
        0x1305,  // TLS_AES_128_CCM_8_SHA256, Tag 8
        aes128,
        ccm,
        8,
        sha2_256,
    },
};

void tls_advisor::load_cipher_suites() {
    // TLS_{Key Exchange}_{Cipher}_{Mac}

    // RFC 8446 B.4.  Cipher Suites
    // RFC 5246 A.5.  The Cipher Suite
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    _cipher_suites.insert({0x0000, "TLS_NULL_WITH_NULL_NULL"});  // MUST NOT be negotiated
    _cipher_suites.insert({0x0001, "TLS_RSA_WITH_NULL_MD5"});
    _cipher_suites.insert({0x0002, "TLS_RSA_WITH_NULL_SHA"});
    _cipher_suites.insert({0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"});
    _cipher_suites.insert({0x0004, "TLS_RSA_WITH_RC4_128_MD5"});
    _cipher_suites.insert({0x0005, "TLS_RSA_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"});
    _cipher_suites.insert({0x0007, "TLS_RSA_WITH_IDEA_CBC_SHA"});
    _cipher_suites.insert({0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"});
    _cipher_suites.insert({0x0009, "TLS_RSA_WITH_DES_CBC_SHA"});
    _cipher_suites.insert({0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"});
    _cipher_suites.insert({0x000c, "TLS_DH_DSS_WITH_DES_CBC_SHA"});
    _cipher_suites.insert({0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"});
    _cipher_suites.insert({0x000f, "TLS_DH_RSA_WITH_DES_CBC_SHA"});
    _cipher_suites.insert({0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"});
    _cipher_suites.insert({0x0012, "TLS_DHE_DSS_WITH_DES_CBC_SHA"});
    _cipher_suites.insert({0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"});
    _cipher_suites.insert({0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA"});
    _cipher_suites.insert({0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"});
    _cipher_suites.insert({0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"});
    _cipher_suites.insert({0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
    _cipher_suites.insert({0x001a, "TLS_DH_anon_WITH_DES_CBC_SHA"});
    _cipher_suites.insert({0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x001e, "TLS_KRB5_WITH_DES_CBC_SHA"});
    _cipher_suites.insert({0x001f, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0020, "TLS_KRB5_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0x0021, "TLS_KRB5_WITH_IDEA_CBC_SHA"});
    _cipher_suites.insert({0x0022, "TLS_KRB5_WITH_DES_CBC_MD5"});
    _cipher_suites.insert({0x0023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"});
    _cipher_suites.insert({0x0024, "TLS_KRB5_WITH_RC4_128_MD5"});
    _cipher_suites.insert({0x0025, "TLS_KRB5_WITH_IDEA_CBC_MD5"});
    _cipher_suites.insert({0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"});
    _cipher_suites.insert({0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"});
    _cipher_suites.insert({0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"});
    _cipher_suites.insert({0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"});
    _cipher_suites.insert({0x002a, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"});
    _cipher_suites.insert({0x002b, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"});
    _cipher_suites.insert({0x002c, "TLS_PSK_WITH_NULL_SHA"});
    _cipher_suites.insert({0x002d, "TLS_DHE_PSK_WITH_NULL_SHA"});
    _cipher_suites.insert({0x002e, "TLS_RSA_PSK_WITH_NULL_SHA"});
    _cipher_suites.insert({0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x003b, "TLS_RSA_WITH_NULL_SHA256"});
    _cipher_suites.insert({0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x003e, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x003f, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"});
    _cipher_suites.insert({0x0042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"});
    _cipher_suites.insert({0x0043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"});
    _cipher_suites.insert({0x0044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"});
    _cipher_suites.insert({0x0045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"});
    _cipher_suites.insert({0x0046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"});
    _cipher_suites.insert({0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x006c, "TLS_DH_anon_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x006d, "TLS_DH_anon_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"});
    _cipher_suites.insert({0x0085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"});
    _cipher_suites.insert({0x0086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"});
    _cipher_suites.insert({0x0087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"});
    _cipher_suites.insert({0x0088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"});
    _cipher_suites.insert({0x0089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"});
    _cipher_suites.insert({0x008a, "TLS_PSK_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0x008b, "TLS_PSK_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x008c, "TLS_PSK_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x008d, "TLS_PSK_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x008e, "TLS_DHE_PSK_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0x008f, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0092, "TLS_RSA_PSK_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0x0093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0096, "TLS_RSA_WITH_SEED_CBC_SHA"});
    _cipher_suites.insert({0x0097, "TLS_DH_DSS_WITH_SEED_CBC_SHA"});
    _cipher_suites.insert({0x0098, "TLS_DH_RSA_WITH_SEED_CBC_SHA"});
    _cipher_suites.insert({0x0099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA"});
    _cipher_suites.insert({0x009a, "TLS_DHE_RSA_WITH_SEED_CBC_SHA"});
    _cipher_suites.insert({0x009b, "TLS_DH_anon_WITH_SEED_CBC_SHA"});
    _cipher_suites.insert({0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0x00a0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0x00a1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0x00a2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0x00a3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0x00a4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0x00a5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0x00a6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0x00a7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0x00a8, "TLS_PSK_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0x00a9, "TLS_PSK_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0x00aa, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0x00ab, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0x00ac, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0x00ad, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0x00ae, "TLS_PSK_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x00af, "TLS_PSK_WITH_AES_256_CBC_SHA384"});
    _cipher_suites.insert({0x00b0, "TLS_PSK_WITH_NULL_SHA256"});
    _cipher_suites.insert({0x00b1, "TLS_PSK_WITH_NULL_SHA384"});
    _cipher_suites.insert({0x00b2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x00b3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"});
    _cipher_suites.insert({0x00b4, "TLS_DHE_PSK_WITH_NULL_SHA256"});
    _cipher_suites.insert({0x00b5, "TLS_DHE_PSK_WITH_NULL_SHA384"});
    _cipher_suites.insert({0x00b6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x00b7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"});
    _cipher_suites.insert({0x00b8, "TLS_RSA_PSK_WITH_NULL_SHA256"});
    _cipher_suites.insert({0x00b9, "TLS_RSA_PSK_WITH_NULL_SHA384"});
    _cipher_suites.insert({0x00ba, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0x00bb, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0x00bc, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0x00bd, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0x00be, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0x00bf, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0x00c0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"});
    _cipher_suites.insert({0x00c1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"});
    _cipher_suites.insert({0x00c2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"});
    _cipher_suites.insert({0x00c3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"});
    _cipher_suites.insert({0x00c4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"});
    _cipher_suites.insert({0x00c5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"});
    _cipher_suites.insert({0x00c6, "TLS_SM4_GCM_SM3"});
    _cipher_suites.insert({0x00c7, "TLS_SM4_CCM_SM3"});
    _cipher_suites.insert({0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"});
    _cipher_suites.insert({0x1301, "TLS_AES_128_GCM_SHA256"});        // TLS 1.3, mandatory, MUST
    _cipher_suites.insert({0x1302, "TLS_AES_256_GCM_SHA384"});        // TLS 1.3, mandatory, SHOULD
    _cipher_suites.insert({0x1303, "TLS_CHACHA20_POLY1305_SHA256"});  // TLS 1.3, mandatory, SHOULD
    _cipher_suites.insert({0x1304, "TLS_AES_128_CCM_SHA256"});        // TLS 1.3
    _cipher_suites.insert({0x1305, "TLS_AES_128_CCM_8_SHA256"});      // TLS 1.3
    _cipher_suites.insert({0x1306, "TLS_AEGIS_256_SHA512"});
    _cipher_suites.insert({0x1307, "TLS_AEGIS_128L_SHA256"});
    _cipher_suites.insert({0x5600, "TLS_FALLBACK_SCSV"});
    _cipher_suites.insert({0xc001, "TLS_ECDH_ECDSA_WITH_NULL_SHA"});
    _cipher_suites.insert({0xc002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0xc003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0xc004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0xc005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0xc006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA"});
    _cipher_suites.insert({0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0xc00b, "TLS_ECDH_RSA_WITH_NULL_SHA"});
    _cipher_suites.insert({0xc00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0xc00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0xc00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0xc00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0xc010, "TLS_ECDHE_RSA_WITH_NULL_SHA"});
    _cipher_suites.insert({0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0xc015, "TLS_ECDH_anon_WITH_NULL_SHA"});
    _cipher_suites.insert({0xc016, "TLS_ECDH_anon_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0xc017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0xc018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0xc019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0xc01a, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0xc01b, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0xc01c, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0xc01d, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0xc01e, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0xc01f, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0xc020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0xc021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0xc022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"});
    _cipher_suites.insert({0xc025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0xc026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"});
    _cipher_suites.insert({0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"});
    _cipher_suites.insert({0xc029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0xc02a, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"});
    _cipher_suites.insert({0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0xc02d, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0xc02e, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0xc031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0xc032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0xc033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0xc034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0xc035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0xc036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0xc037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0xc038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"});
    _cipher_suites.insert({0xc039, "TLS_ECDHE_PSK_WITH_NULL_SHA"});
    _cipher_suites.insert({0xc03a, "TLS_ECDHE_PSK_WITH_NULL_SHA256"});
    _cipher_suites.insert({0xc03b, "TLS_ECDHE_PSK_WITH_NULL_SHA384"});
    _cipher_suites.insert({0xc03c, "TLS_RSA_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc03d, "TLS_RSA_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc03e, "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc03f, "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc040, "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc041, "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc042, "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc043, "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc044, "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc045, "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc046, "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc047, "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc048, "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc049, "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc04a, "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc04b, "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc04c, "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc04d, "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc04e, "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc04f, "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc050, "TLS_RSA_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc051, "TLS_RSA_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc052, "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc053, "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc054, "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc055, "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc056, "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc057, "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc058, "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc059, "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc05a, "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc05b, "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc05c, "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc05d, "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc05e, "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc05f, "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc060, "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc061, "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc062, "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc063, "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc064, "TLS_PSK_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc065, "TLS_PSK_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc066, "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc067, "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc068, "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc069, "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc06a, "TLS_PSK_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc06b, "TLS_PSK_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc06c, "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc06d, "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc06e, "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc06f, "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc070, "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc071, "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc072, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc073, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc074, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc075, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc076, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc077, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc078, "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc079, "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc07a, "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc07b, "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc07c, "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc07d, "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc07e, "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc07f, "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc080, "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc081, "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc082, "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc083, "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc084, "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc085, "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc086, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc087, "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc088, "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc089, "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc08a, "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc08b, "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc08c, "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc08d, "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc08e, "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc08f, "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc090, "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc091, "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc092, "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"});
    _cipher_suites.insert({0xc093, "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"});
    _cipher_suites.insert({0xc094, "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc095, "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc096, "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc097, "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc098, "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc099, "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc09a, "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"});
    _cipher_suites.insert({0xc09b, "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"});
    _cipher_suites.insert({0xc09c, "TLS_RSA_WITH_AES_128_CCM"});
    _cipher_suites.insert({0xc09d, "TLS_RSA_WITH_AES_256_CCM"});
    _cipher_suites.insert({0xc09e, "TLS_DHE_RSA_WITH_AES_128_CCM"});
    _cipher_suites.insert({0xc09f, "TLS_DHE_RSA_WITH_AES_256_CCM"});
    _cipher_suites.insert({0xc0a0, "TLS_RSA_WITH_AES_128_CCM_8"});
    _cipher_suites.insert({0xc0a1, "TLS_RSA_WITH_AES_256_CCM_8"});
    _cipher_suites.insert({0xc0a2, "TLS_DHE_RSA_WITH_AES_128_CCM_8"});
    _cipher_suites.insert({0xc0a3, "TLS_DHE_RSA_WITH_AES_256_CCM_8"});
    _cipher_suites.insert({0xc0a4, "TLS_PSK_WITH_AES_128_CCM"});
    _cipher_suites.insert({0xc0a5, "TLS_PSK_WITH_AES_256_CCM"});
    _cipher_suites.insert({0xc0a6, "TLS_DHE_PSK_WITH_AES_128_CCM"});
    _cipher_suites.insert({0xc0a7, "TLS_DHE_PSK_WITH_AES_256_CCM"});
    _cipher_suites.insert({0xc0a8, "TLS_PSK_WITH_AES_128_CCM_8"});
    _cipher_suites.insert({0xc0a9, "TLS_PSK_WITH_AES_256_CCM_8"});
    _cipher_suites.insert({0xc0aa, "TLS_PSK_DHE_WITH_AES_128_CCM_8"});
    _cipher_suites.insert({0xc0ab, "TLS_PSK_DHE_WITH_AES_256_CCM_8"});
    _cipher_suites.insert({0xc0ac, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"});
    _cipher_suites.insert({0xc0ad, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM"});
    _cipher_suites.insert({0xc0ae, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"});
    _cipher_suites.insert({0xc0af, "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"});
    _cipher_suites.insert({0xc0b0, "TLS_ECCPWD_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0xc0b1, "TLS_ECCPWD_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0xc0b2, "TLS_ECCPWD_WITH_AES_128_CCM_SHA256"});
    _cipher_suites.insert({0xc0b3, "TLS_ECCPWD_WITH_AES_256_CCM_SHA384"});
    _cipher_suites.insert({0xc0b4, "TLS_SHA256_SHA256"});
    _cipher_suites.insert({0xc0b5, "TLS_SHA384_SHA384"});
    _cipher_suites.insert({0xc100, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"});
    _cipher_suites.insert({0xc101, "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"});
    _cipher_suites.insert({0xc102, "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"});
    _cipher_suites.insert({0xc103, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"});
    _cipher_suites.insert({0xc104, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"});
    _cipher_suites.insert({0xc105, "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"});
    _cipher_suites.insert({0xc106, "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"});
    _cipher_suites.insert({0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"});
    _cipher_suites.insert({0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"});
    _cipher_suites.insert({0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"});
    _cipher_suites.insert({0xccab, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"});
    _cipher_suites.insert({0xccac, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"});
    _cipher_suites.insert({0xccad, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"});
    _cipher_suites.insert({0xccae, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"});
    _cipher_suites.insert({0xd001, "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"});
    _cipher_suites.insert({0xd002, "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"});
    _cipher_suites.insert({0xd003, "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"});
    _cipher_suites.insert({0xd005, "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"});

    for (auto i = 0; i < RTL_NUMBER_OF(tls_alg_info); i++) {
        auto item = tls_alg_info + i;
        _tls_alg_info.insert({item->alg, item});
    }
}

void tls_advisor::load_tls_alerts() {
    _tls_alert_level.insert({1, "warning"});
    _tls_alert_level.insert({2, "fatal"});

    _tls_alert_descriptions.insert({0, "close_notify"});
    _tls_alert_descriptions.insert({10, "unexpected_message"});
    _tls_alert_descriptions.insert({20, "bad_record_mac"});
    _tls_alert_descriptions.insert({21, "decryption_failed_RESERVED"});
    _tls_alert_descriptions.insert({22, "record_overflow"});
    _tls_alert_descriptions.insert({30, "decompression_failure_RESERVED"});
    _tls_alert_descriptions.insert({40, "handshake_failure"});
    _tls_alert_descriptions.insert({41, "no_certificate_RESERVED"});
    _tls_alert_descriptions.insert({42, "bad_certificate"});
    _tls_alert_descriptions.insert({43, "unsupported_certificate"});
    _tls_alert_descriptions.insert({44, "certificate_revoked"});
    _tls_alert_descriptions.insert({45, "certificate_expired"});
    _tls_alert_descriptions.insert({46, "certificate_unknown"});
    _tls_alert_descriptions.insert({47, "illegal_parameter"});
    _tls_alert_descriptions.insert({48, "unknown_ca"});
    _tls_alert_descriptions.insert({49, "access_denied"});
    _tls_alert_descriptions.insert({50, "decode_error"});
    _tls_alert_descriptions.insert({51, "decrypt_error"});
    _tls_alert_descriptions.insert({52, "too_many_cids_requested"});
    _tls_alert_descriptions.insert({60, "export_restriction_RESERVED"});
    _tls_alert_descriptions.insert({70, "protocol_version"});
    _tls_alert_descriptions.insert({71, "insufficient_security"});
    _tls_alert_descriptions.insert({80, "internal_error"});
    _tls_alert_descriptions.insert({86, "inappropriate_fallback"});
    _tls_alert_descriptions.insert({90, "user_canceled"});
    _tls_alert_descriptions.insert({100, "no_renegotiation_RESERVED"});
    _tls_alert_descriptions.insert({109, "missing_extension"});
    _tls_alert_descriptions.insert({110, "unsupported_extension"});
    _tls_alert_descriptions.insert({111, "certificate_unobtainable_RESERVED"});
    _tls_alert_descriptions.insert({112, "unrecognized_name"});
    _tls_alert_descriptions.insert({113, "bad_certificate_status_response"});
    _tls_alert_descriptions.insert({114, "bad_certificate_hash_value_RESERVED"});
    _tls_alert_descriptions.insert({115, "unknown_psk_identity"});
    _tls_alert_descriptions.insert({116, "certificate_required"});
    _tls_alert_descriptions.insert({120, "no_application_protocol"});
    _tls_alert_descriptions.insert({121, "ech_required"});
}

void tls_advisor::load_named_curves() {
    // RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
    // ffdhe2048~ffdhe8192

    _named_curves.insert({0x0001, "sect163k1"});  // K-163, ansit163k1
    _named_curves.insert({0x0002, "sect163r1"});  // ansit163r1
    _named_curves.insert({0x0003, "sect163r2"});  // B-163, ansit163r2
    _named_curves.insert({0x0004, "sect193r1"});  // ansit193r1
    _named_curves.insert({0x0005, "sect193r2"});  // sect193r2
    _named_curves.insert({0x0006, "sect233k1"});  // K-233, ansit233k1
    _named_curves.insert({0x0007, "sect233r1"});  // B-233, ansit233r1
    _named_curves.insert({0x0008, "sect239k1"});  // ansit239k1
    _named_curves.insert({0x0009, "sect283k1"});  // K-283, ansit283k1
    _named_curves.insert({0x000a, "sect283r1"});  // B-283, ansit283r1
    _named_curves.insert({0x000b, "sect409k1"});  // K-409, ansit409k1
    _named_curves.insert({0x000c, "sect409r1"});  // B-409, ansit409r1
    _named_curves.insert({0x000d, "sect571k1"});  // K-571, ansit571k1
    _named_curves.insert({0x000e, "sect571r1"});  // B-571, ansit571r1
    _named_curves.insert({0x000f, "secp160k1"});  // ansip160k1
    _named_curves.insert({0x0010, "secp160r1"});  // ansip160r1
    _named_curves.insert({0x0011, "secp160r2"});  // ansip160r2
    _named_curves.insert({0x0012, "secp192k1"});  // ansip192k1
    _named_curves.insert({0x0013, "secp192r1"});  // P-192, prime192v1
    _named_curves.insert({0x0014, "secp224k1"});  // ansip224k1
    _named_curves.insert({0x0015, "secp224r1"});  // ansip224r1
    _named_curves.insert({0x0016, "secp256k1"});  // ansip256k1
    _named_curves.insert({0x0017, "secp256r1"});  // P-256, prime256v1
    _named_curves.insert({0x0018, "secp384r1"});  // P-384, ansip384r1
    _named_curves.insert({0x0019, "secp521r1"});  // P-521, ansip521r1
    _named_curves.insert({0x001a, "brainpoolP256r1"});
    _named_curves.insert({0x001b, "brainpoolP384r1"});
    _named_curves.insert({0x001c, "brainpoolP512r1"});
    _named_curves.insert({0x001d, "x25519"});
    _named_curves.insert({0x001e, "x448"});
    _named_curves.insert({0x001f, "brainpoolP256r1tls13"});
    _named_curves.insert({0x0020, "brainpoolP384r1tls13"});
    _named_curves.insert({0x0021, "brainpoolP512r1tls13"});
    _named_curves.insert({0x0022, "GC256A"});
    _named_curves.insert({0x0023, "GC256B"});
    _named_curves.insert({0x0024, "GC256C"});
    _named_curves.insert({0x0025, "GC256D"});
    _named_curves.insert({0x0026, "GC512A"});
    _named_curves.insert({0x0027, "GC512B"});
    _named_curves.insert({0x0028, "GC512C"});
    _named_curves.insert({0x0029, "curveSM2"});
    _named_curves.insert({0x0100, "ffdhe2048"});
    _named_curves.insert({0x0101, "ffdhe3072"});
    _named_curves.insert({0x0102, "ffdhe4096"});
    _named_curves.insert({0x0103, "ffdhe6144"});
    _named_curves.insert({0x0104, "ffdhe8192"});
    _named_curves.insert({0x0200, "MLKEM512"});
    _named_curves.insert({0x0201, "MLKEM768"});
    _named_curves.insert({0x0202, "MLKEM1024"});
    _named_curves.insert({0x11eb, "SecP256r1MLKEM768"});
    _named_curves.insert({0x11ec, "X25519MLKEM768"});
    _named_curves.insert({0x6399, "X25519Kyber768Draft00 (OBSOLETE)"});
    _named_curves.insert({0x639a, "SecP256r1Kyber768Draft00 (OBSOLETE)"});
    _named_curves.insert({0xff01, "arbitrary_explicit_prime_curves"});
    _named_curves.insert({0xff02, "arbitrary_explicit_char2_curves"});
}

void tls_advisor::load_ec_point_formats() {
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    _ec_point_formats.insert({0, "uncompressed"});
    _ec_point_formats.insert({1, "ansiX962_compressed_prime"});
    _ec_point_formats.insert({2, "ansiX962_compressed_char2"});
}

void tls_advisor::load_signature_schemes() {
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    _signature_schemes.insert({0x0201, "rsa_pkcs1_sha1"});
    _signature_schemes.insert({0x0203, "ecdsa_sha1"});
    _signature_schemes.insert({0x0401, "rsa_pkcs1_sha256"});
    _signature_schemes.insert({0x0403, "ecdsa_secp256r1_sha256"});
    _signature_schemes.insert({0x0420, "rsa_pkcs1_sha256_legacy"});
    _signature_schemes.insert({0x0501, "rsa_pkcs1_sha384"});
    _signature_schemes.insert({0x0503, "ecdsa_secp384r1_sha384"});
    _signature_schemes.insert({0x0520, "rsa_pkcs1_sha384_legacy"});
    _signature_schemes.insert({0x0601, "rsa_pkcs1_sha512"});
    _signature_schemes.insert({0x0603, "ecdsa_secp521r1_sha512"});
    _signature_schemes.insert({0x0620, "rsa_pkcs1_sha512_legacy"});
    _signature_schemes.insert({0x0704, "eccsi_sha256"});
    _signature_schemes.insert({0x0705, "iso_ibs1"});
    _signature_schemes.insert({0x0706, "iso_ibs2"});
    _signature_schemes.insert({0x0707, "iso_chinese_ibs"});
    _signature_schemes.insert({0x0708, "sm2sig_sm3"});
    _signature_schemes.insert({0x0709, "gostr34102012_256a"});
    _signature_schemes.insert({0x070a, "gostr34102012_256b"});
    _signature_schemes.insert({0x070b, "gostr34102012_256c"});
    _signature_schemes.insert({0x070c, "gostr34102012_256d"});
    _signature_schemes.insert({0x070d, "gostr34102012_512a"});
    _signature_schemes.insert({0x070e, "gostr34102012_512b"});
    _signature_schemes.insert({0x070f, "gostr34102012_512c"});
    _signature_schemes.insert({0x0804, "rsa_pss_rsae_sha256"});
    _signature_schemes.insert({0x0805, "rsa_pss_rsae_sha384"});
    _signature_schemes.insert({0x0806, "rsa_pss_rsae_sha512"});
    _signature_schemes.insert({0x0807, "ed25519"});
    _signature_schemes.insert({0x0808, "ed448"});
    _signature_schemes.insert({0x0809, "rsa_pss_pss_sha256"});
    _signature_schemes.insert({0x080a, "rsa_pss_pss_sha384"});
    _signature_schemes.insert({0x080b, "rsa_pss_pss_sha512"});
    _signature_schemes.insert({0x081a, "ecdsa_brainpoolP256r1tls13_sha256"});
    _signature_schemes.insert({0x081b, "ecdsa_brainpoolP384r1tls13_sha384"});
    _signature_schemes.insert({0x081c, "ecdsa_brainpoolP512r1tls13_sha512"});

    //
    _signature_schemes.insert({0x0202, "dsa_sha1_RESERVED"});
    _signature_schemes.insert({0x0402, "dsa_sha256_RESERVED"});
    _signature_schemes.insert({0x0502, "dsa_sha384_RESERVED"});
    _signature_schemes.insert({0x0602, "dsa_sha512_RESERVED"});
}

void tls_advisor::load_psk_kem() {
    _psk_kem.insert({0, "psk_ke"});      // PSK-only key establishment
    _psk_kem.insert({1, "psk_dhe_ke"});  // PSK with (EC)DHE key establishment
}

void tls_advisor::load_certificate_related() {
    // https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    _cert_status_types.insert({1, "ocsp"});
    _cert_status_types.insert({2, "ocsp_multi_RESERVED"});
}

void tls_advisor::load_quic_param() {
    _quic_params.insert({0x00, "original_destination_connection_id"});
    _quic_params.insert({0x01, "max_idle_timeout"});
    _quic_params.insert({0x02, "stateless_reset_token"});
    _quic_params.insert({0x03, "max_udp_payload_size"});
    _quic_params.insert({0x04, "initial_max_data"});
    _quic_params.insert({0x05, "initial_max_stream_data_bidi_local"});
    _quic_params.insert({0x06, "initial_max_stream_data_bidi_remote"});
    _quic_params.insert({0x07, "initial_max_stream_data_uni"});
    _quic_params.insert({0x08, "initial_max_streams_bidi"});
    _quic_params.insert({0x09, "initial_max_streams_uni"});
    _quic_params.insert({0x0a, "ack_delay_exponent"});
    _quic_params.insert({0x0b, "max_ack_delay"});
    _quic_params.insert({0x0c, "disable_active_migration"});
    _quic_params.insert({0x0d, "preferred_address"});
    _quic_params.insert({0x0e, "active_connection_id_limit"});
    _quic_params.insert({0x0f, "initial_source_connection_id"});
    _quic_params.insert({0x10, "retry_source_connection_id"});
}

std::string tls_advisor::content_type_string(uint8 type) {
    std::string value;
    auto iter = _content_types.find(type);
    if (_content_types.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_advisor::handshake_type_string(uint8 type) {
    std::string value;
    auto iter = _handshake_types.find(type);
    if (_handshake_types.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_advisor::tls_version_string(uint16 code) {
    std::string value;
    auto iter = _tls_version.find(code);
    if (_tls_version.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_advisor::tls_extension_string(uint16 code) {
    std::string value;
    auto iter = _tls_extensions.find(code);
    if (_tls_extensions.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_advisor::cipher_suite_string(uint16 code) {
    std::string value;
    auto iter = _cipher_suites.find(code);
    if (_cipher_suites.end() != iter) {
        value = iter->second;
    }
    return value;
}

const tls_alg_info_t* tls_advisor::hintof_tls_algorithm(uint16 code) {
    tls_alg_info_t* item = nullptr;
    auto iter = _tls_alg_info.find(code);
    if (_tls_alg_info.end() != iter) {
        item = iter->second;
    }
    return item;
}

hash_algorithm_t tls_advisor::hash_alg_of(uint16 code) {
    hash_algorithm_t alg = hash_alg_unknown;
    const tls_alg_info_t* hint_tls_alg = hintof_tls_algorithm(code);
    if (hint_tls_alg) {
        alg = hint_tls_alg->mac;
    }
    return alg;
}

std::string tls_advisor::compression_method_string(uint8 code) {
    std::string value;
    if (0 == code) {
        value = "null";
    }
    return value;
}

std::string tls_advisor::alert_level_string(uint8 code) {
    std::string value;
    auto iter = _tls_alert_level.find(code);
    if (_tls_alert_level.end() != iter) {
        value = iter->second;
    }
    return value;
}
std::string tls_advisor::alert_desc_string(uint8 code) {
    std::string value;
    auto iter = _tls_alert_descriptions.find(code);
    if (_tls_alert_descriptions.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_advisor::sni_nametype_string(uint16 code) {
    std::string value;
    if (0 == code) {
        value = "hostname";
    }
    return value;
}

std::string tls_advisor::cert_status_type_string(uint8 code) {
    std::string value;
    auto iter = _cert_status_types.find(code);
    if (_cert_status_types.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_advisor::named_curve_string(uint16 code) {
    std::string value;
    auto iter = _named_curves.find(code);
    if (_named_curves.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_advisor::ec_point_format_string(uint8 code) {
    std::string value;
    auto iter = _ec_point_formats.find(code);
    if (_ec_point_formats.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_advisor::signature_scheme_string(uint16 code) {
    std::string value;
    auto iter = _signature_schemes.find(code);
    if (_signature_schemes.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_advisor::psk_key_exchange_mode_string(uint8 mode) {
    std::string value;
    auto iter = _psk_kem.find(mode);
    if (_psk_kem.end() != iter) {
        value = iter->second;
    }
    return value;
}

std::string tls_advisor::quic_param_string(uint16 code) {
    std::string value;
    auto iter = _quic_params.find(code);
    if (_quic_params.end() != iter) {
        value = iter->second;
    }
    return value;
}

}  // namespace net
}  // namespace hotplace
