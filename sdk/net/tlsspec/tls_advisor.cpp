/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/net/tlsspec/tlsspec.hpp>

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
    load_named_curves();
    load_ec_point_formats();
    load_signature_schemes();
    load_psk_kems();
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
    _cipher_suites.insert({0x1301, "TLS_AES_128_GCM_SHA256"});        // madatory, MUST
    _cipher_suites.insert({0x1302, "TLS_AES_256_GCM_SHA384"});        // madatory, SHOULD
    _cipher_suites.insert({0x1303, "TLS_CHACHA20_POLY1305_SHA256"});  // madatory, SHOULD
    _cipher_suites.insert({0x1304, "TLS_AES_128_CCM_SHA256"});
    _cipher_suites.insert({0x1305, "TLS_AES_128_CCM_8_SHA256"});
    // RFC 5246 A.5.  The Cipher Suite
    _cipher_suites.insert({0x0000, "TLS_NULL_WITH_NULL_NULL"});  // MUST NOT be negotiated
    _cipher_suites.insert({0x0001, "TLS_RSA_WITH_NULL_MD5"});
    _cipher_suites.insert({0x0001, "TLS_RSA_WITH_NULL_MD5"});
    _cipher_suites.insert({0x0002, "TLS_RSA_WITH_NULL_SHA"});
    _cipher_suites.insert({0x003b, "TLS_RSA_WITH_NULL_SHA256"});
    _cipher_suites.insert({0x0004, "TLS_RSA_WITH_RC4_128_MD5"});
    _cipher_suites.insert({0x0005, "TLS_RSA_WITH_RC4_128_SHA"});
    _cipher_suites.insert({0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x0036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x003e, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x003f, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x0040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x0068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x0069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x006a, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"});
    _cipher_suites.insert({0x0018, "TLS_DH_anon_WITH_RC4_128_MD5"});
    _cipher_suites.insert({0x001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"});
    _cipher_suites.insert({0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA"});
    _cipher_suites.insert({0x003a, "TLS_DH_anon_WITH_AES_256_CBC_SHA"});
    _cipher_suites.insert({0x006c, "TLS_DH_anon_WITH_AES_128_CBC_SHA256"});
    _cipher_suites.insert({0x006d, "TLS_DH_anon_WITH_AES_256_CBC_SHA256"});

    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    _cipher_suites.insert({0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"});

    for (auto i = 0; i < RTL_NUMBER_OF(tls_alg_info); i++) {
        auto item = tls_alg_info + i;
        _tls_alg_info.insert({item->alg, item});
    }
}

void tls_advisor::load_named_curves() {
    _named_curves.insert({0x0017, "secp256r1"});
    _named_curves.insert({0x0018, "secp384r1"});
    _named_curves.insert({0x0019, "secp521r1"});
    _named_curves.insert({0x001d, "x25519"});
    _named_curves.insert({0x001e, "x448"});
    // RFC 7919 Negotiated Finite Field Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS)
    _named_curves.insert({0x0100, "ffdhe2048"});
    _named_curves.insert({0x0101, "ffdhe3072"});
    _named_curves.insert({0x0102, "ffdhe4096"});
    _named_curves.insert({0x0103, "ffdhe6144"});
    _named_curves.insert({0x0104, "ffdhe8192"});
}

void tls_advisor::load_ec_point_formats() {
    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    _ec_point_formats.insert({0, "uncompressed"});
    _ec_point_formats.insert({1, "ansiX962_compressed_prime"});
    _ec_point_formats.insert({2, "ansiX962_compressed_char2"});
}

void tls_advisor::load_signature_schemes() {
    _signature_schemes.insert({0x0401, "rsa_pkcs1_sha256"});
    _signature_schemes.insert({0x0501, "rsa_pkcs1_sha384"});
    _signature_schemes.insert({0x0601, "rsa_pkcs1_sha512"});
    _signature_schemes.insert({0x0403, "ecdsa_secp256r1_sha256"});
    _signature_schemes.insert({0x0503, "ecdsa_secp384r1_sha384"});
    _signature_schemes.insert({0x0603, "ecdsa_secp521r1_sha512"});
    _signature_schemes.insert({0x0804, "rsa_pss_rsae_sha256"});
    _signature_schemes.insert({0x0805, "rsa_pss_rsae_sha384"});
    _signature_schemes.insert({0x0806, "rsa_pss_rsae_sha512"});
    _signature_schemes.insert({0x0807, "ed25519"});
    _signature_schemes.insert({0x0808, "ed448"});
    _signature_schemes.insert({0x0809, "rsa_pss_pss_sha256"});
    _signature_schemes.insert({0x080a, "rsa_pss_pss_sha384"});
    _signature_schemes.insert({0x080b, "rsa_pss_pss_sha512"});
    _signature_schemes.insert({0x0201, "rsa_pkcs1_sha1"});
    _signature_schemes.insert({0x0203, "ecdsa_sha1"});

    _signature_schemes.insert({0x0202, "dsa_sha1_RESERVED"});
    _signature_schemes.insert({0x0402, "dsa_sha256_RESERVED"});
    _signature_schemes.insert({0x0502, "dsa_sha384_RESERVED"});
    _signature_schemes.insert({0x0602, "dsa_sha512_RESERVED"});
}

void tls_advisor::load_psk_kems() {
    _psk_kem.insert({0, "psk_ke"});      // PSK-only key establishment
    _psk_kem.insert({1, "psk_dhe_ke"});  // PSK with (EC)DHE key establishment
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

std::string tls_advisor::sni_nametype_string(uint16 code) {
    std::string value;
    if (0 == code) {
        value = "hostname";
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
