/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/net/tls1/tls.hpp>
#include <sdk/net/tls1/tls_advisor.hpp>

namespace hotplace {
namespace net {

hash_algorithm_t algof_mac(const tls_cipher_suite_t* info) { return info ? info->mac : hash_alg_unknown; }

hash_algorithm_t algof_mac1(const tls_cipher_suite_t* info) {
    hash_algorithm_t hash_alg = hash_alg_unknown;
    if (info) {
        hash_alg = (info->mac_tls1) ? info->mac_tls1 : info->mac;
    }
    return hash_alg;
}

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
    load_tls_parameters();
    load_tls_extensiontype_values();
    load_tls_quic();
    load_tls_aead_parameters();

    load_tls_version();
}

void tls_advisor::load_tls_parameters() {
    // code, name
    for (auto i = 0; i < sizeof_tls_alert_level_descs; i++) {
        auto item = tls_alert_level_descs + i;
        _alert_level_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_alert_descs; i++) {
        auto item = tls_alert_descs + i;
        _alert_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_cipher_suite_descs; i++) {
        auto item = tls_cipher_suite_descs + i;
        _cipher_suite_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_content_type_descs; i++) {
        auto item = tls_content_type_descs + i;
        _content_type_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_ec_curve_type_descs; i++) {
        auto item = tls_ec_curve_type_descs + i;
        _ec_curve_type_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_ec_point_format_descs; i++) {
        auto item = tls_ec_point_format_descs + i;
        _ec_point_format_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_handshake_type_descs; i++) {
        auto item = tls_handshake_type_descs + i;
        _handshake_type_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_kdf_id_descs; i++) {
        auto item = tls_kdf_id_descs + i;
        _kdf_id_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_psk_keyexchange_descs; i++) {
        auto item = tls_psk_keyexchange_descs + i;
        _psk_keyexchange_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_sig_schemes; i++) {
        auto item = tls_sig_schemes + i;
        _sig_schemes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_supported_group_descs; i++) {
        auto item = tls_supported_group_descs + i;
        _supported_group_descs.insert({item->code, item});
    }

    // cipher suites
    for (auto i = 0; i < sizeof_tls_cipher_suites; i++) {
        auto item = tls_cipher_suites + i;
        _cipher_suites.insert({item->alg, item});
    }
}

void tls_advisor::load_tls_extensiontype_values() {
    // cert_compression_algid_desc
    for (auto i = 0; i < sizeof_tls_cert_compression_algid_descs; i++) {
        auto item = tls_cert_compression_algid_descs + i;
        _cert_compression_algid_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_extension_type_descs; i++) {
        auto item = tls_extension_type_descs + i;
        _extension_type_descs.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_cert_status_type_descs; i++) {
        auto item = tls_cert_status_type_descs + i;
        _cert_status_type_descs.insert({item->code, item});
    }
}

void tls_advisor::load_tls_quic() {
    for (auto i = 0; i < sizeof_tls_quic_trans_param_descs; i++) {
        auto item = tls_quic_trans_param_descs + i;
        _quic_trans_param_descs.insert({item->code, item});
    }
}

void tls_advisor::load_tls_aead_parameters() {
    for (auto i = 0; i < sizeof_tls_aead_alg_descs; i++) {
        auto item = tls_aead_alg_descs + i;
        _aead_alg_descs.insert({item->code, item});
    }
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
    _tls_version.insert({0xfefc, "DTLS 1.3"});
    _tls_version.insert({0xfefd, "DTLS 1.2"});

    // deprecated
    _tls_version.insert({0x0302, "TLS v1.1"});  // RFC 4346 A.1. Record Layer
    _tls_version.insert({0x0301, "TLS v1.0"});  // RFC 2246 A.1. Record layer
}

const tls_cipher_suite_t* tls_advisor::hintof_cipher_suite(uint16 code) {
    const tls_cipher_suite_t* item = nullptr;
    auto iter = _cipher_suites.find(code);
    if (_cipher_suites.end() != iter) {
        item = iter->second;
    }
    return item;
}

const hint_blockcipher_t* tls_advisor::hintof_blockcipher(uint16 code) {
    const hint_blockcipher_t* hint = nullptr;
    auto hint_alg = hintof_cipher_suite(code);
    if (hint_alg) {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        hint = advisor->hintof_blockcipher(hint_alg->cipher);
    }
    return hint;
}

const hint_digest_t* tls_advisor::hintof_digest(uint16 code) {
    const hint_digest_t* hint = nullptr;
    auto hint_alg = hintof_cipher_suite(code);
    if (hint_alg) {
        crypto_advisor* advisor = crypto_advisor::get_instance();
        hint = advisor->hintof_digest(hint_alg->mac);
    }
    return hint;
}

const tls_sig_scheme_t* tls_advisor::hintof_signature_scheme(uint16 code) {
    const tls_sig_scheme_t* hint = nullptr;
    auto iter = _sig_schemes.find(code);
    if (_sig_schemes.end() != iter) {
        hint = iter->second;
    }
    return hint;
}

hash_algorithm_t tls_advisor::hash_alg_of(uint16 code) {
    hash_algorithm_t alg = hash_alg_unknown;
    const tls_cipher_suite_t* hint_tls_alg = hintof_cipher_suite(code);
    if (hint_tls_alg) {
        alg = hint_tls_alg->mac;
    }
    return alg;
}

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

std::string tls_advisor::alert_level_string(uint8 code) {
    std::string value;
    auto iter = _alert_level_descs.find(code);
    if (_alert_level_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}
std::string tls_advisor::alert_desc_string(uint8 code) {
    /**
     * RFC 5246 7.2.  Alert Protocol
     * RFC 8446 6.  Alert Protocol
     */
    std::string value;
    auto iter = _alert_descs.find(code);
    if (_alert_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::cipher_suite_string(uint16 code) {
    std::string value;
    auto iter = _cipher_suite_descs.find(code);
    if (_cipher_suite_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::content_type_string(uint8 type) {
    std::string value;
    auto iter = _content_type_descs.find(type);
    if (_content_type_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::ec_curve_type_string(uint8 code) {
    std::string value;
    auto iter = _ec_curve_type_descs.find(code);
    if (_ec_curve_type_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::ec_point_format_string(uint8 code) {
    std::string value;
    auto iter = _ec_point_format_descs.find(code);
    if (_ec_point_format_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::handshake_type_string(uint8 type) {
    std::string value;
    auto iter = _handshake_type_descs.find(type);
    if (_handshake_type_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::kdf_id_string(uint16 type) {
    std::string value;
    auto iter = _kdf_id_descs.find(type);
    if (_kdf_id_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::psk_key_exchange_mode_string(uint8 mode) {
    std::string value;
    auto iter = _psk_keyexchange_descs.find(mode);
    if (_psk_keyexchange_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::signature_scheme_string(uint16 code) {
    std::string value;
    auto iter = _sig_schemes.find(code);
    if (_sig_schemes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::supported_group_string(uint16 code) {
    std::string value;
    auto iter = _supported_group_descs.find(code);
    if (_supported_group_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml

std::string tls_advisor::cert_compression_algid_string(uint16 code) {
    std::string value;
    auto iter = _cert_compression_algid_descs.find(code);
    if (_cert_compression_algid_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::tls_extension_string(uint16 code) {
    std::string value;
    auto iter = _extension_type_descs.find(code);
    if (_extension_type_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::cert_status_type_string(uint8 code) {
    std::string value;
    auto iter = _cert_status_type_descs.find(code);
    if (_cert_status_type_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

// https://www.iana.org/assignments/quic/quic.xhtml

std::string tls_advisor::quic_param_string(uint64 code) {
    std::string value;
    auto iter = _quic_trans_param_descs.find(code);
    if (_quic_trans_param_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

// https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml

std::string tls_advisor::aead_alg_string(uint16 code) {
    std::string value;
    auto iter = _aead_alg_descs.find(code);
    if (_aead_alg_descs.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

// etc

std::string tls_advisor::tls_version_string(uint16 code) {
    std::string value;
    auto iter = _tls_version.find(code);
    if (_tls_version.end() != iter) {
        value = iter->second;
    }
    return value;
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

bool tls_advisor::is_basedon_tls13(uint16 ver) { return (tls_13 == ver) || (dtls_13 == ver); }

bool tls_advisor::is_kindof_tls(uint16 ver) {
    bool ret = false;
    switch (ver) {
        case tls_10:
        case tls_11:
        case tls_12:
        case tls_13:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

bool tls_advisor::is_kindof_dtls(uint16 ver) {
    bool ret = false;
    switch (ver) {
        case dtls_12:
        case dtls_13:
            ret = true;
            break;
        default:
            break;
    }
    return ret;
}

bool is_basedon_tls13(uint16 ver) { return tls_advisor::get_instance()->is_basedon_tls13(ver); }

bool is_kindof_tls(uint16 ver) { return tls_advisor::get_instance()->is_kindof_tls(ver); }

bool is_kindof_dtls(uint16 ver) { return tls_advisor::get_instance()->is_kindof_dtls(ver); }

}  // namespace net
}  // namespace hotplace
