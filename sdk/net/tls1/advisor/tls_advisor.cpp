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

hash_algorithm_t algof_mac(const tls_cipher_suite_t* info) {
    hash_algorithm_t alg = hash_alg_unknown;
    if (info) {
        alg = info->mac;
        switch (alg) {
            case md5:
            case sha1:
                // insecure algorithm promotion
                alg = sha2_256;
                break;
            default:
                break;
        }
    }
    return alg;
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
    for (auto i = 0; i < sizeof_tls_alert_level_codes; i++) {
        auto item = tls_alert_level_codes + i;
        _alert_level_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_alert_codes; i++) {
        auto item = tls_alert_codes + i;
        _alert_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_cipher_suites; i++) {
        auto item = tls_cipher_suites + i;
        _cipher_suite_codes.insert({item->code, item});
        if (item->name_iana) {
            _cipher_suite_names.insert({item->name_iana, item});
        }
        if (item->name_ossl) {
            _cipher_suite_names.insert({item->name_ossl, item});
        }
    }
    for (auto i = 0; i < sizeof_tls_content_type_codes; i++) {
        auto item = tls_content_type_codes + i;
        _content_type_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_ec_curve_type_codes; i++) {
        auto item = tls_ec_curve_type_codes + i;
        _ec_curve_type_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_ec_point_format_codes; i++) {
        auto item = tls_ec_point_format_codes + i;
        _ec_point_format_codes.insert({item->code, item});
        _ec_point_format_names.insert({item->desc, item});
    }
    for (auto i = 0; i < sizeof_tls_handshake_type_codes; i++) {
        auto item = tls_handshake_type_codes + i;
        _handshake_type_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_kdf_id_codes; i++) {
        auto item = tls_kdf_id_codes + i;
        _kdf_id_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_psk_keyexchange_codes; i++) {
        auto item = tls_psk_keyexchange_codes + i;
        _psk_keyexchange_codes.insert({item->code, item});
        _psk_keyexchange_names.insert({item->desc, item});
    }
    for (auto i = 0; i < sizeof_tls_sig_schemes; i++) {
        auto item = tls_sig_schemes + i;
        _sig_scheme_codes.insert({item->code, item});
        _sig_scheme_names.insert({item->name, item});
    }
    for (auto i = 0; i < sizeof_tls_groups; i++) {
        auto item = tls_groups + i;
        _supported_group_codes.insert({item->code, item});
        _supported_group_names.insert({item->name, item});
    }
}

void tls_advisor::load_tls_extensiontype_values() {
    // compression_alg_code
    for (auto i = 0; i < sizeof_tls_compression_alg_codes; i++) {
        auto item = tls_compression_alg_codes + i;
        _compression_alg_codes.insert({item->code, item});
        _compression_alg_names.insert({item->desc, item});
    }
    for (auto i = 0; i < sizeof_tls_extension_type_codes; i++) {
        auto item = tls_extension_type_codes + i;
        _extension_type_codes.insert({item->code, item});
    }
    for (auto i = 0; i < sizeof_tls_cert_status_type_codes; i++) {
        auto item = tls_cert_status_type_codes + i;
        _cert_status_type_codes.insert({item->code, item});
    }
}

void tls_advisor::load_tls_quic() {
    for (auto i = 0; i < sizeof_tls_quic_trans_param_codes; i++) {
        auto item = tls_quic_trans_param_codes + i;
        _quic_trans_param_codes.insert({item->code, item});
    }
}

void tls_advisor::load_tls_aead_parameters() {
    for (auto i = 0; i < sizeof_tls_aead_alg_codes; i++) {
        auto item = tls_aead_alg_codes + i;
        _aead_alg_codes.insert({item->code, item});
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
    auto iter = _cipher_suite_codes.find(code);
    if (_cipher_suite_codes.end() != iter) {
        item = iter->second;
    }
    return item;
}

const tls_cipher_suite_t* tls_advisor::hintof_cipher_suite(const std::string& name) {
    const tls_cipher_suite_t* item = nullptr;
    auto iter = _cipher_suite_names.find(name);
    if (_cipher_suite_names.end() != iter) {
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
    auto iter = _sig_scheme_codes.find(code);
    if (_sig_scheme_codes.end() != iter) {
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
    auto iter = _alert_level_codes.find(code);
    if (_alert_level_codes.end() != iter) {
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
    auto iter = _alert_codes.find(code);
    if (_alert_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::cipher_suite_string(uint16 code) {
    std::string value;
    auto iter = _cipher_suite_codes.find(code);
    if (_cipher_suite_codes.end() != iter) {
        auto item = iter->second;
        value = item->name_iana;
    }
    return value;
}

uint16 tls_advisor::cipher_suite_code(const std::string& ciphersuite) {
    uint16 code = 0;
    auto iter = _cipher_suite_names.find(ciphersuite);
    if (_cipher_suite_names.end() != iter) {
        auto item = iter->second;
        code = item->code;
    }
    return code;
}

std::string tls_advisor::content_type_string(uint8 type) {
    std::string value;
    auto iter = _content_type_codes.find(type);
    if (_content_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::ec_curve_type_string(uint8 code) {
    std::string value;
    auto iter = _ec_curve_type_codes.find(code);
    if (_ec_curve_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::ec_point_format_name(uint8 code) {
    std::string value;
    auto iter = _ec_point_format_codes.find(code);
    if (_ec_point_format_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

uint16 tls_advisor::ec_point_format_code(const std::string& name) {
    uint16 value = 0;
    auto iter = _ec_point_format_names.find(name);
    if (_ec_point_format_names.end() != iter) {
        auto item = iter->second;
        value = item->code;
    }
    return value;
}

std::string tls_advisor::handshake_type_string(uint8 type) {
    std::string value;
    auto iter = _handshake_type_codes.find(type);
    if (_handshake_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::kdf_id_string(uint16 type) {
    std::string value;
    auto iter = _kdf_id_codes.find(type);
    if (_kdf_id_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::psk_key_exchange_mode_name(uint8 code) {
    std::string value;
    auto iter = _psk_keyexchange_codes.find(code);
    if (_psk_keyexchange_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

uint8 tls_advisor::psk_key_exchange_mode_code(const std::string& name) {
    uint8 value = 0;
    auto iter = _psk_keyexchange_names.find(name);
    if (_psk_keyexchange_names.end() != iter) {
        auto item = iter->second;
        value = item->code;
    }
    return value;
}

std::string tls_advisor::signature_scheme_name(uint16 code) {
    std::string value;
    auto iter = _sig_scheme_codes.find(code);
    if (_sig_scheme_codes.end() != iter) {
        auto item = iter->second;
        value = item->name;
    }
    return value;
}

uint16 tls_advisor::signature_scheme_code(const std::string& name) {
    uint16 value;
    auto iter = _sig_scheme_names.find(name);
    if (_sig_scheme_names.end() != iter) {
        auto item = iter->second;
        value = item->code;
    }
    return value;
}

std::string tls_advisor::supported_group_name(uint16 code) {
    std::string value;
    auto iter = _supported_group_codes.find(code);
    if (_supported_group_codes.end() != iter) {
        auto item = iter->second;
        value = item->name;
    }
    return value;
}

uint16 tls_advisor::supported_group_code(const std::string& name) {
    uint16 value = 0;
    auto iter = _supported_group_names.find(name);
    if (_supported_group_names.end() != iter) {
        auto item = iter->second;
        value = item->code;
    }
    return value;
}

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml

std::string tls_advisor::compression_alg_name(uint16 code) {
    std::string value;
    auto iter = _compression_alg_codes.find(code);
    if (_compression_alg_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

uint16 tls_advisor::compression_alg_code(const std::string& name) {
    uint16 value = 0;
    auto iter = _compression_alg_names.find(name);
    if (_compression_alg_names.end() != iter) {
        auto item = iter->second;
        value = item->code;
    }
    return value;
}

std::string tls_advisor::tls_extension_string(uint16 code) {
    std::string value;
    auto iter = _extension_type_codes.find(code);
    if (_extension_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::cert_status_type_string(uint8 code) {
    std::string value;
    auto iter = _cert_status_type_codes.find(code);
    if (_cert_status_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

// https://www.iana.org/assignments/quic/quic.xhtml

std::string tls_advisor::quic_param_string(uint64 code) {
    std::string value;
    auto iter = _quic_trans_param_codes.find(code);
    if (_quic_trans_param_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

// https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml

std::string tls_advisor::aead_alg_string(uint16 code) {
    std::string value;
    auto iter = _aead_alg_codes.find(code);
    if (_aead_alg_codes.end() != iter) {
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
    } else if (1 == code) {
        value = "deflate";  // TLS 1.3 deprecated
        /**
         * RFC 3749 2.1.  DEFLATE Compression
         * RFC 5246 6.2.2.  Record Compression and Decompression
         *
         * RFC 8446 4.1.2.  Client Hello
         *   legacy_compression_methods
         *     ...
         *     For every TLS 1.3 ClientHello, this vector MUST contain exactly one byte, set to zero, which corresponds to
         *     the "null" compression method in prior versions of TLS.
         *     ...
         *     If a TLS 1.3 ClientHello is received with any other value in this field, the server MUST abort the handshake with an "illegal_parameter" alert.
         *     ...
         *
         * cf. CRIME attack (Compression Ratio Info-leak Made Easy)
         *     client-side attack
         *     server refuse 0x01 (deflate)
         */
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

bool tls_advisor::is_kindof_tls13(uint16 ver) { return (tls_13 == ver) || (dtls_13 == ver); }

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

bool tls_advisor::is_kindof(uint16 lhs, uint16 rhs) {
    bool ret = false;
    if ((tls_13 == lhs) || (dtls_13 == lhs)) {
        ret = (tls_13 == rhs) || (dtls_13 == rhs);
    } else if ((tls_12 == lhs) || (dtls_12 == lhs)) {
        ret = (tls_12 == rhs) || (dtls_12 == rhs);
    }
    return ret;
}

bool is_kindof_tls13(uint16 ver) { return tls_advisor::get_instance()->is_kindof_tls13(ver); }

bool is_kindof_tls(uint16 ver) { return tls_advisor::get_instance()->is_kindof_tls(ver); }

bool is_kindof_dtls(uint16 ver) { return tls_advisor::get_instance()->is_kindof_dtls(ver); }

}  // namespace net
}  // namespace hotplace
