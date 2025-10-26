/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

std::string tls_advisor::nameof_tls_alert_level(uint8 code) {
    std::string value;
    auto iter = _alert_level_codes.find(code);
    if (_alert_level_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}
std::string tls_advisor::nameof_tls_alert_desc(uint8 code) {
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

std::string tls_advisor::nameof_tls_cipher_suite(uint16 code) {
    std::string value;
    auto iter = _cipher_suite_codes.find(code);
    if (_cipher_suite_codes.end() != iter) {
        auto item = iter->second;
        value = item->name_iana;
    }
    return value;
}

uint16 tls_advisor::valueof_cipher_suite(const std::string& ciphersuite) {
    uint16 code = 0;
    auto iter = _cipher_suite_names.find(ciphersuite);
    if (_cipher_suite_names.end() != iter) {
        auto item = iter->second;
        code = item->code;
    }
    return code;
}

std::string tls_advisor::nameof_tls_record(uint8 type) {
    std::string value;
    auto iter = _content_type_codes.find(type);
    if (_content_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::nameof_ec_curve_type(uint8 code) {
    std::string value;
    auto iter = _ec_curve_type_codes.find(code);
    if (_ec_curve_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::nameof_ec_point_format(uint8 code) {
    std::string value;
    auto iter = _ec_point_format_codes.find(code);
    if (_ec_point_format_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

uint16 tls_advisor::valueof_ec_point_format(const std::string& name) {
    uint16 value = 0;
    auto iter = _ec_point_format_names.find(name);
    if (_ec_point_format_names.end() != iter) {
        auto item = iter->second;
        value = item->code;
    }
    return value;
}

std::string tls_advisor::nameof_tls_handshake(uint8 type) {
    std::string value;
    auto iter = _handshake_type_codes.find(type);
    if (_handshake_type_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::nameof_kdf_id(uint16 type) {
    std::string value;
    auto iter = _kdf_id_codes.find(type);
    if (_kdf_id_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

std::string tls_advisor::nameof_psk_key_exchange_mode(uint8 code) {
    std::string value;
    auto iter = _psk_keyexchange_codes.find(code);
    if (_psk_keyexchange_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

uint8 tls_advisor::valueof_psk_key_exchange_mode(const std::string& name) {
    uint8 value = 0;
    auto iter = _psk_keyexchange_names.find(name);
    if (_psk_keyexchange_names.end() != iter) {
        auto item = iter->second;
        value = item->code;
    }
    return value;
}

std::string tls_advisor::nameof_signature_scheme(uint16 code) {
    std::string value;
    auto iter = _sig_scheme_codes.find(code);
    if (_sig_scheme_codes.end() != iter) {
        auto item = iter->second;
        value = item->name;
    }
    return value;
}

uint16 tls_advisor::valueof_signature_scheme(const std::string& name) {
    uint16 value;
    auto iter = _sig_scheme_names.find(name);
    if (_sig_scheme_names.end() != iter) {
        auto item = iter->second;
        value = item->code;
    }
    return value;
}

std::string tls_advisor::nameof_group(uint16 code) {
    std::string value;
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_tls_group(code);
    if (hint && hint->name) {
        value = hint->name;
    }
    return value;
}

uint16 tls_advisor::valueof_group(const std::string& name) {
    uint16 value = 0;
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_tls_group(name);
    if (hint) {
        value = hint->group;
    }
    return value;
}

}  // namespace net
}  // namespace hotplace
