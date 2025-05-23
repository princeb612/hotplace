/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_advisor.hpp>
#include <sdk/net/tls/tls/tls.hpp>
#include <sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

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

}  // namespace net
}  // namespace hotplace
