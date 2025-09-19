/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/net/tls/tls/tls.hpp>
#include <hotplace/sdk/net/tls/tls_advisor.hpp>

namespace hotplace {
namespace net {

std::string tls_advisor::aead_alg_string(uint16 code) {
    std::string value;
    auto iter = _aead_alg_codes.find(code);
    if (_aead_alg_codes.end() != iter) {
        auto item = iter->second;
        value = item->desc;
    }
    return value;
}

}  // namespace net
}  // namespace hotplace
