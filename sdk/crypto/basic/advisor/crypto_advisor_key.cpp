/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>

namespace hotplace {
namespace crypto {

return_t crypto_advisor::nameof_kty(crypto_kty_t kty, std::string& name) {
    return_t ret = errorcode_t::success;
    __try2 {
        name.clear();

        auto iter = _kty_names.find(kty);
        if (_kty_names.end() == iter) {
            ret = errorcode_t::not_found;
            __leave2;
        } else {
            const hint_kty_name_t* item = iter->second;
            name = item->name;
        }
    }
    __finally2 {}
    return ret;
}

const char* crypto_advisor::nameof_kty(crypto_kty_t kty) {
    const char* value = "";
    auto iter = _kty_names.find(kty);
    if (_kty_names.end() != iter) {
        const auto* item = iter->second;
        value = item->name;
    }
    return value;
}

}  // namespace crypto
}  // namespace hotplace
