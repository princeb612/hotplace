/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_hmac.hpp>

namespace hotplace {
namespace crypto {

crypto_hmac_builder::crypto_hmac_builder() : _alg(hash_alg_unknown) {}

crypto_hmac_builder& crypto_hmac_builder::set(hash_algorithm_t alg) {
    _alg = alg;
    return *this;
}

crypto_hmac_builder& crypto_hmac_builder::set(const binary_t& key) {
    _key = key;
    return *this;
}

crypto_hmac* crypto_hmac_builder::build() { return new crypto_hmac(_alg, _key); }

}  // namespace crypto
}  // namespace hotplace
