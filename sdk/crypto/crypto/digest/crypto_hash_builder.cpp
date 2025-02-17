/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/crypto/crypto_hash.hpp>

namespace hotplace {
namespace crypto {

crypto_hash_builder::crypto_hash_builder() : _alg(hash_alg_unknown) {}

crypto_hash* crypto_hash_builder::build() {
    crypto_hash* obj = nullptr;
    __try_new_catch_only(obj, new crypto_hash(_alg));
    return obj;
}

crypto_hash_builder& crypto_hash_builder::set(hash_algorithm_t alg) {
    _alg = alg;
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
