/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_hash_builder.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_advisor.hpp>
#include <hotplace/sdk/crypto/basic/crypto_hash.hpp>

namespace hotplace {
namespace crypto {

crypto_hash_builder::crypto_hash_builder() : _alg(hash_alg_unknown) {}

crypto_hash* crypto_hash_builder::build() { return new crypto_hash(_alg); }

crypto_hash_builder& crypto_hash_builder::set(hash_algorithm_t alg) {
    _alg = alg;
    return *this;
}

crypto_hash_builder& crypto_hash_builder::set(const char* alg) {
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_digest(alg);
    _alg = typeof_alg(hint);
    return *this;
}

crypto_hash_builder& crypto_hash_builder::set(const std::string& alg) {
    auto advisor = crypto_advisor::get_instance();
    auto hint = advisor->hintof_digest(alg);
    _alg = typeof_alg(hint);
    return *this;
}

}  // namespace crypto
}  // namespace hotplace
