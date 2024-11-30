/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/crypto/crypto_mac.hpp>

namespace hotplace {
namespace crypto {

crypto_hmac::crypto_hmac(hash_algorithm_t alg) : _alg(alg) { _shared.make_share(this); }

return_t crypto_hmac::mac(const binary_t& key, const binary_t& input, binary_t& output) { return mac(key, &input[0], input.size(), output); }

return_t crypto_hmac::mac(const binary_t& key, const byte_t* stream, size_t size, binary_t& output) {
    return_t ret = errorcode_t::success;
    openssl_mac ossl;
    ossl.hmac(get_digest(), key, stream, size, output);
    return ret;
}

hash_algorithm_t crypto_hmac::get_digest() { return _alg; }

void crypto_hmac::addref() { _shared.addref(); }

void crypto_hmac::release() { _shared.delref(); }

crypto_hmac_builder::crypto_hmac_builder() : _alg(hash_alg_unknown) {}

crypto_hmac_builder& crypto_hmac_builder::set(hash_algorithm_t alg) {
    _alg = alg;
    return *this;
}

crypto_hmac* crypto_hmac_builder::build() { return new crypto_hmac(_alg); }

}  // namespace crypto
}  // namespace hotplace
