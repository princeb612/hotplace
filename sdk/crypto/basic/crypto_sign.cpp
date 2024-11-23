/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_sign.hpp>

namespace hotplace {
namespace crypto {

crypto_sign::crypto_sign(hash_algorithm_t hashalg) : _hashalg(hashalg) { _shared.make_share(this); }

hash_algorithm_t crypto_sign::get_digest() { return _hashalg; }

void crypto_sign::addref() { _shared.addref(); }

void crypto_sign::release() { _shared.delref(); }

}  // namespace crypto
}  // namespace hotplace
