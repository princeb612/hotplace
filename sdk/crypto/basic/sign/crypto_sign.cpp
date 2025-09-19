/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_sign.hpp>

namespace hotplace {
namespace crypto {

crypto_sign::crypto_sign(hash_algorithm_t hashalg) : _scheme(crypt_sig_dgst), _hashalg(hashalg), _saltlen(-1) { _shared.make_share(this); }

void crypto_sign::set_scheme(crypt_sig_type_t scheme) { _scheme = scheme; }

void crypto_sign::set_saltlen(int saltlen) { _saltlen = saltlen; }

crypt_sig_type_t crypto_sign::get_scheme() { return _scheme; }

hash_algorithm_t crypto_sign::get_digest() { return _hashalg; }

int crypto_sign::get_saltlen() { return _saltlen; }

void crypto_sign::addref() { _shared.addref(); }

void crypto_sign::release() { _shared.delref(); }

}  // namespace crypto
}  // namespace hotplace
