/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_sign.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_sign.hpp>

namespace hotplace {
namespace crypto {

crypto_sign::crypto_sign(hash_algorithm_t hashalg) : _category(sig_category_t::dgst), _hashalg(hashalg), _saltlen(-1) { _shared.make_share(this); }

crypto_sign::~crypto_sign() {}

void crypto_sign::set_category(sig_category_t category) { _category = category; }

void crypto_sign::set_saltlen(int saltlen) { _saltlen = saltlen; }

sig_category_t crypto_sign::get_category() { return _category; }

hash_algorithm_t crypto_sign::get_digest() { return _hashalg; }

int crypto_sign::get_saltlen() { return _saltlen; }

void crypto_sign::addref() { _shared.addref(); }

void crypto_sign::release() { _shared.delref(); }

}  // namespace crypto
}  // namespace hotplace
