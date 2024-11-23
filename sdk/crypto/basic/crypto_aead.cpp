/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/crypto/basic/crypto_aead.hpp>

namespace hotplace {
namespace crypto {

crypto_aead::crypto_aead(crypto_aead_scheme_t scheme) : _scheme(scheme) { _shared.make_share(this); }

crypto_aead_scheme_t crypto_aead::get_scheme() { return _scheme; }

void crypto_aead::addref() { _shared.addref(); }

void crypto_aead::release() { _shared.delref(); }

}  // namespace crypto
}  // namespace hotplace
