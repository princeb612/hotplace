/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_sign_mldsa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_sign.hpp>

namespace hotplace {
namespace crypto {

crypto_sign_mldsa::crypto_sign_mldsa() : crypto_sign_digestsign() { _kty = kty_mldsa; }

crypto_sign_mldsa::~crypto_sign_mldsa() {}

}  // namespace crypto
}  // namespace hotplace
