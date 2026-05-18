/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_sign_eddsa.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/crypto/basic/crypto_sign.hpp>

namespace hotplace {
namespace crypto {

crypto_sign_eddsa::crypto_sign_eddsa() : crypto_sign_digestsign() { _kty = kty_okp; }

crypto_sign_eddsa::~crypto_sign_eddsa() {}

}  // namespace crypto
}  // namespace hotplace
