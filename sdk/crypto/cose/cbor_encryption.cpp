/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/crypto/cose/cbor_encryption.hpp>

namespace hotplace {
namespace crypto {

// O A128KW
// O A192KW
// O A256KW
// O DIRECT

// O RSA_OAEP_SHA1
// O RSA_OAEP_SHA256
// O RSA_OAEP_SHA512

// O HKDF_SHA_256
// O HKDF_SHA_512
// O HKDF_AES_128
// O HKDF_AES_256

// O ECDH_ES_HKDF_256
// O ECDH_ES_HKDF_512
// O ECDH_SS_HKDF_256
// O ECDH_SS_HKDF_512

// O ECDH_ES_A128KW
// O ECDH_ES_A192KW
// O ECDH_ES_A256KW
// O ECDH_ES_A128KW
// O ECDH_ES_A192KW
// O ECDH_ES_A256KW

// O AES_128_GCM
// O AES_192_GCM
// O AES_256_GCM

// test failed, trying
// X AES_CCM_16_64_128
// X AES_CCM_16_64_256
// X AES_CCM_64_64_128
// X AES_CCM_64_64_256
// X AES_CCM_16_128_128
// X AES_CCM_16_128_256
// X AES_CCM_64_128_128
// X AES_CCM_64_128_256

// O AES_CBC_MAC_128_64
// O AES_CBC_MAC_256_64
// O AES_CBC_MAC_128_128
// O AES_CBC_MAC_256_128

// O CHACHA20_POLY1305

}
}  // namespace
