/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_EVP_KEY__
#define __HOTPLACE_SDK_CRYPTO_EVP_KEY__

#include <sdk/crypto/basic/openssl_sdk.hpp>
#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief curve
 * @param const EVP_PKEY* key [in]
 * @param uint32& nid [out]
 *    415 : NID_X9_62_prime256v1 (prime256v1)
 *    715 : NID_secp384r1 (secp384r1)
 *    716 : NID_secp521r1 (secp521r1)
 *    1087: NID_ED25519
 *    1088: NID_ED448
 * @remarks
 *    opensource native type
 *
 *    # define EVP_PKEY_HMAC     NID_hmac
 *    # define EVP_PKEY_RSA      NID_rsaEncryption
 *    # define EVP_PKEY_EC       NID_X9_62_id_ecPublicKey
 *    # define EVP_PKEY_X25519   NID_X25519
 *    # define EVP_PKEY_X448     NID_X448
 *    # define EVP_PKEY_ED25519  NID_ED25519
 *    # define EVP_PKEY_ED448    NID_ED448
 *
 *    #define NID_hmac                   855
 *    #define NID_rsaEncryption          6
 *    #define NID_X9_62_id_ecPublicKey   408
 *    #define NID_X25519                 1034
 *    #define NID_X448                   1035
 *    #define NID_ED25519                1087
 *    #define NID_ED448                  1088
 *
 *    #define NID_X9_62_prime256v1       415
 *    #define NID_secp384r1              715
 *    #define NID_secp521r1              716
 */
return_t nidof_evp_pkey(const EVP_PKEY* key, uint32& nid);
/**
 * @brief kindof
 * @param const EVP_PKEY* pkey [in]
 */
bool kindof_ecc(const EVP_PKEY* pkey);

/**
 * @param const EVP_PKEY* key [in]
 */
crypto_kty_t typeof_crypto_key(const EVP_PKEY* key);

/**
 * @brief is private key
 * @param const EVP_PKEY* pkey [in]
 * @param bool& result [out]
 * @return error code (see error.hpp)
 */
return_t is_private_key(const EVP_PKEY* pkey, bool& result);

/**
 * @brief kindof
 * @param crypto_kty_t type [in]
 */
bool kindof_ecc(crypto_kty_t type);
/**
 * @brief kty from key
 * @param crypto_kty_t type
 * @return oct, RSA, EC, OKP
 */
const char* nameof_key_type(crypto_kty_t type);
/**
 * @brief compare
 * @param const EVP_PKEY* pkey [in]
 * @param crypto_kty_t type [in]
 */
bool is_kindof(const EVP_PKEY* pkey, crypto_kty_t type);

}  // namespace crypto
}  // namespace hotplace

#endif
