/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_OPENSSLECDH__
#define __HOTPLACE_SDK_CRYPTO_BASIC_OPENSSLECDH__

#include <hotplace/sdk/crypto/basic/openssl_sdk.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief   public key of peer
 * @example
 *          const EVP_PKEY* alicePublicKey = get_public_key (alicePrivateKey);
 *          crypto_key_free ((EVP_PKEY*)alicePublicKey);
 */
const EVP_PKEY* get_public_key(const EVP_PKEY* pkey);
/**
 * @brief   Diffie–Hellman key exchange
 * @example
 *          crypto_key keys;
 *          crypto_keychain keyset;
 *
 *          binary_t x_alice;
 *          binary_t y_alice;
 *          binary_t d_alice;
 *          binary_t x_bob;
 *          binary_t y_bob;
 *          binary_t d_bob;
 *          binary_t secret_alice;
 *          binary_t secret_bob;
 *
 *          keyset.add_ec (&keys, "alice", NID_secp384r1);
 *          keyset.add_ec (&keys, "bob", NID_secp384r1);
 *
 *          const EVP_PKEY* alicePrivateKey = keys.find ("alice", crypto_kty_t::kty_ec);
 *          const EVP_PKEY* bobPrivateKey = keys.find ("bob", crypto_kty_t::kty_ec);
 *
 *          const EVP_PKEY* alicePublicKey = get_public_key (alicePrivateKey);
 *          const EVP_PKEY* bobPublicKey = get_public_key (bobPrivateKey);
 *
 *          keys.get_public_key (alicePrivateKey, x_alice, y_alice);
 *          keys.get_private_key (alicePrivateKey, d_alice);
 *          keys.get_public_key (bobPrivateKey, x_bob, y_bob);
 *          keys.get_private_key (bobPrivateKey, d_bob);
 *
 *          dh_key_agreement (alicePrivateKey, bobPublicKey, secret_alice);
 *          dh_key_agreement (bobPrivateKey, alicePublicKey, secret_bob);
 *
 *          crypto_key_free ((EVP_PKEY*)alicePublicKey);
 *          crypto_key_free ((EVP_PKEY*)bobPublicKey);
 */
return_t dh_key_agreement(const EVP_PKEY* privkey, const EVP_PKEY* pubkey, binary_t& secret);

binary_t kdf_parameter_int(uint32 source);
binary_t kdf_parameter_string(const char* source);
binary_t kdf_parameter_string(const byte_t* source, uint32 sourcelen);
return_t ecdh_es(const EVP_PKEY* pkey, const EVP_PKEY* peer, const char* algid, const char* apu, const char* apv, uint32 keylen, binary_t& derived);
return_t compose_otherinfo(const char* algid, const char* apu, const char* apv, uint32 keybits, binary_t& otherinfo);
return_t concat_kdf(binary_t dh_secret, binary_t otherinfo, unsigned int keylen, binary_t& derived);

}  // namespace crypto
}  // namespace hotplace

#endif
