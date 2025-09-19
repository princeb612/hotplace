/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2009.06.18   Soo Han, Kim        implemented (codename.merlin)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOAEAD__
#define __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOAEAD__

#include <hotplace/sdk/base/system/shared_instance.hpp>
#include <hotplace/sdk/crypto/basic/openssl_crypt.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @sample
 *          auto aead = builder.set_scheme(crypto_scheme_aes_128_gcm).build();
 *          if (aead) {
 *              // do something
 *              aead->release();
 *          }
 */
class crypto_aead_builder {
   public:
    crypto_aead_builder();

    crypto_aead* build();

    crypto_scheme_t get_scheme();
    crypto_aead_builder& set_scheme(crypto_scheme_t scheme);

   protected:
   private:
    crypto_scheme_t _scheme;
};

class crypto_aead {
   public:
    crypto_aead(crypto_scheme_t scheme);

    crypto_scheme_t get_scheme();

    return_t encrypt(const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag);
    return_t encrypt(const binary_t& key, const binary_t& iv, const unsigned char* stream, size_t size, binary_t& ciphertext, const binary_t& aad,
                     binary_t& tag);
    return_t decrypt(const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext, const binary_t& aad, const binary_t& tag);
    return_t decrypt(const binary_t& key, const binary_t& iv, const unsigned char* stream, size_t size, binary_t& plaintext, const binary_t& aad,
                     const binary_t& tag);

    void addref();
    void release();

   protected:
   private:
    t_shared_reference<crypto_aead> _shared;
    crypto_scheme_t _scheme;
};

}  // namespace crypto
}  // namespace hotplace

#endif
