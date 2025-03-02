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

#ifndef __HOTPLACE_SDK_CRYPTO_CRYPTO_ENCRYPT__
#define __HOTPLACE_SDK_CRYPTO_CRYPTO_ENCRYPT__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

class crypto_encrypt {
    friend class crypto_encrypt_builder;

   public:
    return_t encrypt(const EVP_PKEY* pkey, const binary_t& plaintext, binary_t& ciphertext);
    return_t encrypt(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& ciphertext);
    return_t decrypt(const EVP_PKEY* pkey, const binary_t& ciphertext, binary_t& plaintext);
    return_t decrypt(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& plaintext);

    void addref();
    void release();

   protected:
    crypto_encrypt(crypt_enc_t enc);

    t_shared_reference<crypto_encrypt> _shared;
    crypt_enc_t _enc;
};

class crypto_encrypt_rsa15 : public crypto_encrypt {
   public:
    crypto_encrypt_rsa15() : crypto_encrypt(rsa_1_5) {}
};
class crypto_encrypt_rsa_oaep : public crypto_encrypt {
   public:
    crypto_encrypt_rsa_oaep() : crypto_encrypt(rsa_oaep) {}
};
class crypto_encrypt_rsa_oaep256 : public crypto_encrypt {
   public:
    crypto_encrypt_rsa_oaep256() : crypto_encrypt(rsa_oaep256) {}
};
class crypto_encrypt_rsa_oaep384 : public crypto_encrypt {
   public:
    crypto_encrypt_rsa_oaep384() : crypto_encrypt(rsa_oaep384) {}
};
class crypto_encrypt_rsa_oaep512 : public crypto_encrypt {
   public:
    crypto_encrypt_rsa_oaep512() : crypto_encrypt(rsa_oaep512) {}
};

/**
 * @sample
 *          crypto_encrypt_builder builder;
 *          auto crypto = builder.set(rsa_1_5).build();
 *          if (crypto) {
 *              crypto->encrypt(pkey, plaintext, ciphertext);
 *              crypto->encrypt(pkey, ciphertext, plaintext);
 *              crypto->release();
 *          }
 */
class crypto_encrypt_builder {
   public:
    crypto_encrypt_builder();
    crypto_encrypt* build();

    crypto_encrypt_builder& set(crypt_enc_t enc);

   protected:
    crypt_enc_t _enc;
};

}  // namespace crypto
}  // namespace hotplace

#endif
