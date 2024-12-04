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
#include <sdk/crypto/crypto/types.hpp>

namespace hotplace {
namespace crypto {

class cipher_encrypt {
   public:
    cipher_encrypt(crypt_algorithm_t alg, crypt_mode_t mode);

    return_t encrypt(const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext);
    return_t encrypt(const binary_t& key, const binary_t& iv, const byte_t* stream, size_t size, binary_t& ciphertext);
    return_t decrypt(const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext);
    return_t decrypt(const binary_t& key, const binary_t& iv, const byte_t* stream, size_t size, binary_t& plaintext);

    void addref();
    void release();

   protected:
    t_shared_reference<cipher_encrypt> _shared;
    crypt_algorithm_t _alg;
    crypt_mode_t _mode;
};

/**
 * @sample
 *          cipher_encrypt_builder builder;
 *          auto cipher = builder.set(aes128, cbc).build();
 *          if(cipher) {
 *              cipher->encrypt(key, iv, plaintext, ciphertext);
 *              cipher->decrypt(key, iv, ciphertext, plaintext);
 *              cipher->release();
 *          }
 */
class cipher_encrypt_builder {
   public:
    cipher_encrypt_builder();
    cipher_encrypt* build();

    cipher_encrypt_builder& set(crypt_algorithm_t alg, crypt_mode_t mode);

   protected:
    crypt_algorithm_t _alg;
    crypt_mode_t _mode;
};

class cipher_encrypt_aes128cbc : public cipher_encrypt {
   public:
    cipher_encrypt_aes128cbc() : cipher_encrypt(aes128, cbc) {}
};
class cipher_encrypt_aes128cfb : public cipher_encrypt {
   public:
    cipher_encrypt_aes128cfb() : cipher_encrypt(aes128, cfb) {}
};
class cipher_encrypt_aes128ofb : public cipher_encrypt {
   public:
    cipher_encrypt_aes128ofb() : cipher_encrypt(aes128, ofb) {}
};

class cipher_encrypt_aes192cbc : public cipher_encrypt {
   public:
    cipher_encrypt_aes192cbc() : cipher_encrypt(aes192, cbc) {}
};
class cipher_encrypt_aes192cfb : public cipher_encrypt {
   public:
    cipher_encrypt_aes192cfb() : cipher_encrypt(aes192, cfb) {}
};
class cipher_encrypt_aes192ofb : public cipher_encrypt {
   public:
    cipher_encrypt_aes192ofb() : cipher_encrypt(aes192, ofb) {}
};

class cipher_encrypt_aes256cbc : public cipher_encrypt {
   public:
    cipher_encrypt_aes256cbc() : cipher_encrypt(aes256, cbc) {}
};
class cipher_encrypt_aes256cfb : public cipher_encrypt {
   public:
    cipher_encrypt_aes256cfb() : cipher_encrypt(aes256, cfb) {}
};
class cipher_encrypt_aes256ofb : public cipher_encrypt {
   public:
    cipher_encrypt_aes256ofb() : cipher_encrypt(aes256, ofb) {}
};

class cipher_encrypt_chacha20 : public cipher_encrypt {
   public:
    cipher_encrypt_chacha20() : cipher_encrypt(chacha20, crypt_cipher) {}
};

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
