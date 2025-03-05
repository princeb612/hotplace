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

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_CIPHERENCRYPT__
#define __HOTPLACE_SDK_CRYPTO_BASIC_CIPHERENCRYPT__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/types.hpp>

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
   private:
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
    cipher_encrypt_chacha20() : cipher_encrypt(chacha20, mode_cipher) {}
};

}  // namespace crypto
}  // namespace hotplace

#endif
