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

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/crypto/basic/openssl_crypt.hpp>
#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

enum crypto_aead_scheme_t : uint16 {
    aead_scheme_unknown = 0,
    aead_scheme_aes128_gcm = 1,
    aead_scheme_aes192_gcm = 2,
    aead_scheme_aes256_gcm = 3,
    aead_scheme_aes128_ccm = 4,
    aead_scheme_aes192_ccm = 5,
    aead_scheme_aes256_ccm = 6,
    aead_scheme_aes128_ccm8 = 7,
    aead_scheme_aes192_ccm8 = 8,
    aead_scheme_aes256_ccm8 = 9,
    aead_scheme_chacha20_poly1305 = 10,
    aead_scheme_aes128_cbc_hmac_sha2 = 11,
    aead_scheme_aes192_cbc_hmac_sha2 = 12,
    aead_scheme_aes256_cbc_hmac_sha2 = 13,
};

/**
 * @sample
 *          auto aead = builder.set_scheme(aead_scheme_aes128_gcm).build();
 *          if (aead) {
 *              // do something
 *              aead->release();
 *          }
 */
class crypto_aead_builder {
   public:
    crypto_aead_builder();

    crypto_aead* build();

    crypto_aead_scheme_t get_scheme();
    crypto_aead_builder& set_scheme(crypto_aead_scheme_t scheme);

   protected:
   private:
    crypto_aead_scheme_t _scheme;
};

class crypto_aead {
    friend class crypto_aead_builder;

   public:
    crypto_aead_scheme_t get_scheme();

    virtual return_t encrypt(const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag) = 0;
    virtual return_t encrypt(const binary_t& key, const binary_t& iv, const unsigned char* stream, size_t size, binary_t& ciphertext, const binary_t& aad,
                             binary_t& tag) = 0;
    virtual return_t decrypt(const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext, const binary_t& aad,
                             const binary_t& tag) = 0;
    virtual return_t decrypt(const binary_t& key, const binary_t& iv, const unsigned char* stream, size_t size, binary_t& plaintext, const binary_t& aad,
                             const binary_t& tag) = 0;

    void addref();
    void release();

   protected:
    crypto_aead(crypto_aead_scheme_t scheme);

   private:
    t_shared_reference<crypto_aead> _shared;
    crypto_aead_scheme_t _scheme;
};

class crypto_aead_aes : public crypto_aead {
   public:
    crypto_aead_aes(crypto_aead_scheme_t scheme);
    std::string algorithm_str();

    virtual return_t encrypt(const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag);
    virtual return_t encrypt(const binary_t& key, const binary_t& iv, const unsigned char* stream, size_t size, binary_t& ciphertext, const binary_t& aad,
                             binary_t& tag);
    virtual return_t decrypt(const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext, const binary_t& aad,
                             const binary_t& tag);
    virtual return_t decrypt(const binary_t& key, const binary_t& iv, const unsigned char* stream, size_t size, binary_t& plaintext, const binary_t& aad,
                             const binary_t& tag);
};

class crypto_aead_aes128gcm : public crypto_aead_aes {
   public:
    crypto_aead_aes128gcm() : crypto_aead_aes(aead_scheme_aes128_gcm) {}
};
class crypto_aead_aes192gcm : public crypto_aead_aes {
   public:
    crypto_aead_aes192gcm() : crypto_aead_aes(aead_scheme_aes192_gcm) {}
};
class crypto_aead_aes256gcm : public crypto_aead_aes {
   public:
    crypto_aead_aes256gcm() : crypto_aead_aes(aead_scheme_aes256_gcm) {}
};

class crypto_aead_aes128ccm : public crypto_aead_aes {
   public:
    crypto_aead_aes128ccm() : crypto_aead_aes(aead_scheme_aes128_ccm) {}
};
class crypto_aead_aes192ccm : public crypto_aead_aes {
   public:
    crypto_aead_aes192ccm() : crypto_aead_aes(aead_scheme_aes192_ccm) {}
};
class crypto_aead_aes256ccm : public crypto_aead_aes {
   public:
    crypto_aead_aes256ccm() : crypto_aead_aes(aead_scheme_aes256_ccm) {}
};

class crypto_aead_aes128ccm8 : public crypto_aead_aes {
   public:
    crypto_aead_aes128ccm8() : crypto_aead_aes(aead_scheme_aes128_ccm8) {}
};
class crypto_aead_aes192ccm8 : public crypto_aead_aes {
   public:
    crypto_aead_aes192ccm8() : crypto_aead_aes(aead_scheme_aes192_ccm8) {}
};
class crypto_aead_aes256ccm8 : public crypto_aead_aes {
   public:
    crypto_aead_aes256ccm8() : crypto_aead_aes(aead_scheme_aes256_ccm8) {}
};

// class aead_scheme_aes192_cbc_hmac_sha2 : public crypto_aead {};

/**
 * @brief   sample
 *          openssl_chacha20_iv(nonce, counter, iv);
 *          crypto_aead_chacha20_poly1305 crypt;
 */
class crypto_aead_chacha20_poly1305 : public crypto_aead {
   public:
    crypto_aead_chacha20_poly1305();

    virtual return_t encrypt(const binary_t& key, const binary_t& nonce, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag);
    virtual return_t encrypt(const binary_t& key, const binary_t& nonce, const unsigned char* stream, size_t size, binary_t& ciphertext, const binary_t& aad,
                             binary_t& tag);
    virtual return_t decrypt(const binary_t& key, const binary_t& nonce, const binary_t& ciphertext, binary_t& plaintext, const binary_t& aad,
                             const binary_t& tag);
    virtual return_t decrypt(const binary_t& key, const binary_t& nonce, const unsigned char* stream, size_t size, binary_t& plaintext, const binary_t& aad,
                             const binary_t& tag);
};

// class crypto_aead_aes_cbc_hmac_sha2 : public crypto_aead { ... };

}  // namespace crypto
}  // namespace hotplace

#endif
