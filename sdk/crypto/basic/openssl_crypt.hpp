/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm (September 2002)
 *  RFC 5649 Advanced Encryption Starndard (AES) Key Wrap with Padding Algorithm (September 2009)
 *  RFC 8017 PKCS #1: RSA Cryptography Specifications Version 2.2
 *
 * Revision History
 * Date         Name                Description
 * 2009.06.18   Soo Han, Kim        implemented (codename.merlin)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPT__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_CRYPT__

#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto.hpp>

namespace hotplace {
namespace crypto {

typedef struct _encrypt_option_t {
    crypt_ctrl_t ctrl;
    uint16 value;
} encrypt_option_t;

/**
 * @brief openssl_crypt
 * @example
 *          constexpr byte_t data_plain[] = "still a man hears what he wants to hear and disregards the rest";
 *          size_t size_plain = RTL_NUMBER_OF (data_plain);
 *
 *          openssl_crypt crypt;
 *          crypt_context_t* handle = nullptr;
 *          binary_t data_encrypted;
 *          binary_t data_decrypted;
 *
 *          // key
 *          binary_t key;
 *          binary_t iv;
 *          key.resize (32);
 *          iv.resize (32);
 *          for (int i = 0; i < 32; i++) {
 *              key[i] = i;
 *              iv[i] = i;
 *          }
 *
 *          // block cipher
 *          {
 *              crypt.open (&handle, crypt_algorithm_t::aes256, crypt_mode_t::cbc, &key[0], key.size (), &iv[0], iv.size ());
 *              crypt.encrypt (handle, data_plain, size_plain, data_encrypted);
 *              crypt.decrypt (handle, &data_encrypted[0], data_encrypted.size (), data_decrypted);
 *              crypt.close (handle);
 *          }
 *
 *          // AEAD
 *          {
 *              binary_t aad;
 *              binary_t tag;
 *              openssl_prng rand;
 *              rand.random (aad, 32);
 *              crypt.open (&handle, crypt_algorithm_t::aes256, crypt_mode_t::gcm, &key[0], key.size (), &iv[0], iv.size ());
 *              crypt.encrypt2 (handle, data_plain, size_plain, data_encrypted, &aad, &tag);
 *              crypt.decrypt2 (handle, &data_encrypted[0], data_encrypted.size (), data_decrypted, &aad, &tag);
 *              crypt.close (handle);
 *          }
 */
class openssl_crypt : public crypt_t {
   public:
    /**
     * @brief constructor
     */
    openssl_crypt();
    /**
     * @brief destructor
     */
    virtual ~openssl_crypt();

    /**
     * @brief create a context handle (symmetric)
     * @param crypt_context_t** handle [out]
     * @param crypt_algorithm_t algorithm [in]
     * @param crypt_mode_t mode [in]
     * @param const unsigned char* key [in]
     * @param unsigned size_key [in]
     * @param const unsigned char* iv [in] see openssl_chacha20_iv in case of crypt_algorithm_t::chacha20
     * @param unsigned size_iv [in]
     * @return error code (see error.hpp)
     * @example
     *        openssl_crypt crypt;
     *        crypt_context_t* handle = nullptr;
     *        crypt.open(&handle, crypt_algorithm_t::aes256, crypt_mode_t::cbc, key, size_key, iv, size_iv);
     *        crypt.close(handle);
     */
    virtual return_t open(crypt_context_t** handle, crypt_algorithm_t algorithm, crypt_mode_t mode, const unsigned char* key, unsigned size_key,
                          const unsigned char* iv, unsigned size_iv);
    /**
     * @brief create a context handle (symmetric)
     * @param crypt_context_t** handle [out]
     * @param crypt_algorithm_t algorithm [in]
     * @param crypt_mode_t mode [in]
     * @param const binary_t& key [in]
     * @param const binary_t& iv [in]
     * @return error code (see error.hpp)
     */
    virtual return_t open(crypt_context_t** handle, crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv);
    /**
     * @brief create a context handle (symmetric)
     * @param crypt_context_t** handle [out]
     * @param const char* cipher [in]
     *      "aes-128-cbc", "aes-128-ccm", "aes-128-cfb", "aes-128-cfb1", "aes-128-cfb8", "aes-128-ctr", "aes-128-ecb", "aes-128-gcm", "aes-128-ofb",
     *      "aes-192-cbc", "aes-192-ccm", "aes-192-cfb", "aes-192-cfb1", "aes-192-cfb8", "aes-192-ctr", "aes-192-ecb", "aes-192-gcm", "aes-192-ofb",
     *      "aes-256-cbc", "aes-256-ccm", "aes-256-cfb", "aes-256-cfb1", "aes-256-cfb8", "aes-256-ctr", "aes-256-ecb", "aes-256-gcm", "aes-256-ofb",
     *      "aria-128-cbc", "aria-128-ccm", "aria-128-cfb", "aria-128-cfb1", "aria-128-cfb8", "aria-128-ctr", "aria-128-ecb", "aria-128-gcm", "aria-128-ofb",
     *      "aria-192-cbc", "aria-192-ccm", "aria-192-cfb", "aria-192-cfb1", "aria-192-cfb8", "aria-192-ctr", "aria-192-ecb", "aria-192-gcm", "aria-192-ofb",
     *      "aria-256-cbc", "aria-256-ccm", "aria-256-cfb", "aria-256-cfb1", "aria-256-cfb8", "aria-256-ctr", "aria-256-ecb", "aria-256-gcm", "aria-256-ofb",
     *      "bf-cbc", "bf-cfb", "bf-ecb", "bf-ofb",
     *      "camellia-128-cbc", "camellia-128-cfb", "camellia-128-cfb1", "camellia-128-cfb8", "camellia-128-ctr", "camellia-128-ecb", "camellia-128-ofb",
     *      "camellia-192-cbc", "camellia-192-cfb", "camellia-192-cfb1", "camellia-192-cfb8", "camellia-192-ctr", "camellia-192-ecb", "camellia-192-ofb",
     *      "camellia-256-cbc", "camellia-256-cfb", "camellia-256-cfb1", "camellia-256-cfb8", "camellia-256-ctr", "camellia-256-ecb", "camellia-256-ofb",
     *      "cast5-cbc", "cast5-cfb", "cast5-ecb", "cast5-ofb",
     *      "idea-cbc", "idea-cfb", "idea-ecb", "idea-ofb",
     *      "rc2-cbc", "rc2-cfb", "rc2-ecb", "rc2-ofb",
     *      "rc5-cbc", "rc5-cfb", "rc5-ecb", "rc5-ofb",
     *      "sm4-cbc", "sm4-cfb", "sm4-ecb", "sm4-ofb", "sm4-ctr",
     *      "seed-cbc", "seed-cfb", "seed-ecb", "seed-ofb",
     *      "rc4",
     *      "chacha20", "chacha20-poly1305",
     *      "aes-128-wrap", "aes-192-wrap", "aes-256-wrap"
     *
     *      unsupported algorithms
     *      openssl 1.1.1 - rc5
     *      openssl 3.0   - bf, cast5, idea, rc2, rc5, seed series
     *      openssl 3.1   - bf, cast5, idea, rc2, rc5, seed series
     *
     * @param const binary_t& key [in]
     * @param const binary_t& iv [in]
     * @return error code (see error.hpp)
     */
    virtual return_t open(crypt_context_t** handle, const char* cipher, const unsigned char* key, size_t size_key, const unsigned char* iv, size_t size_iv);
    virtual return_t open(crypt_context_t** handle, const char* cipher, const binary_t& key, const binary_t& iv);
    /**
     * @brief destroy a context handle
     * @param crypt_context_t* handle [in]
     * @return error code (see error.hpp)
     */
    virtual return_t close(crypt_context_t* handle);
    /**
     * @brief set
     * @param crypt_context_t* handle [in]
     * @param crypt_ctrl_t id [in]
     * @param uint16 param [in]
     * @return error code (see error.hpp)
     */
    virtual return_t set(crypt_context_t* handle, crypt_ctrl_t id, uint16 param);

    /**
     * @brief symmetric encrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_plain [in]
     * @param size_t size_plain [in]
     * @param unsigned char** data_encrypted [out]
     * @param size_t* size_encrypted [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.encrypt(handle, data_plain, size_plain, &data_encrypted, &size_encrypted);
     *        crypt.free_data(data_encrypted);
     */
    virtual return_t encrypt(crypt_context_t* handle, const unsigned char* data_plain, size_t size_plain, unsigned char** data_encrypted,
                             size_t* size_encrypted);
    /**
     * @brief symmetric encrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_plain [in]
     * @param size_t size_plain [in]
     * @param binary_t& out_encrypted [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.encrypt(handle, data_plain, size_plain, data_encrypted);
     */
    virtual return_t encrypt(crypt_context_t* handle, const unsigned char* data_plain, size_t size_plain, binary_t& out_encrypted);
    /**
     * @brief encrypt
     * @param crypt_context_t* handle [in]
     * @param const binary_t& input [in]
     * @param binary_t& out [out]
     * @return error code (see error.hpp)
     */
    virtual return_t encrypt(crypt_context_t* handle, const binary_t& input, binary_t& out);
    /**
     * @brief encrypt (GCM/CCM)
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_plain [in]
     * @param size_t size_plain [in]
     * @param binary_t& out_encrypte [out]
     * @param binary_t* aad [inopt]
     * @param binary_t* tag [outopt]
     * @return error code (see error.hpp)
     */
    virtual return_t encrypt2(crypt_context_t* handle, const unsigned char* data_plain, size_t size_plain, binary_t& out_encrypted,
                              const binary_t* aad = nullptr, binary_t* tag = nullptr);
    /**
     * @brief encrypt (GCM/CCM)
     * @param crypt_context_t* handle [in]
     * @param const binary_t& plain [in]
     * @param binary_t& out_encrypte [out]
     * @param binary_t* aad [inopt]
     * @param binary_t* tag [outopt]
     * @return error code (see error.hpp)
     */
    virtual return_t encrypt2(crypt_context_t* handle, const binary_t& plain, binary_t& out_encrypted, const binary_t* aad = nullptr, binary_t* tag = nullptr);
    /**
     * @brief encrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_plain [in]
     * @param size_t size_plain [in]
     * @param unsigned char* out_encrypted [out] allocated buffer
     * @param size_t* size* size_encrypted [inout] should be at least size_encrypted + EVP_MAX_BLOCK_LENGTH
     * @param binary_t* aad [inopt]
     * @param binary_t* tag [inopt]
     * @return error code (see error.hpp)
     */
    return_t encrypt2(crypt_context_t* handle, const unsigned char* data_plain, size_t size_plain, unsigned char* out_encrypted, size_t* size_encrypted,
                      const binary_t* aad = nullptr, binary_t* tag = nullptr);
    /**
     * @brief symmetric decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_encrypted [in]
     * @param size_t size_encrypted [in]
     * @param unsigned char** data_plain [out]
     * @param size_t* size_plain [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.decrypt(handle, data_encrypted, size_encrypted, &data_decrypted, &size_decrypted);
     *        crypt.free_data(data_decrypted);
     */
    virtual return_t decrypt(crypt_context_t* handle, const unsigned char* data_encrypted, size_t size_encrypted, unsigned char** data_plain,
                             size_t* size_plain);
    /**
     * @brief symmetric decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_encrypted [in]
     * @param size_t size_encrypted [in]
     * @param binary_t& out_decrypted [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.decrypt(handle, data_encrypted, size_encrypted, data_decrypted);
     */
    virtual return_t decrypt(crypt_context_t* handle, const unsigned char* data_encrypted, size_t size_encrypted, binary_t& out_decrypted);
    /**
     * @brief decrypt
     * @param crypt_context_t* handle [in]
     * @param const binary_t& input [in]
     * @param binary_t& out [out]
     * @return error code (see error.hpp)
     * @return error code (see error.hpp)
     */
    virtual return_t decrypt(crypt_context_t* handle, const binary_t& input, binary_t& out);

    /**
     * @brief decrypt (GCM/CCOM)
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_encrypted [in]
     * @param size_t size_encrypted [in]
     * @param binary_t& out_decrypted [out]
     * @param binary_t* aad [inpot]
     * @param binary_t* tag [inopt]
     * @return error code (see error.hpp)
     */
    virtual return_t decrypt2(crypt_context_t* handle, const unsigned char* data_encrypted, size_t size_encrypted, binary_t& out_decrypted,
                              const binary_t* aad = nullptr, const binary_t* tag = nullptr);
    /**
     * @brief decrypt (GCM/CCOM)
     * @param crypt_context_t* handle [in]
     * @param const binary_t& data_encrypted [in]
     * @param binary_t& out_decrypted [out]
     * @param binary_t* aad [inpot]
     * @param binary_t* tag [inopt]
     * @return error code (see error.hpp)
     */
    virtual return_t decrypt2(crypt_context_t* handle, const binary_t& data_encrypted, binary_t& out_decrypted, const binary_t* aad = nullptr,
                              const binary_t* tag = nullptr);
    /**
     * @brief decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* data_encrypted [in]
     * @param size_t size_encrypted [in]
     * @param byte_t* out_decrypted [out] allocated buffer
     * @param size_t* size_decrypted [inout] should be at least size_encrypted + EVP_MAX_BLOCK_LENGTH
     * @param binary_t* aad [inopt]
     * @param binary_t* tag [inopt]
     * @return error code (see error.hpp)
     */
    return_t decrypt2(crypt_context_t* handle, const unsigned char* data_encrypted, size_t size_encrypted, byte_t* out_decrypted, size_t* size_decrypted,
                      const binary_t* aad = nullptr, const binary_t* tag = nullptr);
    /**
     * @brief free memory
     * @return error code (see error.hpp)
     * @remarks see encrypt, decrypt
     */
    virtual return_t free_data(unsigned char* data);

    /**
     * @biref asymmetric encrypt
     * @param const EVP_PKEY* pkey [in]
     * @param const binary_t& input [in]
     * @param binary_t& output [out]
     * @param crypt_enc_t mode [in]
     * @return error code (see error.hpp)
     */
    return_t encrypt(const EVP_PKEY* pkey, const binary_t& input, binary_t& output, crypt_enc_t mode);
    /**
     * @biref asymmetric decrypt
     * @param const EVP_PKEY* pkey [in]
     * @param const binary_t& input [in]
     * @param binary_t& output [out]
     * @param crypt_enc_t mode [in]
     * @return error code (see error.hpp)
     */
    return_t decrypt(const EVP_PKEY* pkey, const binary_t& input, binary_t& output, crypt_enc_t mode);

    /**
     * @brief simple api
     * @return error code (see error.hpp)
     * @example
     *      encrypt_option_t options[] = {
     *          { crypt_ctrl_padding, 0 }, { },
     *      };
     *      encrypt("aes-128-cbc", cek, iv, plaintext, ciphertext, options);
     */
    return_t encrypt(const char* alg, const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext,
                     encrypt_option_t* options = nullptr);
    return_t encrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext,
                     encrypt_option_t* options = nullptr);
    return_t encrypt(const char* alg, const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad,
                     binary_t& tag, encrypt_option_t* options = nullptr);
    return_t encrypt(const char* alg, const binary_t& key, const binary_t& iv, const unsigned char* plaintext, size_t size_plaintext, binary_t& ciphertext,
                     const binary_t& aad, binary_t& tag, encrypt_option_t* options = nullptr);
    return_t encrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext,
                     const binary_t& aad, binary_t& tag, encrypt_option_t* options = nullptr);
    return_t encrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const unsigned char* plaintext,
                     size_t size_plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag, encrypt_option_t* options = nullptr);
    return_t decrypt(const char* alg, const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext,
                     encrypt_option_t* options = nullptr);
    return_t decrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext,
                     encrypt_option_t* options = nullptr);
    return_t decrypt(const char* alg, const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext, const binary_t& aad,
                     const binary_t& tag, encrypt_option_t* options = nullptr);
    return_t decrypt(const char* alg, const binary_t& key, const binary_t& iv, const unsigned char* ciphertext, size_t size_ciphertext, binary_t& plaintext,
                     const binary_t& aad, const binary_t& tag, encrypt_option_t* options = nullptr);
    return_t decrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext,
                     const binary_t& aad, const binary_t& tag, encrypt_option_t* options = nullptr);
    return_t decrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const unsigned char* ciphertext,
                     size_t size_ciphertext, binary_t& plaintext, const binary_t& aad, const binary_t& tag, encrypt_option_t* options = nullptr);

    /**
     * @brief deprecated - expect block operation size
     * @param crypt_context_t* handle [in]
     * @param size_t size_data [in]
     * @param size_t* size_expect [out]
     * @return error code (see error.hpp)
     */
    // virtual return_t expect(crypt_context_t* handle, size_t size_data, size_t* size_expect);
    /**
     * @brief crypt_poweredby_t
     * @return see crypt_poweredby_t
     */
    virtual crypt_poweredby_t get_type();

    /**
     * @brief query
     * @param crypt_context_t* handle [in]
     * @param size_t cmd [in] 1 key size, 2 iv size
     * @param size_t& value [out]
     * @return error code (see error.hpp)
     */
    virtual return_t query(crypt_context_t* handle, size_t cmd, size_t& value);
};

/**
 * @brief   EVP_chacha20
 * @return  error code (see error.hpp)
 * @desc
 *          RFC 7539 ChaCha20 and Poly1305 for IETF Protocols
 *          RFC 8439 ChaCha20 and Poly1305 for IETF Protocols
 *
 *          key 256bits (32bytes)
 *          iv 96bits (12bytes)
 *          https://www.openssl.org/docs/man1.1.1/man3/EVP_chacha20.html
 *          openssl iv 128bites (16bytes) = counter 32bits(LE) + iv 96bits
 *
 *          cf.
 *          https://www.openssl.org/docs/man3.0/man3/EVP_chacha20.html
 *          openssl iv 128bites (16bytes) = counter 64bits(LE) + iv 64bits - 96 or 64
 * @example
 *          constexpr byte_t data_plain[] = "still a man hears what he wants to hear and disregards the rest";
 *          size_t size_plain = RTL_NUMBER_OF (data_plain);
 *
 *          openssl_crypt crypt;
 *          crypt_context_t* handle = nullptr;
 *          binary_t data_encrypted;
 *          binary_t data_decrypted;
 *
 *          // key
 *          binary_t key;
 *          key.resize (32);
 *          for (int i = 0; i < 32; i++) {
 *              key[i] = i;
 *          }
 *
 *          // initial vector
 *          byte_t nonce_source [12] = { 0, 0, 0, 0, 0, 0, 0, 0x4a, };
 *          binary_t iv;
 *          openssl_chacha20_iv (iv, 1, nonce_source, 12);
 *
 *          // stream cipher
 *          {
 *              crypt.open (&handle, crypt_algorithm_t::chacha20, crypt_mode_t::stream_cipher, key, iv);
 *              crypt.encrypt (handle, data_plain, size_plain, data_encrypted);
 *              crypt.decrypt (handle, data_encrypted, data_decrypted);
 *              crypt.close (handle);
 *          }
 *
 *          // AEAD
 *          {
 *              binary_t aad;
 *              binary_t tag;
 *              openssl_prng rand;
 *              rand.random (aad, 32);
 *              crypt.open (&handle, crypt_algorithm_t::chacha20, crypt_mode_t::stream_aead, key, iv);
 *              crypt.encrypt2 (handle, data_plain, size_plain, data_encrypted, &aad, &tag);
 *              crypt.decrypt2 (handle, data_encrypted, data_decrypted, &aad, &tag);
 *              crypt.close (handle);
 *          }
 */
return_t openssl_chacha20_iv(binary_t& iv, uint32 counter, const binary_t& nonce);
return_t openssl_chacha20_iv(binary_t& iv, uint32 counter, const byte_t* nonce, size_t nonce_size);

/**
 * @brief aes_cbc_hmac_sha2_encrypt
 *        https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
 *        2.4 AEAD_AES_128_CBC_HMAC_SHA_256 AES-128 SHA-256 K 32 MAC_KEY_LEN 16 ENC_KEY_LEN 16 T_LEN=16
 *        2.5 AEAD_AES_192_CBC_HMAC_SHA_384 AES-192 SHA-384 K 48 MAC_KEY_LEN 24 ENC_KEY_LEN 24 T_LEN=24
 *        2.6 AEAD_AES_256_CBC_HMAC_SHA_384 AES-256 SHA-384 K 56 MAC_KEY_LEN 32 ENC_KEY_LEN 24 T_LEN=24
 *        2.7 AEAD_AES_256_CBC_HMAC_SHA_512 AES-256 SHA-512 K 64 MAC_KEY_LEN 32 ENC_KEY_LEN 32 T_LEN=32
 */

class openssl_aead {
   public:
    openssl_aead();
    /**
     * @brief   Authenticated Encryption with AES-CBC and HMAC-SHA
     * @param   const char* enc_alg [in] "aes-128-cbc"
     * @param   const char* mac_alg [in] "sha256"
     * @param   const binary_t& k [in] MAC_KEY || ENC_KEY
     * @param   const binary_t& iv [in] iv
     * @param   const binary_t& a [in] aad
     * @param   const binary_t& p [in] plaintext
     * @param   binary_t& q [out] ciphertext
     * @param   binary_t& t [out] AE tag
     * @return  error code (see error.hpp)
     * @desc
     *
     *          K = MAC_KEY || ENC_KEY
     *          MAC_KEY = initial MAC_KEY_LEN bytes of K
     *          ENC_KEY = final ENC_KEY_LEN bytes of K
     *
     * @sa      RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
     */
    return_t aes_cbc_hmac_sha2_encrypt(const char* enc_alg, const char* mac_alg, const binary_t& k, const binary_t& iv, const binary_t& a, const binary_t& p,
                                       binary_t& q, binary_t& t);
    return_t aes_cbc_hmac_sha2_encrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& k, const binary_t& iv,
                                       const binary_t& a, const binary_t& p, binary_t& q, binary_t& t);

    /**
     * @brief   Authenticated Encryption with AES-CBC and HMAC-SHA
     * @return  error code (see error.hpp)
     * @desc    each ENC_KEY, MAC_KEY
     */
    return_t aes_cbc_hmac_sha2_encrypt(const char* enc_alg, const char* mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                       const binary_t& a, const binary_t& p, binary_t& q, binary_t& t);
    return_t aes_cbc_hmac_sha2_encrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k,
                                       const binary_t& iv, const binary_t& a, const binary_t& p, binary_t& q, binary_t& t);
    /**
     * @brief   Authenticated Encryption with AES-CBC and HMAC-SHA
     * @param   const char* enc_alg [in] "aes-128-cbc"
     * @param   const char* mac_alg [in] "sha256"
     * @param   const binary_t& k [in] MAC_KEY || ENC_KEY
     * @param   const binary_t& iv [in] iv
     * @param   const binary_t& a [in] aad
     * @param   const binary_t& q [in] ciphertext
     * @param   binary_t& p [out] plaintext
     * @param   binary_t& t [in] AE tag
     * @return  error code (see error.hpp)
     * @desc
     *          K = MAC_KEY || ENC_KEY
     *          MAC_KEY = initial MAC_KEY_LEN bytes of K
     *          ENC_KEY = final ENC_KEY_LEN bytes of K
     * @sa      RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
     */
    return_t aes_cbc_hmac_sha2_decrypt(const char* enc_alg, const char* mac_alg, const binary_t& k, const binary_t& iv, const binary_t& a, const binary_t& q,
                                       binary_t& p, const binary_t& t);
    return_t aes_cbc_hmac_sha2_decrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& k, const binary_t& iv,
                                       const binary_t& a, const binary_t& q, binary_t& p, const binary_t& t);
    /**
     * @brief   Authenticated Encryption with AES-CBC and HMAC-SHA
     * @return  error code (see error.hpp)
     * @desc    each ENC_KEY, MAC_KEY
     */
    return_t aes_cbc_hmac_sha2_decrypt(const char* enc_alg, const char* mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                       const binary_t& a, const binary_t& q, binary_t& p, const binary_t& t);
    return_t aes_cbc_hmac_sha2_decrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k,
                                       const binary_t& iv, const binary_t& a, const binary_t& q, binary_t& p, const binary_t& t);
};

}  // namespace crypto
}  // namespace hotplace

#endif
