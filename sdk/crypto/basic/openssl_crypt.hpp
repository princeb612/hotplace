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
 *          constexpr byte_t text[] = "still a man hears what he wants to hear and disregards the rest";
 *          size_t plainsize = RTL_NUMBER_OF (text);
 *
 *          openssl_crypt crypt;
 *          crypt_context_t* handle = nullptr;
 *          binary_t ciphertext;
 *          binary_t plaintext;
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
 *              crypt.encrypt (handle, text, plainsize, ciphertext);
 *              crypt.decrypt (handle, &ciphertext[0], ciphertext.size (), plaintext);
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
 *              crypt.encrypt (handle, text, plainsize, ciphertext, &aad, &tag);
 *              crypt.decrypt (handle, &ciphertext[0], ciphertext.size (), plaintext, &aad, &tag);
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
     * @return  error code (see error.hpp)
     * @sample
     *
     *          {
     *              // > key 752a18e7a9fcb7cbcdd8f98dd8f769eb
     *              // > iv 5152535455565758595a5b5c5d5e5f60
     *              // > ciphertext
     *              //   00000000 : 18 E0 75 31 7B 10 03 15 F6 08 1F CB F3 13 78 1A | ..u1{.........x.
     *              //   00000010 : AC 73 EF E1 9F E2 5B A1 AF 59 C2 0B E9 4F C0 1B | .s....[..Y...O..
     *              //   00000020 : DA 2D 68 00 29 8B 73 A7 E8 49 D7 4B D4 94 CF 7D | .-h.).s..I.K...}
     *
     *              crypt.set(handle, crypt_ctrl_padding, 1);
     *
     *              // > plaintext
     *              //   00000000 : 14 00 00 0C 84 4D 3C 10 74 6D D7 22 F9 2F 0C 7E | .....M<.tm."./.~
     *              //   00000010 : 20 C4 97 46 D2 A3 0F 23 57 39 90 58 07 53 52 43 |  ..F...#W9.X.SRC
     *              //   00000020 : AF F2 BF E0 0B -- -- -- -- -- -- -- -- -- -- -- | .....
     *
     *              crypt.set(handle, crypt_ctrl_padding, 0);
     *
     *              // > plaintext
     *              //   00000000 : 14 00 00 0C 84 4D 3C 10 74 6D D7 22 F9 2F 0C 7E | .....M<.tm."./.~
     *              //   00000010 : 20 C4 97 46 D2 A3 0F 23 57 39 90 58 07 53 52 43 |  ..F...#W9.X.SRC
     *              //   00000020 : AF F2 BF E0 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B | ................
     *          }
     *
     *          {
     *              // AES-128-CCM8
     *              crypt.set(handle, crypt_ctrl_tsize, 8);
     *
     *              // > key
     *              //    00000000 : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ................
     *              //    00000010 : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F | ................
     *              // > iv
     *              //    00000000 : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ................
     *              // > aad
     *              //    00000000 : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ................
     *              // > ciphertext
     *              //    00000000 : 00 71 93 88 52 E8 26 7B 8C 7C C3 84 ED 8F 69 D8 | .q..R.&{.|....i.
     *              //    00000010 : FF 52 7E FC 0E E6 36 57 A1 E5 D9 DC 75 DA EF FD | .R~...6W....u...
     *              //    00000020 : C6 6E A6 36 72 91 72 17 B7 CD 87 9F CC 5D 25 9A | .n.6r.r......]%.
     *              //    00000030 : 41 04 C5 97 D0 C5 FC 64 DE 27 62 90 E9 4F CA BF | A......d.'b..O..
     *              //    00000040 : 6E D4 8D 6A F5 AD 49 6A 0F 24 -- -- -- -- -- -- | n..j..Ij.$
     *              // > tag
     *              //    00000000 : DF 1A C9 09 08 53 E0 B5 -- -- -- -- -- -- -- -- | .....S..
     *              // > plaintext
     *              //    00000000 : 57 65 20 64 6F 6E 27 74 20 70 6C 61 79 69 6E 67 | We don't playing
     *              //    00000010 : 20 62 65 63 61 75 73 65 20 77 65 20 67 72 6F 77 |  because we grow
     *              //    00000020 : 20 6F 6C 64 3B 20 77 65 20 67 72 6F 77 20 6F 6C |  old; we grow ol
     *              //    00000030 : 64 20 62 65 63 61 75 73 65 20 77 65 20 73 74 6F | d because we sto
     *              //    00000040 : 70 20 70 6C 61 79 69 6E 67 2E -- -- -- -- -- -- | p playing.
     *          }
     *
     *          {
     *              // AES-128-CCM
     *              // crypt.set(handle, crypt_ctrl_tsize, 14);
     *
     *              // > ciphertext
     *              //    00000000 : 00 71 93 88 52 E8 26 7B 8C 7C C3 84 ED 8F 69 D8 | .q..R.&{.|....i.
     *              //    00000010 : FF 52 7E FC 0E E6 36 57 A1 E5 D9 DC 75 DA EF FD | .R~...6W....u...
     *              //    00000020 : C6 6E A6 36 72 91 72 17 B7 CD 87 9F CC 5D 25 9A | .n.6r.r......]%.
     *              //    00000030 : 41 04 C5 97 D0 C5 FC 64 DE 27 62 90 E9 4F CA BF | A......d.'b..O..
     *              //    00000040 : 6E D4 8D 6A F5 AD 49 6A 0F 24 -- -- -- -- -- -- | n..j..Ij.$
     *              // > tag
     *              //    00000000 : 81 22 4B 18 4D A8 70 75 2A 31 46 C5 D7 5B -- -- | ."K.M.pu*1F..[
     *          }
     */
    virtual return_t set(crypt_context_t* handle, crypt_ctrl_t id, uint16 param);

    /**
     * @brief symmetric encrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* plaintext [in]
     * @param size_t plainsize [in]
     * @param unsigned char** ciphertext [out]
     * @param size_t* ciphersize [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.encrypt(handle, plaintext, plainsize, &ciphertext, &ciphersize);
     *        crypt.free_data(ciphertext);
     */
    virtual return_t encrypt(crypt_context_t* handle, const unsigned char* plaintext, size_t plainsize, unsigned char** ciphertext, size_t* ciphersize);
    /**
     * @brief symmetric encrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* plaintext [in]
     * @param size_t plainsize [in]
     * @param binary_t& ciphertext [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.encrypt(handle, plaintext, plainsize, ciphertext);
     */
    virtual return_t encrypt(crypt_context_t* handle, const unsigned char* plaintext, size_t plainsize, binary_t& ciphertext);
    /**
     * @brief encrypt
     * @param crypt_context_t* handle [in]
     * @param const binary_t& plaintext [in]
     * @param binary_t& ciphertext [out]
     * @return error code (see error.hpp)
     */
    virtual return_t encrypt(crypt_context_t* handle, const binary_t& plaintext, binary_t& ciphertext);
    /**
     * @brief encrypt (GCM/CCM)
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* plaintext [in]
     * @param size_t plainsize [in]
     * @param binary_t& ciphertext [out]
     * @param const binary_t& aad [in]
     * @param binary_t& tag [out]
     * @return error code (see error.hpp)
     */
    virtual return_t encrypt(crypt_context_t* handle, const unsigned char* plaintext, size_t plainsize, binary_t& ciphertext, const binary_t& aad,
                             binary_t& tag);
    /**
     * @brief encrypt (GCM/CCM)
     * @param crypt_context_t* handle [in]
     * @param const binary_t& plaintext [in]
     * @param binary_t& ciphertext [out]
     * @param const binary_t& aad [in]
     * @param binary_t& tag [out]
     * @return error code (see error.hpp)
     */
    virtual return_t encrypt(crypt_context_t* handle, const binary_t& plaintext, binary_t& ciphertext, const binary_t& aad, binary_t& tag);

    /**
     * @brief symmetric decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* ciphertext [in]
     * @param size_t ciphersize [in]
     * @param unsigned char** plaintext [out]
     * @param size_t* plainsize [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.decrypt(handle, ciphertext, ciphersize, &plaintext, &plainsize);
     *        crypt.free_data(plaintext);
     */
    virtual return_t decrypt(crypt_context_t* handle, const unsigned char* ciphertext, size_t ciphersize, unsigned char** plaintext, size_t* plainsize);
    /**
     * @brief symmetric decrypt
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* ciphertext [in]
     * @param size_t ciphersize [in]
     * @param binary_t& plaintext [out]
     * @return error code (see error.hpp)
     * @example
     *        crypt.decrypt(handle, ciphertext, ciphersize, plaintext);
     */
    virtual return_t decrypt(crypt_context_t* handle, const unsigned char* ciphertext, size_t ciphersize, binary_t& plaintext);
    /**
     * @brief decrypt
     * @param crypt_context_t* handle [in]
     * @param const binary_t& ciphertext [in]
     * @param binary_t& plaintext [out]
     * @return error code (see error.hpp)
     * @return error code (see error.hpp)
     */
    virtual return_t decrypt(crypt_context_t* handle, const binary_t& ciphertext, binary_t& plaintext);

    /**
     * @brief decrypt (GCM/CCOM)
     * @param crypt_context_t* handle [in]
     * @param const unsigned char* ciphertext [in]
     * @param size_t ciphersize [in]
     * @param binary_t& plaintext [out]
     * @param const binary_t& aad [in]
     * @param const binary_t& tag [in]
     * @return error code (see error.hpp)
     */
    virtual return_t decrypt(crypt_context_t* handle, const unsigned char* ciphertext, size_t ciphersize, binary_t& plaintext, const binary_t& aad,
                             const binary_t& tag);
    /**
     * @brief decrypt (GCM/CCOM)
     * @param crypt_context_t* handle [in]
     * @param const binary_t& ciphertext [in]
     * @param binary_t& plaintext [out]
     * @param const binary_t& aad [in]
     * @param const binary_t& tag [in]
     * @return error code (see error.hpp)
     */
    virtual return_t decrypt(crypt_context_t* handle, const binary_t& ciphertext, binary_t& plaintext, const binary_t& aad, const binary_t& tag);

    /**
     * @brief free memory
     * @return error code (see error.hpp)
     * @remarks see encrypt, decrypt
     */
    virtual return_t free_data(unsigned char* data);

    /**
     * @biref asymmetric encrypt
     * @param const EVP_PKEY* pkey [in]
     * @param const binary_t& plaintext [in]
     * @param binary_t& ciphertext [out]
     * @param crypt_enc_t mode [in]
     * @return error code (see error.hpp)
     * @sample
     *         // generate RSA key (2048bits)
     *         crypto_key key;
     *         crypto_keychain keychain;
     *         keychain.add_rsa(&key, nid_rsa, 2048, keydesc("RSA key"));
     *         auto pkey = key.find("RSA key");
     *
     *         // openssl_crypt
     *         openssl_crypt crypt;
     *         crypt.encrypt(pkey, plaintext, ciphertext, rsa_oaep256);
     *
     *         // crypto_encrypt
     *         crypto_encrypt_builder builder;
     *         auto crypto = builder.set(rsa_oaep256).build();
     *         if (crypto) {
     *             binary_t ciphertext;
     *             ret = crypto->encrypt(pkey, stream, size, ciphertext);
     *             crypto->release();
     *         }
     */
    return_t encrypt(const EVP_PKEY* pkey, const binary_t& plaintext, binary_t& ciphertext, crypt_enc_t mode);
    return_t encrypt(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& ciphertext, crypt_enc_t mode);
    /**
     * @biref asymmetric decrypt
     * @param const EVP_PKEY* pkey [in]
     * @param const binary_t& ciphertext [in]
     * @param binary_t& plaintext [out]
     * @param crypt_enc_t mode [in]
     * @return error code (see error.hpp)
     */
    return_t decrypt(const EVP_PKEY* pkey, const binary_t& ciphertext, binary_t& plaintext, crypt_enc_t mode);
    return_t decrypt(const EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& plaintext, crypt_enc_t mode);

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
    return_t encrypt(const char* alg, const binary_t& key, const binary_t& iv, const unsigned char* plaintext, size_t plainsize, binary_t& ciphertext,
                     const binary_t& aad, binary_t& tag, encrypt_option_t* options = nullptr);
    return_t encrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const binary_t& plaintext, binary_t& ciphertext,
                     const binary_t& aad, binary_t& tag, encrypt_option_t* options = nullptr);
    return_t encrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const unsigned char* plaintext, size_t plainsize,
                     binary_t& ciphertext, const binary_t& aad, binary_t& tag, encrypt_option_t* options = nullptr);
    return_t decrypt(const char* alg, const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext,
                     encrypt_option_t* options = nullptr);
    return_t decrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext,
                     encrypt_option_t* options = nullptr);
    return_t decrypt(const char* alg, const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext, const binary_t& aad,
                     const binary_t& tag, encrypt_option_t* options = nullptr);
    return_t decrypt(const char* alg, const binary_t& key, const binary_t& iv, const unsigned char* ciphertext, size_t ciphersize, binary_t& plaintext,
                     const binary_t& aad, const binary_t& tag, encrypt_option_t* options = nullptr);
    return_t decrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const binary_t& ciphertext, binary_t& plaintext,
                     const binary_t& aad, const binary_t& tag, encrypt_option_t* options = nullptr);
    return_t decrypt(crypt_algorithm_t algorithm, crypt_mode_t mode, const binary_t& key, const binary_t& iv, const unsigned char* ciphertext,
                     size_t ciphersize, binary_t& plaintext, const binary_t& aad, const binary_t& tag, encrypt_option_t* options = nullptr);

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

    /**
     * @brief Authenticated Encryption with AES-CBC and HMAC-SHA (JOSE)
     *          tag = HMAC(aad || iv || ciphertext || uint64(aad_len))
     *
     *        https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
     *        2.4 AEAD_AES_128_CBC_HMAC_SHA_256 AES-128 SHA-256 K 32 MAC_KEY_LEN 16 ENC_KEY_LEN 16 T_LEN=16
     *        2.5 AEAD_AES_192_CBC_HMAC_SHA_384 AES-192 SHA-384 K 48 MAC_KEY_LEN 24 ENC_KEY_LEN 24 T_LEN=24
     *        2.6 AEAD_AES_256_CBC_HMAC_SHA_384 AES-256 SHA-384 K 56 MAC_KEY_LEN 32 ENC_KEY_LEN 24 T_LEN=24
     *        2.7 AEAD_AES_256_CBC_HMAC_SHA_512 AES-256 SHA-512 K 64 MAC_KEY_LEN 32 ENC_KEY_LEN 32 T_LEN=32
     * @param   const char* enc_alg [in] "aes-128-cbc"
     * @param   const char* mac_alg [in] "sha256"
     * @param   const binary_t& k [in] MAC_KEY || ENC_KEY
     * @param   const binary_t& iv [in] iv
     * @param   const binary_t& a [in] aad
     * @param   const binary_t& p [in] plaintext
     * @param   binary_t& q [out] ciphertext
     * @param   binary_t& t [out] AE tag
     * @return  error code (see error.hpp)
     * @remarks
     *
     *          K = MAC_KEY || ENC_KEY
     *          MAC_KEY = initial MAC_KEY_LEN bytes of K
     *          ENC_KEY = final ENC_KEY_LEN bytes of K
     *
     *          JOSE
     *              "A128CBC-HS256"
     *              "A192CBC-HS384"
     *              "A256CBC-HS512"
     *
     * @sa      RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
     */
    return_t cbc_hmac_rfc7516_encrypt(const char* enc_alg, const char* mac_alg, const binary_t& k, const binary_t& iv, const binary_t& a, const binary_t& p,
                                      binary_t& q, binary_t& t);
    return_t cbc_hmac_rfc7516_encrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& k, const binary_t& iv,
                                      const binary_t& a, const binary_t& p, binary_t& q, binary_t& t);

    /**
     * @brief   Authenticated Encryption with AES-CBC and HMAC-SHA (JOSE)
     * @return  error code (see error.hpp)
     * @desc    ENC_KEY, MAC_KEY
     */
    return_t cbc_hmac_rfc7516_encrypt(const char* enc_alg, const char* mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                      const binary_t& a, const binary_t& p, binary_t& q, binary_t& t);
    return_t cbc_hmac_rfc7516_encrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k,
                                      const binary_t& iv, const binary_t& a, const binary_t& p, binary_t& q, binary_t& t);
    /**
     * @brief   Authenticated Encryption with AES-CBC and HMAC-SHA (JOSE)
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
     *
     *          JOSE
     *              "A128CBC-HS256"
     *              "A192CBC-HS384"
     *              "A256CBC-HS512"
     *
     * @sa      RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
     */
    return_t cbc_hmac_rfc7516_decrypt(const char* enc_alg, const char* mac_alg, const binary_t& k, const binary_t& iv, const binary_t& a, const binary_t& q,
                                      binary_t& p, const binary_t& t);
    return_t cbc_hmac_rfc7516_decrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& k, const binary_t& iv,
                                      const binary_t& a, const binary_t& q, binary_t& p, const binary_t& t);
    /**
     * @brief   Authenticated Encryption with AES-CBC and HMAC-SHA (JOSE)
     * @return  error code (see error.hpp)
     * @desc    ENC_KEY, MAC_KEY
     */
    return_t cbc_hmac_rfc7516_decrypt(const char* enc_alg, const char* mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                      const binary_t& a, const binary_t& q, binary_t& p, const binary_t& t);
    return_t cbc_hmac_rfc7516_decrypt(crypt_algorithm_t enc_alg, crypt_mode_t enc_mode, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k,
                                      const binary_t& iv, const binary_t& a, const binary_t& q, binary_t& p, const binary_t& t);

    /**
     * @brief   Authenticated Encryption with AES-CBC and HMAC-SHA (TLS)
     *            tag = HMAC(uint64(sequence) || uint8(content_type) || hton16(tls_version) || hton16(plaintext.size) || plaintext)
     *            ciphertext = ENCRYPT(plaintext || tag || pad1)
     *            plaintag = DECRYPT(ciphertext) || tag
     *            plainsize = DECRYPT(ciphertext).size - tag.size - 1
     *            plaintext = binary_t(plaintag.begin(), plaintag.begin() + plainsize)
     *
     *            scv = hton64(sequence) || uint8(content_type) || hton16(tls_version)
     *
     *          while decryption
     *            plaintag = decrypt(ciphertext) // including tag
     *            tag = HMAC(scv || hton16(plaintext.size) || plaintext)
     *
     *          plaintext
     *            // sample #1
     *            {
     *              // plaintag = plaintext || tag
     *              //                    \- ptsize
     *              binary_t plaintag;
     *              size_t ptsize = 0;
     *              cbc_hmac_tls_decrypt(aes128, sha1, key, mackey, iv, aad, ciphertext, plaintag, ptsize);
     *              binary_t pt(plaintag.begin(), plaintag.begin() + ptsize);
     *            }
     *            // sample #2
     *            {
     *              // plaintext, tag separated
     *              binary_t plaintext;
     *              binary_t tag;
     *              cbc_hmac_tls_decrypt(aes128, sha1, key, mackey, iv, aad, ciphertext, plaintext, tag);
     *            }
     */
    return_t cbc_hmac_tls_encrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                  const binary_t& scv, const binary_t& plaintext, binary_t& ciphertext);
    return_t cbc_hmac_tls_encrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                  const binary_t& scv, const byte_t* plaintext, size_t size, binary_t& ciphertext);
    return_t cbc_hmac_tls_decrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                  const binary_t& scv, const binary_t& ciphertext, binary_t& plaintag, size_t& ptsize);
    return_t cbc_hmac_tls_decrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                  const binary_t& scv, const byte_t* ciphertext, size_t size, binary_t& plaintag, size_t& ptsize);
    return_t cbc_hmac_tls_decrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                  const binary_t& scv, const binary_t& ciphertext, binary_t& plaintext, binary_t& tag);
    return_t cbc_hmac_tls_decrypt(crypt_algorithm_t enc_alg, hash_algorithm_t mac_alg, const binary_t& enc_k, const binary_t& mac_k, const binary_t& iv,
                                  const binary_t& scv, const byte_t* ciphertext, size_t size, binary_t& plaintext, binary_t& tag);

   protected:
    return_t encrypt_internal(crypt_context_t* handle, const unsigned char* plaintext, size_t plainsize, unsigned char* ciphertext, size_t* ciphersize,
                              const binary_t* aad = nullptr, binary_t* tag = nullptr);
    return_t decrypt_internal(crypt_context_t* handle, const unsigned char* ciphertext, size_t ciphersize, unsigned char* plaintext, size_t* plainsize,
                              const binary_t* aad = nullptr, const binary_t* tag = nullptr);
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
 *          constexpr byte_t plaintext[] = "still a man hears what he wants to hear and disregards the rest";
 *          size_t plainsize = RTL_NUMBER_OF (plaintext);
 *
 *          openssl_crypt crypt;
 *          crypt_context_t* handle = nullptr;
 *          binary_t ciphertext;
 *          binary_t plaintext;
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
 *              crypt.open (&handle, crypt_algorithm_t::chacha20, crypt_mode_t::mode_cipher, key, iv);
 *              crypt.encrypt (handle, plaintext, plainsize, ciphertext);
 *              crypt.decrypt (handle, ciphertext, plaintext);
 *              crypt.close (handle);
 *          }
 *
 *          // AEAD
 *          {
 *              binary_t aad;
 *              binary_t tag;
 *              openssl_prng rand;
 *              rand.random (aad, 32);
 *              crypt.open (&handle, crypt_algorithm_t::chacha20, crypt_mode_t::mode_poly1305, key, iv);
 *              crypt.encrypt (handle, plaintext, plainsize, ciphertext, &aad, &tag);
 *              crypt.decrypt (handle, ciphertext, plaintext, &aad, &tag);
 *              crypt.close (handle);
 *          }
 */
return_t openssl_chacha20_iv(binary_t& iv, uint32 counter, const binary_t& nonce);
return_t openssl_chacha20_iv(binary_t& iv, uint32 counter, const byte_t* nonce, size_t nonce_size);

}  // namespace crypto
}  // namespace hotplace

#endif
