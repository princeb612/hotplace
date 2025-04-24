/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOCBCHMAC__
#define __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOCBCHMAC__

#include <sdk/base/system/shared_instance.hpp>
#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto.hpp>

namespace hotplace {
namespace crypto {

/**
 * @remarks
 *
 *  survey
 *
 *  | specification            | type | tag              | example                                                  |
 *  | --                       | --   | --               | --                                                       |
 *  | JOSE                     | EtM  | separated tag    | JOSE A128CBC-HS256, A192CBC-HS384, A256CBC-HS512         |
 *  | TLS w/o encrypt_then_mac | MtE  | nested tag       | TLS 1.2 w/o encrypt_then_mac extension                   |
 *  | TLS encrypt_then_mac     | EtM  | concatenated tag | TLS 1.2 encrypt_then_mac extension, TLS 1.3 ciphersuites |
 *
 *  JOSE
 *      EtM encrypt-then-mac
 *          separated tag = MAC(AAD || IV || ciphertext || uint64(AAD.length))
 *
 *          for more details
 *
 *              Authenticated Encryption with AES-CBC and HMAC-SHA (JOSE)
 *              RFC 7516 Appendix B.  Example AES_128_CBC_HMAC_SHA_256 Computation
 *              https://datatracker.ietf.org/doc/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
 *
 *                  tag = HMAC(aad || iv || ciphertext || uint64(aad_len))
 *
 *              https://www.ietf.org/archive/id/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.txt
 *                  2.4 AEAD_AES_128_CBC_HMAC_SHA_256 AES-128 SHA-256 K 32 MAC_KEY_LEN 16 ENC_KEY_LEN 16 T_LEN=16
 *                  2.5 AEAD_AES_192_CBC_HMAC_SHA_384 AES-192 SHA-384 K 48 MAC_KEY_LEN 24 ENC_KEY_LEN 24 T_LEN=24
 *                  2.6 AEAD_AES_256_CBC_HMAC_SHA_384 AES-256 SHA-384 K 56 MAC_KEY_LEN 32 ENC_KEY_LEN 24 T_LEN=24
 *                  2.7 AEAD_AES_256_CBC_HMAC_SHA_512 AES-256 SHA-512 K 64 MAC_KEY_LEN 32 ENC_KEY_LEN 32 T_LEN=32
 *
 *              JOSE
 *                  "A128CBC-HS256"
 *                  "A192CBC-HS384"
 *                  "A256CBC-HS512"
 *  TLS
 *      MtE mac-then-encrypt (w/o encrypt_then_mac extension)
 *          AAD = uint64(sequence) || uint8(type) || uint16(version)
 *          nested tag = MAC(AAD || uint16(plaintext.length) || plaintext)
 *          ciphertext = CBC(plaintext || tag || pad1)
 *          image = ciphertext
 *
 *          for more details
 *              https://tls12.xargs.org
 *
 *      EtM encrypt-then-mac (encrypt_then_mac extension)
 *          ciphertext = CBC(plaintext)
 *          AAD = uint64(sequence) || uint8(type) || uint16(version) || uint16(ciphertext.length)
 *          concatenated tag = CBC-HMAC(AAD || ciphertext)
 *          image = CBC(plaintext) || tag
 *
 *          for more details
 *              RFC 7366 Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
 *
 * @example
 *
 *      // JWE
 *          crypto_cbc_hmac cbchmac;
 *          binary_t enckey;
 *          binary_t mackey;
 *          cbchmac.set_enc(enc_crypt_alg).set_mac(enc_hash_alg).set_flag(jose_encrypt_then_mac);
 *          cbchmac.split_key(cek, enckey, mackey);
 *          ret = cbchmac.encrypt(enckey, mackey, iv, aad, input, ciphertext, tag);
 *          ret = cbchmac.decrypt(enckey, mackey, iv, aad, ciphertext, output, tag);
 *      // TLS
 *          crypto_cbc_hmac cbchmac;
 *          cbchmac.set_enc(enc_alg).set_mac(hmac_alg).set_flag(tls_mac_then_encrypt);
 *          ret = cbchmac.encrypt(enckey, mackey, iv, aad, plaintext, ciphertext);
 *          ret = cbchmac.decrypt(enckey, mackey, iv, aad, ciphertext, plaintext);
 */

class crypto_cbc_hmac {
   public:
    crypto_cbc_hmac();

    crypto_cbc_hmac& set_enc(const char* enc_alg);
    crypto_cbc_hmac& set_enc(crypt_algorithm_t enc_alg);
    crypto_cbc_hmac& set_mac(const char* mac_alg);
    crypto_cbc_hmac& set_mac(hash_algorithm_t mac_alg);
    crypto_cbc_hmac& set_flag(uint16 flag);

    crypt_algorithm_t get_enc_alg();
    hash_algorithm_t get_mac_alg();
    uint16 get_flag();

    /**
     * key = enckey || mackey
     */
    return_t split_key(const binary_t key, binary_t& enckey, binary_t& mackey);

    /* concatenated/nested tag
     * case tls_encrypt_then_mac:
     *      concatenated tag
     *      ciphertext || tag
     * case tls_mac_then_encrypt :
     *      nested tag
     *      ciphertext = ENC (plaintext || tag || pad)
     */
    return_t encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& plaintext, binary_t& ciphertext);
    return_t encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const byte_t* plaintext, size_t plainsize,
                     binary_t& ciphertext);
    return_t decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& ciphertext, binary_t& plaintext);
    return_t decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const byte_t* ciphertext, size_t ciphersize,
                     binary_t& plaintext);

    /* separated tag
     * case jose_encrypt_then_mac :
     *      separated tag
     */
    return_t encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& plaintext, binary_t& ciphertext,
                     binary_t& tag);
    return_t encrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const byte_t* plaintext, size_t plainsize,
                     binary_t& ciphertext, binary_t& tag);
    return_t decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const binary_t& ciphertext, binary_t& plaintext,
                     const binary_t& tag);
    return_t decrypt(const binary_t& enckey, const binary_t& mackey, const binary_t& iv, const binary_t& aad, const byte_t* ciphertext, size_t ciphersize,
                     binary_t& plaintext, const binary_t& tag);

    void addref();
    void release();

   protected:
    t_shared_reference<crypto_cbc_hmac> _shared;

    crypt_algorithm_t _enc_alg;
    hash_algorithm_t _mac_alg;
    uint16 _flag;  // authenticated_encryption_flag_t
};

}  // namespace crypto
}  // namespace hotplace

#endif
