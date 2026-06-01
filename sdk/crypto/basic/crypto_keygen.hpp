/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   crypto_keygen.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOKEYGEN__
#define __HOTPLACE_SDK_CRYPTO_BASIC_CRYPTOKEYGEN__

#include <hotplace/sdk/crypto/basic/crypto_key.hpp>

namespace hotplace {
namespace crypto {

/**
 * @comments
 *          // sketch
 *          crypto_key key;
 *
 *          // kty_ec, secp256r1
 *          crypto_keygen keygen_p256(&key, "P-256");
 *          keygen_p256.set(keydesc("P-256")).gen();
 *
 *          // kty_okp, x25519, base16
 *          crypto_keygen keygen_x25519(&key, "X25519");
 *          keygen_x25519.set(keydesc("X25519"))
 *              .set(crypt_item_t::ec_x, "...")
 *              .set(crypt_item_t::ec_d, "...")
 *              .build();  // private key (x, d)
 *
 *          // kty_ec, secp384r1, base64url
 *          crypto_keygen keygen_p384(&key, "P-384", encoding_t::encoding_base64url);
 *          keygen_p384.set(keydesc("P-384"))
 *              .set(crypt_item_t::ec_x, "...")
 *              .set(crypt_item_t::ec_y, "...")
 *              .set(crypt_item_t::ec_d, "...")
 *              .build();
 *
 *          crypto_keygen keygen_p256uncompressed(&key, "P-256");
 *          keygen_p256uncompressed.set(keydesc("P-256 uncompressed"))
 *              .set("uncompressed", "...")
 *              .set("d", "...")
 *              .build();
 *
 *          crypto_keygen keygen_p256compressed(&key, "P-256");
 *          keygen_p256compressed.set(keydesc("P-256 compressed public"))
 *              .set("x", "...")
 *              .set("ybit", true)
 *              .build();
 *
 *          crypto_keygen keygen_x25519(&key, "X25519");
 *          keygen_x25519.set(keydesc("X25519"))
 *              .set("x", "...")
 *              .set("d", "...")
 *              .build();  // private key (x, d)
 */
class crypto_keygen {
   public:
    /**
     * @brief   key generator
     * @param   crypto_key* key [in]
     * @param   const std::string& name [in]
     * @param   encoding_t encoding [inopt] default encoding_base16
     */
    crypto_keygen(crypto_key* key, const std::string& name, encoding_t encoding = {});

    crypto_keygen& set(keydesc&& desc);
    crypto_keygen& set(crypt_item_t item, binary_t&& value);
    crypto_keygen& set(crypt_item_t item, const char* value);
    crypto_keygen& set(crypt_item_t item, bool value);
    crypto_keygen& set(const char* item, binary_t&& value);
    crypto_keygen& set(const char* item, const char* value);
    crypto_keygen& set(const char* item, bool value);

    crypto_keygen& gen();
    /**
     * @brief   generate pkey into crypto_key
     * @remarks clear all crypt_item_t
     */
    crypto_keygen& build();
    return_t result();

    /**
     * @brief   OCT
     */
    static return_t add_oct(crypto_key* cryptokey, size_t size, keydesc&& desc);
    static return_t add_oct(crypto_key* cryptokey, const byte_t* k, size_t size, keydesc&& desc);
    /**
     * @param   uint32 nid [in] "rsaEncryption" EVP_PKEY_RSA (NID_rsaEncryption)
     * @remarks
     *          RSA2 not supported
     *              "RSA" EVP_PKEY_RSA2 (NID_rsa)
     */
    static return_t add_rsa(crypto_key* cryptokey, uint32 nid, size_t bits, keydesc&& desc);
    static return_t add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, keydesc&& desc);
    static return_t add_rsa(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, const binary_t& p, const binary_t& q,
                            const binary_t& dp, const binary_t& dq, const binary_t& qi, keydesc&& desc);
    /**
     * @param   uint32 nid [in] "RSASSA-PSS"    EVP_PKEY_RSA_PSS (NID_rsassaPss)
     */
    static return_t add_rsapss(crypto_key* cryptokey, uint32 nid, const binary_t& n, const binary_t& e, const binary_t& d, keydesc&& desc);
    /**
     * @brief   EC
     */
    static return_t add_ec(crypto_key* cryptokey, uint32 nid, keydesc&& desc);
    static return_t add_ec(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& y, const binary_t& d, keydesc&& desc);
    static return_t add_ec_compressed(crypto_key* cryptokey, uint32 nid, const binary_t& x, bool ysign, const binary_t& d, keydesc&& desc);
    static return_t add_ec_uncompressed(crypto_key* cryptokey, uint32 nid, const byte_t* pubkey, size_t pubsize, const byte_t* privkey, size_t privsize, keydesc&& desc);
    /**
     * @brief   OKP
     */
    static return_t add_okp(crypto_key* cryptokey, uint32 nid, keydesc&& desc);
    static return_t add_okp(crypto_key* cryptokey, uint32 nid, const binary_t& x, const binary_t& d, keydesc&& desc);
    static return_t add_okp(crypto_key* cryptokey, uint32 nid, const byte_t* x, size_t pubsize, const byte_t* d, size_t privsize, keydesc&& desc);
    /**
     * @brief   DH
     */
    static return_t add_dh(crypto_key* cryptokey, uint32 nid, keydesc&& desc);
    static return_t add_dh(crypto_key* cryptokey, uint32 nid, const binary_t& y, const binary_t& x, keydesc&& desc);
    static return_t add_dh(crypto_key* cryptokey, uint32 nid, const binary_t& p, const binary_t& q, const binary_t& g, const binary_t& x, keydesc&& desc);
    /**
     * @brief   DSA
     */
    static return_t add_dsa(crypto_key* cryptokey, uint32 nid, keydesc&& desc);
    static return_t add_dsa(crypto_key* cryptokey, uint32 nid, const binary_t& y, const binary_t& x, const binary_t& p, const binary_t& q, const binary_t& g,
                            keydesc&& desc);
    /**
     * @brief   ML-KEM, ML-DSA, SLH-DSA
     */
    static return_t pkey_keygen_byname(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const char* name);
    static return_t pkey_encode_format(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase = nullptr);
    static return_t pkey_decode_format(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase = nullptr);
    static return_t pkey_decode_format(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                                       const char* passphrase = nullptr);
    static return_t pkey_encode_raw(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding);
    static return_t pkey_decode(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                                const char* passphrase = nullptr);
    static return_t pkey_decode_raw(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding);
    static bool pkey_is_private(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey);
    static return_t add_ossl3(crypto_key* cryptokey, uint32 nid, keydesc&& desc);
    static return_t add_ossl3(crypto_key* cryptokey, const char* name, keydesc&& desc);
    static return_t add_ossl3(crypto_key* cryptokey, const char* name, const byte_t* keydata, size_t keysize, key_encoding_t encoding, keydesc&& desc);

   protected:
   private:
    critical_section _lock;
    crypto_key* _key;
    std::string _name;     // "P-256", ...
    encoding_t _encoding;  // see encoding_t
    keydesc _desc;         // kid, use
    std::map<crypt_item_t, binary_t> _map;
    std::map<crypt_item_t, variant> _vtmap;
};

}  // namespace crypto
}  // namespace hotplace

#endif
