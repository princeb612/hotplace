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
