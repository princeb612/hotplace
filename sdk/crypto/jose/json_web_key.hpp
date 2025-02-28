/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @desc
 *  RFC 7517 JSON Web Key (JWK)
 *  RFC 8037 CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_JOSE_JWK__
#define __HOTPLACE_SDK_CRYPTO_JOSE_JWK__

#include <jansson.h>

#include <sdk/crypto/basic/crypto_keychain.hpp>  // crypto_keychain
#include <sdk/crypto/jose/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief RFC 7517 JSON Web Key (JWK)
 * @remarks
 *      support JWK (kty oct, RSA, EC, OKP
 *      support PEM
 *
 *          crypto_key key;
 *          json_web_key jwk;
 *          jwk.load_file (&key, "rfc7515.jwk", 0);
 *          jwk.load_pem_file (&key, "test.pem");
 */
class json_web_key : public crypto_keychain {
    friend class json_object_signing_encryption;

   public:
    json_web_key();
    virtual ~json_web_key();

    /**
     * @brief load from buffer
     * @param crypto_key* cryptokey [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param const char* buffer [in]
     * @param size_t size [in]
     * @param const keydesc& desc [inopt]
     * @param int flag [inopt]
     * @return error code (see error.hpp)
     */
    virtual return_t load(crypto_key* cryptokey, keyflag_t mode, const char* buffer, size_t size, const keydesc& desc = keydesc(), int flag = 0);
    return_t load_pem(crypto_key* cryptokey, const char* buffer, size_t size, const keydesc& desc = keydesc(), int flag = 0);
    /**
     * @brief write
     * @brief write into buffer
     * @param crypto_key* cryptokey [in]
     * @param keyflag_t mode [in] see keyflag_t
     * @param stream_t* stream [in]
     * @param int flags [in] public_key | private_key
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          size_t size = 0;
     *          std::vector<char> bin;
     *          jwk.write (&privkey, &bin[0], &size);
     *          bin.resize (size);
     *          jwk.write (&privkey, &bin[0], &size);
     */
    virtual return_t write(crypto_key* cryptokey, keyflag_t mode, stream_t* stream, int flags = public_key);
    /**
     * @brief   write
     * @param   crypto_key* cryptokey [in]
     * @param   std::string& buf [out]
     * @param   int flags [inopt] public_key | private_key
     */
    return_t write(crypto_key* cryptokey, std::string& buf, int flags = public_key);
    /**
     * @brief   write
     * @param   crypto_key* cryptokey [in]
     * @param   stream_t* buf [out]
     * @param   int flags [inopt] public_key | private_key
     */
    return_t write(crypto_key* cryptokey, stream_t* buf, int flags = public_key);

   protected:
    return_t read_json_keynode(crypto_key* cryptokey, json_t* json);
};

}  // namespace crypto
}  // namespace hotplace

#endif
