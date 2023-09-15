/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @desc
 *  RFC 7517 JSON Web Key (JWK)
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_JOSE_JWK__
#define __HOTPLACE_SDK_CRYPTO_JOSE_JWK__

#include <hotplace/sdk/crypto/basic/crypto_json_key.hpp>
#include <hotplace/sdk/crypto/jose/types.hpp>

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
class json_web_key : public crypto_json_key
{
    friend class json_object_signing_encryption;
public:
    json_web_key ();
    virtual ~json_web_key ();

    /**
     * @brief load JWK from a buffer
     * @param crypto_key * crypto_key [in]
     * @param const char* buffer [in]
     * @param int flags [in] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t load (crypto_key* crypto_key, const char* buffer, int flags = 0);
    /**
     * @brief write
     * @param crypto_key* crypto_key [in]
     * @param char* buf [out] null-terminated
     * @param size_t* buflen [inout]
     * @param int flag [in] 0 public only, 1 also private
     * @return error code (see error.hpp)
     */
    virtual return_t write (crypto_key* crypto_key, char* buf, size_t* buflen, int flags = 0);
    /**
     * @brief write JWK to a file
     * @param crypto_key * crypto_key [in]
     * @param const char* file [in]
     * @param int flag [in] 0 public only, 1 also private
     * @return error code (see error.hpp)
     */
    virtual return_t write_json (crypto_key* crypto_key, const char* file, int flags = 0);

protected:

    /**
     * @brief parse
     * @param crypto_key* crypto_key [in]
     * @param json_t* json [in]
     */
    virtual return_t read (crypto_key* crypto_key, json_t* json);
};

}
}  // namespace

#endif
