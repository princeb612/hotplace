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

#include <hotplace/sdk/crypto/basic/crypto_keyext.hpp>
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
class json_web_key : public crypto_keyext
{
    friend class json_object_signing_encryption;
public:
    json_web_key ();
    virtual ~json_web_key ();

    /**
     * @brief load JWK from a buffer
     * @param crypto_key * crypto_key [in]
     * @param const char* buffer [in] json formatted string
     * @param int flags [inopt] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t load (crypto_key* crypto_key, const char* buffer, int flags = 0);
    /**
     * @brief write
     * @param crypto_key* crypto_key [in]
     * @param char* buf [out] null-terminated
     * @param size_t* buflen [inout]
     * @param int flag [inopt] 0 public only, 1 also private
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          size_t size = 0;
     *          std::vector<char> bin;
     *          jwk.write (&privkey, &bin[0], &size);
     *          bin.resize (size);
     *          jwk.write (&privkey, &bin[0], &size);
     */
    virtual return_t write (crypto_key* crypto_key, char* buf, size_t* buflen, int flags = 0);
    /**
     * @brief   write
     * @param   crypto_key* crypto_key [in]
     * @param   std::string& buf [out]
     * @param   int flags [inopt]
     */
    return_t write (crypto_key* crypto_key, std::string& buf, int flags = 0);
    /**
     * @brief   write
     * @param   crypto_key* crypto_key [in]
     * @param   stream_t* buf [out]
     * @param   int flags [inopt]
     */
    return_t write (crypto_key* crypto_key, stream_t* buf, int flags = 0);
    /**
     * @brief load key from a file
     * @param crypto_key * crypto_key [in]
     * @param const char* file [in]
     * @param int flags [inopt] reserved
     * @return error code (see error.hpp)
     */
    virtual return_t load_file (crypto_key* crypto_key, const char* file, int flags = 0);
    /**
     * @brief write JWK to a file
     * @param crypto_key * crypto_key [in]
     * @param const char* file [in]
     * @param int flag [inopt] 0 public only, 1 also private
     * @return error code (see error.hpp)
     */
    virtual return_t write_file (crypto_key* crypto_key, const char* file, int flags = 0);

protected:
    return_t read_json_keynode (crypto_key* crypto_key, json_t* json);
};

}
}  // namespace

#endif
