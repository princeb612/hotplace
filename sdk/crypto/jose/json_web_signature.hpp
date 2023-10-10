/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7515 JSON Web Signature (JWS)
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_JOSE_JWS__
#define __HOTPLACE_SDK_CRYPTO_JOSE_JWS__

#include <hotplace/sdk/crypto/jose/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief RFC 7515 JSON Web Signature (JWS)
 *
 * @remarks
 *
 *  1. algorithm implementation
 *
 *  alg           | support |
 *  HS256/384/512 |    O    | HMAC using SHA-256/SHA-384/SHA-512
 *  RS256/384/512 |    O    | RSASSA-PKCS1-v1_5 using SHA-256/SHA-384/SHA-512
 *  ES256/384/512 |    O    | ECDSA using P-256 and SHA-256/P-384 and SHA-384/P-521 and SHA-512
 *  PS256/384/512 |    O    | RSASSA-PSS using SHA-256 and MGF1 with SHA-256/P-384 and SHA-384/P-521 and SHA-512
 *
 *  2. signatrure format
 *
 *  compact
 *  base64_url_encode(header) || . || base64_url_encode(claims) || . || base64_url_encode(signature)
 *
 *  json
 *  {
 *    payload:base64_url_encode(claims), // {iss:iss_value, exp:exp_value}
 *    signatures:[
 *     {
 *      protected:base64_url_encode(header1), // {alg:ES256}
 *      header:string({kid:kid_name1}), //
 *      signature:base64_url_encode(signature1)
 *     },
 *     {
 *      protected:base64_url_encode(header2), // {alg:RS256}
 *      header:string({kid:kid_name2}), //
 *      signature:base64_url_encode(signature2)
 *     }
 *    ]
 *  }
 *
 * flat
 *  {
 *    payload:base64_url_encode(claims), // {iss:iss_value, exp:exp_value}
 *    protected:base64_url_encode(header), // {alg:RS256}
 *    header:string({kid:kid_name}), //
 *    signature:base64_url_encode(signature)
 *  }
 *
 */
class json_web_signature {
   public:
    json_web_signature();
    ~json_web_signature();

    /**
     * @brief sign
     * @param crypto_key* crypto_key [in]
     * @param std::string const& header [in]
     * @param std::string const& claims [in]
     * @param std::string& signature [out]
     * @param jose_serialization_t mode [in]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::sign
     * @example
     *          const char claim[] = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
     *          crypto_key key;
     *          json_web_key jwk;
     *          jwk.load_file (&key, "rfc7515.jwk", 0);
     *          jws.sign (&key, jws_t::jws_es256, claim, signature);
     *          //  eyJhbGciOiJFUzI1NiJ9
     *          //  .
     *          //  eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ
     *          //  .
     *          // DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q
     */
    return_t sign(crypto_key* crypto_key, std::string const& header, std::string const& claims, std::string& signature,
                  jose_serialization_t mode = jose_serialization_t::jose_compact);
    /**
     * @brief sign
     * @param crypto_key* crypto_key [in]
     * @param std::list<std::string> const& headers [in]
     * @param std::string const& claims [in]
     * @param std::string& signature [out]
     * @param jose_serialization_t mode [in]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::sign
     * @example
     *          headers.push_back (hs256_header);
     *          headers.push_back (rs256_header);
     *          headers.push_back (es256_header);
     *          headers.push_back (ps256_header);
     *          jws.sign (&crypto_key, headers, claim, signature);
     */
    return_t sign(crypto_key* crypto_key, std::list<std::string> const& headers, std::string const& claims, std::string& signature,
                  jose_serialization_t mode = jose_serialization_t::jose_compact);
    /**
     * @brief sign
     * @param crypto_key* crypto_key [in]
     * @param jws_t alg header [in]
     * @param std::string const& claims [in]
     * @param std::string& signature [out]
     * @param jose_serialization_t mode [in]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::sign
     * @example
     *          jws.sign (&crypto_key, jws_t::jws_hs256, claim, signature);
     */
    return_t sign(crypto_key* crypto_key, jws_t alg, std::string const& claims, std::string& signature,
                  jose_serialization_t mode = jose_serialization_t::jose_compact);
    /**
     * @brief sign
     * @param crypto_key* crypto_key [in]
     * @param std::list<jws_t> const& algs [in]
     * @param std::string const& claims [in]
     * @param std::string& signature [out]
     * @param jose_serialization_t mode [in]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::sign
     * @example
     *          algs.push_back (jws_t::jws_hs256);
     *          algs.push_back (jws_t::jws_rs256);
     *          algs.push_back (jws_t::jws_es256);
     *          algs.push_back (jws_t::jws_ps256);
     *          jws.sign (&crypto_key, algs, claim, signature);
     */
    return_t sign(crypto_key* crypto_key, std::list<jws_t> const& algs, std::string const& claims, std::string& signature,
                  jose_serialization_t mode = jose_serialization_t::jose_compact);
    /**
     * @brief verify
     * @param crypto_key* crypto_key [in]
     * @param std::string const& signature [in]
     * @param bool& result [out]
     * @return error code (see error.hpp)
     * @remarks see json_object_signing_encryption::verify
     */
    return_t verify(crypto_key* crypto_key, std::string const& signature, bool& result);
};

}  // namespace crypto
}  // namespace hotplace

#endif
