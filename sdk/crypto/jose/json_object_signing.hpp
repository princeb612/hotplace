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

#ifndef __HOTPLACE_SDK_CRYPTO_JOSE_JSONOBJECTSIGNING__
#define __HOTPLACE_SDK_CRYPTO_JOSE_JSONOBJECTSIGNING__

#include <sdk/crypto/jose/types.hpp>

namespace hotplace {
namespace crypto {

class json_object_signing {
   public:
    json_object_signing();
    ~json_object_signing();

    /**
     * @brief sign
     * @param jose_context_t* context [in]
     * @param jws_t method [in]
     * @param const std::string& input [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          crypto_key crypto_key;
     *          jwk.load_file (&crypto_key, "rfc7515.jwk", 0);
     *          json_object_signing_encryption jose;
     *          bool result = false;
     *          std::string jws_result;
     *
     *          jose_context_t* jose_context = nullptr;
     *          jose.open (&jose_context, &crypto_key);
     *          jose.sign (jose_context, jws_t::jws_hs256, claim, jws_result);
     *          jose.verify (jose_context, jws_result, result);
     *          jose.close (jose_context);
     */
    return_t sign(jose_context_t* context, jws_t method, const std::string& input, std::string& output,
                  jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief sign
     * @param jose_context_t* context [in]
     * @param std::list <jws_t> const& methods [in]
     * @param const std::string& input [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          crypto_key crypto_key;
     *          jwk.load_file (&crypto_key, "rfc7515.jwk", 0);
     *          json_object_signing_encryption jose;
     *          bool result = false;
     *          std::string jws_result;
     *          std::list <jws_t> methods;
     *          methods.push_back (jws_t::jws_hs256);
     *          methods.push_back (jws_t::jws_rs256);
     *          methods.push_back (jws_t::jws_es256);
     *
     *          jose_context_t* jose_context = nullptr;
     *          jose.open (&jose_context, &crypto_key);
     *          jose.sign (jose_context, methods, claim, jws_result);
     *          jose.verify (jose_context, jws_result, result);
     *          jose.close (jose_context);
     */
    return_t sign(jose_context_t* context, std::list<jws_t> const& methods, const std::string& input, std::string& output,
                  jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief sign
     * @param jose_context_t* context [in]
     * @param const std::string& protected_header [in]
     * @param const std::string& input [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     * @return error code (see error.hpp)
     * @example
     *          json_web_key jwk;
     *          crypto_key crypto_key;
     *          jwk.load_file (&crypto_key, "rfc7515.jwk", 0);
     *          json_object_signing_encryption jose;
     *          bool result = false;
     *          std::string jws_result;
     *
     *          jose_context_t* jose_context = nullptr;
     *          jose.open (&jose_context, &crypto_key);
     *          jose.sign (jose_context, (char*) hs256_header, claim, jws_result);
     *          jose.verify (jose_context, jws_result, result);
     *          jose.close (jose_context);
     */
    return_t sign(jose_context_t* context, const std::string& protected_header, const std::string& input, std::string& output,
                  jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief sign
     * @param jose_context_t* context [in]
     * @param std::list<std::string> const& headers [in]
     * @param const std::string& input [in]
     * @param std::string& output [out]
     * @param jose_serialization_t type [inopt]
     * @return error code (see error.hpp)
     */
    return_t sign(jose_context_t* context, std::list<std::string> const& headers, const std::string& input, std::string& output,
                  jose_serialization_t type = jose_serialization_t::jose_compact);
    /**
     * @brief verify
     * @param jose_context_t* context [in]
     * @param const std::string& input [in]
     * @param bool& result [out]
     * @return error code (see error.hpp)
     */
    return_t verify(jose_context_t* context, const std::string& input, bool& result);

   protected:
    /**
     * @brief sign
     * @param crypto_key* key [in]
     * @param jws_t method [in]
     * @param const binary_t& input [in]
     * @param binary_t& output [out]
     * @remarks see json_object_signing_encryption::sign
     */
    return_t dosign(crypto_key* key, jws_t method, const binary_t& input, binary_t& output);
    /**
     * @brief sign and return signature and kid
     * @param crypto_key* key [in]
     * @param jws_t method [in]
     * @param const binary_t& input [in]
     * @param binary_t& output [out]
     * @param std::string& kid [out]
     * @remarks see json_object_signing_encryption::sign
     */
    return_t dosign(crypto_key* key, jws_t method, const binary_t& input, binary_t& output, std::string& kid);
    /**
     * @brief verify
     * @param crypto_key* key [in]
     * @param jws_t method [in]
     * @param const binary_t& input [in]
     * @param const binary_t& output [in]
     * @param bool& result [out]
     * @remarks see json_object_signing_encryption::verify
     */
    return_t doverify(crypto_key* key, jws_t method, const binary_t& input, const binary_t& output, bool& result);
    /**
     * @brief verify with kid
     * @param crypto_key* key [in]
     * @param const char* kid [in]
     * @param jws_t method [in]
     * @param const binary_t& input [in]
     * @param const binary_t& output [in]
     * @param bool& result [out]
     * @remarks see json_object_signing_encryption::verify
     */
    return_t doverify(crypto_key* key, const char* kid, jws_t method, const binary_t& input, const binary_t& output, bool& result);

    /**
     * @brief constraints
     * @param jws_t sig [in]
     * @param const EVP_PKEY* pkey [in]
     */
    return_t check_constraints(jws_t sig, const EVP_PKEY* pkey);

    class composer {
       public:
        composer();
        /**
         * @brief parse
         * @param jose_context_t* context [in]
         * @param const char* signature [in]
         */
        return_t parse_signature(jose_context_t* context, const char* signature);
        /**
         * @brief parse
         * @param jose_context_t* context [in]
         * @param const char* protected_header [in]
         * @param jws_t& method [out]
         * @param std::string& keyid [out]
         */
        return_t parse_signature_protected_header(jose_context_t* context, const char* protected_header, jws_t& method, std::string& keyid);
        /**
         * @brief write
         * @param jose_context_t* context [in]
         * @param std::string& signature [out]
         * @param jose_serialization_t type [inopt]
         */
        return_t compose_signature(jose_context_t* context, std::string& signature, jose_serialization_t type = jose_serialization_t::jose_compact);
    };
};

}  // namespace crypto
}  // namespace hotplace

#endif
