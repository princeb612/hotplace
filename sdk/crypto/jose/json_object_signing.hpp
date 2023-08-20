/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 7515 JSON Web Signature (JWS)
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_JOSE_SIGNING__
#define __HOTPLACE_SDK_CRYPTO_JOSE_SIGNING__

#include <hotplace/sdk/crypto/jose/types.hpp>

namespace hotplace {
namespace crypto {

class json_object_signing
{
public:
    json_object_signing ();
    ~json_object_signing ();

    /*
     * @brief sign
     * @param crypto_key* key [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign (crypto_key* key, crypt_sig_t method, binary_t input, binary_t& output);
    /*
     * @brief sign and return signature and kid
     * @param crypto_key* key [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     * @param std::string& kid [out]
     * @remarks see json_object_signing_encryption::sign
     */
    return_t sign (crypto_key* key, crypt_sig_t method, binary_t input, binary_t& output, std::string& kid);
    /*
     * @brief verify
     * @param crypto_key* key [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t output [in]
     * @param bool& result [out]
     * @remarks see json_object_signing_encryption::verify
     */
    return_t verify (crypto_key* key, crypt_sig_t method, binary_t input, binary_t output, bool& result);
    /*
     * @brief verify with kid
     * @param crypto_key* key [in]
     * @param const char* kid [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t output [in]
     * @param bool& result [out]
     * @remarks see json_object_signing_encryption::verify
     */
    return_t verify (crypto_key* key, const char* kid, crypt_sig_t method, binary_t input, binary_t output, bool& result);

protected:
    /*
     * @brief sign
     * @param EVP_PKEY* pkey [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     */
    return_t sign_general (EVP_PKEY* pkey, crypt_sig_t method, binary_t input, binary_t& output);
    /*
     * @brief sign (X9_62_prime256v1, secp384r1, secp521r1)
     * @param EVP_PKEY* pkey [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     */
    return_t sign_ecdsa (EVP_PKEY* pkey, crypt_sig_t method, binary_t input, binary_t& output);
    /*
     * @brief sign (Ed25519, Ed448)
     * @param EVP_PKEY* pkey [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     */
    return_t sign_eddsa (EVP_PKEY* pkey, crypt_sig_t method, binary_t input, binary_t& output);
    /*
     * @brief sign
     * @param EVP_PKEY* pkey [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t& output [out]
     * @remarks PKCS#1 v2.1
     */
    return_t sign_rsassa_pss (EVP_PKEY* pkey, crypt_sig_t method, binary_t input, binary_t& output);
    /*
     * @brief verify
     * @param EVP_PKEY* pkey [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t output [in]
     * @param bool& result [out]
     */
    return_t verify_hmac (EVP_PKEY* pkey, crypt_sig_t method, binary_t input, binary_t output, bool& result);
    /*
     * @brief verify
     * @param EVP_PKEY* pkey [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t output [in]
     * @param bool& result [out]
     * @remarks PKCS#1 v1.5
     */
    return_t verify_rsassa_pkcs1_v1_5 (EVP_PKEY* pkey, crypt_sig_t method, binary_t input, binary_t output, bool& result);
    /*
     * @brief verify (X9_62_prime256v1, secp384r1, secp521r1)
     * @param EVP_PKEY* pkey [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t output [in]
     * @param bool& result [out]
     */
    return_t verify_ecdsa (EVP_PKEY* pkey, crypt_sig_t method, binary_t input, binary_t output, bool& result);
    /*
     * @brief verify (Ed25519, Ed448)
     * @param EVP_PKEY* pkey [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t output [in]
     * @param bool& result [out]
     */
    return_t verify_eddsa (EVP_PKEY* pkey, crypt_sig_t method, binary_t input, binary_t output, bool& result);
    /*
     * @brief verify
     * @param EVP_PKEY* pkey [in]
     * @param crypt_sig_t method [in]
     * @param binary_t input [in]
     * @param binary_t output [in]
     * @param bool& result [out]
     * @remarks PKCS#1 v2.1
     */
    return_t verify_rsassa_pss (EVP_PKEY* pkey, crypt_sig_t method, binary_t input, binary_t output, bool& result);
    /*
     * @brief constraints
     * @param crypt_sig_t sig [in]
     * @param EVP_PKEY* pkey [in]
     */
    return_t  check_constraints (crypt_sig_t sig, EVP_PKEY* pkey);
};

}
}  // namespace

#endif
