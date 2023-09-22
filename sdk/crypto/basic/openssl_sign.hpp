/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2009.06.18   Soo Han, Kim        implemented (codename.merlin)
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_SIGN__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_SIGN__

#include <hotplace/sdk/crypto/crypto.hpp>
#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief openssl_sign
 */
class openssl_sign
{
public:
    /**
     * @brief constructor
     */
    openssl_sign ();
    /**
     * @brief destructor
     */
    virtual ~openssl_sign ();

    /**
     * @biref   sign
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t& signature [out]
     * @param   crypt_sig_t mode [in]
     */
    return_t sign (EVP_PKEY* pkey, binary_t const& input, binary_t& signature, crypt_sig_t mode);
    /**
     * @biref   verify
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   crypt_sig_t mode [in]
     */
    return_t verify (EVP_PKEY* pkey, binary_t const& input, binary_t const& signature, crypt_sig_t mode);

    /*
     * @brief   sign
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    HS256, HS384, HS512
     */
    return_t sign_digest (EVP_PKEY* pkey, binary_t const& input, binary_t& signature, hash_algorithm_t hashalg);
    /*
     * @brief   sign
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    HS256, HS384, HS512
     */
    return_t sign_hmac (EVP_PKEY* pkey, binary_t const& input, binary_t& signature, hash_algorithm_t hashalg);
    /*
     * @brief   sign
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    RS256, RS384, RS512
     */
    return_t sign_rsassa_pkcs15 (EVP_PKEY* pkey, binary_t const& input, binary_t& signature, hash_algorithm_t hashalg);
    /*
     * @brief   sign
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    ES256, ES384, ES512, ES256K
     */
    return_t sign_ecdsa (EVP_PKEY* pkey, binary_t const& input, binary_t& signature, hash_algorithm_t hashalg);
    /*
     * @brief   sign
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    PS256, PS384, PS512
     */
    return_t sign_rsassa_pss (EVP_PKEY* pkey, binary_t const& input, binary_t& signature, hash_algorithm_t hashalg);
    /*
     * @brief   sign
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    EdDSA
     */
    return_t sign_eddsa (EVP_PKEY* pkey, binary_t const& input, binary_t& signature, hash_algorithm_t hashalg);
    /*
     * @brief   verify
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    HS256, HS384, HS512
     */
    return_t verify_digest (EVP_PKEY* pkey, binary_t const& input, binary_t const& signature, hash_algorithm_t hashalg);
    /*
     * @brief   verify
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    HS256, HS384, HS512
     */
    return_t verify_hmac (EVP_PKEY* pkey, binary_t const& input, binary_t const& signature, hash_algorithm_t hashalg);
    /*
     * @brief   verify
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    RS256, RS384, RS512
     */
    return_t verify_rsassa_pkcs15 (EVP_PKEY* pkey, binary_t const& input, binary_t const& signature, hash_algorithm_t hashalg);
    /*
     * @brief   verify
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    ES256, ES384, ES512, ES256K
     */
    return_t verify_ecdsa (EVP_PKEY* pkey, binary_t const& input, binary_t const& signature, hash_algorithm_t hashalg);
    /*
     * @brief   verify
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    PS256, PS384, PS512
     */
    return_t verify_rsassa_pss (EVP_PKEY* pkey, binary_t const& input, binary_t const& signature, hash_algorithm_t hashalg);
    /*
     * @brief   verify
     * @param   EVP_PKEY* pkey [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @param   hash_algorithm_t hashalg [in]
     * @desc    EdDSA
     */
    return_t verify_eddsa (EVP_PKEY* pkey, binary_t const& input, binary_t const& signature, hash_algorithm_t hashalg);
};

}
}  // namespace

#endif
