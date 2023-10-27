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

#include <sdk/crypto/basic/types.hpp>
#include <sdk/crypto/crypto.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief openssl_sign
 */
class openssl_sign {
   public:
    /**
     * @brief constructor
     */
    openssl_sign();
    /**
     * @brief destructor
     */
    virtual ~openssl_sign();

    /**
     * @biref   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   crypt_sig_t mode [in]
     * @param   binary_t const& input [in]
     * @param   binary_t& signature [out]
     */
    return_t sign(const EVP_PKEY* pkey, crypt_sig_t mode, binary_t const& input, binary_t& signature);
    /**
     * @biref   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   crypt_sig_t mode [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     */
    return_t verify(const EVP_PKEY* pkey, crypt_sig_t mode, binary_t const& input, binary_t const& signature);

    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    HS256, HS384, HS512
     */
    return_t sign_digest(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t& signature);
    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    HS256, HS384, HS512
     */
    return_t sign_hmac(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t& signature);
    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    RS256, RS384, RS512
     */
    return_t sign_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t& signature);
    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    ES256, ES384, ES512, ES256K
     */
    return_t sign_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t& signature);
    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    PS256, PS384, PS512
     */
    return_t sign_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t& signature);
    /*
     * @brief   sign
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    EdDSA
     */
    return_t sign_eddsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t& signature);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    HS256, HS384, HS512
     */
    return_t verify_digest(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t const& signature);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    HS256, HS384, HS512
     */
    return_t verify_hmac(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t const& signature);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    RS256, RS384, RS512
     */
    return_t verify_rsassa_pkcs15(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t const& signature);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    ES256, ES384, ES512, ES256K
     */
    return_t verify_ecdsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t const& signature);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    PS256, PS384, PS512
     */
    return_t verify_rsassa_pss(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t const& signature);
    /*
     * @brief   verify
     * @param   const EVP_PKEY* pkey [in]
     * @param   hash_algorithm_t hashalg [in]
     * @param   binary_t const& input [in]
     * @param   binary_t const& signature [in]
     * @desc    EdDSA
     */
    return_t verify_eddsa(const EVP_PKEY* pkey, hash_algorithm_t hashalg, binary_t const& input, binary_t const& signature);
};

}  // namespace crypto
}  // namespace hotplace

#endif
