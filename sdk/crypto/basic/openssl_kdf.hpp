/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *  RFC 6070 PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2)
 *  RFC 7914 The scrypt Password-Based Key Derivation Function
 *  RFC 9106 Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
 *  - openssl-3.2 required
 *
 *  HKDF = KDF_Extract + KDF_Expand
 *
 *      HKDF(okm, alg, dlen, ikm, salt, info);
 *
 *      KDF_Extract (prk, alg, salt, ikm);
 *      KDF_Expand (okm, alg, dlen, prk, info);
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_CRYPTO_OPENSSL_KDF__
#define __HOTPLACE_SDK_CRYPTO_OPENSSL_KDF__

#include <sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

// openssl-3.2
// argon2d (data-depending memory access)
// argon2i (data-independing memory access)
// argon2id (mixed, hashing, derivation)

enum argon2_t {
    argon2d = 1,
    argon2i = 2,
    argon2id = 3,
};

class openssl_kdf {
   public:
    openssl_kdf();
    ~openssl_kdf();

    /**
     * @desc
     *      HKDF(okm, alg, dlen, ikm, salt, info);
     *
     *      KDF_Extract (prk, alg, salt, ikm);
     *      KDF_Expand (okm, alg, dlen, prk, info);
     */

    /**
     * @brief   HKDF (Extract and Expand)
     * @param   binary_t& okm [out] output key material
     * @param   hash_algorithm_t alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& ikm [in] input key material
     * @param   const binary_t& salt [in] salt
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     */
    return_t hmac_kdf(binary_t& derived, hash_algorithm_t alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info);
    /**
     * @brief   HKDF (Extract and Expand)
     * @param   binary_t& okm [out] output key material
     * @param   const char* alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& ikm [in] input key material
     * @param   const binary_t& salt [in] salt
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     */
    return_t hmac_kdf(binary_t& derived, const char* alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info);

    /**
     * @brief   HKDF_Extract (aka HMAC)
     * @param   binary_t& prk [out] pseudo-random key
     * @param   const char* alg [in] algorithm
     * @param   const binary_t& salt [in] salt
     * @param   const binary_t& ikm [in] input key material
     * @return  error code (see error.hpp)
     */
    return_t hmac_kdf_extract(binary_t& prk, const char* alg, const binary_t& salt, const binary_t& ikm);
    /**
     * @brief   HKDF_Expand
     * @param   binary_t& okm [out] output key material
     * @param   const char* alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& prk [in] pseudo-random key
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     * @remarks
     */
    return_t hkdf_expand(binary_t& okm, const char* alg, size_t dlen, const binary_t& prk, const binary_t& info);
    /**
     * @brief   AES-based KDF_Expand
     * @param   binary_t& okm [out] output key material
     * @param   const char* alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& prk [in] pseudo-random key
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     * @remarks RFC 8152 direct+HKDF-AES-128, direct+HKDF-AES-256
     *          reference https://travis-ci.org/cose-wg/
     *          just HKDF wo extract
     */
    return_t hkdf_expand_aes_rfc8152(binary_t& okm, const char* alg, size_t dlen, const binary_t& prk, const binary_t& info);
    /**
     * @brief   CMAC-based Extract-and-Expand Key Derivation Function (CKDF)
     * @param   binary_t& okm [out] output key material
     * @param   crypt_algorithm_t alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& ikm [in] input key material
     * @param   const binary_t& salt [in] salt
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     * @remarks
     *          CMAC = CKDF-Extract + CKDF-Expand
     *
     *          CMAC "aes-128-cbc"
     *          CKDF-Extract "aes-128-cbc"
     *          CKDF-Expand "aes-128-ecb"
     * @desc    RFC 4493 Figure 2.3.  Algorithm AES-CMAC
     */
    return_t cmac_kdf(binary_t& okm, crypt_algorithm_t alg, size_t dlen, const binary_t& ikm, const binary_t& salt, const binary_t& info);
    /**
     * @brief   CMAC-based Extract
     * @param   binary_t& prk [out] pseudo-random key
     * @param   crypt_algorithm_t alg [in] algorithm
     * @param   const binary_t& salt [in] salt
     * @param   const binary_t& ikm [in] input key material
     * @return  error code (see error.hpp)
     * @desc    RFC 4493 Figure 2.3.  Algorithm AES-CMAC
     */
    return_t cmac_kdf_extract(binary_t& prk, crypt_algorithm_t alg, const binary_t& salt, const binary_t& ikm);
    /**
     * @brief   CMAC-based Expand
     * @param   binary_t& okm [in] output key material
     * @param   crypt_algorithm_t alg [in] algorithm
     * @param   size_t dlen [in] length
     * @param   const binary_t& prk [in] pseudo-random key
     * @param   const binary_t& info [in] info
     * @return  error code (see error.hpp)
     * @desc    RFC 4493 Figure 2.3.  Algorithm AES-CMAC
     */
    return_t cmac_kdf_expand(binary_t& okm, crypt_algorithm_t alg, size_t dlen, const binary_t& prk, const binary_t& info);
    /**
     * @brief   PBKDF2
     * @param   binary_t& derived [out]
     * @param   hash_algorithm_t alg [in]
     * @param   size_t dlen [in]
     * @param   const std::string& password [in]
     * @param   const binary_t& salt [in]
     * @param   int iter [in]
     * @return  error code (see error.hpp)
     */
    return_t pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const std::string& password, const binary_t& salt, int iter);
    return_t pbkdf2(binary_t& derived, const char* alg, size_t dlen, const std::string& password, const binary_t& salt, int iter);
    return_t pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const binary_t& password, const binary_t& salt, int iter);
    return_t pbkdf2(binary_t& derived, const char* alg, size_t dlen, const binary_t& password, const binary_t& salt, int iter);
    return_t pbkdf2(binary_t& derived, hash_algorithm_t alg, size_t dlen, const char* password, size_t size_password, const byte_t* salt, size_t size_salt,
                    int iter);
    return_t pbkdf2(binary_t& derived, const char* alg, size_t dlen, const char* password, size_t size_password, const byte_t* salt, size_t size_salt,
                    int iter);
    /**
     * @brief   scrypt
     * @param   binary_t& derived [out]
     * @param   size_t dlen [in]
     * @param   const std::string& password [in]
     * @param   const binary_t& salt [in]
     * @param   int n [in]
     * @param   int r [in]
     * @param   int p [in]
     */
    return_t scrypt(binary_t& derived, size_t dlen, const std::string& password, const binary_t& salt, int n, int r, int p);

    // bcrypt - blowfish based... (openssl 3.x deprecates bf)

    /**
     * @brief   argon2d/2i/2id openssl-3.2 required
     * @param   binary_t& derived [in]
     * @param   argon2_t mode [in]
     * @param   size_t dlen [in]
     * @param   const binary_t& password [in]
     * @param   const binary_t& salt [in]
     * @param   const binary_t& ad [in]
     * @param   const binary_t& secret [in]
     * @param   uint32 iteration_cost [inopt] default 3
     * @param   uint32 parallel_cost [inopt] default 4
     * @param   uint32 memory_cost [inopt] default 32
     * @return  error code (see error.hpp)
     *          not_supported .. openssl-1.1.1, 3.0
     */
    return_t argon2(binary_t& derived, argon2_t mode, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                    uint32 iteration_cost = 3, uint32 parallel_cost = 4, uint32 memory_cost = 32);
    return_t argon2d(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                     uint32 iteration_cost = 3, uint32 parallel_cost = 4, uint32 memory_cost = 32);
    return_t argon2i(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                     uint32 iteration_cost = 3, uint32 parallel_cost = 4, uint32 memory_cost = 32);
    return_t argon2id(binary_t& derived, size_t dlen, const binary_t& password, const binary_t& salt, const binary_t& ad, const binary_t& secret,
                      uint32 iteration_cost = 3, uint32 parallel_cost = 4, uint32 memory_cost = 32);
};

}  // namespace crypto
}  // namespace hotplace

#endif
