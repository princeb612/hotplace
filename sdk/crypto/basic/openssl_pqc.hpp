/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_CRYPTO_BASIC_OPENSSLPQC__
#define __HOTPLACE_SDK_CRYPTO_BASIC_OPENSSLPQC__

#include <hotplace/sdk/crypto/basic/types.hpp>

namespace hotplace {
namespace crypto {

/**
 * @brief ML-KEM
 * @remarks
 *      ML-KEM - openssl-3.5 required
 *
 *      | name          | group | NID                         | encode | encaps |
 *      | "ML-KEM-512"  |   512 | 1454 (EVP_PKEY_ML_KEM_512)  |    800 |    768 |
 *      | "ML-KEM-768"  |   513 | 1455 (EVP_PKEY_ML_KEM_768)  |   1184 |   1088 |
 *      | "ML-KEM-1024" |   514 | 1456 (EVP_PKEY_ML_KEM_1024) |   1568 |   1568 |
 *
 *      hybrid ECDHE-MLKEM
 *
 *      | name               | group | encode    | encaps    |
 *      | SecP256r1MLKEM768  |  4587 | 1184 + 65 | 1088 + 65 |
 *      | X25519MLKEM768     |  4588 | 1184 + 32 | 1088 + 32 |
 *      | SecP384r1MLKEM1024 |  4589 | 1568 + 97 | 1568 + 97 |
 *
 *      oqs-provider - openssl-3.0 required
 */

class openssl_pqc {
   public:
    openssl_pqc();
    ~openssl_pqc();

    /**
     * @brief emcode
     * @param OSSL_LIB_CTX* libctx [in]
     * @param const EVP_PKEY* pkey [in]
     * @param binary_t& keydata [out]
     * @param key_encoding_t encoding [in]
     * @param const char* passphrase [inopt]
     */
    return_t encode(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keydata, key_encoding_t encoding, const char* passphrase = nullptr);
    /**
     * @param OSSL_LIB_CTX* libctx [in]
     * @param EVP_PKEY** pkey [out]
     * @param const binary_t& keydata [in]
     * @param key_encoding_t encoding [in]
     *          key_encoding_priv_pem
     *          key_encoding_encrypted_priv_pem
     *          key_encoding_pub_pem
     *          key_encoding_priv_der
     *          key_encoding_encrypted_priv_der
     *          key_encoding_pub_der
     * @param const char* passphrase [inopt]
     */
    return_t decode(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding, const char* passphrase = nullptr);
    return_t decode(OSSL_LIB_CTX* libctx, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding, const char* passphrase = nullptr);
    /**
     * @param OSSL_LIB_CTX* libctx [in]
     * @param const char* name [in]
     * @param EVP_PKEY** pkey [out]
     * @param const binary_t& keydata [in]
     * @param key_encoding_t encoding [in]
     *          key_encoding_priv_pem
     *          key_encoding_encrypted_priv_pem
     *          key_encoding_pub_pem
     *          key_encoding_priv_der
     *          key_encoding_encrypted_priv_der
     *          key_encoding_pub_der
     *          key_encoding_priv_raw
     *          key_encoding_pub_raw
     * @param const char* passphrase [inopt]
     */
    return_t decode(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const binary_t& keydata, key_encoding_t encoding,
                    const char* passphrase = nullptr);
    return_t decode(OSSL_LIB_CTX* libctx, const char* name, EVP_PKEY** pkey, const byte_t* keystream, size_t keysize, key_encoding_t encoding,
                    const char* passphrase = nullptr);
    /**
     * @brief encaps
     * @param OSSL_LIB_CTX* libctx [in]
     * @param const EVP_PKEY* pkey [in] public key
     * @param binary_t& keycapsule [out]
     * @param binary_t& sharedsecret [out]
     */
    return_t encapsule(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, binary_t& keycapsule, binary_t& sharedsecret);
    /**
     * @brief decaps
     * @param OSSL_LIB_CTX* libctx [in]
     * @param const EVP_PKEY* pkey [in] private key
     * @param const binary_t& keycapsule [in] see encapsule
     * @param binary_t& sharedsecret [out]
     */
    return_t decapsule(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, const binary_t& keycapsule, binary_t& sharedsecret);
    return_t decapsule(OSSL_LIB_CTX* libctx, const EVP_PKEY* pkey, const byte_t* capsulekeystream, size_t capsulekeysize, binary_t& sharedsecret);
    /**
     * @brief sign
     * @param OSSL_LIB_CTX* libctx [in]
     * @param EVP_PKEY* pkey [in]
     * @param const byte_t* stream [in]
     * @param size_t size [in]
     * @param binary_t& signature [out]
     */
    return_t sign(OSSL_LIB_CTX* libctx, EVP_PKEY* pkey, const byte_t* stream, size_t size, binary_t& signature);
    /**
     * @brief verify
     * @param OSSL_LIB_CTX* libctx [in]
     * @param EVP_PKEY* pkey [in]
     * @param const byte_t* stream [in]
     * @param size_t size [in]
     * @param const binary_t& signature [in]
     */
    return_t verify(OSSL_LIB_CTX* libctx, EVP_PKEY* pkey, const byte_t* stream, size_t size, const binary_t& signature);
};

}  // namespace crypto
}  // namespace hotplace

#endif
